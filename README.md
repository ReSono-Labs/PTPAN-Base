# PTPAN

PTPAN (Private-to-Private Agent Network) connects two independently operated agent platforms. Each platform keeps its own accounts, agents, storage, identifiers and task runtime. PTPAN gives both the same rules for trusting each other and for carrying one private request, and later the agent's traffic, from a user on one platform to an agent on the other.

A platform serves its own users with no peer connected. PTPAN is involved only when a user asks to reach an agent on another platform. Both platforms run the same package; "source" and "destination" are roles in one request.

## What a platform keeps, and what it shares

A platform's internals stay its own: storage, internal IDs, address format, certificate issuing and language. Platforms share only what crosses a boundary:

- the wire messages (`schemas/`),
- the address envelope,
- the agent certificate rule,
- the adapter–platform API (`proto/ptpan/platform/v1/platform.proto`),
- the behaviours the API implies (inbox for the owning account only, atomic decisions, local cutoff before propagation, and so on).

Account lists, agent inventories, internal IDs, grants, keys and task bodies never cross.

## What you install

Each provider runs its own copy of everything below. Two providers share nothing.

| Piece | What it is |
|---|---|
| Your platform | Implements `PlatformService` from the proto file over its own tables. |
| `ptpan-adapter` (Rust) | The adapter runtime: peers, the exchange with other platforms, the platform resolver, admission checks over Base. It serves `AdapterService` to your platform. |
| `bridge-runtime` (Go) | Carries control messages and agent streams between providers over SPIFFE mutual TLS. It makes no trust decision. |
| PostgreSQL | The adapter's exchange store (peers, outbox, inbox). It holds no account data. |
| [SPIRE](https://github.com/spiffe/spire) 1.15.5 server and agent | Issues the bridge its control and edge identities and federates trust bundles with each peer. |

AGNTCY [Directory](https://github.com/agntcy/dir) and [OASF](https://github.com/agntcy/oasf) are optional. A Directory record can be added as extra evidence; onboarding does not need one.

Build with Rust 1.85 and Go 1.27.1:

```sh
cargo build --locked --release -p ptpan-adapter
cd bridge && go build -mod=readonly -o bridge-runtime ./cmd/bridge-runtime
```

`Cargo.lock`, `bridge/go.mod` and `bridge/go.sum` lock every dependency.

### Running it

The adapter, the bridge and the platform run as three different users in one dedicated group. They talk over local Unix sockets (mode 0660), and each side checks the other's exact user ID on every connection.

- Adapter: `ptpan-adapter run adapter.json`. The JSON config holds the platform ID, the provider domain, the adapter's control and edge SPIFFE IDs, the PostgreSQL URL, the socket paths and the user IDs of the platform and bridge, the path of this provider's manifest, the evidence profile and a worker ID. It accepts no unknown fields.
- Bridge: `bridge-runtime --control-listen … --edge-listen … --control-service-id spiffe://<domain>/federation/control --edge-service-id spiffe://<domain>/federation/edge --bridge-socket … --runtime-socket … --runtime-uid … --egress-socket … --ingress-socket … --platform-uid …`, with `SPIFFE_ENDPOINT_SOCKET` pointing at the SPIRE agent. Register both SPIFFE IDs for the bridge's user.
- Operator commands: `ptpan-adapter peer add|approve|approve-pending|suspend|resume|remove`, `ptpan-adapter manifest propose`, `ptpan-adapter status`.

## Connecting two providers

Trust is between operators. It is not a directory of customers.

1. **Bootstrap.** Each operator configures the other provider locally: platform ID, provider domain, exact control and edge SPIFFE IDs and endpoints, and SPIRE bundle endpoint and profile. A remote message cannot replace this.
2. **Manifest.** The first message is the peer's provider manifest (`federation-provider/2`). It carries the platform and operator details; the trust domain, bundle endpoint and the exact control and edge service IDs; the control and edge endpoints; the supported protocols; and the agent CA root. Directory details are optional. Display and operator names stay claims.
3. **Domain proof.** The adapter fetches `https://<provider domain>/.well-known/ptpan-provider.json` (`ptpan-provider-domain/1`). The document is served with the provider's normal WebPKI certificate. It publishes only the platform ID, the control and edge SPIFFE IDs and the agent CA root, and every field must match the manifest and the bootstrap.
4. **Two approvals.** Each operator approves the peer. Request delivery opens only when the peer is active, the identity check has passed, both approvals are recorded, and the authenticated service on the connection is the exact one expected. Either operator can suspend or remove the peer at any time. Removal is final for that record.

**Manifest changes.** Every manifest change must be validated again.

- **Planned change:** the provider sends the proposed revision and its effective time to every peer in advance (`ptpan-adapter manifest propose`). If the peer's operator approves it before that time (`peer approve-pending`), the switch causes no outage.
- **Unapproved or unannounced change:** all traffic with that peer stops until the change is validated and approved again. Revoke, block, withdrawal and suspension still flow while traffic is stopped. Routine certificate renewal under the same identity is not a manifest change.

## From one agent to another

**Addresses.** An address is `<opaque part>.<provider domain>`. PTPAN routes it by the longest trusted provider domain it ends in (case-insensitive, punycode form). The only other checks are for wire safety: at most 253 bytes, using letters, digits, hyphen and dot. The opaque part is carried byte for byte. Only the platform that issued it resolves it.

**The request.** A user on platform A asks to connect one of their agents to an address on B. The request carries:

- A's platform ID,
- the requesting agent's own address (the requester reference),
- the user's name,
- the requested permission and lifetime,
- the target address.

It names no internal account or agent ID on either side.

**On B.** B's platform resolves the address. Only the current owning account gets an inbox item. An unknown, retired or blocked address is answered "not recognized", and nothing more is revealed.

**The decision.** B's owner may:

- approve, possibly with a narrower permission and a shorter lifetime,
- deny,
- block.

An approval carries the owner's name and an FRL/1 lease: fixed expiry, until revoked, or single task. Denials and blocks carry no name. The relationship becomes Ready only after both sides acknowledge the applied configuration. A's acknowledgment also binds the requesting agent's Ed25519 admission key.

**Each call.** A's agent opens a stream through its own bridge with a fresh admission token (a compact JWS, `typ ptpan-admission+jwt`). The token is signed by the agent's key and bound to B's edge identity, the relationship, the lease and a single-use nonce. B checks it, and B's platform decides with an atomic nonce and key-revision check. An allowed stream lasts at most 300 seconds. Revoke, expiry, block, withdrawal or peer suspension stops new calls and closes open streams.

**Agent TLS.** The destination agent's certificate must chain to the destination platform's private CA root, as published in its manifest. It must name the exact address the caller used. No public CA is involved.

The reverse direction is a separate relationship.

## Repository layout

| Path | What it is |
|---|---|
| `crates/federation-base` | Base: every shared rule, implemented once (addresses, manifests, identity evidence, peer transitions, requests, leases, lifecycle, admission) |
| `crates/federation-ipc` | Adapter ↔ bridge local socket protocol (`base-bridge-ipc/v2`) |
| `crates/ptpan-platform-api` | Rust binding of the platform API, Unix-socket transport, stateless policy calls |
| `crates/ptpan-adapter` | Adapter runtime and CLI |
| `bridge` | Go bridge runtime |
| `schemas`, `proto` | Wire schemas, vectors and the platform API |
| `docs/framework` | Developer documentation; `raw/platform-wiring.md` lists everything a platform wires in |
| `crates/ptpan-conformance` | Black-box conformance suite for any `PlatformService` implementation |
| `reference-platform`, `crates/ptpan-test-support` | A small SQLite test platform implementing `PlatformService`, and test stand-ins |
| `scripts/ladder`, `deploy/ladder` | Two-provider Docker ladder, created and removed per run |

Tests: `cargo test --locked --workspace` and `cd bridge && go test ./...`. The PostgreSQL end-to-end tests are ignored by default and read a connection string from `PTPAN_TEST_PG`. The two-provider ladder is `scripts/ladder/run.sh` (Docker).

## Not in this package

- PTPAN does not publish private agents in a public catalog and does not resolve addresses through DNS.
- SLIM is not built. The bridge has a transport seam for it, and `--agent-transport slim` refuses to start; the SLIM implementation is deferred.
- Public `ans://` names and the AGNTCY Identity Service are not part of this connection. If they are enabled later, they must be the upstream projects, not a second copy written here.

## Agent capabilities

The agent's behaviour and capabilities are the responsibility of its owner and its framework. Cross-platform identity, authorization, admission and connection security are the responsibility of the participating platforms.

A platform may later require an external agent to meet an accepted security profile before it allows a connection. PTPAN verifies and enforces that requirement. PTPAN does not define:

- the agent sandbox,
- prompt-injection defences,
- tool permissions,
- secret storage,
- runtime isolation.
