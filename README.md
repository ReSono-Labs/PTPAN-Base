# Federation Base

Federation Base is the connection between two independently operated agent platforms. Each platform keeps its own accounts, agents, grants, keys, and task runtime. Base does not merge those interiors. It gives both platforms the same rules for trusting each other and for carrying one private request from a user on one platform to an agent that lives on the other.

A platform can keep serving its own users with no peer connected. Base is involved when a user asks to reach an agent on a different platform.

Both platforms run this same package. "Source" and "destination" are roles in one request, not two different products.

## What stays inside a platform

The platform's own host adapter is the authority for:

- accounts and login
- which account owns which agent
- the private index from a short handle to that agent
- the enforceable grant
- the agent's admission signing key
- task execution

Federation Base supplies the policy types and the required outcomes. It does not ship a shared account database or a production SQL schema. Two platforms never query each other's account tables.

## What you install

Install Rust (edition 2021) and Go **1.27.1**. From this repository:

```sh
cargo build --locked --workspace
cd bridge
go build -mod=readonly -o bridge-runtime ./cmd/bridge-runtime
```

`Cargo.lock`, `bridge/go.mod`, and `bridge/go.sum` are the locked dependencies. The Go module path is `federation-base/bridge`.

That build produces libraries and one bridge process. It does not start a platform. Each provider also runs its **own** copies of the services below. Provider A and provider B do not share them.

| Service | Pinned release | What it is for |
|---|---|---|
| [AGNTCY Directory](https://github.com/agntcy/dir) API server and reconciler | v1.7.1 | This provider's record store, signatures, naming, and selected sync |
| [AGNTCY OASF](https://github.com/agntcy/oasf) server | 1.1.1, schema 1.1.0 | Validates this provider's public records |
| [SPIRE](https://github.com/spiffe/spire) server and agent | 1.11.2 | Workload certificates and federated trust bundles |
| OCI registry and Postgres | Directory's own backing services | Directory content and its database, local to this provider |

Go modules called by the bridge:

| Module | Version | Called for |
|---|---|---|
| `github.com/agntcy/dir/client` and `github.com/agntcy/dir/api` | v1.7.1 | Directory store, sign, routing, naming, and catalog clients |
| `github.com/agntcy/oasf-sdk/pkg` | v1.1.0 | Record validation against the local OASF server |
| `github.com/spiffe/go-spiffe/v2` | v2.8.1 | SPIRE Workload API, mutual TLS, exact SPIFFE ID checks |

## How those frameworks are wired in

The Rust crates do not speak Directory or SPIRE. The Go bridge does, and it does not make trust decisions.

```text
platform host  -->  federation-base (policy)
       |                 ^
       |                 | private Unix socket, already-authenticated SPIFFE ID
       v                 |
account / grant    bridge-runtime
store                   |
                        +--> this provider's Directory (exact server SPIFFE ID)
                        +--> this provider's OASF server
                        +--> this provider's SPIRE agent
                        +--> the other provider's control endpoint (exact peer SPIFFE ID)
```

**Directory.** `bridge/upstream` builds the official Directory client interfaces on one gRPC connection. It does not use the upstream convenience constructor whose x509 mode accepts any SPIFFE ID. The connection requires the Directory server ID configured for this provider, for example `spiffe://provider-a.example/directory/server`. The client can push, pull, sign, verify, publish, unpublish, and resolve names. The running bridge uses it to fetch Directory's verification result for one record CID and hand that evidence to Base. Publishing a record is a separate operator action. Connecting to another provider does not publish this provider's agents.

**OASF.** At startup the bridge opens the OASF validator and schema client against this provider's OASF URL. A record that fails that check is not provider evidence. OASF does not approve a peer or a relationship.

**SPIRE.** The bridge reads `SPIFFE_ENDPOINT_SOCKET`. SPIRE issues the bridge's X.509 SVID and refreshes federated bundles. Peer control is mutual TLS to `https://<peer>/control`. Both sides authorize one exact service ID, `spiffe://<their-domain>/federation/control`, not "any service in that trust domain." SPIRE, not Base, administers bundle rotation.

**The socket between Base and the bridge.** Schema `base-bridge-ipc/v1`. The operations are send control, receive control, and resolve name evidence. The socket file is private to the two local processes, and each side checks the other's user ID. The SPIFFE ID on an inbound call is the one the bridge took from the peer certificate. A platform ID written in JSON is not authentication.

## Provider-to-provider trust

Trust is between operators, about their control services. It is not a directory of customers.

Before the first hello, each operator locally configures the other provider's platform ID, domain, exact control SPIFFE ID, control URL, Directory endpoint, and bundle endpoint. That local configuration is the bootstrap. A remote message cannot replace it.

The first message the other provider sends is a provider manifest. It describes the provider, not its customers:

- platform ID, display name, operator name, and website
- its Directory endpoint, catalog URL, and the CIDs of the public records it is willing to name
- trust domain, SPIRE bundle endpoint, bundle profile, and the exact control-service SPIFFE ID with role `CONTROL`
- its control URL, the protocols `federation-peer/v1` and `federation-control/v1`, and lease profile `FRL/1`

Display name and operator name remain claims. Base records each checked field separately. The peer is accepted only when all of the following match the local bootstrap:

- the SPIFFE ID on the live connection
- the service ID and `CONTROL` role in the manifest
- the trust domain and the website host
- the control URL, both control protocols, and `FRL/1`
- the Directory endpoint, bundle endpoint, and bundle profile
- Directory's own verification of the named record: domain, key ID, verification time, record name, and a CID listed on the manifest

A certificate alone does not open trust. A Directory record alone does not open trust. An operator approval alone does not open trust.

After the evidence matches, each operator still has to approve the peer it will accept. Request delivery stays closed until the peer is active, both approvals are recorded, the identity check passed, and the exact control service is the one on the connection. Either operator can suspend or remove the peer. A changed manifest drops approval until it is reviewed again.

## What is shared, and what is not

On first connection the two providers exchange the manifest above and Directory's verification result for the named public record. They do not exchange:

- account lists or agent inventories
- private short handles
- grants, leases, or admission keys
- task bodies or connector credentials
- SPIRE private keys or Directory signing keys

A later agent request adds one address and the requester's own identifiers. It still does not include the destination account.

## From one agent to another

A user on platform A already has B's short handle, for example `0123456789abcdef.provider-b.example`. The characters before the dot are an opaque label. They are not a DNS name and they are not an account ID. A does not look them up.

A looks only at the suffix, `provider-b.example`. That suffix must be the verified domain of a provider A already trusts, and A's request gate to that provider must be open. If the suffix belongs to anyone else, A refuses to send. If it matches, A sends the whole string, unchanged, to B's control service.

The request names A's platform, A's account, and A's agent. It names the permission and lifetime A is asking for. It does not name B's account or B's agent. B is the only platform that can know those.

B checks that the suffix is B's own domain, then looks the label up in B's private index and joins it to the agent B owns right now. One current owner gets an inbox item. That is a request waiting for a decision, not access. If the label is unknown or retired, B returns `ADDRESS_NOT_RECOGNIZED` and creates no grant. A's requesting account sees a correction notice. No other account on A sees it, and the notice does not reveal who owns what on B.

B's owner may refuse, or approve a narrower permission and a shorter lifetime. B issues an FRL/1 lease in one of three modes: a fixed expiry, until revoked, or a single task. B installs the grant in B's own store. Both sides acknowledge the configuration. The relationship is usable only when the grant, the lease, the current owner, and those acknowledgements still agree. A status message cannot create that permission.

When A's agent actually calls, A signs a fresh one-time challenge with that agent's admission key. B checks the signature, the audience, the nonce, the lease, the grant, and the deadline. The allow covers that call. It is not a reusable credential and it is not the task body. Revocation, expiry, a withdrawn source, or a suspended peer stops later calls.

The reverse direction is a second relationship. B asks for an A-domain handle, and A resolves it in A's own index. A grant from A to B does not authorize B to A.

## Layout of this repository

| Path | What it is |
|---|---|
| `crates/federation-base` | Identity checks, peer gate, requests, FRL/1 leases, lifecycle, admission decision |
| `crates/federation-store` | Ports a platform implements for peers, durable events, and the private short-address index |
| `crates/federation-ipc` | The local socket protocol between the host and the bridge |
| `bridge` | Directory, OASF, and SPIRE integration, and authenticated control delivery |
| `schemas` | Control and admission JSON profiles used on the wire |

## Not in this package

This profile does not publish private agents into a public catalog. It does not resolve short handles through DNS. Public `ans://` names, SLIM transport, and the AGNTCY Identity Service are not part of this connection; if one of those is enabled later, it has to be the upstream project, not a second copy written here. A Directory record, a SPIRE certificate, and an owner approval answer different questions, and all three are required before a request can be delivered.
