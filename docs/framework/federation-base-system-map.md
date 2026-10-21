# PTPAN system map

Working map for developers. Versions are the pins in `Cargo.lock`, `bridge/go.mod` and `compatibility/selected-upstream.json`.

## 1. Processes at one provider

Each provider runs its own copy of every piece; two providers share nothing.

| Piece | Role | Talks to |
|---|---|---|
| Platform | Accounts, agents, ownership, addresses, inbox, grants, agent keys, task runtime. Implements `PlatformService`. | Adapter (gRPC over a Unix socket), bridge (agent stream sockets) |
| `ptpan-adapter` | Peers and their state machine, the exchange outbox and inbox (PostgreSQL), the platform resolver, admission verification. Serves `AdapterService`. All rules come from Base. | Platform, bridge (`base-bridge-ipc/v2`), PostgreSQL |
| `federation-base` | The library holding every shared rule: address envelope, manifest parsing, identity evidence, peer transitions, requests, leases, lifecycle, admission JWS. | Linked into the adapter and the API crate |
| `bridge-runtime` | SPIFFE mutual TLS for peer control (`POST /control`) and agent streams (edge). Fetches the provider domain document. Makes no trust decision. | Adapter, platform stream sockets, SPIRE agent, peer bridges |
| SPIRE server and agent | Issue the bridge its control and edge SVIDs; federate bundles with each peer (`https_spiffe`). | Bridge (Workload API) |
| PostgreSQL | The adapter's exchange store. No account data. | Adapter |

Local sockets are mode 0660 in one dedicated group; every connection checks the exact peer user ID (`SO_PEERCRED`).

## 2. Bridge IPC (`base-bridge-ipc/v2`)

Adapter to bridge: `SEND_CONTROL` (exact bytes to one exact control service), `SET_PEERS` (the live peer set: control and edge service IDs and endpoints), `FETCH_DOMAIN_PROOF`, `CLOSE_STREAMS`. Bridge to adapter: `RECEIVE_CONTROL` (bytes plus the authenticated SPIFFE ID), `ADMIT` (an inbound stream's admission frame), `ROUTE_EGRESS` (where an outbound stream goes). A platform ID inside a JSON body is never authentication.

## 3. Onboarding

1. The operator adds a bootstrap for the peer (`ptpan-adapter peer add`): platform ID, provider domain, exact control and edge IDs and endpoints, bundle endpoint and profile.
2. The peer's first message is its manifest (`federation-provider/2`, `schemas/provider-manifest-v2.json`).
3. The adapter has the bridge fetch `https://<domain>/.well-known/ptpan-provider.json` (`ptpan-provider-domain/1`). `evaluate_provider_identity` accepts the peer only when the authenticated service, the manifest, the bootstrap and the document all agree.
4. Both operators approve. `PeerRecord` (Base) opens request delivery only when active, verified, approved on both sides and authenticated as the exact expected service.
5. Manifest changes: an announced revision approved in advance keeps traffic; anything else cuts it off until approved again. Restrictions still flow.

Directory and OASF are optional evidence. Their clients are in `bridge/upstream`; the runtime does not open them.

## 4. One request

```text
A platform --hand-off--> A adapter --control/mTLS--> B adapter --DeliverInbound--> B platform (resolves, owner inbox)
B platform --hand-off (decision via ComputeLease)--> B adapter --> A adapter --ApplyDecision--> A platform
both platforms --CONFIG_ACK hand-offs--> Ready on both sides; A's ack binds the agent's Ed25519 key
```

The source routes by `ResolveAddress` (longest trusted domain). The destination resolves the opaque part itself. Unknown, retired and blocked addresses all answer "not recognized".

## 5. One call

The source agent writes an admission frame with a fresh JWS (`typ ptpan-admission+jwt`) to the platform's egress socket. The bridge asks the adapter where it goes (`ROUTE_EGRESS`), opens the edge mTLS connection to the exact peer edge ID, and the destination bridge hands the frame to its adapter (`ADMIT`). The adapter verifies the token over the key from `GetBoundKey`, then the platform decides atomically in `AdmitCall` (nonce, key revision, Ready). An allowed stream gets a deadline of at most 300 s; revoke, block, suspension or removal closes it through `CLOSE_STREAMS`.

## 6. Not in this profile

No public DNS resolution of addresses, no public agent catalog, no `ans://` verifier, no AGNTCY Identity Service. SLIM is not built: the bridge's transport seam refuses it (`ErrSLIMNotBuilt`) and the implementation is deferred. A real-domain WebPKI run of the domain document has not been done yet; the Docker ladder proves the same rule over HTTP in its test profile.
