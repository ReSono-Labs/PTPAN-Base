# Federation Base

Federation Base is a host-neutral policy and lifecycle library for relationships between independently operated agent platforms. Each provider runs the same package in both roles. Its own host adapter remains the authority for accounts, agent ownership, grants, admission keys, and task execution. A trusted provider can deliver a request to one private address; provider trust does not publish or enumerate accounts or agents.

## What runs at each provider

| Component | Responsibility |
| --- | --- |
| `federation-base` Rust crate | Provider identity observations, peer policy, directional requests, FRL/1 leases, restrictive lifecycle, and bounded admission. |
| `federation-store` Rust crate | Persistence and host ports. Each provider maps these to its own account, ownership, grant, key, and durable event systems; there is no shared database schema. |
| `federation-ipc` Rust crate | Framed private Unix-socket boundary between the host/Base process and Go bridge. |
| `bridge` Go module | AGNTCY Directory and OASF calls, SPIRE workload identity, and mutual-TLS control delivery. It supplies the authenticated SPIFFE service ID to Base; it cannot approve a peer or relationship. |

The Go bridge is a running service. The Rust crates are libraries called by the provider host; they do not start a background account service. SPIRE agents supply short-lived workload certificates and federated trust bundles through the Workload API. A Directory reconciler processes configured record and name jobs. Base applies policy when its host or bridge calls it and persists transitions through the host adapter.

## Dependencies and build

Install Rust with Cargo for edition 2021 and Go **1.27.1**. `Cargo.lock`, `bridge/go.mod`, and `bridge/go.sum` lock the source dependencies:

```sh
cargo build --locked --workspace
cd bridge
go build -mod=readonly -o bridge-runtime ./cmd/bridge-runtime
```

Each provider deployment runs its **own** AGNTCY Directory API server and reconciler **v1.7.1**, OASF server **v1.1.1** serving schema **1.1.0**, Directory OCI registry and backing database, and SPIRE server and agent **v1.11.2**. The bridge pins `github.com/agntcy/dir/client` and `/api` **v1.7.1**, `github.com/agntcy/oasf-sdk/pkg` **v1.1.0**, and `github.com/spiffe/go-spiffe/v2` **v2.8.1**. These are upstream clients and services. The Directory client supplies record push/pull, signing, verification, publication, naming, and selected synchronization calls; the OASF SDK validates records. The running bridge resolves Directory name evidence by CID and passes it to Base for policy evaluation. Directory owns its records, OCI content, naming results, and reconciliation.

## Provider setup

1. **Create independent infrastructure.** Give each provider its own Directory/OASF, OCI storage, database, SPIRE server and agent, trust domain, and host account/grant store. Configure Directory gRPC X.509 authentication and register its server workload ID, for example `spiffe://provider-a.example/directory/server`.
2. **Configure SPIRE federation.** Register the local control bridge as `spiffe://provider-a.example/federation/control`. Configure reciprocal `https_spiffe` bundle endpoints in the SPIRE servers, bootstrap the foreign bundles, and authorize each bridge registration to federate with the other trust domain. SPIRE issues the bridge's X.509 SVID and refreshes bundles; the bridge reads them from `SPIFFE_ENDPOINT_SOCKET`. Keep an old CA trusted until agents and the foreign bundle have the new CA, then retire it. Both peers match the **exact** control-service ID, not merely the trust domain.
3. **Provision provider evidence.** Keep the Directory record-signing key with its provider. Validate the permitted public OASF provider record, then use Directory's SDK to push, sign, publish, and verify it. Configure Directory naming verification against a provider-controlled domain and its key endpoint. The record and manifest may describe the provider; private agent addresses and account inventories stay out of both.
4. **Configure each host adapter.** Bind the platform ID, address domain, exact peer control endpoint and SPIFFE ID, local Directory service ID, expected provider domain, bundle profile, and independently approved bootstrap authority. Implement the `federation-store` ports with atomic inbox/outbox, current ownership checks, enforceable grants, and private admission-key custody. The account database and schema belong to that provider.
5. **Run one bridge per provider.** Mount a private socket shared only with that provider's Base/host process and the SPIRE Workload API socket. Pass the exact local Directory and foreign control identities. For example:

```sh
SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/agent.sock ./bridge-runtime \
  --listen :8444 \
  --directory directory:8888 \
  --directory-server-id spiffe://provider-a.example/directory/server \
  --oasf http://oasf:8080 \
  --peer-endpoint https://provider-b.example:8444/control \
  --expected-peer spiffe://provider-b.example/federation/control \
  --base-socket /run/federation/base.sock \
  --bridge-socket /run/federation/bridge.sock \
  --base-uid 1000
```

The host supplies the matching Base-side Unix socket and its UID. For multiple approved routes, repeat `--peer spiffe-id=https://host/control`; the bridge sends only to an exact configured service ID. The IPC socket checks the local process UID, and the network listener accepts only an authenticated foreign service ID.

## Trust and request flow

1. **Identify the other provider.** The bridge authenticates the remote control service with SPIRE mutual TLS. Base compares the manifest's platform, domain, service, endpoints, and Directory CID with locally configured bootstrap authority and Directory's verified name, domain, key ID, and record evidence. Each checked field has its own observation. A certificate or Directory record alone does not grant provider trust.
2. **Approve both directions of provider trust.** One operator sends a trust request; the other explicitly approves or rejects it. Each operator independently approves the peer it will accept. Only a verified service, accepted identity evidence, and the required local and remote decisions open request delivery. Removing or suspending a peer closes that gate.
3. **Ask for one private agent.** The source account owner supplies the full destination-domain agent address. Its host checks current source ownership; Base sends an idempotent request over the exact authenticated route. The destination host resolves that address against **its own** account store and queues an Inbox item only for the current owner. An unknown address returns a correlated failure with no destination account disclosure or grant.
4. **Decide the relationship.** The destination owner may deny or approve narrower permissions and lifetime. The destination issues an FRL/1 lease (`FIXED`, `UNTIL_REVOKED`, or `SINGLE_TASK`), installs and checks its enforceable grant, and returns the exact effective terms. The two hosts exchange versioned configuration acknowledgments. Ready is derived from current ownership, grant, lease, key binding, and acknowledged terms; a status message cannot create permission.
5. **Admit each call.** The source host signs a fresh, one-time challenge with its account-owned agent Ed25519 admission key. The destination stores only the scoped public-key binding for that relationship and verifies the signature, source service, agent, key purpose/revision, audience, nonce, lease, current grant, and deadline. An allow is short-lived; it is neither a credential nor a task payload. Revocation, source withdrawal, expiry, and peer suspension restrict later use. A→B and B→A have separate leases and decisions.

The Directory record-signing key, SPIRE CA and workload keys, and account-agent admission key serve different purposes. SPIRE authenticates **which service connected**; Directory verifies **published provider evidence**; Base and the two account authorities decide **whether this exact relationship and call are allowed**. No private key, account inventory, task body, or connector credential travels in the federation control exchange.

Thank you to the AGNTCY developer group for the work on Directory, OASF, and the supporting modules that let separate providers share verifiable public evidence while keeping their private agents under their own control.
