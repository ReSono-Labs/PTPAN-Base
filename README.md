# Federation Base

Federation Base is a reusable policy and lifecycle layer for relationships between independently operated agent platforms. Each provider runs the same Base, retains authority over its own accounts and agents, and connects the Base to its own account, grant, and runtime systems through host adapters.

The current implementation has three Rust crates and a Go bridge. `federation-base` defines provider identity observations, peer policy, directional relationship requests, destination-issued FRL/1 leases, restrictive lifecycle rules, and live admission decisions. `federation-store` defines the provider-owned persistence and host contracts. `federation-ipc` defines the private boundary between Base and the bridge. The bridge uses the pinned AGNTCY and SPIFFE Go SDKs for Directory operations and authenticated service transport.

## How two providers connect

1. **Establish provider identity.** Each provider presents a versioned provider manifest. The receiving provider compares its fields with independently configured bootstrap authority, AGNTCY Directory naming and record evidence, and the authenticated SPIFFE control-service identity. Identity observations are saved field by field.
2. **Approve the peer.** Each operator makes its own trust decision. A verified service and reciprocal operator approval together open the provider gate for bounded requests. The same Base handles the sending and receiving roles on either provider.
3. **Request one relationship.** A source account owner names a specific agent address at the destination. The source host verifies ownership and sends a durable, idempotent request over the authenticated control connection. The destination host resolves that exact address against its private account store and places the request in the owning account’s inbox. Peer approval exposes no account list or private agent catalog.
4. **Decide and enforce.** The destination owner approves a subset of the requested permissions and lifetime, or denies it. The destination issues the FRL/1 lease and its host adapter provides the enforceable grant. The source stores the exact effective lease. `SINGLE_TASK`, `FIXED`, and `UNTIL_REVOKED` express the relationship lifetime; short live admissions are capped independently.
5. **Maintain authority.** The Base processes acknowledgments, withdrawal, revocation, expiry, renewal, and peer suspension with revision checks and durable event receipts. A live admission call carries a fresh source-host authorization assertion to the destination, where the destination host checks its current grant and issues the bounded result.

Requests work in both directions. A relationship from A to B is separate from a relationship from B to A. Each provider controls its own account decisions, lease enforcement, and local restrictions.

## Upstream components and boundaries

The Go adapter uses `github.com/agntcy/dir/client` and `github.com/agntcy/dir/api` **v1.7.1** for Directory record, naming, signing, verification, and selected synchronization calls. It uses `github.com/agntcy/oasf-sdk/pkg` **v1.1.0** to validate OASF records. `github.com/spiffe/go-spiffe/v2` **v2.8.1** obtains SPIRE workload identities and federated bundles and requires the exact peer service identity on control connections. The bridge passes authenticated evidence and message bytes to Base; Base makes the provider and relationship policy decisions.

The Base keeps provider trust, account consent, and runtime authorization separate. Directory evidence describes a provider or published resource. SPIFFE authenticates a service. The source and destination account owners authorize their respective sides of an exact directional relationship. Provider-managed host adapters own account storage and grant enforcement. The control exchange carries scoped references and decisions; private account inventories, task bodies, and credentials stay with their providers.

Thank you to the AGNTCY developer group for the work on Directory, OASF, and the supporting modules that make independently operated agent platforms interoperable.
