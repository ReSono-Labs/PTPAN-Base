# PTPAN platform wiring (raw framework reference)

Status: raw implementation instructions for platform developers, and the source for the later framework and install documentation. The normative sources are `proto/ptpan/platform/v1/platform.proto` (the platform boundary) and `schemas/` (the wire messages). Where this page and those sources disagree, they win.

## 1. What this covers

This page lists everything a platform must wire in to take part in PTPAN, grouped by where the work lands:

- **Backend:** the gRPC service the platform serves to its adapter, the adapter calls it makes, and the two agent stream sockets (sections 4–6).
- **Data:** what the platform must store, in its own database and schema (section 7).
- **Product surface:** the screens, fields and actions that users and operators need (section 8).
- **Operations:** what is deployed and configured next to the platform (section 9).
- **Wire details:** payloads, frames, configuration and flags (section 14).

A platform keeps its own design. Its tables, IDs, address format, certificate issuing and language stay its own. It only has to meet the behaviour described here.

The reference platform (`reference-platform/`, SQLite) is a complete working example of every item. The conformance suite (`crates/ptpan-conformance`, section 13) checks an implementation as a black box.

## 2. Who owns what

| The platform owns | The PTPAN adapter owns |
|---|---|
| Accounts, login, users, agents, agent keys | The trusted peer list and its state machine (add, approve, suspend, remove, manifest changes) |
| Addresses: issuing, resolving, retiring (its own format under its provider domain) | The platform resolver: address → trusted peer (longest matching domain) |
| Source authority: this account owns this agent | Peer control: mutual TLS with exact SPIFFE IDs, through the bridge |
| Sent list, inbox, notices, the human decision | The exchange: exact event bytes, outbox and inbox in PostgreSQL, retries, receipts, expiry |
| Relationships, leases and grants (authoritative), nonces, pair blocks and block enforcement | Admission token verification (signature, audience, times); stateless policy calls (request validation, terms digest, lease) |
| The hand-off queue: every cross-platform action, written in the same transaction as the action | Delivering hand-off records to peers, and peer events back to the platform |
| Local cutoff on revoke, block, withdrawal and expiry | Propagation to the peer, and closing open streams |
| Carrying agent streams between its agents and the local bridge | Carrying agent streams between providers (bridge relay and edge) |

The adapter never treats grants, leases, ownership or nonces as its own truth; it asks the platform. The platform never talks to another platform directly.

## 3. Endpoints

```text
                       PROVIDER A                                                 PROVIDER B
 +--------------------------------------------+               +--------------------------------------------+
 | Platform                                   |               | Platform                                   |
 |  P1 PlatformService (gRPC, served)  <--+   |               |   +-->  P1 PlatformService                 |
 |  egress socket client  ==========+     |   |               |   |     ingress socket (served)  <====+    |
 |  ingress socket (served) <====+  |     |   |               |   |                                   |    |
 +-------------------------------|--|-----|---+               +---|-----------------------------------|----+
 | ptpan-adapter                 |  |     |   |               |   |  ptpan-adapter                    |    |
 |  A1 AdapterService (gRPC) ----+--|-----+   |               |   +--- A1 AdapterService              |    |
 |  bridge IPC <-> bridge-runtime   |         |               |        bridge IPC <-> bridge-runtime  |    |
 |  PostgreSQL (exchange store)     |         |               |        PostgreSQL                     |    |
 +----------------------------------|---------+               +---------------------------------------|----+
 | bridge-runtime                   v         |               | bridge-runtime                        |    |
 |  C1 /control (mTLS)  <=====================|===============|=====>  C1 /control                    |    |
 |  E1 edge (mTLS)      <=====================|===============|=====>  E1 edge ========================+    |
 |  SPIRE agent (S1)                          |               |  SPIRE agent (S1)                          |
 +--------------------------------------------+               +--------------------------------------------+
   SPIRE server bundle endpoint S2 <================ https_spiffe ================> S2
   W1 https://<provider domain>/.well-known/ptpan-provider.json   (each side's bridge fetches the other's)
```

| ID | Endpoint | Served by | Called by | Transport and authentication |
|---|---|---|---|---|
| P1 | `PlatformService` | Platform | Its own adapter only | gRPC over a Unix socket (mode 0660, one dedicated group). The platform checks the adapter's exact user ID on every connection |
| A1 | `AdapterService` | Adapter | Its own platform only | As P1. The adapter checks the platform's user ID |
| EG | Egress stream socket | Bridge | Platform, for its agents' outbound calls | Unix socket. The platform checks the bridge's user ID. admission framing |
| IN | Ingress stream socket | Platform | Bridge only | Unix socket. The platform checks the bridge's user ID. Header `ptpan-ingress/1` |
| C1 | Peer control `POST /control` | Bridge | Peer bridges | HTTPS, mutual TLS, exact control SPIFFE ID |
| E1 | Agent edge | Bridge | Peer bridges | Mutual TLS, exact edge SPIFFE ID. Carries agent bytes without opening them |
| W1 | Domain document `/.well-known/ptpan-provider.json` | The platform's public web server | Peer bridges | HTTPS with the platform's normal WebPKI certificate |
| S1 | SPIRE Workload API | Local SPIRE agent | Bridge | Local socket |
| S2 | SPIRE bundle endpoint | Platform's SPIRE server | Peer SPIRE servers | `https_spiffe` federation |
| — | Directory / OASF | Optional local services | Bridge tools | Optional evidence only; not needed to onboard |

Peers see only C1, E1, W1 and S2. Agent addresses, internal APIs, the internal resolver and account data are never exposed.

## 4. Backend: `PlatformService` (P1), served by the platform

The adapter retries after failures and restarts. Every RPC marked as returning the same result on replay must do so.

| RPC | When the adapter calls it | What the platform must do | Returns |
|---|---|---|---|
| `GetPlatformInfo` | On every connect | Report its platform ID, its provider domain (lowercase, punycode form) and the API majors it serves (`1`) | `PlatformInfo` |
| `ReadHandoff(after_cursor, limit)` | Continuously, by polling (`Wake` makes it faster) | Return unacknowledged hand-off records after the cursor, in commit order. Each record carries the kind, peer platform ID, relationship ID, request ID, the exact payload JSON (section 14.1), the commit time and this platform's side | `HandoffRecord[]` |
| `AckHandoff(handoff_id)` | Once the event bytes are in the adapter's outbox | Mark the record done. It must stay readable until this call | — |
| `AuthorizeSource(request_id)` | Before a request leaves | Recheck that the requesting account still owns the requesting agent | `authorized`, `ownership_revision` |
| `DeliverInbound(source_platform_id, event_id, request_json)` | A peer's request arrived | Resolve `target_address` with the platform's own resolver. If it maps to a current agent, the address is not retired and the pair is not blocked, create an inbox item for the owning account only. Store the result by (source, event ID); a replay returns the stored result | `QUEUED_FOR_LOCAL_OWNER` or `ADDRESS_NOT_RECOGNIZED`. The second is identical for unknown, retired and blocked addresses |
| `ApplyDecision(source_platform_id, event_id, request_id, decision_json, peer_agent_ca_root, peer_edge_service_id)` | The destination decided on one of our requests | **Approved:** store on the relationship the lease, the owner's name, the peer CA root and the peer edge ID; update the Sent item; write a `CONFIG_ACK` hand-off that binds the requesting agent's Ed25519 admission key. **Denied or blocked:** set the Sent item to "denied" (a block is shown as denied). For a block, also record account-wide block enforcement for that destination address. A replay returns the same result | `APPLIED` or `REJECTED` |
| `ApplyLifecycle(peer_platform_id, event_id, kind, relationship_id, payload_json)` | A peer's revoke, status, source authorization, configuration acknowledgment or pair-block status arrived | **Revoke or status:** cut the relationship off locally. **`CONFIG_ACK` from a source:** bind the peer agent's admission key (did:key and revision) to the relationship, then write our own `CONFIG_ACK`. **`PAIR_BLOCK_STATUS`:** set or clear block enforcement for that requester reference and address | `APPLIED` or `REJECTED` |
| `ConfirmReceipt(handoff_id, result)` | The peer's receipt for one of our events matched the stored bytes | Record the delivery; for example, the Sent item becomes "delivered" | — |
| `RecordNotice(request_id, kind)` | The delivery status of a request we sent changed | Show the requester-only notice on the Sent item: waiting for delivery, delivered, not recognized, unknown provider, peer not active, expired undelivered, or source not authorized | — |
| `GetBoundKey(relationship_id)` | Before verifying an inbound admission token | Return the peer agent's bound admission key | `found`, `did_key`, `key_revision` |
| `AdmitCall(relationship_id, claims_json, verified_key_revision)` | An inbound stream's token passed verification | In one atomic step, check that: the key revision is unchanged; the nonce (`jti`) is unused, and consume it; the relationship is Ready; the lease is current and unexpired; the owner is unchanged; nothing is revoked or blocked. Set a deadline of at most 300 s, never past the lease expiry | `allowed` and `deadline`, or `reason` |

**Readiness.** A relationship is Ready on a side only when all of these hold:

- its lease is current,
- the owner is unchanged,
- it is not revoked, withdrawn or blocked,
- both configuration acknowledgments are recorded.

Base's `derive_ready` implements this rule. Rust platforms call it; platforms in other languages apply the same rule.

## 5. Backend: `AdapterService` (A1), called by the platform

| RPC | When the platform calls it | Use |
|---|---|---|
| `ResolveAddress(address)` | Optional, when a user types a target address | Early feedback. Results: `PEER` (with the peer's agent CA root), `BAD_SYNTAX`, `UNKNOWN_PROVIDER`, `PEER_NOT_ACTIVE`, or `OWN_PLATFORM` (route it internally instead). The adapter checks again at send time either way |
| `ValidateRequest(request_json)` | Before committing a new request | Applies Base's request rules: address envelope, lifetime, permissions, expiry |
| `ComputeTermsDigest(request_json)` | When creating a request | Returns the request terms digest that goes into the request payload |
| `ComputeLease(request_json, lease_id, revision, decision_id, mode, effective_from, expires_at, permissions, ownership_revision, owner_name)` | When an owner approves | Returns the FRL/1 lease with its terms digest. Refuses anything broader than requested (more permissions, or a later expiry) |
| `Wake()` | After committing a hand-off record | A hint only; never needed for correctness |
| `GetHealth()` | For the operator dashboard and "temporarily unavailable" states | Returns component states and, per peer, the state, reachability and number of queued events |

The platform never blocks on the adapter. If the adapter is down, requests commit with their hand-off record. An approval commits as an approved intent, and the lease is computed once the adapter is back.

## 6. Backend: agent streams

**Outbound (source side).**

1. For each call, the platform signs a fresh admission token with the requesting agent's Ed25519 key. The token is a compact JWS with `typ ptpan-admission+jwt` and claims per `schemas/live-admission-v3.json`:
   - `iss`: the platform ID
   - `sub`: the requester reference
   - `aud`: the peer edge ID received in `ApplyDecision`
   - `iat`, and `exp` at most 60 s later
   - `jti`: single use
   - relationship ID, lease ID and lease revision, operation, destination address, key revision

   Rust platforms use Base `sign_admission_token`.
2. It connects to the egress socket and writes one admission frame (section 14.2).
3. It reads one decision frame.
4. On `ALLOW`, it carries the agent's bytes (the agents' own end-to-end TLS) until the deadline.

**Inbound (destination side).** The bridge connects to the platform's ingress socket and writes one `ptpan-ingress/1` header with `destination_address`, `relationship_id` and `deadline`. The platform resolves the address to its agent and passes the bytes to it without decrypting them. It closes the stream at the deadline or at a local cutoff.

**Agent TLS.** The destination agent presents a certificate that chains to its platform's private agent CA root and names the exact address the caller used. The source agent verifies it with the peer CA root it received in `ApplyDecision`.

## 7. Data the platform must store

These are logical records; the platform chooses its own tables and names. The reference platform's tables are in `reference-platform/src/store.rs`.

| Record | Fields needed | Notes |
|---|---|---|
| Account | Internal ID, given name, family name | Names travel in requests (the requester's) and approvals (the owner's) |
| Agent | Internal ID, owning account, ownership revision, Ed25519 admission key and key revision | The revision increments when ownership changes |
| Address | Address (`<opaque>.<provider domain>`), agent, retired flag | Never reassigned or deleted. Retiring stops new requests only. The requesting agent needs an address too: it is the requester reference |
| Sent item | Request ID, account, agent, request JSON, state (waiting for delivery, delivered, not recognized, unknown provider, peer not active, expired, approved, denied) | Visible to the requesting account only |
| Inbox item | Source platform ID, request ID, request JSON, resolved account and agent, ownership revision, approval intent, state (pending, approved intent, configuring, denied, blocked) | Visible to the owning account only |
| Relationship | Relationship ID, side (source or destination), peer platform ID, account, agent, ownership revision, request JSON, lease JSON, local and remote terms digests, owner name, peer CA root, peer edge ID, peer agent key (did:key and revision), both acknowledgments, revoked and withdrawn flags | The authoritative grant |
| Hand-off record | Hand-off ID, cursor, kind, peer, relationship ID, request ID, payload JSON, side, commit time, acknowledged flag | Written in the same transaction as the user action |
| Pair block (destination) | Source platform, requester reference, destination address, state, revision | Makes later requests "not recognized" |
| Block enforcement (source) | Account, destination address, state, revision | Stops every agent of the account from requesting that address |
| Used nonces | `jti`, relationship | Consumed atomically in `AdmitCall`. Can be pruned once the token has expired |
| Inbound event results | Source platform, event ID, result | Makes replays of `DeliverInbound` and the `Apply*` calls return the first result |

The adapter's own PostgreSQL holds only peers, its outbox and inbox, and its own manifest. It never holds account data.

## 8. Product surface: screens, fields and actions

The wording is up to each platform. The content below is what the protocol needs a user or operator to see and do.

### 8.1 Agent owner (any user who owns agents)

| Surface | Fields shown | Actions |
|---|---|---|
| Agent details | The agent's addresses, copyable, so the owner can share them off-platform | Retire an address. New requests to it become "not recognized"; existing relationships continue |
| "Connect to an agent on another platform" | Target address (text input, with an optional live check through `ResolveAddress`); which of my agents makes the request; requested permission; lifetime mode (fixed duration, until revoked, single task) and duration | Send. Addresses on the platform's own domain are routed internally. Possible errors: bad address, unknown provider, provider not connected |
| Sent requests | Target address, my agent, requested terms, status from section 7 (including "waiting for delivery" and "temporarily unavailable") | Withdraw a pending or active relationship |
| Inbox (incoming requests) | Requester's name (given and family), requester reference (their agent's address), source platform, which of my agents was addressed, requested permission, lifetime, request expiry. No free text is carried | Approve (optionally with a narrower permission and a shorter lifetime, never longer than requested), deny, block |
| Relationships | Direction ("I connect to" or "connects to me"), the counterpart's name and address, permission, lease mode and expiry, whether it is Ready and, if not, why (waiting for acknowledgment, revoked, peer suspended, temporarily unavailable) | Revoke (destination side) or withdraw (source side) |
| Blocks | Blocked requester references and addresses | Unblock |

The requester learns nothing about the destination account except the owner's name on an approval. Denials and blocks carry no name and look the same.

### 8.2 Platform operator (admin)

| Surface | Source | Actions |
|---|---|---|
| Peer providers | Adapter `GetHealth` (state, reachability, queued events); `ptpan-adapter status` | Add a peer bootstrap, approve, approve a pending manifest revision, suspend, resume, remove (`ptpan-adapter peer …`). A platform may wrap these CLI commands in its admin UI |
| Peer bootstrap form | Platform ID, provider domain, control SPIFFE ID and endpoint, edge SPIFFE ID and endpoint, SPIRE bundle endpoint and profile, maximum evidence age (section 14.3) | Saved locally only. A remote message cannot change it |
| Peer review before approval | The peer's manifest (display and operator names are claims), the result of the domain-document check, any field mismatches | Approve, or leave pending |
| Own manifest | Current revision; any proposed revision and its effective time | `ptpan-adapter manifest propose` for planned changes |
| Health | Adapter, bridge and SPIRE components; reachability per peer | Drives "temporarily unavailable" in user views |

## 9. Operations: what to deploy and configure

1. **Provider domain and W1.** Serve `https://<provider domain>/.well-known/ptpan-provider.json` (`schemas/provider-domain-v1.json`) with the platform ID, the control and edge SPIFFE IDs and the agent CA root. Every field must match the manifest.
2. **Agent CA.** Run a private CA whose root appears in the manifest and in W1. Agent certificates name their addresses.
3. **SPIRE.** Run a server in the provider's own trust domain, with a bundle endpoint federated with each peer, and an agent on the bridge host. Create the two bridge registrations (section 14.6).
4. **Processes.** Run three users in one group:
   - the platform,
   - `ptpan-adapter run adapter.json`, with PostgreSQL (section 14.4),
   - `bridge-runtime` (section 14.5).

   Expose C1 and E1 to peers. Keep every socket local.
5. **Manifest.** Place a `federation-provider/2` manifest (`schemas/provider-manifest-v2.json`) at the adapter's `manifest_path`.
6. **Rate limits and audit.** Apply rate limits per peer and per requester reference. Audit consent and enforcement metadata only, never task content or secrets.

## 10. Flows

**Onboarding (once per peer).**

1. The operators exchange bootstrap details out of band, and each adds the other's.
2. The bridges exchange manifests over C1.
3. Each adapter fetches the other's W1 document and checks every field.
4. Both operators approve. The peer becomes active without restarts.

**Request.**

1. The user sends from the connect screen (8.1).
2. The platform commits the Sent item and a `RELATIONSHIP_REQUEST` hand-off in one transaction.
3. The adapter reads the hand-off, calls `AuthorizeSource`, resolves the peer, sends the request over C1 and acknowledges the hand-off.
4. B's adapter calls `DeliverInbound`, and B's owner sees an inbox item.
5. A sees "delivered" through `ConfirmReceipt` and `RecordNotice`.

**Decision.**

1. B's owner approves.
2. B calls `ComputeLease`, then commits the relationship, the grant (not yet usable) and a `RELATIONSHIP_DECISION` hand-off.
3. A's adapter calls `ApplyDecision`.
4. A writes a `CONFIG_ACK` carrying the agent's key.
5. B binds the key through `ApplyLifecycle` and acknowledges.
6. Both sides are Ready.

**Call.**

1. A's agent opens a stream through EG (section 6).
2. B's bridge sends `ADMIT` to its adapter.
3. B's adapter verifies the token using `GetBoundKey`.
4. B's platform decides in `AdmitCall`.
5. Bytes flow to B's agent through IN until the deadline.

**Revoke, block, withdraw.** The platform cuts off locally first, then writes the hand-off. The peer applies it through `ApplyLifecycle`, and both adapters close open streams. Blocks and unblocks travel as `PAIR_BLOCK_STATUS`.

## 11. Failure behaviour

| Down | Effect | Recovery |
|---|---|---|
| Adapter, bridge or SPIRE agent | Cross-platform features fail closed. New requests and approvals wait as hand-off records or intents. Local cutoffs still apply. The platform's own features are unaffected | The adapter resumes from the hand-off queue and its outbox; nothing is redone |
| The platform (P1) | The adapter keeps peer events queued | Delivered when P1 is back |
| A peer | Events stay queued until they expire; calls fail | Delivered when the peer returns |
| Optional Directory/OASF | No effect on onboarding or traffic | — |

## 12. Checklist

- [ ] P1: all `PlatformService` RPCs in section 4, with replay-safe results, on a local socket that only the adapter can reach
- [ ] A1 calls: `ValidateRequest`, `ComputeTermsDigest`, `ComputeLease`, `Wake`, `GetHealth`, and optionally `ResolveAddress`
- [ ] A hand-off record in the same transaction as every cross-platform action
- [ ] Addresses under the provider domain, never reassigned, retire-only, one for each participating agent
- [ ] The records in section 7, including nonces, blocks and inbound event results
- [ ] The user surfaces in 8.1 and the operator surfaces in 8.2
- [ ] Egress signing and ingress delivery (section 6); agent certificates per the agent TLS rule (section 6)
- [ ] The W1 document, SPIRE registrations, process users and sockets (section 9)
- [ ] The conformance suite passes against the implementation (section 13). The Docker ladder (`scripts/ladder/run.sh`) shows the end-to-end pattern

## 13. Checking an implementation

`crates/ptpan-conformance` drives a `PlatformService` as a black box. It stands in for the adapter, serving `AdapterService` from the same Base policy calls, and plays the peer. The platform supplies a `Driver` for the actions the API does not carry: add an account and an agent, retire an address, create a request, approve, block, revoke. `reference-platform/tests/conformance.rs` is a complete driver.

The suite checks:

- hand-off records persist until acknowledged;
- no internal account or agent ID appears in what crosses;
- the request carries the requester reference and name;
- replaying a decision returns the same result;
- the source acknowledgment binds the agent's key;
- pair blocks apply to the whole account;
- unknown, retired and blocked addresses all answer "not recognized";
- an approval carries the owner's name;
- the bound key is returned;
- a nonce is single-use;
- the key revision is rechecked;
- streams are capped at 300 s;
- a revoke cuts off admission;
- block decisions carry no name.

It does not check agent TLS, `SINGLE_TASK` binding, rate limits or audit.

## 14. Wire details

### 14.1 Hand-off payloads (`payload_json`, per `ControlKind`)

All shapes are defined in `schemas/control-event-v3.json` (`$defs`); unknown fields are refused. Times are RFC 3339 UTC. Digests are lowercase hex SHA-256 over RFC 8785 JCS.

| Kind | Written by | Payload fields |
|---|---|---|
| `RELATIONSHIP_REQUEST` | Source, when the user sends | `request` (below), `request_terms_digest` (from `ComputeTermsDigest`) |
| `RELATIONSHIP_DECISION` | Destination, after the owner decides | `decision_id`, `result` (`APPROVED`, `DENIED`, `BLOCKED`), `bound_request_revision`, `request_terms_digest`, `destination_ownership_revision`, `destination_owner_name` (approval only), `lease` (approval only, from `ComputeLease`) |
| `RELATIONSHIP_REVOKE` | Either side | `revocation_id`, `lease_id`, `lease_revision`, `reason_code`, `effective_at` |
| `RELATIONSHIP_STATUS` | Either side | `lease_id`, `lease_revision`, `state` (`CONFIGURING`, `READY`, `REVOKED`, `EXPIRED`, `CONSUMED`, `SUSPENDED`), `observed_at` |
| `SOURCE_AUTHORIZATION_STATUS` | Source (withdrawal) | `lease_id`, `lease_revision`, `authorization_revision`, `status` (`AUTHORIZED`, `WITHDRAWN`), `effective_at` |
| `CONFIG_ACK` | Both sides, after applying | `lease_id`, `lease_revision`, `configuration_revision`, `key_purpose_revision`, `acknowledged_at`. The source also adds `source_key`: `requester_reference`, `destination_address`, `terms_digest`, `key_purpose` (`ed25519_admission`), `public_key` (hex) |
| `PAIR_BLOCK_STATUS` | Destination, on block and unblock | `requester_reference`, `destination_address`, `state` (`BLOCKED`, `OPEN`), `block_revision`, `effective_at`. The relationship ID is empty |

The adapter wraps each payload in the event envelope (event ID, sender, recipient, actor side and revision, delivery expiry). The platform never builds envelopes.

**Request** (`relationshipRequest`):

| Field | Content |
|---|---|
| `relationship_id`, `request_id` | Opaque IDs chosen by the source |
| `source` | `platform_id`, and `address` (the requester reference) |
| `source_ownership_revision` | The requesting agent's ownership revision |
| `requester_name` | `given_name`, `family_name` |
| `request_kind` | `ESTABLISH`, `RENEW` or `MODIFY` |
| `request_revision` | Revision of this request |
| `base_lease_revision` | Null for `ESTABLISH` |
| `application_protocol` | `a2a` |
| `transport` | `tls13` |
| `target_address` | The destination address |
| `requested_permissions` | For example `a2a.invoke` |
| `requested_lifetime` | `mode` (`SINGLE_TASK`, `FIXED` or `UNTIL_REVOKED`); `expires_at` for the first two |
| `created_at`, `request_expires_at` | Unix seconds |

**Lease** (`lease`): `lease_id`, `lease_revision`, `mode`, `effective_from`, `expires_at`, `max_tasks`, `effective_permissions`, `terms_digest`. Store it exactly as returned.

### 14.2 Stream frames

Every frame is a 4-byte big-endian length followed by a JSON body of 1 to 8192 bytes.

- **Egress, platform → bridge:** `{"schema": "live-admission/v3", "token": "<JWS>", "destination_address": "...", "relationship_id": "..."}`. The reply is `{"result": "ALLOW", "deadline": <unix s>}` or `{"result": "DENY", "reason": "..."}`. After `ALLOW`, raw agent bytes flow in both directions.
- **Ingress, bridge → platform:** `{"schema": "ptpan-ingress/1", "destination_address": "...", "relationship_id": "...", "deadline": <unix s>}`, followed by raw agent bytes.

### 14.3 Peer bootstrap (operator input, `ptpan-adapter peer add <config> <bootstrap.json>`)

| Field | Content |
|---|---|
| `peer` | Peer platform ID |
| `provider_domain` | Peer provider domain |
| `expected_control_service_id` | Peer control SPIFFE ID |
| `expected_control_endpoint` | `https://…/control` |
| `expected_edge_service_id` | Peer edge SPIFFE ID |
| `expected_edge_endpoint` | `host:port` |
| `expected_bundle_endpoint` | Peer SPIRE bundle endpoint |
| `expected_bundle_profile` | `https_spiffe` |
| `max_evidence_age_seconds` | Maximum evidence age |

### 14.4 Adapter configuration (`adapter.json`, unknown fields refused)

| Field | Content |
|---|---|
| `platform_id`, `provider_domain` | This platform's identity |
| `control_service_id`, `edge_service_id` | This adapter's control and edge SPIFFE IDs |
| `database_url` | PostgreSQL connection string |
| `platform_socket` | P1 |
| `adapter_socket` | A1 |
| `platform_uid` | User ID of the platform process |
| `runtime_socket` | Served for the bridge |
| `bridge_socket` | The bridge's socket |
| `bridge_uid` | User ID of the bridge process |
| `manifest_path` | This provider's manifest |
| `evidence_profile` | `PRODUCTION_HTTPS`; `LOCAL_HTTP_TEST` only for isolated test stacks |
| `worker_id` | Unique per adapter copy |

### 14.5 Bridge flags

| Flag | Value |
|---|---|
| `--control-listen` | Control listener address |
| `--edge-listen` | Edge listener address |
| `--control-service-id` | This platform's control SPIFFE ID |
| `--edge-service-id` | This platform's edge SPIFFE ID |
| `--bridge-socket` | IPC socket the bridge serves for the adapter |
| `--runtime-socket` | The adapter's IPC socket |
| `--runtime-uid` | User ID of the adapter process |
| `--egress-socket` | Socket for the platform's outbound agent streams |
| `--ingress-socket` | The platform's socket for inbound agent streams |
| `--platform-uid` | User ID of the platform process |
| `--agent-transport` | `tls` (the only transport; SLIM is not built) |
| `--test-allow-http-domain-proof` | Isolated test stacks only |

The environment variable `SPIFFE_ENDPOINT_SOCKET` points at the local SPIRE agent.

### 14.6 SPIRE registration

On the provider's SPIRE server, create two entries for the bridge host's agent:

- `spiffe://<domain>/federation/control`
- `spiffe://<domain>/federation/edge`

Both select the bridge's user (for example `unix:uid:<bridge uid>`) and both carry `-federatesWith spiffe://<peer domain>` for each peer. Row 01 of `scripts/ladder/run.sh` shows the exact commands.

## 15. Not covered

These are still open or deferred:

- SLIM: not built; deferred. When built, it applies only to platforms whose agents speak SLIM natively; a platform must not terminate agent traffic in a SLIM-to-TLS gateway, because PTPAN's ingress carries opaque agent bytes.
- Source-owner attestation: today the destination trusts the source platform's statement that its account authorized the request.
- Group consent for multi-agent work.
