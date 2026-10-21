# Reference labels used in the code

Code comments, schemas and tests cite short labels for the rule they implement. This page says what each label means.

## Design decisions (D)

| Label | Rule |
|---|---|
| D1 | The adapter runs as a separate service next to the platform. The platform owns accounts, agents, grants, leases, nonces and its hand-off queue. The adapter owns peers and the exchange with other platforms, and offers stateless policy calls (request validation, terms digest, lease). |
| D2 | One language-neutral adapter–platform API (`proto/ptpan/platform/v1/platform.proto`) with declared versions; unknown versions are refused. |
| D3 | The adapter carries agent traffic between platforms: source relay to destination edge over mutual TLS with the exact edge SPIFFE ID, agent TLS passed through unopened. SLIM is not built. |
| D4 | Per-call admission: the requesting agent signs a compact JWS with its Ed25519 key (`did:key` kid); the destination adapter verifies it, and the platform decides atomically (nonce, key revision). |
| D5 | Identity on the wire is addresses only: the target address and the requester reference (the requesting agent's own address). No internal account or agent ID crosses. |
| D6 | Both humans' names cross: the requester's on the request, the owner's on an approval. Denials and blocks carry no name. |
| D7 | Blocks: the destination records a pair block and sends `PAIR_BLOCK_STATUS`; the source enforces it for every agent of the account. A block looks like a denial. |
| D8 | Every manifest change is revalidated. An announced revision approved before its effective time causes no outage; anything else cuts traffic off until approved. Restrictions still flow. |
| D10 | Address model: `<opaque part>.<provider domain>`, routed by the longest trusted domain; only wire safety is checked; only the issuing platform resolves the opaque part. |
| D11 | Admission framing: one length-prefixed JSON frame before the agent bytes on the egress socket and on the edge. |
| D12 | Lifetimes: proof window at most 60 s, streams at most 300 s and never past the lease, clock skew at most 5 s. |
| D13 | Agent TLS: the destination agent's certificate chains to its platform's private CA root from the manifest and names the exact address used. No public CA. |
| D14 | Domain proof: `https://<provider domain>/.well-known/ptpan-provider.json`, served with the platform's WebPKI certificate, naming the platform ID, control and edge SPIFFE IDs and agent CA root. Directory evidence is optional. |

## Platform requirements (H)

| Label | Requirement |
|---|---|
| H1 | Platform identity: platform ID, provider domain, control and edge SPIFFE IDs and endpoints, bundle endpoint. |
| H2 | Addresses bound to one current agent, never reassigned, retired permanently. |
| H3 | Internal resolver: address → current owner and agent; unknown, retired or blocked → "not recognized". |
| H4 | Source authority: the account owns the requesting agent, with an ownership revision. |
| H5 | Sent list and requester-only notices. |
| H6 | Inbox for the owning account only; approve (optionally narrower), deny, block. |
| H7 | One transaction for decision, lease, grant and hand-off record. |
| H8 | Replays return the first result; altered bytes conflict. |
| H9 | Binding of the peer agent's admission key per relationship. |
| H10 | Ready only after both sides acknowledge the applied configuration. |
| H11 | Per-call admission: signature, audience, nonce, lease, grant, owner, deadline. |
| H12a, H12b | Agent stream egress to the local bridge, and ingress from the local bridge only, without decrypting. |
| H13 | Revoke, expiry, withdrawal and block: local cutoff first, then propagation; open streams closed. |
| H14 | Rate limits; audit of consent and enforcement metadata only. |
| H15 | Hand-off queue: every cross-platform action written in the same transaction as the action, kept until the adapter acknowledges it. |

## Principles

| Label | Principle |
|---|---|
| principle 3 | Resolution happens on platforms only: the source routes by domain, the destination resolves the opaque part. |
| principle 9 | The adapter is separate from the platform; a platform's own features never depend on it. |
| principle 10 | One live list of trusted peers; configuration changes need no restarts. |
| principle 11 | Fail closed and recover: when a component is down, cross-platform work waits and resumes; nothing is redone. |

## Other labels

| Label | Meaning |
|---|---|
| review 11.2 | The platform resolver in the adapter: address → trusted peer. |
| review 11.8 | A black-box conformance suite for any `PlatformService` (`crates/ptpan-conformance`). |
| review 12.5 | "Not recognized" is identical for unknown, retired and blocked addresses. |
| review 16.8 | Open question: SLIM between independently operated platforms. |
| review section 14 | The platform requirements list (H1–H15 above). |
