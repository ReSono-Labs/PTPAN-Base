//! Generates and verifies `schemas/terms-v1/vectors.json`, the Rust/Go
//! canonical-terms parity vectors. `--verify` compares; no argument prints.
use federation_base::encoding::hex_lower as hex;
use federation_base::{
    LeaseMode, LifetimeRequest, OpaqueId, Participant, PersonName, PlatformId, RelationshipLease,
    RelationshipRequest, RequestKind,
};
use std::collections::BTreeSet;

fn id(value: &str) -> OpaqueId {
    OpaqueId::new(value).unwrap()
}
fn platform(value: &str) -> PlatformId {
    PlatformId::new(value).unwrap()
}

fn main() {
    let request = RelationshipRequest {
        relationship_id: id("rel-a-b-1"),
        request_id: id("req-a-1"),
        source: Participant {
            platform_id: platform("provider-a"),
            address: "Team.Calendar-7.provider-a.test".into(),
        },
        source_ownership_revision: 1,
        requester_name: PersonName {
            given_name: "José".into(),
            family_name: "Núñez".into(),
        },
        request_kind: RequestKind::Establish,
        request_revision: 1,
        base_lease_revision: None,
        application_protocol: "a2a".into(),
        transport: "https".into(),
        target_address: "0123456789abcdef.provider-b.test".into(),
        requested_permissions: BTreeSet::from(["a2a.invoke".into()]),
        requested_lifetime: LifetimeRequest::Fixed {
            expires_at: 2_593_000,
        },
        created_at: 1_000,
        request_expires_at: 1_200,
    };
    let owner = PersonName {
        given_name: "Grace".into(),
        family_name: "Hopper".into(),
    };
    let lease = RelationshipLease {
        lease_id: id("lease-b-1"),
        relationship_id: id("rel-a-b-1"),
        lease_revision: 1,
        mode: LeaseMode::Fixed,
        effective_from: 1_100,
        expires_at: Some(4_700),
        max_tasks: None,
        granted_by_platform_id: platform("provider-b"),
        decision_id: id("decision-b-1"),
        request_id: id("req-a-1"),
        effective_permissions: BTreeSet::from(["a2a.invoke".into()]),
        terms_digest: [0; 32],
    };
    let request_json = String::from_utf8(request.canonical_requested_terms().unwrap()).unwrap();
    let request_sha = hex(&request.request_terms_digest().unwrap());
    let effective_json = String::from_utf8(
        lease
            .canonical_effective_terms(&request, 1, &owner)
            .unwrap(),
    )
    .unwrap();
    let effective_sha = hex(&lease
        .compute_terms_digest(&request, 1, &owner)
        .unwrap());
    let vector = serde_json::json!({
        "profile": "federation-terms-v1",
        "description": "A requests 30-day FIXED; B approves one hour. Agents are named only by address and requester reference; humans by their account names. No internal account or agent ID.",
        "request_canonical": request_json,
        "request_sha256": request_sha,
        "effective_canonical": effective_json,
        "effective_sha256": effective_sha,
    });
    if std::env::args().any(|arg| arg == "--verify") {
        let saved: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/terms-v1/vectors.json")).unwrap();
        assert_eq!(saved, vector, "schemas/terms-v1/vectors.json is stale");
        println!("RUST-TERMS-VECTORS PASS");
    } else {
        println!("{}", serde_json::to_string_pretty(&vector).unwrap());
    }
}
