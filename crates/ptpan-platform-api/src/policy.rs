//! The stateless `AdapterService` policy calls (D1), implemented once on
//! Base. The adapter serves them; tools that stand in for an adapter (the
//! conformance runner) use the same functions.

use crate::v1 as api;
use federation_base::control_event::LeaseWire;
use federation_base::encoding::hex_lower;
use federation_base::{parse_relationship_request_json, LeaseMode, OpaqueId, OwnerTerms, PersonName, PlatformId, RelationshipLease};

pub fn validate_request(request: &api::ValidateRequestRequest) -> api::ValidateRequestResponse {
    let result = parse_relationship_request_json(&request.request_json);
    api::ValidateRequestResponse { valid: result.is_ok(), error: result.err().map(|e| format!("{e:?}")).unwrap_or_default() }
}

pub fn compute_terms_digest(request: &api::ComputeTermsDigestRequest) -> api::ComputeTermsDigestResponse {
    match parse_relationship_request_json(&request.request_json).and_then(|r| r.request_terms_digest()) {
        Ok(digest) => api::ComputeTermsDigestResponse { request_terms_digest: hex_lower(&digest), error: String::new() },
        Err(e) => api::ComputeTermsDigestResponse { request_terms_digest: String::new(), error: format!("{e:?}") },
    }
}

/// `ComputeLease` for the destination platform `issuer`.
pub fn compute_lease(issuer: &PlatformId, r: api::ComputeLeaseRequest) -> api::ComputeLeaseResponse {
    let error = |e: String| api::ComputeLeaseResponse { lease_json: Vec::new(), error: e };
    let request = match parse_relationship_request_json(&r.request_json) {
        Ok(request) => request,
        Err(e) => return error(format!("{e:?}")),
    };
    let mode = match r.mode.as_str() {
        "SINGLE_TASK" => LeaseMode::SingleTask,
        "FIXED" => LeaseMode::Fixed,
        "UNTIL_REVOKED" => LeaseMode::UntilRevoked,
        _ => return error("mode".into()),
    };
    let (Ok(lease_id), Ok(decision_id)) = (OpaqueId::new(r.lease_id), OpaqueId::new(r.decision_id)) else {
        return error("lease_id and decision_id are required".into());
    };
    let Some(name) = r.destination_owner_name else { return error("destination_owner_name".into()) };
    let terms = OwnerTerms {
        lease_id,
        lease_revision: r.lease_revision,
        decision_id,
        mode,
        effective_from: r.effective_from,
        expires_at: (r.expires_at != 0).then_some(r.expires_at),
        effective_permissions: r.effective_permissions.into_iter().collect(),
    };
    let owner = PersonName { given_name: name.given_name, family_name: name.family_name };
    match RelationshipLease::issue(&request, issuer, terms, r.destination_ownership_revision, &owner) {
        Ok(lease) => match serde_json::to_vec(&LeaseWire::from_lease(&lease)) {
            Ok(lease_json) => api::ComputeLeaseResponse { lease_json, error: String::new() },
            Err(e) => error(e.to_string()),
        },
        Err(e) => error(format!("{e:?}")),
    }
}
