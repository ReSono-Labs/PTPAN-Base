//! Live admission is not a lifecycle event. It is not stored in the outbox
//! and it is not retried as a task. A durable `AUTHORIZED` hint is not fresh
//! proof. This decision does not issue a destination credential; only the
//! destination host does that.

use crate::relationship_lifecycle::DurableSourceAuthorization;
use crate::{OpaqueId, PeerState, PlatformId};
use serde::{Deserialize, Serialize};

pub const ADMISSION_SCHEMA: &str = "live-admission/v1";
const MAX_ADMISSION_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionParseError {
    TooLarge,
    InvalidJson,
    InvalidSchema,
    InvalidField,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionWire {
    schema: String,
    source_platform: PlatformId,
    relationship_id: OpaqueId,
    lease_id: OpaqueId,
    lease_revision: u64,
    source_subject: OpaqueId,
    source_resource: OpaqueId,
    destination_platform: PlatformId,
    destination_resource: OpaqueId,
    caller_key_purpose: String,
    caller_key_revision: u64,
    audience: String,
    challenge_nonce: String,
    operation: String,
    deadline: u64,
    source_authorization: SourceChallenge,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdmissionRequest {
    pub relationship_id: OpaqueId,
    pub lease_id: OpaqueId,
    pub lease_revision: u64,
    pub source_subject: OpaqueId,
    pub source_resource: OpaqueId,
    pub destination_platform: PlatformId,
    pub destination_resource: OpaqueId,
    pub caller_key_purpose: String,
    pub caller_key_revision: u64,
    pub audience: String,
    pub challenge_nonce: String,
    pub operation: String,
    pub deadline: u64,
}

pub fn admission_call_json(call: &LiveAdmissionCall) -> Result<Vec<u8>, serde_json::Error> {
    let mut body = serde_json::to_value(&call.request)?;
    let object = body.as_object_mut().expect("admission request is an object");
    object.insert("schema".into(), serde_json::json!(ADMISSION_SCHEMA));
    object.insert("source_platform".into(), serde_json::to_value(&call.source_platform)?);
    object.insert(
        "source_authorization".into(),
        serde_json::to_value(&call.source_authorization)?,
    );
    serde_json::to_vec(&body)
}

/// Fresh source-host assertion bound to one challenge. A stored
/// `SOURCE_AUTHORIZATION_STATUS` of `AUTHORIZED` is not this value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceChallenge {
    pub nonce: String,
    pub relationship_id: OpaqueId,
    pub lease_revision: u64,
    pub source_subject: OpaqueId,
    pub source_resource: OpaqueId,
    pub destination_platform: PlatformId,
    pub audience: String,
    pub caller_key_purpose: String,
    pub caller_key_revision: u64,
    pub deadline: u64,
    pub withdrawn: bool,
}

/// One live call from the authenticated source service. The source host
/// produces the assertion after checking its own current account authority;
/// the destination must bind `source_platform` to the mTLS service identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveAdmissionCall {
    pub source_platform: PlatformId,
    pub request: AdmissionRequest,
    pub source_authorization: SourceChallenge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionFacts<'a> {
    pub now: u64,
    pub peer: PeerState,
    pub relationship_ready: bool,
    pub grant_allows_operation: bool,
    pub current_lease_id: &'a OpaqueId,
    pub current_lease_revision: u64,
    pub current_destination_resource: &'a OpaqueId,
    pub durable_source_authorization: DurableSourceAuthorization,
    pub nonce_already_used: bool,
    pub source_challenge: Option<&'a SourceChallenge>,
    /// `None` means the lease mode contributes no timestamp (`UNTIL_REVOKED`).
    pub lease_expires_at: Option<u64>,
    /// Source authorization, grant, credential, workload, peer-policy, and
    /// the configured short admission cap. A 30-day lease is not among these
    /// when a shorter cap is present.
    pub other_deadlines: &'a [u64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDeny {
    PeerNotActive,
    NotReady,
    GrantDenied,
    ReusedNonce,
    StaleDeadline,
    ChallengeMismatch,
    SourceWithdrawn,
    DurableAuthorizedIsNotProof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDecision {
    Allow { deadline: u64 },
    Deny(AdmissionDeny),
}

pub fn evaluate_admission(request: &AdmissionRequest, facts: AdmissionFacts<'_>) -> AdmissionDecision {
    if facts.peer != PeerState::Active {
        return AdmissionDecision::Deny(AdmissionDeny::PeerNotActive);
    }
    if facts.now >= request.deadline {
        return AdmissionDecision::Deny(AdmissionDeny::StaleDeadline);
    }
    if request.deadline > facts.now.saturating_add(60) {
        return AdmissionDecision::Deny(AdmissionDeny::StaleDeadline);
    }
    if facts.nonce_already_used || request.challenge_nonce.is_empty() {
        return AdmissionDecision::Deny(AdmissionDeny::ReusedNonce);
    }
    if matches!(
        facts.durable_source_authorization,
        DurableSourceAuthorization::Withdrawn { .. }
    ) {
        return AdmissionDecision::Deny(AdmissionDeny::SourceWithdrawn);
    }
    let Some(challenge) = facts.source_challenge else {
        return AdmissionDecision::Deny(AdmissionDeny::DurableAuthorizedIsNotProof);
    };
    if !challenge_matches(request, challenge) {
        return AdmissionDecision::Deny(AdmissionDeny::ChallengeMismatch);
    }
    if facts.now >= challenge.deadline {
        return AdmissionDecision::Deny(AdmissionDeny::StaleDeadline);
    }
    if challenge.deadline > facts.now.saturating_add(60) {
        return AdmissionDecision::Deny(AdmissionDeny::StaleDeadline);
    }
    if challenge.withdrawn {
        return AdmissionDecision::Deny(AdmissionDeny::SourceWithdrawn);
    }
    if let Some(expiry) = facts.lease_expires_at {
        if facts.now >= expiry {
            return AdmissionDecision::Deny(AdmissionDeny::StaleDeadline);
        }
    }
    if !facts.relationship_ready {
        return AdmissionDecision::Deny(AdmissionDeny::NotReady);
    }
    if !facts.grant_allows_operation
        || facts.current_lease_id != &request.lease_id
        || facts.current_lease_revision != request.lease_revision
        || facts.current_destination_resource != &request.destination_resource
    {
        return AdmissionDecision::Deny(AdmissionDeny::GrantDenied);
    }
    let mut deadline = request.deadline.min(challenge.deadline);
    if let Some(expiry) = facts.lease_expires_at {
        deadline = deadline.min(expiry);
    }
    for extra in facts.other_deadlines {
        if *extra == 0 || facts.now >= *extra {
            return AdmissionDecision::Deny(AdmissionDeny::StaleDeadline);
        }
        deadline = deadline.min(*extra);
    }
    if deadline <= facts.now {
        return AdmissionDecision::Deny(AdmissionDeny::StaleDeadline);
    }
    AdmissionDecision::Allow { deadline }
}

pub fn parse_admission_request(bytes: &[u8]) -> Result<LiveAdmissionCall, AdmissionParseError> {
    if bytes.is_empty() || bytes.len() > MAX_ADMISSION_BYTES {
        return Err(AdmissionParseError::TooLarge);
    }
    let wire: AdmissionWire =
        serde_json::from_slice(bytes).map_err(|_| AdmissionParseError::InvalidJson)?;
    if wire.schema != ADMISSION_SCHEMA {
        return Err(AdmissionParseError::InvalidSchema);
    }
    if wire.lease_revision == 0
        || wire.caller_key_revision == 0
        || wire.deadline == 0
        || !bounded(&wire.caller_key_purpose)
        || !bounded(&wire.audience)
        || !bounded(&wire.challenge_nonce)
        || !bounded(&wire.operation)
        || !bounded(wire.relationship_id.as_str())
        || !bounded(wire.lease_id.as_str())
        || !bounded(wire.source_subject.as_str())
        || !bounded(wire.source_resource.as_str())
        || !bounded(wire.destination_platform.as_str())
        || !bounded(wire.destination_resource.as_str())
    {
        return Err(AdmissionParseError::InvalidField);
    }
    let request = AdmissionRequest {
        relationship_id: wire.relationship_id,
        lease_id: wire.lease_id,
        lease_revision: wire.lease_revision,
        source_subject: wire.source_subject,
        source_resource: wire.source_resource,
        destination_platform: wire.destination_platform,
        destination_resource: wire.destination_resource,
        caller_key_purpose: wire.caller_key_purpose,
        caller_key_revision: wire.caller_key_revision,
        audience: wire.audience,
        challenge_nonce: wire.challenge_nonce,
        operation: wire.operation,
        deadline: wire.deadline,
    };
    if !challenge_matches(&request, &wire.source_authorization)
        || wire.source_authorization.withdrawn
        || wire.source_authorization.deadline == 0
    {
        return Err(AdmissionParseError::InvalidField);
    }
    Ok(LiveAdmissionCall {
        source_platform: wire.source_platform,
        request,
        source_authorization: wire.source_authorization,
    })
}

pub fn admission_response_json(decision: &AdmissionDecision) -> String {
    let body = match decision {
        AdmissionDecision::Allow { deadline } => serde_json::json!({
            "schema": ADMISSION_SCHEMA,
            "result": "ALLOW",
            "deadline": deadline
        }),
        AdmissionDecision::Deny(reason) => serde_json::json!({
            "schema": ADMISSION_SCHEMA,
            "result": "DENY",
            "reason": deny_reason(*reason)
        }),
    };
    body.to_string()
}

fn deny_reason(reason: AdmissionDeny) -> &'static str {
    match reason {
        AdmissionDeny::PeerNotActive => "PEER_NOT_ACTIVE",
        AdmissionDeny::NotReady => "NOT_READY",
        AdmissionDeny::GrantDenied => "GRANT_DENIED",
        AdmissionDeny::ReusedNonce => "REUSED_NONCE",
        AdmissionDeny::StaleDeadline => "STALE_DEADLINE",
        AdmissionDeny::ChallengeMismatch => "CHALLENGE_MISMATCH",
        AdmissionDeny::SourceWithdrawn => "SOURCE_WITHDRAWN",
        AdmissionDeny::DurableAuthorizedIsNotProof => "DURABLE_AUTHORIZED_IS_NOT_PROOF",
    }
}

fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256
}

fn challenge_matches(request: &AdmissionRequest, challenge: &SourceChallenge) -> bool {
    challenge.nonce == request.challenge_nonce
        && challenge.relationship_id == request.relationship_id
        && challenge.lease_revision == request.lease_revision
        && challenge.source_subject == request.source_subject
        && challenge.source_resource == request.source_resource
        && challenge.destination_platform == request.destination_platform
        && challenge.audience == request.audience
        && challenge.caller_key_purpose == request.caller_key_purpose
        && challenge.caller_key_revision == request.caller_key_revision
}
