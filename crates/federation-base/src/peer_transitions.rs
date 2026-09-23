//! Peer trust transitions. A provider adapter loads its own rows, calls these
//! functions, and persists the returned effect. Account tables are not an input.

use crate::peer_control::TrustDecisionResult;
use crate::{PeerRequestGate, PeerState};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRuleError {
    InvalidTransition,
    ManifestMismatch,
    ServiceMismatch,
    PeerNotFound,
    EvidenceMismatch,
    DuplicateMessageConflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidatePlan {
    Insert,
    Unchanged,
    AdvanceRevision,
    ResetApprovals,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidatePrior<'a> {
    pub revision: u64,
    pub digest: &'a [u8],
    pub service: &'a str,
    pub removed: bool,
}

pub fn plan_candidate(
    prior: Option<CandidatePrior<'_>>,
    revision: u64,
    digest: &[u8],
    service: &str,
) -> Result<CandidatePlan, PeerRuleError> {
    if revision == 0 || service.is_empty() {
        return Err(PeerRuleError::InvalidTransition);
    }
    let Some(prior) = prior else {
        return Ok(CandidatePlan::Insert);
    };
    if prior.removed || revision < prior.revision {
        return Err(PeerRuleError::InvalidTransition);
    }
    if revision == prior.revision && prior.digest != digest {
        return Err(PeerRuleError::ManifestMismatch);
    }
    if revision == prior.revision && prior.service != service {
        return Err(PeerRuleError::ServiceMismatch);
    }
    if revision > prior.revision && (prior.digest != digest || prior.service != service) {
        Ok(CandidatePlan::ResetApprovals)
    } else if revision > prior.revision {
        Ok(CandidatePlan::AdvanceRevision)
    } else {
        Ok(CandidatePlan::Unchanged)
    }
}

pub fn stored_peer_state(value: &str) -> Option<PeerState> {
    match value {
        "pending" => Some(PeerState::Pending),
        "active" => Some(PeerState::Active),
        "suspended" => Some(PeerState::Suspended),
        "removed" => Some(PeerState::Removed),
        _ => None,
    }
}

pub fn bootstrap_replaces(prior: Option<&[u8]>, next: &[u8]) -> bool {
    prior != Some(next)
}

pub fn hello_sender_service(
    sender_matches: bool,
    authenticated_service: &str,
    expected_service: &str,
) -> Result<(), PeerRuleError> {
    if sender_matches && authenticated_service == expected_service {
        Ok(())
    } else {
        Err(PeerRuleError::ServiceMismatch)
    }
}

pub fn hello_generation_is_current(stored: u64, message: u64) -> Result<(), PeerRuleError> {
    if stored == message {
        Ok(())
    } else {
        Err(PeerRuleError::InvalidTransition)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestSlot {
    Insert,
    Same,
}

pub fn same_digest_slot(prior: Option<&[u8]>, digest: &[u8]) -> Result<DigestSlot, PeerRuleError> {
    match prior {
        Some(prior) if prior != digest => Err(PeerRuleError::ManifestMismatch),
        Some(_) => Ok(DigestSlot::Same),
        None => Ok(DigestSlot::Insert),
    }
}

pub fn authenticated_control_parties(
    sender_matches: bool,
    recipient_matches: bool,
    authenticated_service: &str,
    expected_service: &str,
) -> Result<(), PeerRuleError> {
    if sender_matches
        && recipient_matches
        && authenticated_service == expected_service
        && !expected_service.is_empty()
    {
        Ok(())
    } else {
        Err(PeerRuleError::ServiceMismatch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorInbox<'a> {
    pub sender: &'a str,
    pub body_digest: &'a [u8],
    pub exact_bytes: &'a [u8],
    pub generation: i64,
    pub result: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboxReplay<'a> {
    First,
    Same(&'a str),
}

pub fn classify_peer_inbox<'a>(
    prior: Option<PriorInbox<'a>>,
    sender: &str,
    body_digest: &[u8],
    exact_bytes: &[u8],
    generation: i64,
) -> Result<InboxReplay<'a>, PeerRuleError> {
    let Some(prior) = prior else {
        return Ok(InboxReplay::First);
    };
    if prior.sender == sender
        && prior.body_digest == body_digest
        && prior.exact_bytes == exact_bytes
        && prior.generation == generation
    {
        Ok(InboxReplay::Same(prior.result))
    } else {
        Err(PeerRuleError::DuplicateMessageConflict)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelloPeer {
    pub generation: i64,
    pub removed: bool,
}

pub fn accept_hello_generation(
    current: Option<HelloPeer>,
    message_generation: i64,
) -> Result<(), PeerRuleError> {
    match current {
        None if message_generation == 1 => Ok(()),
        Some(peer) if peer.generation == message_generation && !peer.removed => Ok(()),
        _ => Err(PeerRuleError::InvalidTransition),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredManifest<'a> {
    pub digest: &'a [u8],
    pub exact_bytes: &'a [u8],
    pub service: &'a str,
}

pub fn exact_manifest_slot(
    prior: Option<StoredManifest<'_>>,
    digest: &[u8],
    exact_bytes: &[u8],
    service: &str,
) -> Result<DigestSlot, PeerRuleError> {
    match prior {
        Some(prior)
            if prior.digest != digest
                || prior.exact_bytes != exact_bytes
                || prior.service != service =>
        {
            Err(PeerRuleError::ManifestMismatch)
        }
        Some(_) => Ok(DigestSlot::Same),
        None => Ok(DigestSlot::Insert),
    }
}

pub fn accept_continuing_peer(
    removed: bool,
    stored_generation: i64,
    message_generation: i64,
    expected_service: &str,
    authenticated_service: &str,
) -> Result<(), PeerRuleError> {
    if removed
        || stored_generation != message_generation
        || expected_service != authenticated_service
    {
        Err(PeerRuleError::InvalidTransition)
    } else {
        Ok(())
    }
}

pub fn trust_request_matches(
    peer_digest: &[u8; 32],
    sender_digest: Option<[u8; 32]>,
    own_digest: &[u8; 32],
    recipient_digest: Option<[u8; 32]>,
    capabilities: &BTreeSet<String>,
    pending: bool,
    still_valid: bool,
) -> Result<(), PeerRuleError> {
    let only_delivery = capabilities.len() == 1 && capabilities.contains("REQUEST_DELIVERY");
    if sender_digest.as_ref() != Some(peer_digest)
        || recipient_digest.as_ref() != Some(own_digest)
        || !only_delivery
        || !pending
    {
        return Err(PeerRuleError::ManifestMismatch);
    }
    if !still_valid {
        return Err(PeerRuleError::InvalidTransition);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteTrustWrite {
    Approve,
    Reject,
}

pub fn remote_trust_decision(
    sender_digest: Option<[u8; 32]>,
    peer_digest: &[u8; 32],
    recipient_digest: Option<[u8; 32]>,
    own_digest: &[u8; 32],
    result: TrustDecisionResult,
    capabilities: &BTreeSet<String>,
) -> Result<RemoteTrustWrite, PeerRuleError> {
    if sender_digest.as_ref() != Some(peer_digest) || recipient_digest.as_ref() != Some(own_digest)
    {
        return Err(PeerRuleError::ManifestMismatch);
    }
    match result {
        TrustDecisionResult::Approved
            if capabilities.len() == 1 && capabilities.contains("REQUEST_DELIVERY") =>
        {
            Ok(RemoteTrustWrite::Approve)
        }
        TrustDecisionResult::Rejected if capabilities.is_empty() => Ok(RemoteTrustWrite::Reject),
        _ => Err(PeerRuleError::InvalidTransition),
    }
}

pub fn next_pending_state(
    local_approved: bool,
    remote_confirmed: bool,
    identity_verified: bool,
    exact_service_authenticated: bool,
) -> PeerState {
    if local_approved && remote_confirmed && identity_verified && exact_service_authenticated {
        PeerState::Active
    } else {
        PeerState::Pending
    }
}

pub fn apply_evidence_freshness(mut gate: PeerRequestGate, fresh: bool) -> PeerRequestGate {
    if !fresh {
        gate.peer_identity_verified = false;
        if gate.state == PeerState::Active {
            gate.state = PeerState::Pending;
        }
    }
    gate
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboundDecisionFacts {
    pub pending: bool,
    pub digest_matches: bool,
    pub removed_or_suspended: bool,
    pub expiry_still_valid: Option<bool>,
}

pub fn inbound_operator_may_decide(facts: InboundDecisionFacts) -> Result<(), PeerRuleError> {
    if !facts.pending {
        return Err(PeerRuleError::InvalidTransition);
    }
    if !facts.digest_matches {
        return Err(PeerRuleError::ManifestMismatch);
    }
    if facts.removed_or_suspended {
        return Err(PeerRuleError::InvalidTransition);
    }
    if facts.expiry_still_valid == Some(false) {
        return Err(PeerRuleError::InvalidTransition);
    }
    Ok(())
}

pub fn digest_matches_current(current: Option<&[u8]>, digest: &[u8]) -> Result<(), PeerRuleError> {
    match current {
        None => Err(PeerRuleError::PeerNotFound),
        Some(value) if value != digest => Err(PeerRuleError::ManifestMismatch),
        Some(_) => Ok(()),
    }
}

pub fn trust_request_may_be_recorded(removed: bool) -> Result<(), PeerRuleError> {
    if removed {
        Err(PeerRuleError::InvalidTransition)
    } else {
        Ok(())
    }
}

pub fn observe_exact_service(expected: &str, observed: &str) -> Result<(), PeerRuleError> {
    if expected == observed {
        Ok(())
    } else {
        Err(PeerRuleError::ServiceMismatch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityFacts<'a> {
    pub profile_allowed: bool,
    pub current_digest: Option<&'a [u8]>,
    pub reported_digest: &'a [u8],
    pub peer_present: bool,
    pub removed: bool,
    pub revision_matches: bool,
    pub service_matches: bool,
    pub bootstrap_matches: bool,
    pub observed_service_matches: bool,
}

pub fn accept_verified_identity(facts: IdentityFacts<'_>) -> Result<(), PeerRuleError> {
    if !facts.profile_allowed {
        return Err(PeerRuleError::EvidenceMismatch);
    }
    digest_matches_current(facts.current_digest, facts.reported_digest)?;
    if !facts.peer_present {
        return Err(PeerRuleError::PeerNotFound);
    }
    if facts.removed
        || !facts.revision_matches
        || !facts.service_matches
        || !facts.bootstrap_matches
    {
        return Err(PeerRuleError::EvidenceMismatch);
    }
    if !facts.observed_service_matches {
        return Err(PeerRuleError::EvidenceMismatch);
    }
    Ok(())
}

pub fn remote_decision_service(
    expected: Option<&str>,
    observed: &str,
) -> Result<(), PeerRuleError> {
    if expected == Some(observed) {
        Ok(())
    } else {
        Err(PeerRuleError::ServiceMismatch)
    }
}

pub fn local_operator_may_approve(state: Option<PeerState>) -> Result<(), PeerRuleError> {
    match state {
        Some(state) if state != PeerState::Removed => Ok(()),
        _ => Err(PeerRuleError::InvalidTransition),
    }
}

pub fn suspend_transition(state: Option<PeerState>) -> Result<(), PeerRuleError> {
    match state {
        Some(PeerState::Active) => Ok(()),
        _ => Err(PeerRuleError::InvalidTransition),
    }
}

pub fn remove_transition(state: Option<PeerState>) -> Result<(), PeerRuleError> {
    match state {
        Some(state) if state != PeerState::Removed => Ok(()),
        _ => Err(PeerRuleError::InvalidTransition),
    }
}

pub fn regrant_transition(
    current: Option<(u64, PeerState)>,
    revision: u64,
    service: &str,
) -> Result<(), PeerRuleError> {
    if revision == 0 || service.is_empty() {
        return Err(PeerRuleError::InvalidTransition);
    }
    let Some((old_revision, state)) = current else {
        return Err(PeerRuleError::PeerNotFound);
    };
    if state != PeerState::Removed || revision <= old_revision {
        Err(PeerRuleError::InvalidTransition)
    } else {
        Ok(())
    }
}
