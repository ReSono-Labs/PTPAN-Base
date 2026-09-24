//! Durable relationship exchange rules. A provider adapter supplies local
//! account and ownership facts, applies the result, and keeps its own schema.
//! Peer trust still admits only a bounded request: these rules never return
//! an account list.

use crate::control_event::{
    ControlPayload, ControlReceipt, DecisionPayload, DecisionResult, LeaseWire, ParsedControlEvent,
    ReceiptResult,
};
use crate::{
    ModelError, OpaqueId, Participant, PlatformId, RelationshipLease, RelationshipRequest,
    RequestDeliveryResult,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExchangeRuleError {
    WrongControlKind,
    WrongAuthenticatedPeer,
    SourceNotAuthorized,
    DuplicateConflict,
    OutOfRange,
    ReceiptMismatch,
    NotCurrentOwner,
    RequestNotPending,
    DecisionExpired,
    GrantNotAuthorized,
    StaleDecision,
    Model(ModelError),
}

pub fn recorded_sent_is_local(
    request: &RelationshipRequest,
    local: &PlatformId,
    actor: &OpaqueId,
    ownership_revision: u64,
) -> Result<(), ExchangeRuleError> {
    if request.direction.source_platform_id != *local
        || request.source.platform_id != *local
        || request.source.subject_id != *actor
        || request.source_ownership_revision != ownership_revision
    {
        Err(ExchangeRuleError::SourceNotAuthorized)
    } else {
        Ok(())
    }
}

pub fn outbound_request_event_matches(
    event: &ParsedControlEvent,
    request: &RelationshipRequest,
    local: &PlatformId,
    peer_generation: u64,
) -> Result<(), ExchangeRuleError> {
    let payload_matches = matches!(
        &event.event.payload,
        ControlPayload::Request(payload) if payload.request == *request
    );
    if peer_generation == 0
        || event.event.sender_platform_id != *local
        || event.event.recipient_platform_id != request.direction.destination_platform_id
        || !payload_matches
    {
        Err(ExchangeRuleError::WrongControlKind)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentOutboxIdentity {
    pub event_id: String,
    pub generation: i64,
    pub digest: Vec<u8>,
}

pub fn same_sent_outbox(
    prior: &SentOutboxIdentity,
    event_id: &str,
    generation: i64,
    digest: &[u8],
) -> bool {
    prior.event_id == event_id && prior.generation == generation && prior.digest == digest
}

pub fn same_request_snapshot(
    prior: Option<&str>,
    snapshot: &str,
) -> Result<bool, ExchangeRuleError> {
    match prior {
        None => Ok(false),
        Some(prior) if prior == snapshot => Ok(true),
        Some(_) => Err(ExchangeRuleError::DuplicateConflict),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceReceiptPlan {
    Commit {
        receipt_result: &'static str,
        sent_state: &'static str,
    },
    Replay,
}

pub fn plan_source_control_receipt(
    receipt: &ControlReceipt,
    local: &PlatformId,
    stored_recipient: &str,
    stored_generation: i64,
    stored_digest: &[u8],
    peer_generation: u64,
    state: &str,
    prior_result: Option<&str>,
) -> Result<SourceReceiptPlan, ExchangeRuleError> {
    let generation = i64::try_from(peer_generation).map_err(|_| ExchangeRuleError::OutOfRange)?;
    let digest_hex = hex(stored_digest);
    let allowed = matches!(
        receipt.result,
        ReceiptResult::QueuedForLocalOwner | ReceiptResult::AddressNotRecognized
    );
    if receipt.schema != "federation-receipt/v1"
        || receipt.sender_platform_id != *local
        || receipt.recipient_platform_id.as_str() != stored_recipient
        || receipt.body_digest != digest_hex
        || generation != stored_generation
        || !allowed
    {
        return Err(ExchangeRuleError::ReceiptMismatch);
    }
    let (receipt_result, sent_state) = match receipt.result {
        ReceiptResult::QueuedForLocalOwner => ("queued_for_local_owner", "delivered"),
        ReceiptResult::AddressNotRecognized => ("address_not_recognized", "address_not_recognized"),
        _ => unreachable!("allowed results are queued or address-not-recognized"),
    };
    if state == "committed" {
        return if prior_result == Some(receipt_result) {
            Ok(SourceReceiptPlan::Replay)
        } else {
            Err(ExchangeRuleError::ReceiptMismatch)
        };
    }
    Ok(SourceReceiptPlan::Commit {
        receipt_result,
        sent_state,
    })
}

pub fn open_inbound_request<'a>(
    event: &'a ParsedControlEvent,
    authenticated_peer: &PlatformId,
    local: &PlatformId,
) -> Result<&'a RelationshipRequest, ExchangeRuleError> {
    if &event.event.sender_platform_id != authenticated_peer
        || event.event.recipient_platform_id != *local
    {
        return Err(ExchangeRuleError::WrongAuthenticatedPeer);
    }
    match &event.event.payload {
        ControlPayload::Request(payload) => Ok(&payload.request),
        _ => Err(ExchangeRuleError::WrongControlKind),
    }
}

pub fn positive_generation(peer_generation: u64) -> Result<i64, ExchangeRuleError> {
    if peer_generation == 0 {
        return Err(ExchangeRuleError::OutOfRange);
    }
    i64::try_from(peer_generation).map_err(|_| ExchangeRuleError::OutOfRange)
}

pub fn replay_request_control(
    prior_generation: i64,
    prior_digest: &[u8],
    prior_result: &str,
    generation: i64,
    digest: &[u8],
) -> Result<RequestDeliveryResult, ExchangeRuleError> {
    if prior_generation != generation || prior_digest != digest {
        return Err(ExchangeRuleError::DuplicateConflict);
    }
    Ok(if prior_result == "queued" {
        RequestDeliveryResult::QueuedForLocalOwner
    } else {
        RequestDeliveryResult::AddressNotRecognized
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressReplay {
    Queued,
    AddressNotRecognized,
}

pub fn replay_ingress_receipt(
    prior_snapshot: &str,
    prior_result: &str,
    snapshot: &str,
) -> Result<IngressReplay, ExchangeRuleError> {
    if prior_snapshot != snapshot {
        return Err(ExchangeRuleError::DuplicateConflict);
    }
    match prior_result {
        "queued" => Ok(IngressReplay::Queued),
        "address_not_recognized" => Ok(IngressReplay::AddressNotRecognized),
        _ => unreachable!("ingress receipt result is constrained by the adapter"),
    }
}

pub fn destination_approval_event(
    event: &ParsedControlEvent,
    request: &RelationshipRequest,
    local: &PlatformId,
    actor: &OpaqueId,
    destination: &Participant,
    ownership_revision: u64,
    lease: &RelationshipLease,
    peer_generation: u64,
    now: u64,
) -> Result<(), ExchangeRuleError> {
    if peer_generation == 0
        || event.event.sender_platform_id != *local
        || event.event.recipient_platform_id != request.direction.source_platform_id
        || event.event.originating_platform_id != request.direction.source_platform_id
        || event.event.relationship_id != request.relationship_id
        || event.event.request_id.as_ref() != Some(&request.request_id)
        || destination.platform_id != *local
        || destination.subject_id != *actor
        || lease.decision_id.as_str().is_empty()
    {
        return Err(ExchangeRuleError::WrongControlKind);
    }
    let ControlPayload::Decision(payload) = &event.event.payload else {
        return Err(ExchangeRuleError::WrongControlKind);
    };
    if payload.result != DecisionResult::Approved
        || payload.destination.as_ref() != Some(destination)
        || payload.destination_ownership_revision != Some(ownership_revision)
        || payload.decision_id != lease.decision_id
        || payload
            .lease_against(request)
            .map_err(|_| ExchangeRuleError::GrantNotAuthorized)?
            != *lease
    {
        return Err(ExchangeRuleError::GrantNotAuthorized);
    }
    if !lease.is_effective_at(now) {
        return Err(ExchangeRuleError::GrantNotAuthorized);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerApprovalFacts {
    pub actor_is_owner: bool,
    pub agent_matches: bool,
    pub revision_matches: bool,
    pub pending: bool,
    pub decision_already_set: bool,
    pub now: i64,
    pub expiry: i64,
    pub current_owner_matches: bool,
    pub snapshot_matches: bool,
}

pub fn commit_owner_approval(facts: OwnerApprovalFacts) -> Result<(), ExchangeRuleError> {
    if !facts.actor_is_owner
        || !facts.agent_matches
        || !facts.revision_matches
        || !facts.pending
        || facts.decision_already_set
    {
        return Err(ExchangeRuleError::NotCurrentOwner);
    }
    if facts.now >= facts.expiry {
        return Err(ExchangeRuleError::DecisionExpired);
    }
    if !facts.current_owner_matches {
        return Err(ExchangeRuleError::NotCurrentOwner);
    }
    if !facts.snapshot_matches {
        return Err(ExchangeRuleError::GrantNotAuthorized);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalDenial {
    Denied,
    Blocked,
}

impl LocalDenial {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Blocked => "blocked",
        }
    }
}

pub fn destination_denial_event(
    event: &ParsedControlEvent,
    request: &RelationshipRequest,
    local: &PlatformId,
    peer_generation: u64,
) -> Result<LocalDenial, ExchangeRuleError> {
    let ControlPayload::Decision(payload) = &event.event.payload else {
        return Err(ExchangeRuleError::WrongControlKind);
    };
    let denial = match payload.result {
        DecisionResult::Denied => LocalDenial::Denied,
        DecisionResult::Blocked => LocalDenial::Blocked,
        DecisionResult::Approved => return Err(ExchangeRuleError::WrongControlKind),
    };
    let digest = request
        .request_terms_digest()
        .map_err(ExchangeRuleError::Model)?;
    if peer_generation == 0
        || payload.destination.is_some()
        || payload.destination_ownership_revision.is_some()
        || payload.lease.is_some()
        || payload.bound_request_revision != request.request_revision
        || payload.request_terms_digest != hex(&digest)
        || event.event.sender_platform_id != *local
        || event.event.recipient_platform_id != request.direction.source_platform_id
        || event.event.originating_platform_id != request.direction.source_platform_id
        || event.event.relationship_id != request.relationship_id
        || event.event.request_id.as_ref() != Some(&request.request_id)
    {
        return Err(ExchangeRuleError::WrongControlKind);
    }
    Ok(denial)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerDenialFacts {
    pub actor_is_owner: bool,
    pub pending: bool,
    pub now: i64,
    pub expiry: i64,
    pub snapshot_matches: bool,
    pub current_owner_matches: bool,
}

pub fn commit_owner_denial(facts: OwnerDenialFacts) -> Result<(), ExchangeRuleError> {
    if !facts.actor_is_owner || !facts.pending {
        return Err(ExchangeRuleError::NotCurrentOwner);
    }
    if facts.now >= facts.expiry {
        return Err(ExchangeRuleError::DecisionExpired);
    }
    if !facts.snapshot_matches {
        return Err(ExchangeRuleError::GrantNotAuthorized);
    }
    if !facts.current_owner_matches {
        return Err(ExchangeRuleError::NotCurrentOwner);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationReceiptPlan {
    Commit,
    Replay,
}

pub fn destination_receipt_is_applied(
    receipt: &ControlReceipt,
    local: &PlatformId,
) -> Result<(), ExchangeRuleError> {
    if receipt.schema != "federation-receipt/v1"
        || receipt.sender_platform_id != *local
        || receipt.result != ReceiptResult::Applied
    {
        Err(ExchangeRuleError::ReceiptMismatch)
    } else {
        Ok(())
    }
}

pub fn plan_destination_receipt(
    receipt: &ControlReceipt,
    stored_recipient: &str,
    stored_generation: i64,
    stored_digest: &[u8],
    peer_generation: u64,
    state: &str,
    prior_result: Option<&str>,
) -> Result<DestinationReceiptPlan, ExchangeRuleError> {
    let generation = i64::try_from(peer_generation).map_err(|_| ExchangeRuleError::OutOfRange)?;
    if stored_recipient != receipt.recipient_platform_id.as_str()
        || stored_generation != generation
        || hex(stored_digest) != receipt.body_digest
    {
        return Err(ExchangeRuleError::ReceiptMismatch);
    }
    if state == "committed" {
        return if prior_result == Some("applied") {
            Ok(DestinationReceiptPlan::Replay)
        } else {
            Err(ExchangeRuleError::ReceiptMismatch)
        };
    }
    Ok(DestinationReceiptPlan::Commit)
}

pub fn open_inbound_decision<'a>(
    event: &'a ParsedControlEvent,
    authenticated_peer: &PlatformId,
    local: &PlatformId,
    peer_generation: u64,
) -> Result<&'a DecisionPayload, ExchangeRuleError> {
    let ControlPayload::Decision(payload) = &event.event.payload else {
        return Err(ExchangeRuleError::WrongControlKind);
    };
    if event.event.sender_platform_id != *authenticated_peer
        || event.event.recipient_platform_id != *local
        || event.event.originating_platform_id != *local
        || peer_generation == 0
    {
        return Err(ExchangeRuleError::ReceiptMismatch);
    }
    Ok(payload)
}

pub fn replay_applied_control(
    prior_generation: i64,
    prior_digest: &[u8],
    prior_result: &str,
    generation: i64,
    digest: &[u8],
) -> Result<(), ExchangeRuleError> {
    if prior_generation == generation && prior_digest == digest && prior_result == "applied" {
        Ok(())
    } else {
        Err(ExchangeRuleError::DuplicateConflict)
    }
}

pub fn sent_ready_for_decision(state: &str) -> Result<(), ExchangeRuleError> {
    if state == "delivered" {
        Ok(())
    } else {
        Err(ExchangeRuleError::StaleDecision)
    }
}

pub fn source_decision_fields_match(
    request: &RelationshipRequest,
    event: &ParsedControlEvent,
    payload: &DecisionPayload,
    authenticated_peer: &PlatformId,
    request_id: &OpaqueId,
) -> Result<(), ExchangeRuleError> {
    let digest = request
        .request_terms_digest()
        .map_err(ExchangeRuleError::Model)?;
    if request.relationship_id != event.event.relationship_id
        || request.direction.destination_platform_id != *authenticated_peer
        || request.request_id != *request_id
        || payload.bound_request_revision != request.request_revision
        || payload.request_terms_digest != hex(&digest)
    {
        Err(ExchangeRuleError::StaleDecision)
    } else {
        Ok(())
    }
}

pub fn source_owner_still_current(matches: bool) -> Result<(), ExchangeRuleError> {
    if matches {
        Ok(())
    } else {
        Err(ExchangeRuleError::SourceNotAuthorized)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceDecisionRecord<'a> {
    Approved {
        destination: &'a Participant,
        ownership_revision: u64,
        lease: &'a LeaseWire,
    },
    Denied,
    Blocked,
}

pub fn source_decision_record<'a>(
    payload: &'a DecisionPayload,
    request: &RelationshipRequest,
) -> Result<SourceDecisionRecord<'a>, ExchangeRuleError> {
    match payload.result {
        DecisionResult::Approved => {
            let _lease = payload
                .lease_against(request)
                .map_err(|_| ExchangeRuleError::StaleDecision)?;
            let destination = payload
                .destination
                .as_ref()
                .ok_or(ExchangeRuleError::StaleDecision)?;
            let ownership_revision = payload
                .destination_ownership_revision
                .ok_or(ExchangeRuleError::StaleDecision)?;
            let lease = payload
                .lease
                .as_ref()
                .ok_or(ExchangeRuleError::StaleDecision)?;
            Ok(SourceDecisionRecord::Approved {
                destination,
                ownership_revision,
                lease,
            })
        }
        DecisionResult::Denied => Ok(SourceDecisionRecord::Denied),
        DecisionResult::Blocked => Ok(SourceDecisionRecord::Blocked),
    }
}

pub fn local_owner_consent(
    actor_is_owner: bool,
    pending: bool,
    now: i64,
    expiry: i64,
    current_owner_matches: bool,
) -> Result<(), ExchangeRuleError> {
    if !actor_is_owner {
        return Err(ExchangeRuleError::NotCurrentOwner);
    }
    if !pending {
        return Err(ExchangeRuleError::RequestNotPending);
    }
    if now >= expiry {
        return Err(ExchangeRuleError::DecisionExpired);
    }
    if !current_owner_matches {
        return Err(ExchangeRuleError::NotCurrentOwner);
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Direction, LifetimeRequest, PendingTarget, RequestKind};
    use std::collections::BTreeSet;

    fn platform(value: &str) -> PlatformId {
        PlatformId::new(value).unwrap()
    }

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).unwrap()
    }

    fn request() -> RelationshipRequest {
        RelationshipRequest {
            relationship_id: id("relationship-a-b"),
            request_id: id("request-1"),
            direction: Direction::new(platform("a"), platform("b")).unwrap(),
            source: Participant {
                platform_id: platform("a"),
                subject_id: id("a-account"),
                resource_id: id("a-agent"),
            },
            source_ownership_revision: 1,
            request_kind: RequestKind::Establish,
            request_revision: 1,
            base_lease_revision: None,
            application_protocol: "a2a".into(),
            transport: "https".into(),
            target: PendingTarget {
                destination_platform_id: platform("b"),
                full_agent_address: "0123456789abcdef.providerb.example".into(),
            },
            requested_permissions: BTreeSet::from(["a2a.invoke".into()]),
            requested_lifetime: LifetimeRequest::Fixed { expires_at: 3000 },
            created_at: 1000,
            request_expires_at: 1200,
        }
    }

    #[test]
    fn sent_record_stays_on_the_local_source_account() {
        let request = request();
        assert!(recorded_sent_is_local(&request, &platform("a"), &id("a-account"), 1).is_ok());
        assert_eq!(
            recorded_sent_is_local(&request, &platform("a"), &id("other"), 1),
            Err(ExchangeRuleError::SourceNotAuthorized)
        );
        assert_eq!(
            same_request_snapshot(Some("{\"id\":1}"), "{\"id\":2}"),
            Err(ExchangeRuleError::DuplicateConflict)
        );
        assert!(same_request_snapshot(Some("same"), "same").unwrap());
    }

    #[test]
    fn identical_control_bytes_replay_and_changed_bytes_conflict() {
        assert_eq!(
            replay_request_control(1, &[1; 32], "queued", 1, &[1; 32]).unwrap(),
            RequestDeliveryResult::QueuedForLocalOwner
        );
        assert_eq!(
            replay_request_control(1, &[1; 32], "address_not_recognized", 1, &[1; 32]).unwrap(),
            RequestDeliveryResult::AddressNotRecognized
        );
        assert_eq!(
            replay_request_control(1, &[1; 32], "queued", 1, &[2; 32]),
            Err(ExchangeRuleError::DuplicateConflict)
        );
        assert_eq!(
            replay_ingress_receipt("snap", "queued", "snap").unwrap(),
            IngressReplay::Queued
        );
        assert!(replay_applied_control(1, &[1; 32], "applied", 1, &[1; 32]).is_ok());
        assert_eq!(
            replay_applied_control(1, &[1; 32], "queued", 1, &[1; 32]),
            Err(ExchangeRuleError::DuplicateConflict)
        );
    }

    #[test]
    fn denial_and_expired_owner_action_create_no_grant_path() {
        assert_eq!(
            local_owner_consent(false, true, 1, 5, true),
            Err(ExchangeRuleError::NotCurrentOwner)
        );
        assert_eq!(
            local_owner_consent(true, true, 5, 5, true),
            Err(ExchangeRuleError::DecisionExpired)
        );
        assert_eq!(
            commit_owner_denial(OwnerDenialFacts {
                actor_is_owner: true,
                pending: true,
                now: 1,
                expiry: 5,
                snapshot_matches: true,
                current_owner_matches: true,
            }),
            Ok(())
        );
        assert_eq!(
            commit_owner_approval(OwnerApprovalFacts {
                actor_is_owner: true,
                agent_matches: true,
                revision_matches: true,
                pending: false,
                decision_already_set: false,
                now: 1,
                expiry: 5,
                current_owner_matches: true,
                snapshot_matches: true,
            }),
            Err(ExchangeRuleError::NotCurrentOwner)
        );
    }

    #[test]
    fn source_receipt_replay_must_repeat_the_same_result() {
        let local = platform("a");
        let receipt = ControlReceipt {
            schema: "federation-receipt/v1".into(),
            sender_platform_id: local.clone(),
            recipient_platform_id: platform("b"),
            event_id: id("event-1"),
            body_digest: hex(&[9; 32]),
            result: ReceiptResult::QueuedForLocalOwner,
        };
        assert_eq!(
            plan_source_control_receipt(&receipt, &local, "b", 1, &[9; 32], 1, "queued", None)
                .unwrap(),
            SourceReceiptPlan::Commit {
                receipt_result: "queued_for_local_owner",
                sent_state: "delivered",
            }
        );
        assert_eq!(
            plan_source_control_receipt(
                &receipt,
                &local,
                "b",
                1,
                &[9; 32],
                1,
                "committed",
                Some("address_not_recognized")
            ),
            Err(ExchangeRuleError::ReceiptMismatch)
        );
        assert!(destination_receipt_is_applied(&receipt, &local).is_err());
    }
}
