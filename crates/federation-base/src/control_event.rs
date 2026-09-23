//! Strict project-owned durable lifecycle wire. AGNTCY Directory and SPIRE
//! supply discovery and workload authentication; they do not define owner
//! relationship events. Receipt storage and account decisions remain local.

use crate::{
    provider_manifest::utc_timestamp, LeaseMode, ModelError, OpaqueId, Participant, PlatformId,
    RelationshipLease, RelationshipRequest, MAX_JCS_INTEGER,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_CONTROL_EVENT_BYTES: usize = 32 << 10;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActorSide {
    Source,
    Destination,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventKind {
    RelationshipRequest,
    RelationshipDecision,
    RelationshipRevoke,
    RelationshipStatus,
    SourceAuthorizationStatus,
    ConfigAck,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestPayload {
    pub request: RelationshipRequest,
    pub request_terms_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionResult {
    Approved,
    Denied,
    Blocked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseWire {
    pub lease_id: OpaqueId,
    pub lease_revision: u64,
    pub mode: LeaseMode,
    pub effective_from: u64,
    pub expires_at: Option<u64>,
    pub max_tasks: Option<u32>,
    pub effective_permissions: BTreeSet<String>,
    pub terms_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionPayload {
    pub decision_id: OpaqueId,
    pub result: DecisionResult,
    pub bound_request_revision: u64,
    pub request_terms_digest: String,
    pub destination: Option<Participant>,
    pub destination_ownership_revision: Option<u64>,
    pub lease: Option<LeaseWire>,
}

impl DecisionPayload {
    pub fn lease_against(
        &self,
        request: &RelationshipRequest,
    ) -> Result<RelationshipLease, ControlError> {
        if self.result != DecisionResult::Approved
            || self.bound_request_revision != request.request_revision
            || self.request_terms_digest
                != hex(&request
                    .request_terms_digest()
                    .map_err(ControlError::Model)?)
        {
            return Err(ControlError::InvalidBinding);
        }
        let destination = self
            .destination
            .as_ref()
            .ok_or(ControlError::InvalidBinding)?;
        let revision = self
            .destination_ownership_revision
            .ok_or(ControlError::InvalidBinding)?;
        let wire = self.lease.as_ref().ok_or(ControlError::InvalidBinding)?;
        let lease = RelationshipLease {
            lease_id: wire.lease_id.clone(),
            relationship_id: request.relationship_id.clone(),
            lease_revision: wire.lease_revision,
            mode: wire.mode.clone(),
            effective_from: wire.effective_from,
            expires_at: wire.expires_at,
            max_tasks: wire.max_tasks,
            granted_by_platform_id: request.direction.destination_platform_id.clone(),
            decision_id: self.decision_id.clone(),
            request_id: request.request_id.clone(),
            effective_permissions: wire.effective_permissions.clone(),
            terms_digest: decode_digest(&wire.terms_digest)?,
        };
        lease
            .validate_against(request, destination)
            .map_err(ControlError::Model)?;
        lease
            .verify_terms_digest(request, destination, revision)
            .map_err(ControlError::Model)?;
        Ok(lease)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokePayload {
    pub revocation_id: OpaqueId,
    pub lease_id: OpaqueId,
    pub lease_revision: u64,
    pub reason_code: String,
    pub effective_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelationshipState {
    Configuring,
    Ready,
    Revoked,
    Expired,
    Consumed,
    Suspended,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusPayload {
    pub lease_id: OpaqueId,
    pub lease_revision: u64,
    pub state: RelationshipState,
    pub observed_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceAuthorization {
    Authorized,
    Withdrawn,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAuthorizationPayload {
    pub lease_id: OpaqueId,
    pub lease_revision: u64,
    pub authorization_revision: u64,
    pub status: SourceAuthorization,
    pub effective_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigAckPayload {
    pub lease_id: OpaqueId,
    pub lease_revision: u64,
    pub configuration_revision: u64,
    pub key_purpose_revision: u64,
    pub acknowledged_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlPayload {
    Request(RequestPayload),
    Decision(DecisionPayload),
    Revoke(RevokePayload),
    Status(StatusPayload),
    SourceAuthorization(SourceAuthorizationPayload),
    ConfigAck(ConfigAckPayload),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlEvent {
    pub event_id: OpaqueId,
    pub sender_platform_id: PlatformId,
    pub recipient_platform_id: PlatformId,
    pub originating_platform_id: PlatformId,
    pub relationship_id: OpaqueId,
    pub request_id: Option<OpaqueId>,
    pub actor_side: ActorSide,
    pub actor_revision: u64,
    pub created_at: String,
    pub delivery_expires_at: String,
    pub payload: ControlPayload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedControlEvent {
    pub event: ControlEvent,
    pub exact_bytes: Vec<u8>,
    pub canonical_bytes: Vec<u8>,
    pub body_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlError {
    TooLarge,
    InvalidJson,
    InvalidSchema,
    InvalidField,
    InvalidBinding,
    WrongPeer,
    Model(ModelError),
    Canonicalization,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvent {
    schema: String,
    event_id: OpaqueId,
    kind: EventKind,
    sender_platform_id: PlatformId,
    recipient_platform_id: PlatformId,
    originating_platform_id: PlatformId,
    relationship_id: OpaqueId,
    request_id: Option<OpaqueId>,
    actor_side: ActorSide,
    actor_revision: u64,
    created_at: String,
    delivery_expires_at: String,
    payload: Box<RawValue>,
}

pub fn parse_control_event(
    bytes: &[u8],
    authenticated_sender: &PlatformId,
    local_platform: &PlatformId,
) -> Result<ParsedControlEvent, ControlError> {
    if bytes.is_empty() || bytes.len() > MAX_CONTROL_EVENT_BYTES {
        return Err(ControlError::TooLarge);
    }
    let raw: RawEvent = serde_json::from_slice(bytes).map_err(|_| ControlError::InvalidJson)?;
    if raw.schema != "federation-control/v1" {
        return Err(ControlError::InvalidSchema);
    }
    if &raw.sender_platform_id != authenticated_sender
        || &raw.recipient_platform_id != local_platform
        || raw.sender_platform_id == raw.recipient_platform_id
    {
        return Err(ControlError::WrongPeer);
    }
    if (raw.actor_side == ActorSide::Source
        && raw.originating_platform_id != raw.sender_platform_id)
        || (raw.actor_side == ActorSide::Destination
            && raw.originating_platform_id != raw.recipient_platform_id)
    {
        return Err(ControlError::InvalidBinding);
    }
    for value in [
        raw.event_id.as_str(),
        raw.sender_platform_id.as_str(),
        raw.recipient_platform_id.as_str(),
        raw.originating_platform_id.as_str(),
        raw.relationship_id.as_str(),
    ] {
        if value.is_empty() || value.len() > 256 {
            return Err(ControlError::InvalidField);
        }
    }
    if raw.actor_revision == 0 || raw.actor_revision > MAX_JCS_INTEGER {
        return Err(ControlError::InvalidField);
    }
    let created = utc_timestamp(&raw.created_at).map_err(|_| ControlError::InvalidField)?;
    let deadline =
        utc_timestamp(&raw.delivery_expires_at).map_err(|_| ControlError::InvalidField)?;
    if created >= deadline {
        return Err(ControlError::InvalidField);
    }
    let payload = match raw.kind {
        EventKind::RelationshipRequest => ControlPayload::Request(decode(&raw.payload)?),
        EventKind::RelationshipDecision => ControlPayload::Decision(decode(&raw.payload)?),
        EventKind::RelationshipRevoke => ControlPayload::Revoke(decode(&raw.payload)?),
        EventKind::RelationshipStatus => ControlPayload::Status(decode(&raw.payload)?),
        EventKind::SourceAuthorizationStatus => {
            ControlPayload::SourceAuthorization(decode(&raw.payload)?)
        }
        EventKind::ConfigAck => ControlPayload::ConfigAck(decode(&raw.payload)?),
    };
    match &payload {
        ControlPayload::Request(p) => {
            p.request.validate().map_err(ControlError::Model)?;
            if raw.actor_side != ActorSide::Source
                || raw.originating_platform_id != raw.sender_platform_id
                || raw.request_id.as_ref() != Some(&p.request.request_id)
                || raw.relationship_id != p.request.relationship_id
                || p.request.direction.source_platform_id != raw.sender_platform_id
                || p.request.direction.destination_platform_id != raw.recipient_platform_id
                || p.request_terms_digest
                    != hex(&p
                        .request
                        .request_terms_digest()
                        .map_err(ControlError::Model)?)
            {
                return Err(ControlError::InvalidBinding);
            }
        }
        ControlPayload::Decision(p) => {
            if raw.actor_side != ActorSide::Destination
                || raw.request_id.is_none()
                || raw.originating_platform_id != raw.recipient_platform_id
                || p.bound_request_revision == 0
                || decode_digest(&p.request_terms_digest).is_err()
            {
                return Err(ControlError::InvalidBinding);
            }
            let approved = p.result == DecisionResult::Approved;
            if approved
                != (p.destination.is_some()
                    && p.destination_ownership_revision.is_some()
                    && p.lease.is_some())
            {
                return Err(ControlError::InvalidBinding);
            }
            if !approved
                && (p.destination.is_some()
                    || p.destination_ownership_revision.is_some()
                    || p.lease.is_some())
            {
                return Err(ControlError::InvalidBinding);
            }
        }
        ControlPayload::Revoke(p) => {
            if raw.actor_side != ActorSide::Destination
                || p.lease_revision == 0
                || p.reason_code.is_empty()
            {
                return Err(ControlError::InvalidField);
            }
            utc_timestamp(&p.effective_at).map_err(|_| ControlError::InvalidField)?;
        }
        ControlPayload::Status(p) => {
            if p.lease_revision == 0 {
                return Err(ControlError::InvalidField);
            }
            utc_timestamp(&p.observed_at).map_err(|_| ControlError::InvalidField)?;
        }
        ControlPayload::SourceAuthorization(p) => {
            if raw.actor_side != ActorSide::Source
                || p.lease_revision == 0
                || p.authorization_revision == 0
            {
                return Err(ControlError::InvalidField);
            }
            utc_timestamp(&p.effective_at).map_err(|_| ControlError::InvalidField)?;
        }
        ControlPayload::ConfigAck(p) => {
            if p.lease_revision == 0 || p.configuration_revision == 0 || p.key_purpose_revision == 0
            {
                return Err(ControlError::InvalidField);
            }
            utc_timestamp(&p.acknowledged_at).map_err(|_| ControlError::InvalidField)?;
        }
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ControlError::InvalidJson)?;
    let canonical_bytes =
        serde_json_canonicalizer::to_vec(&value).map_err(|_| ControlError::Canonicalization)?;
    let body_digest = Sha256::digest(&canonical_bytes).into();
    Ok(ParsedControlEvent {
        event: ControlEvent {
            event_id: raw.event_id,
            sender_platform_id: raw.sender_platform_id,
            recipient_platform_id: raw.recipient_platform_id,
            originating_platform_id: raw.originating_platform_id,
            relationship_id: raw.relationship_id,
            request_id: raw.request_id,
            actor_side: raw.actor_side,
            actor_revision: raw.actor_revision,
            created_at: raw.created_at,
            delivery_expires_at: raw.delivery_expires_at,
            payload,
        },
        exact_bytes: bytes.to_vec(),
        canonical_bytes,
        body_digest,
    })
}

fn decode<T: serde::de::DeserializeOwned>(json: &RawValue) -> Result<T, ControlError> {
    serde_json::from_str(json.get()).map_err(|_| ControlError::InvalidJson)
}

fn decode_digest(value: &str) -> Result<[u8; 32], ControlError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(ControlError::InvalidField);
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ControlError::InvalidField)?;
    }
    Ok(bytes)
}
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReceiptResult {
    QueuedForLocalOwner,
    AddressNotRecognized,
    Applied,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlReceipt {
    pub schema: String,
    pub sender_platform_id: PlatformId,
    pub recipient_platform_id: PlatformId,
    pub event_id: OpaqueId,
    pub body_digest: String,
    pub result: ReceiptResult,
}

impl ControlReceipt {
    pub fn for_event(event: &ParsedControlEvent, result: ReceiptResult) -> Self {
        Self {
            schema: "federation-receipt/v1".into(),
            sender_platform_id: event.event.sender_platform_id.clone(),
            recipient_platform_id: event.event.recipient_platform_id.clone(),
            event_id: event.event.event_id.clone(),
            body_digest: hex(&event.body_digest),
            result,
        }
    }
    pub fn validate_against(&self, event: &ParsedControlEvent) -> Result<(), ControlError> {
        if self.schema != "federation-receipt/v1"
            || self.sender_platform_id != event.event.sender_platform_id
            || self.recipient_platform_id != event.event.recipient_platform_id
            || self.event_id != event.event.event_id
            || decode_digest(&self.body_digest)? != event.body_digest
        {
            return Err(ControlError::InvalidBinding);
        }
        Ok(())
    }
}

pub fn parse_receipt(bytes: &[u8]) -> Result<ControlReceipt, ControlError> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(ControlError::TooLarge);
    }
    let receipt: ControlReceipt =
        serde_json::from_slice(bytes).map_err(|_| ControlError::InvalidJson)?;
    if receipt.schema != "federation-receipt/v1" {
        return Err(ControlError::InvalidSchema);
    }
    decode_digest(&receipt.body_digest)?;
    Ok(receipt)
}
