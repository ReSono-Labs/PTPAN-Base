//! Strict project-owned durable lifecycle wire. AGNTCY Directory and SPIRE
//! supply discovery and workload authentication; they do not define owner
//! relationship events. Receipt storage and account decisions remain local.

use crate::{
    encoding::{canonical_digest, decode_hex32, hex_lower, is_lower_hex},
    time::parse_utc,
    address::valid_address,
    LeaseMode, ModelError, OpaqueId, PersonName, PlatformId, RelationshipLease,
    RelationshipRequest, MAX_JCS_INTEGER,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::collections::BTreeSet;

pub const MAX_CONTROL_EVENT_BYTES: usize = 32 << 10;
/// The only accepted control-event schema (D5–D7).
pub const CONTROL_SCHEMA: &str = "federation-control/v3";

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
    PairBlockStatus,
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

impl LeaseWire {
    /// The wire form of an issued lease (`ComputeLease`, D1).
    pub fn from_lease(lease: &RelationshipLease) -> Self {
        Self {
            lease_id: lease.lease_id.clone(),
            lease_revision: lease.lease_revision,
            mode: lease.mode.clone(),
            effective_from: lease.effective_from,
            expires_at: lease.expires_at,
            max_tasks: lease.max_tasks,
            effective_permissions: lease.effective_permissions.clone(),
            terms_digest: hex_lower(&lease.terms_digest),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionPayload {
    pub decision_id: OpaqueId,
    pub result: DecisionResult,
    pub bound_request_revision: u64,
    pub request_terms_digest: String,
    pub destination_ownership_revision: Option<u64>,
    /// The destination owner's name, present only on an approval (D6).
    pub destination_owner_name: Option<PersonName>,
    pub lease: Option<LeaseWire>,
}

impl DecisionPayload {
    /// The approved lease, issued by `issuer` (the authenticated sender of
    /// the decision), validated against the stored request.
    pub fn lease_against(
        &self,
        request: &RelationshipRequest,
        issuer: &PlatformId,
    ) -> Result<RelationshipLease, ControlError> {
        if self.result != DecisionResult::Approved
            || self.bound_request_revision != request.request_revision
            || self.request_terms_digest
                != hex_lower(&request
                    .request_terms_digest()
                    .map_err(ControlError::Model)?)
        {
            return Err(ControlError::InvalidBinding);
        }
        let owner_name = self
            .destination_owner_name
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
            granted_by_platform_id: issuer.clone(),
            decision_id: self.decision_id.clone(),
            request_id: request.request_id.clone(),
            effective_permissions: wire.effective_permissions.clone(),
            terms_digest: decode_digest(&wire.terms_digest)?,
        };
        lease
            .validate_against(request)
            .map_err(ControlError::Model)?;
        lease
            .verify_terms_digest(request, revision, owner_name)
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_key: Option<SourceKeyBinding>,
}

/// The source platform's statement of its agent's admission public key for
/// one relationship. Agents are named by requester reference and destination
/// address (D5). The destination platform binds the key to its own grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceKeyBinding {
    pub requester_reference: String,
    pub destination_address: String,
    pub terms_digest: String,
    pub key_purpose: String,
    pub public_key: String,
}

impl SourceKeyBinding {
    pub fn matches_approved_lease(
        &self,
        request: &RelationshipRequest,
        lease: &RelationshipLease,
    ) -> bool {
        self.requester_reference == request.source.address
            && self.destination_address == request.target_address
            && self.terms_digest == hex_lower(&lease.terms_digest)
            && self.key_purpose == "ed25519_admission"
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PairBlockState {
    Blocked,
    Open,
}

/// A destination owner's block or unblock of one requester reference against
/// one of its own addresses (D7). It is pair-scoped, not tied to a
/// relationship.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairBlockStatusPayload {
    pub requester_reference: String,
    pub destination_address: String,
    pub state: PairBlockState,
    pub block_revision: u64,
    pub effective_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlPayload {
    Request(RequestPayload),
    Decision(DecisionPayload),
    Revoke(RevokePayload),
    Status(StatusPayload),
    SourceAuthorization(SourceAuthorizationPayload),
    ConfigAck(ConfigAckPayload),
    PairBlockStatus(PairBlockStatusPayload),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlEvent {
    pub schema: String,
    pub event_id: OpaqueId,
    pub sender_platform_id: PlatformId,
    pub recipient_platform_id: PlatformId,
    pub originating_platform_id: PlatformId,
    /// Absent only for `PAIR_BLOCK_STATUS`.
    pub relationship_id: Option<OpaqueId>,
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
    relationship_id: Option<OpaqueId>,
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
    if raw.schema != CONTROL_SCHEMA {
        return Err(ControlError::InvalidSchema);
    }
    if (raw.kind == EventKind::PairBlockStatus) != raw.relationship_id.is_none() {
        return Err(ControlError::InvalidBinding);
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
        raw.relationship_id.as_ref().map_or("-", OpaqueId::as_str),
    ] {
        if value.is_empty() || value.len() > 256 {
            return Err(ControlError::InvalidField);
        }
    }
    if raw.actor_revision == 0 || raw.actor_revision > MAX_JCS_INTEGER {
        return Err(ControlError::InvalidField);
    }
    let created = parse_utc(&raw.created_at).ok_or(ControlError::InvalidField)?;
    let deadline =
        parse_utc(&raw.delivery_expires_at).ok_or(ControlError::InvalidField)?;
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
        EventKind::PairBlockStatus => ControlPayload::PairBlockStatus(decode(&raw.payload)?),
    };
    match &payload {
        ControlPayload::Request(p) => {
            p.request.validate().map_err(ControlError::Model)?;
            if raw.actor_side != ActorSide::Source
                || raw.originating_platform_id != raw.sender_platform_id
                || raw.request_id.as_ref() != Some(&p.request.request_id)
                || raw.relationship_id.as_ref() != Some(&p.request.relationship_id)
                || p.request.source.platform_id != raw.sender_platform_id
                || p.request_terms_digest
                    != hex_lower(&p
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
            let fields = [
                p.destination_owner_name.is_some(),
                p.destination_ownership_revision.is_some(),
                p.lease.is_some(),
            ];
            if fields.iter().any(|present| *present != approved) {
                return Err(ControlError::InvalidBinding);
            }
            if let Some(name) = &p.destination_owner_name {
                name.validate().map_err(ControlError::Model)?;
            }
        }
        ControlPayload::Revoke(p) => {
            if raw.actor_side != ActorSide::Destination
                || p.lease_revision == 0
                || p.reason_code.is_empty()
            {
                return Err(ControlError::InvalidField);
            }
            parse_utc(&p.effective_at).ok_or(ControlError::InvalidField)?;
        }
        ControlPayload::Status(p) => {
            if p.lease_revision == 0 {
                return Err(ControlError::InvalidField);
            }
            parse_utc(&p.observed_at).ok_or(ControlError::InvalidField)?;
        }
        ControlPayload::SourceAuthorization(p) => {
            if raw.actor_side != ActorSide::Source
                || p.lease_revision == 0
                || p.authorization_revision == 0
            {
                return Err(ControlError::InvalidField);
            }
            parse_utc(&p.effective_at).ok_or(ControlError::InvalidField)?;
        }
        ControlPayload::ConfigAck(p) => {
            if p.lease_revision == 0 || p.configuration_revision == 0 || p.key_purpose_revision == 0
            {
                return Err(ControlError::InvalidField);
            }
            parse_utc(&p.acknowledged_at).ok_or(ControlError::InvalidField)?;
            match (&raw.actor_side, &p.source_key) {
                (ActorSide::Source, Some(binding)) => {
                    if binding.key_purpose != "ed25519_admission"
                        || decode_digest(&binding.terms_digest).is_err()
                        || !valid_address(&binding.requester_reference)
                        || !valid_address(&binding.destination_address)
                        || !is_lower_hex(&binding.public_key, 32)
                    {
                        return Err(ControlError::InvalidField);
                    }
                }
                (ActorSide::Source, None) | (ActorSide::Destination, Some(_)) => {
                    return Err(ControlError::InvalidBinding);
                }
                (ActorSide::Destination, None) => {}
            }
        }
        ControlPayload::PairBlockStatus(p) => {
            if raw.actor_side != ActorSide::Destination
                || raw.request_id.is_some()
                || p.block_revision == 0
                || p.block_revision > MAX_JCS_INTEGER
                || !valid_address(&p.requester_reference)
                || !valid_address(&p.destination_address)
            {
                return Err(ControlError::InvalidField);
            }
            parse_utc(&p.effective_at).ok_or(ControlError::InvalidField)?;
        }
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ControlError::InvalidJson)?;
    let (canonical_bytes, body_digest) =
        canonical_digest(&value).ok_or(ControlError::Canonicalization)?;
    Ok(ParsedControlEvent {
        event: ControlEvent {
            schema: raw.schema,
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
    decode_hex32(value).ok_or(ControlError::InvalidField)
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
            body_digest: hex_lower(&event.body_digest),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn a() -> PlatformId {
        PlatformId::new("provider-a").unwrap()
    }
    fn b() -> PlatformId {
        PlatformId::new("provider-b").unwrap()
    }

    fn envelope(kind: &str, actor: &str, relationship: serde_json::Value, payload: serde_json::Value) -> serde_json::Value {
        // The originating platform is always the relationship's source (A).
        let originating = "provider-a";
        let (sender, recipient) = if actor == "SOURCE" { ("provider-a", "provider-b") } else { ("provider-b", "provider-a") };
        serde_json::json!({
            "schema":CONTROL_SCHEMA,"event_id":"e1","kind":kind,
            "sender_platform_id":sender,"recipient_platform_id":recipient,
            "originating_platform_id":originating,"relationship_id":relationship,
            "request_id":null,"actor_side":actor,"actor_revision":1,
            "created_at":"2026-09-23T08:00:00Z","delivery_expires_at":"2026-09-23T08:01:00Z",
            "payload":payload
        })
    }

    fn bytes(value: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    #[test]
    fn strict_status_wire_rejects_spoof_duplicate_unknown_and_old_schema() {
        let body = envelope("RELATIONSHIP_STATUS", "SOURCE", "r1".into(), serde_json::json!({
            "lease_id":"l1","lease_revision":1,"state":"READY","observed_at":"2026-09-23T08:00:00Z"}));
        let raw = bytes(&body);
        let parsed = parse_control_event(&raw, &a(), &b()).unwrap();
        assert_eq!(parsed.exact_bytes, raw);
        assert_ne!(parsed.body_digest, [0; 32]);
        assert_eq!(parse_control_event(&raw, &b(), &a()), Err(ControlError::WrongPeer));
        let text = String::from_utf8(raw.clone()).unwrap();
        let duplicate = text.replace("\"state\":\"READY\"", "\"state\":\"READY\",\"state\":\"REVOKED\"");
        assert_eq!(parse_control_event(duplicate.as_bytes(), &a(), &b()), Err(ControlError::InvalidJson));
        let unknown = text.replace("\"observed_at\":", "\"account_inventory\":[],\"observed_at\":");
        assert_eq!(parse_control_event(unknown.as_bytes(), &a(), &b()), Err(ControlError::InvalidJson));
        for old in ["federation-control/v1", "federation-control/v2"] {
            let mut legacy = body.clone();
            legacy["schema"] = old.into();
            assert_eq!(parse_control_event(&bytes(&legacy), &a(), &b()), Err(ControlError::InvalidSchema));
        }
        let mut no_relationship = body.clone();
        no_relationship["relationship_id"] = serde_json::Value::Null;
        assert_eq!(parse_control_event(&bytes(&no_relationship), &a(), &b()), Err(ControlError::InvalidBinding));
    }

    #[test]
    fn control_schema_names_the_seven_kinds_and_shares_the_address_pattern() {
        let schema = include_str!("../../../schemas/control-event-v3.json");
        let value: serde_json::Value = serde_json::from_str(schema).unwrap();
        assert_eq!(value["$id"], CONTROL_SCHEMA);
        assert_eq!(value["additionalProperties"], false);
        let kinds = value["properties"]["kind"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            [
                "RELATIONSHIP_REQUEST",
                "RELATIONSHIP_DECISION",
                "RELATIONSHIP_REVOKE",
                "RELATIONSHIP_STATUS",
                "SOURCE_AUTHORIZATION_STATUS",
                "CONFIG_ACK",
                "PAIR_BLOCK_STATUS"
            ]
        );
        assert_eq!(value["$defs"]["address"]["pattern"], crate::address::ADDRESS_PATTERN);
        for forbidden in ["subject_id", "resource_id", "source_subject", "destination_resource", "account_inventory"] {
            assert!(!schema.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn checked_in_schema_matches_every_payload_type() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/control-event-v3.json")).unwrap();
        let defs = &schema["$defs"];
        let payloads = [
            ("sourceKey", source_key()),
            ("configAckPayload", key_ack("SOURCE", Some(source_key()))["payload"].clone()),
            ("pairBlockStatusPayload", block("BLOCKED", 1)["payload"].clone()),
        ];
        for (name, payload) in payloads {
            crate::schema_check::matches(&schema, &defs[name], &payload, name);
        }
        let request = crate::tests::request_value();
        crate::schema_check::matches(&schema, &defs["relationshipRequest"], &request, "request");
        let envelope = block("OPEN", 2);
        let mut keys: Vec<&str> = envelope.as_object().unwrap().keys().map(String::as_str).collect();
        let mut required: Vec<&str> = schema["required"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        keys.sort();
        required.sort();
        assert_eq!(keys, required);
    }

    fn key_ack(actor: &str, source_key: Option<serde_json::Value>) -> serde_json::Value {
        let mut payload = serde_json::json!({"lease_id":"lease-1","lease_revision":1,"configuration_revision":1,
            "key_purpose_revision":1,"acknowledged_at":"2026-09-23T08:00:00Z"});
        if let Some(key) = source_key {
            payload["source_key"] = key;
        }
        envelope("CONFIG_ACK", actor, "relationship-1".into(), payload)
    }

    fn source_key() -> serde_json::Value {
        serde_json::json!({"requester_reference":"Requester.7.provider-a.test",
            "destination_address":"0123456789abcdef.provider-b.test",
            "terms_digest":"aa".repeat(32),"key_purpose":"ed25519_admission","public_key":"bb".repeat(32)})
    }

    #[test]
    fn source_ack_carries_an_address_bound_key_and_destination_ack_does_not() {
        assert!(parse_control_event(&bytes(&key_ack("SOURCE", Some(source_key()))), &a(), &b()).is_ok());
        assert_eq!(parse_control_event(&bytes(&key_ack("SOURCE", None)), &a(), &b()), Err(ControlError::InvalidBinding));
        assert!(parse_control_event(&bytes(&key_ack("DESTINATION", None)), &b(), &a()).is_ok());
        assert_eq!(parse_control_event(&bytes(&key_ack("DESTINATION", Some(source_key()))), &b(), &a()), Err(ControlError::InvalidBinding));
        let mut wrong = source_key();
        wrong["key_purpose"] = "spiffe".into();
        assert_eq!(parse_control_event(&bytes(&key_ack("SOURCE", Some(wrong))), &a(), &b()), Err(ControlError::InvalidField));
        let mut internal = source_key();
        internal["requester_reference"] = "account_1".into();
        assert_eq!(parse_control_event(&bytes(&key_ack("SOURCE", Some(internal))), &a(), &b()), Err(ControlError::InvalidField));
        let mut legacy = source_key();
        legacy["source_subject"] = "account-1".into();
        assert_eq!(parse_control_event(&bytes(&key_ack("SOURCE", Some(legacy))), &a(), &b()), Err(ControlError::InvalidJson));
    }

    fn block(state: &str, revision: u64) -> serde_json::Value {
        envelope("PAIR_BLOCK_STATUS", "DESTINATION", serde_json::Value::Null, serde_json::json!({
            "requester_reference":"Requester.7.provider-a.test",
            "destination_address":"0123456789abcdef.provider-b.test",
            "state":state,"block_revision":revision,"effective_at":"2026-09-23T08:00:00Z"}))
    }

    #[test]
    fn pair_block_status_is_destination_only_and_pair_scoped() {
        let parsed = parse_control_event(&bytes(&block("BLOCKED", 1)), &b(), &a()).unwrap();
        let ControlPayload::PairBlockStatus(payload) = parsed.event.payload else { panic!() };
        assert_eq!(payload.state, PairBlockState::Blocked);
        assert!(parsed.event.relationship_id.is_none());
        assert!(parse_control_event(&bytes(&block("OPEN", 2)), &b(), &a()).is_ok());
        assert_eq!(parse_control_event(&bytes(&block("BLOCKED", 0)), &b(), &a()), Err(ControlError::InvalidField));
        let mut with_relationship = block("BLOCKED", 1);
        with_relationship["relationship_id"] = "r1".into();
        assert_eq!(parse_control_event(&bytes(&with_relationship), &b(), &a()), Err(ControlError::InvalidBinding));
        let mut from_source = block("BLOCKED", 1);
        from_source["actor_side"] = "SOURCE".into();
        assert!(parse_control_event(&bytes(&from_source), &b(), &a()).is_err());
    }

    #[test]
    fn decision_name_appears_only_on_approval() {
        let digest = "cc".repeat(32);
        let mut denied = envelope("RELATIONSHIP_DECISION", "DESTINATION", "r1".into(), serde_json::json!({
            "decision_id":"d1","result":"DENIED","bound_request_revision":1,"request_terms_digest":digest,
            "destination_ownership_revision":null,"destination_owner_name":null,"lease":null}));
        denied["request_id"] = "q1".into();
        assert!(parse_control_event(&bytes(&denied), &b(), &a()).is_ok());
        denied["payload"]["destination_owner_name"] = serde_json::json!({"given_name":"Grace","family_name":"Hopper"});
        assert_eq!(parse_control_event(&bytes(&denied), &b(), &a()), Err(ControlError::InvalidBinding));
        denied["payload"]["destination"] = serde_json::json!({"platform_id":"provider-b","subject_id":"x","resource_id":"y"});
        assert_eq!(parse_control_event(&bytes(&denied), &b(), &a()), Err(ControlError::InvalidJson));
    }
}
