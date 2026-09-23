//! Provider operator trust protocol. These messages are Base-owned because
//! Directory federation and SPIRE workload trust do not express business
//! operator request/approval. They travel over exact-ID SPIFFE mTLS.

use crate::provider_manifest::{parse_manifest, utc_timestamp, ManifestSnapshot};
use crate::{OpaqueId, PlatformId, MAX_JCS_INTEGER};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_PEER_MESSAGE_BYTES: usize = 72 << 10;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PeerKind {
    PeerHello,
    TrustRequest,
    TrustDecision,
    TrustSuspend,
    TrustRemove,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustDecisionResult {
    Approved,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRequestPayload {
    pub request_id: OpaqueId,
    pub sender_manifest_digest: String,
    pub recipient_manifest_digest: String,
    pub requested_capabilities: BTreeSet<String>,
    pub expires_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustDecisionPayload {
    pub request_id: OpaqueId,
    pub result: TrustDecisionResult,
    pub sender_manifest_digest: String,
    pub recipient_manifest_digest: String,
    pub approved_capabilities: BTreeSet<String>,
    pub decided_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestrictionPayload {
    pub reason_code: String,
    pub effective_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerPayload {
    Hello(ManifestSnapshot),
    Request(TrustRequestPayload),
    Decision(TrustDecisionPayload),
    Suspend(RestrictionPayload),
    Remove(RestrictionPayload),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerMessage {
    pub message_id: OpaqueId,
    pub sender_platform_id: PlatformId,
    pub recipient_platform_id: PlatformId,
    pub generation: u64,
    pub sent_at: String,
    pub payload: PeerPayload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedPeerMessage {
    pub message: PeerMessage,
    pub exact_bytes: Vec<u8>,
    pub canonical_bytes: Vec<u8>,
    pub body_digest: [u8; 32],
}

/// A network receipt is correlated to exact peer bytes. It is not operator
/// approval or relationship readiness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerReceipt {
    pub schema: String,
    pub sender_platform_id: PlatformId,
    pub recipient_platform_id: PlatformId,
    pub generation: u64,
    pub message_id: OpaqueId,
    pub body_digest: String,
    pub result: String,
}

pub fn parse_peer_receipt(
    bytes: &[u8],
    sent: &ParsedPeerMessage,
    authenticated_peer: &PlatformId,
) -> Result<PeerReceipt, PeerWireError> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(PeerWireError::TooLarge);
    }
    let receipt: PeerReceipt =
        serde_json::from_slice(bytes).map_err(|_| PeerWireError::InvalidJson)?;
    if receipt.schema != "federation-peer-receipt/v1" {
        return Err(PeerWireError::InvalidSchema);
    }
    if &receipt.sender_platform_id != authenticated_peer
        || receipt.recipient_platform_id != sent.message.sender_platform_id
        || receipt.sender_platform_id != sent.message.recipient_platform_id
    {
        return Err(PeerWireError::WrongPeer);
    }
    if receipt.generation != sent.message.generation
        || receipt.message_id != sent.message.message_id
        || receipt.body_digest != hex_digest(&sent.body_digest)
        || !matches!(
            receipt.result.as_str(),
            "CANDIDATE_SAVED" | "REQUEST_QUEUED" | "DECISION_RECORDED" | "SUSPENDED" | "REMOVED"
        )
    {
        return Err(PeerWireError::InvalidField);
    }
    Ok(receipt)
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerWireError {
    TooLarge,
    InvalidJson,
    InvalidSchema,
    InvalidField,
    WrongPeer,
    WrongService,
    InvalidManifest,
    Canonicalization,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMessage {
    schema: String,
    message_id: OpaqueId,
    kind: PeerKind,
    sender_platform_id: PlatformId,
    recipient_platform_id: PlatformId,
    generation: u64,
    sent_at: String,
    payload: Box<RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHello {
    manifest: Box<RawValue>,
}

pub fn parse_peer_message(
    bytes: &[u8],
    authenticated_sender: &PlatformId,
    local_platform: &PlatformId,
    authenticated_service_id: &str,
    expected_service_id: &str,
) -> Result<ParsedPeerMessage, PeerWireError> {
    if bytes.is_empty() || bytes.len() > MAX_PEER_MESSAGE_BYTES {
        return Err(PeerWireError::TooLarge);
    }
    if authenticated_service_id != expected_service_id || expected_service_id.is_empty() {
        return Err(PeerWireError::WrongService);
    }
    let raw: RawMessage = serde_json::from_slice(bytes).map_err(|_| PeerWireError::InvalidJson)?;
    if raw.schema != "federation-peer/v1" {
        return Err(PeerWireError::InvalidSchema);
    }
    if &raw.sender_platform_id != authenticated_sender
        || &raw.recipient_platform_id != local_platform
        || raw.sender_platform_id == raw.recipient_platform_id
    {
        return Err(PeerWireError::WrongPeer);
    }
    if raw.generation == 0
        || raw.generation > MAX_JCS_INTEGER
        || raw.message_id.as_str().is_empty()
        || raw.message_id.as_str().len() > 256
    {
        return Err(PeerWireError::InvalidField);
    }
    utc_timestamp(&raw.sent_at).map_err(|_| PeerWireError::InvalidField)?;
    let payload = match raw.kind {
        PeerKind::PeerHello => {
            let hello: RawHello =
                serde_json::from_str(raw.payload.get()).map_err(|_| PeerWireError::InvalidJson)?;
            let snapshot = parse_manifest(hello.manifest.get().as_bytes())
                .map_err(|_| PeerWireError::InvalidManifest)?;
            snapshot
                .manifest
                .check_authenticated_binding(authenticated_sender, authenticated_service_id)
                .map_err(|_| PeerWireError::WrongService)?;
            PeerPayload::Hello(snapshot)
        }
        PeerKind::TrustRequest => {
            let request: TrustRequestPayload =
                serde_json::from_str(raw.payload.get()).map_err(|_| PeerWireError::InvalidJson)?;
            digest(&request.sender_manifest_digest)?;
            digest(&request.recipient_manifest_digest)?;
            if request.request_id.as_str().is_empty()
                || request.requested_capabilities.len() > 64
                || request
                    .requested_capabilities
                    .iter()
                    .any(|c| c.is_empty() || c.len() > 256)
            {
                return Err(PeerWireError::InvalidField);
            }
            let expiry =
                utc_timestamp(&request.expires_at).map_err(|_| PeerWireError::InvalidField)?;
            let sent = utc_timestamp(&raw.sent_at).map_err(|_| PeerWireError::InvalidField)?;
            if expiry <= sent {
                return Err(PeerWireError::InvalidField);
            }
            PeerPayload::Request(request)
        }
        PeerKind::TrustDecision => {
            let decision: TrustDecisionPayload =
                serde_json::from_str(raw.payload.get()).map_err(|_| PeerWireError::InvalidJson)?;
            digest(&decision.sender_manifest_digest)?;
            digest(&decision.recipient_manifest_digest)?;
            utc_timestamp(&decision.decided_at).map_err(|_| PeerWireError::InvalidField)?;
            if decision.request_id.as_str().is_empty()
                || decision.approved_capabilities.len() > 64
                || (decision.result == TrustDecisionResult::Rejected
                    && !decision.approved_capabilities.is_empty())
            {
                return Err(PeerWireError::InvalidField);
            }
            PeerPayload::Decision(decision)
        }
        PeerKind::TrustSuspend => {
            let restriction: RestrictionPayload =
                serde_json::from_str(raw.payload.get()).map_err(|_| PeerWireError::InvalidJson)?;
            validate_restriction(&restriction)?;
            PeerPayload::Suspend(restriction)
        }
        PeerKind::TrustRemove => {
            let restriction: RestrictionPayload =
                serde_json::from_str(raw.payload.get()).map_err(|_| PeerWireError::InvalidJson)?;
            validate_restriction(&restriction)?;
            PeerPayload::Remove(restriction)
        }
    };
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| PeerWireError::InvalidJson)?;
    let canonical_bytes =
        serde_json_canonicalizer::to_vec(&value).map_err(|_| PeerWireError::Canonicalization)?;
    let body_digest = Sha256::digest(&canonical_bytes).into();
    Ok(ParsedPeerMessage {
        message: PeerMessage {
            message_id: raw.message_id,
            sender_platform_id: raw.sender_platform_id,
            recipient_platform_id: raw.recipient_platform_id,
            generation: raw.generation,
            sent_at: raw.sent_at,
            payload,
        },
        exact_bytes: bytes.to_vec(),
        canonical_bytes,
        body_digest,
    })
}

fn validate_restriction(value: &RestrictionPayload) -> Result<(), PeerWireError> {
    if value.reason_code.is_empty() || value.reason_code.len() > 256 {
        return Err(PeerWireError::InvalidField);
    }
    utc_timestamp(&value.effective_at).map_err(|_| PeerWireError::InvalidField)?;
    Ok(())
}
fn digest(value: &str) -> Result<(), PeerWireError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Err(PeerWireError::InvalidField)
    } else {
        Ok(())
    }
}

pub fn decode_digest(value: &str) -> Result<[u8; 32], PeerWireError> {
    digest(value)?;
    let mut bytes = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or(PeerWireError::InvalidField)?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or(PeerWireError::InvalidField)?;
        bytes[index] = ((high << 4) | low) as u8;
    }
    Ok(bytes)
}
