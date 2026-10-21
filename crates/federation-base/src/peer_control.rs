//! Provider operator trust protocol. These messages are Base-owned because
//! Directory federation and SPIRE workload trust do not express business
//! operator request/approval. They travel over exact-ID SPIFFE mTLS.

use crate::encoding::{canonical_digest, decode_hex32, hex_lower};
use crate::provider_manifest::{parse_manifest, ManifestSnapshot};
use crate::time::parse_utc;
use crate::{OpaqueId, PlatformId, MAX_JCS_INTEGER};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::collections::BTreeSet;

pub const MAX_PEER_MESSAGE_BYTES: usize = 72 << 10;
/// The only accepted peer-message schema.
pub const PEER_SCHEMA: &str = "federation-peer/v2";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PeerKind {
    PeerHello,
    TrustDecision,
    TrustSuspend,
    TrustRemove,
    ManifestPending,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustDecisionResult {
    Approved,
    Rejected,
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

/// A planned manifest revision announced before it takes effect (D8). Each
/// receiving operator revalidates and approves it before `effective_at`;
/// otherwise traffic stops at that time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingManifest {
    pub manifest: ManifestSnapshot,
    pub effective_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerPayload {
    Hello(ManifestSnapshot),
    ManifestPending(PendingManifest),
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
        || receipt.body_digest != hex_lower(&sent.body_digest)
        || !matches!(
            receipt.result.as_str(),
            "CANDIDATE_SAVED"
                | "DECISION_RECORDED"
                | "SUSPENDED"
                | "REMOVED"
                | "PENDING_RECORDED"
        )
    {
        return Err(PeerWireError::InvalidField);
    }
    Ok(receipt)
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPending {
    manifest: Box<RawValue>,
    effective_at: String,
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
    if raw.schema != PEER_SCHEMA {
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
    parse_utc(&raw.sent_at).ok_or(PeerWireError::InvalidField)?;
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
        PeerKind::TrustDecision => {
            let decision: TrustDecisionPayload =
                serde_json::from_str(raw.payload.get()).map_err(|_| PeerWireError::InvalidJson)?;
            decode_digest(&decision.sender_manifest_digest)?;
            decode_digest(&decision.recipient_manifest_digest)?;
            parse_utc(&decision.decided_at).ok_or(PeerWireError::InvalidField)?;
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
        PeerKind::ManifestPending => {
            let pending: RawPending =
                serde_json::from_str(raw.payload.get()).map_err(|_| PeerWireError::InvalidJson)?;
            let snapshot = parse_manifest(pending.manifest.get().as_bytes())
                .map_err(|_| PeerWireError::InvalidManifest)?;
            // The new revision may change service identities; only the
            // platform must stay the same. Revalidation is the receiver's job.
            if &snapshot.manifest.platform.platform_id != authenticated_sender {
                return Err(PeerWireError::WrongPeer);
            }
            let effective = parse_utc(&pending.effective_at).ok_or(PeerWireError::InvalidField)?;
            let sent = parse_utc(&raw.sent_at).ok_or(PeerWireError::InvalidField)?;
            if effective <= sent {
                return Err(PeerWireError::InvalidField);
            }
            PeerPayload::ManifestPending(PendingManifest {
                manifest: snapshot,
                effective_at: pending.effective_at,
            })
        }
    };
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| PeerWireError::InvalidJson)?;
    let (canonical_bytes, body_digest) =
        canonical_digest(&value).ok_or(PeerWireError::Canonicalization)?;
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
    parse_utc(&value.effective_at).ok_or(PeerWireError::InvalidField)?;
    Ok(())
}
pub fn decode_digest(value: &str) -> Result<[u8; 32], PeerWireError> {
    decode_hex32(value).ok_or(PeerWireError::InvalidField)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_manifest_names_the_same_platform_and_a_future_time() {
        let a = PlatformId::new("provider-a").unwrap();
        let b = PlatformId::new("provider-b").unwrap();
        let control = "spiffe://provider-b.test/federation/control";
        let mut next = crate::provider_manifest::tests::valid();
        next.revision = 2;
        next.workload_trust.control_service_identity = "spiffe://provider-b.test/federation/control-2".into();
        let message = |manifest: &crate::provider_manifest::ProviderManifest, effective: &str| {
            serde_json::to_vec(&serde_json::json!({"schema":PEER_SCHEMA,"message_id":"m9","kind":"MANIFEST_PENDING",
                "sender_platform_id":"provider-b","recipient_platform_id":"provider-a","generation":3,
                "sent_at":"2026-09-23T08:00:00Z","payload":{"manifest":manifest,"effective_at":effective}})).unwrap()
        };
        let parsed = parse_peer_message(&message(&next, "2026-09-30T08:00:00Z"), &b, &a, control, control).unwrap();
        let PeerPayload::ManifestPending(pending) = parsed.message.payload else { panic!() };
        assert_eq!(pending.manifest.manifest.revision, 2);
        assert_eq!(
            parse_peer_message(&message(&next, "2026-09-23T08:00:00Z"), &b, &a, control, control).err(),
            Some(PeerWireError::InvalidField)
        );
        let mut other = next.clone();
        other.platform.platform_id = PlatformId::new("provider-c").unwrap();
        assert_eq!(
            parse_peer_message(&message(&other, "2026-09-30T08:00:00Z"), &b, &a, control, control).err(),
            Some(PeerWireError::WrongPeer)
        );
        let legacy = String::from_utf8(message(&next, "2026-09-30T08:00:00Z")).unwrap().replace(PEER_SCHEMA, "federation-peer/v1");
        assert_eq!(
            parse_peer_message(legacy.as_bytes(), &b, &a, control, control).err(),
            Some(PeerWireError::InvalidSchema)
        );
    }
    #[test]
    fn trust_decision_is_bounded_and_sender_bound() {
        let zero = "00".repeat(32);
        let one = "11".repeat(32);
        let json = serde_json::json!({"schema":"federation-peer/v2","message_id":"m1","kind":"TRUST_DECISION","sender_platform_id":"provider-a","recipient_platform_id":"provider-b","generation":1,"sent_at":"2026-09-23T08:00:00Z","payload":{"request_id":"trust-1","result":"APPROVED","sender_manifest_digest":zero,"recipient_manifest_digest":one,"approved_capabilities":["REQUEST_DELIVERY"],"decided_at":"2026-09-23T08:00:00Z"}});
        let bytes = serde_json::to_vec(&json).unwrap();
        let a = PlatformId::new("provider-a").unwrap();
        let b = PlatformId::new("provider-b").unwrap();
        assert!(parse_peer_message(
            &bytes,
            &a,
            &b,
            "spiffe://provider-a.test/federation/control",
            "spiffe://provider-a.test/federation/control"
        )
        .is_ok());
        assert_eq!(
            parse_peer_message(
                &bytes,
                &b,
                &a,
                "spiffe://provider-a.test/federation/control",
                "spiffe://provider-a.test/federation/control"
            ),
            Err(PeerWireError::WrongPeer)
        );
        assert_eq!(
            parse_peer_message(
                &bytes,
                &a,
                &b,
                "spiffe://provider-a.test/other",
                "spiffe://provider-a.test/federation/control"
            ),
            Err(PeerWireError::WrongService)
        );
    }

    #[test]
    fn peer_receipt_binds_exact_message_and_receiver() {
        let a = PlatformId::new("provider-a").unwrap();
        let b = PlatformId::new("provider-b").unwrap();
        let request = serde_json::json!({"schema":"federation-peer/v2","message_id":"m1","kind":"TRUST_REMOVE","sender_platform_id":"provider-a","recipient_platform_id":"provider-b","generation":2,"sent_at":"2026-09-23T08:00:00Z","payload":{"reason_code":"OPERATOR_REMOVED","effective_at":"2026-09-23T08:00:00Z"}});
        let sent = parse_peer_message(
            &serde_json::to_vec(&request).unwrap(),
            &a,
            &b,
            "spiffe://provider-a.test/control",
            "spiffe://provider-a.test/control",
        )
        .unwrap();
        let mut receipt = serde_json::json!({"schema":"federation-peer-receipt/v1","sender_platform_id":"provider-b","recipient_platform_id":"provider-a","generation":2,"message_id":"m1","body_digest":hex_lower(&sent.body_digest),"result":"REMOVED"});
        assert!(parse_peer_receipt(&serde_json::to_vec(&receipt).unwrap(), &sent, &b).is_ok());
        receipt["body_digest"] = serde_json::json!("00".repeat(32));
        assert_eq!(
            parse_peer_receipt(&serde_json::to_vec(&receipt).unwrap(), &sent, &b),
            Err(PeerWireError::InvalidField)
        );
    }
}
