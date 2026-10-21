//! Per-call admission (D4, D11, D12). Each agent stream opens with one
//! admission proof: a compact JWS signed by the requesting agent's Ed25519
//! admission key. The destination edge (adapter) runs the stateless checks in
//! `verify_admission_token`; the destination platform then runs
//! `evaluate_admission` in one atomic step with nonce consumption. Admission
//! is not a lifecycle event, is never retried as a task, and never becomes a
//! reusable credential.

use crate::address::valid_address;
use crate::time::MAX_CLOCK_SKEW_SECONDS;
use crate::{OpaqueId, PlatformId};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Schema of the admission frame and of the admission response.
pub const ADMISSION_SCHEMA: &str = "live-admission/v3";
/// Explicit JWT type (RFC 8725) so no other token signed by the same key is
/// accepted as an admission.
pub const ADMISSION_JWT_TYPE: &str = "ptpan-admission+jwt";
/// Fully specified JOSE identifier emitted by PTPAN (RFC 9864).
pub const ADMISSION_ALG: &str = "Ed25519";
/// Deprecated polymorphic identifier, accepted only with an Ed25519 key.
pub const LEGACY_ADMISSION_ALG: &str = "EdDSA";
/// The proof's own window: the time allowed to open the stream.
pub const MAX_PROOF_WINDOW_SECONDS: u64 = 60;
/// Longest stream one admission may cover (D12).
pub const MAX_STREAM_SECONDS: u64 = 300;
pub const MAX_ADMISSION_FRAME_BYTES: usize = 8 * 1024;
const MULTICODEC_ED25519_PUB: [u8; 2] = [0xed, 0x01];

/// `did:key` for an Ed25519 public key (multicodec `ed25519-pub`, base58btc).
pub fn did_key_from_ed25519(public_key: &[u8; 32]) -> String {
    let mut bytes = MULTICODEC_ED25519_PUB.to_vec();
    bytes.extend_from_slice(public_key);
    format!("did:key:z{}", bs58::encode(bytes).into_string())
}

/// The Ed25519 public key in a `did:key`, or `None` for any other key type
/// (including Ed448) or encoding.
pub fn ed25519_from_did_key(did: &str) -> Option<[u8; 32]> {
    let encoded = did.strip_prefix("did:key:z")?;
    let bytes = bs58::decode(encoded).into_vec().ok()?;
    let key = bytes.strip_prefix(&MULTICODEC_ED25519_PUB)?;
    key.try_into().ok()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

/// Claims of one admission proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionClaims {
    /// Source platform; must equal the peer authenticated by mutual TLS.
    pub iss: PlatformId,
    /// Requester reference (D5).
    pub sub: String,
    /// Destination edge service SPIFFE ID.
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    /// Single-use nonce, consumed by the destination platform.
    pub jti: String,
    pub relationship_id: OpaqueId,
    pub lease_id: OpaqueId,
    pub lease_revision: u64,
    pub operation: String,
    /// Destination address, exactly as the requester entered it.
    pub destination_address: String,
    pub key_revision: u64,
}

/// Admission frame on the edge (D11): the token plus the routing values the
/// destination needs before it trusts any claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionFrame {
    pub schema: String,
    pub token: String,
    pub destination_address: String,
    pub relationship_id: OpaqueId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDeny {
    /// Adapter: malformed token, wrong type, algorithm, key or signature.
    BadProof,
    WrongAudience,
    WrongIssuer,
    PeerNotActive,
    /// The proof window is over, too long, or issued in the future.
    StaleDeadline,
    /// Platform: the bound key changed after the adapter's key lookup.
    KeyRevisionChanged,
    ReusedNonce,
    GrantDenied,
    NotReady,
    SourceWithdrawn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDecision {
    Allow { deadline: u64 },
    Deny(AdmissionDeny),
}

/// Sign one admission proof. Every platform signs through this function so
/// the bytes and header are identical everywhere.
pub fn sign_admission_token(claims: &AdmissionClaims, key: &SigningKey) -> String {
    let header = Header {
        alg: ADMISSION_ALG.into(),
        typ: ADMISSION_JWT_TYPE.into(),
        kid: did_key_from_ed25519(key.verifying_key().as_bytes()),
    };
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims"));
    let signing_input = format!("{header}.{payload}");
    let signature = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

/// Stateless checks at the destination edge. `bound_key` is the `did:key`
/// the destination platform returned from `GetBoundKey`; `authenticated_peer`
/// comes from mutual TLS, never from the token.
pub fn verify_admission_token(
    token: &str,
    bound_key: &str,
    authenticated_peer: &PlatformId,
    expected_audience: &str,
    peer_active: bool,
    now: u64,
) -> Result<AdmissionClaims, AdmissionDeny> {
    if !peer_active {
        return Err(AdmissionDeny::PeerNotActive);
    }
    if token.len() > MAX_ADMISSION_FRAME_BYTES {
        return Err(AdmissionDeny::BadProof);
    }
    let mut parts = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AdmissionDeny::BadProof);
    };
    let decode = |part: &str| URL_SAFE_NO_PAD.decode(part).map_err(|_| AdmissionDeny::BadProof);
    let header: Header =
        serde_json::from_slice(&decode(header_b64)?).map_err(|_| AdmissionDeny::BadProof)?;
    if (header.alg != ADMISSION_ALG && header.alg != LEGACY_ADMISSION_ALG)
        || header.typ != ADMISSION_JWT_TYPE
        || header.kid != bound_key
    {
        return Err(AdmissionDeny::BadProof);
    }
    // `kid` must be the bound key, and that key must be Ed25519. This is what
    // limits the legacy `EdDSA` identifier to Ed25519 (never Ed448).
    let key = ed25519_from_did_key(bound_key)
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        .ok_or(AdmissionDeny::BadProof)?;
    let signature_bytes: [u8; 64] = decode(signature_b64)?
        .try_into()
        .map_err(|_| AdmissionDeny::BadProof)?;
    let signing_input = &token[..header_b64.len() + 1 + payload_b64.len()];
    key.verify_strict(signing_input.as_bytes(), &Signature::from_bytes(&signature_bytes))
        .map_err(|_| AdmissionDeny::BadProof)?;
    let claims: AdmissionClaims =
        serde_json::from_slice(&decode(payload_b64)?).map_err(|_| AdmissionDeny::BadProof)?;
    if !valid_address(&claims.sub)
        || !valid_address(&claims.destination_address)
        || claims.jti.is_empty()
        || claims.jti.len() > 256
        || claims.operation.is_empty()
        || claims.lease_revision == 0
        || claims.key_revision == 0
    {
        return Err(AdmissionDeny::BadProof);
    }
    if &claims.iss != authenticated_peer {
        return Err(AdmissionDeny::WrongIssuer);
    }
    if claims.aud != expected_audience {
        return Err(AdmissionDeny::WrongAudience);
    }
    if claims.exp <= claims.iat
        || claims.exp - claims.iat > MAX_PROOF_WINDOW_SECONDS
        || claims.iat > now + MAX_CLOCK_SKEW_SECONDS
        || now >= claims.exp
    {
        return Err(AdmissionDeny::StaleDeadline);
    }
    Ok(claims)
}

/// The destination platform's own facts, read in the same atomic step that
/// consumes the nonce (`AdmitCall`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionFacts<'a> {
    pub now: u64,
    /// Key revision the adapter verified against, and the one bound now.
    pub verified_key_revision: u64,
    pub bound_key_revision: u64,
    pub nonce_already_used: bool,
    pub source_withdrawn: bool,
    pub relationship_ready: bool,
    pub grant_allows_operation: bool,
    pub current_lease_id: &'a OpaqueId,
    pub current_lease_revision: u64,
    /// `None` is `UNTIL_REVOKED` (no lease clock).
    pub lease_expires_at: Option<u64>,
    /// Other platform deadlines (grant, credential, policy). Zero denies.
    pub other_deadlines: &'a [u64],
}

/// Platform decision for one verified proof. Allow carries the stream
/// deadline: at most 300 seconds and never past the lease expiry (D12).
pub fn evaluate_admission(claims: &AdmissionClaims, facts: &AdmissionFacts<'_>) -> AdmissionDecision {
    let deny = AdmissionDecision::Deny;
    if facts.verified_key_revision != facts.bound_key_revision
        || claims.key_revision != facts.bound_key_revision
    {
        return deny(AdmissionDeny::KeyRevisionChanged);
    }
    if facts.nonce_already_used {
        return deny(AdmissionDeny::ReusedNonce);
    }
    if facts.source_withdrawn {
        return deny(AdmissionDeny::SourceWithdrawn);
    }
    if !facts.relationship_ready {
        return deny(AdmissionDeny::NotReady);
    }
    if !facts.grant_allows_operation
        || facts.current_lease_id != &claims.lease_id
        || facts.current_lease_revision != claims.lease_revision
    {
        return deny(AdmissionDeny::GrantDenied);
    }
    if facts.now >= claims.exp {
        return deny(AdmissionDeny::StaleDeadline);
    }
    let mut deadline = facts.now.saturating_add(MAX_STREAM_SECONDS);
    for limit in facts.lease_expires_at.iter().chain(facts.other_deadlines) {
        if *limit == 0 || facts.now >= *limit {
            return deny(AdmissionDeny::StaleDeadline);
        }
        deadline = deadline.min(*limit);
    }
    AdmissionDecision::Allow { deadline }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionParseError {
    TooLarge,
    InvalidJson,
    InvalidSchema,
    InvalidField,
}

pub fn parse_admission_frame(bytes: &[u8]) -> Result<AdmissionFrame, AdmissionParseError> {
    if bytes.is_empty() || bytes.len() > MAX_ADMISSION_FRAME_BYTES {
        return Err(AdmissionParseError::TooLarge);
    }
    let frame: AdmissionFrame =
        serde_json::from_slice(bytes).map_err(|_| AdmissionParseError::InvalidJson)?;
    if frame.schema != ADMISSION_SCHEMA {
        return Err(AdmissionParseError::InvalidSchema);
    }
    if frame.token.is_empty() || !valid_address(&frame.destination_address) {
        return Err(AdmissionParseError::InvalidField);
    }
    Ok(frame)
}

/// The edge's answer to the source relay.
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

pub fn deny_reason(reason: AdmissionDeny) -> &'static str {
    match reason {
        AdmissionDeny::BadProof => "BAD_PROOF",
        AdmissionDeny::WrongAudience => "WRONG_AUDIENCE",
        AdmissionDeny::WrongIssuer => "WRONG_ISSUER",
        AdmissionDeny::PeerNotActive => "PEER_NOT_ACTIVE",
        AdmissionDeny::StaleDeadline => "STALE_DEADLINE",
        AdmissionDeny::KeyRevisionChanged => "KEY_REVISION_CHANGED",
        AdmissionDeny::ReusedNonce => "REUSED_NONCE",
        AdmissionDeny::GrantDenied => "GRANT_DENIED",
        AdmissionDeny::NotReady => "NOT_READY",
        AdmissionDeny::SourceWithdrawn => "SOURCE_WITHDRAWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUDIENCE: &str = "spiffe://provider-b.test/federation/edge";
    const NOW: u64 = 1_000;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn did(key: &SigningKey) -> String {
        did_key_from_ed25519(key.verifying_key().as_bytes())
    }

    fn claims() -> AdmissionClaims {
        AdmissionClaims {
            iss: PlatformId::new("provider-a").unwrap(),
            sub: "Team.Calendar-7.provider-a.test".into(),
            aud: AUDIENCE.into(),
            iat: NOW,
            exp: NOW + 60,
            jti: "nonce-1".into(),
            relationship_id: OpaqueId::new("relationship-1").unwrap(),
            lease_id: OpaqueId::new("lease-1").unwrap(),
            lease_revision: 2,
            operation: "a2a.invoke".into(),
            destination_address: "0123456789abcdef.provider-b.test".into(),
            key_revision: 4,
        }
    }

    fn verify(token: &str, bound: &str, now: u64) -> Result<AdmissionClaims, AdmissionDeny> {
        verify_admission_token(token, bound, &PlatformId::new("provider-a").unwrap(), AUDIENCE, true, now)
    }

    /// Build a token with an arbitrary header, signed by `signer`.
    fn custom(header: serde_json::Value, claims: &serde_json::Value, signer: &SigningKey) -> String {
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let input = format!("{h}.{p}");
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signer.sign(input.as_bytes()).to_bytes()))
    }

    #[test]
    fn did_key_round_trips_and_rejects_other_key_types() {
        let k = key(7);
        let d = did(&k);
        assert!(d.starts_with("did:key:z6Mk"), "{d}");
        assert_eq!(ed25519_from_did_key(&d), Some(*k.verifying_key().as_bytes()));
        let mut ed448 = vec![0x83, 0x04];
        ed448.extend_from_slice(&[1; 57]);
        let ed448_did = format!("did:key:z{}", bs58::encode(ed448).into_string());
        assert_eq!(ed25519_from_did_key(&ed448_did), None);
        assert_eq!(ed25519_from_did_key("did:web:provider-a.test"), None);
    }

    #[test]
    fn a_signed_proof_verifies_once_with_the_bound_key() {
        let k = key(1);
        let token = sign_admission_token(&claims(), &k);
        assert_eq!(verify(&token, &did(&k), NOW + 10), Ok(claims()));
        assert_eq!(verify(&token, &did(&key(2)), NOW), Err(AdmissionDeny::BadProof));
        assert_eq!(
            verify_admission_token(&token, &did(&k), &PlatformId::new("provider-c").unwrap(), AUDIENCE, true, NOW),
            Err(AdmissionDeny::WrongIssuer)
        );
        assert_eq!(
            verify_admission_token(&token, &did(&k), &PlatformId::new("provider-a").unwrap(), "spiffe://provider-c.test/federation/edge", true, NOW),
            Err(AdmissionDeny::WrongAudience)
        );
        assert_eq!(
            verify_admission_token(&token, &did(&k), &PlatformId::new("provider-a").unwrap(), AUDIENCE, false, NOW),
            Err(AdmissionDeny::PeerNotActive)
        );
    }

    #[test]
    fn header_profile_is_pinned() {
        let k = key(1);
        let body = serde_json::to_value(claims()).unwrap();
        let header = |alg: &str, typ: &str, kid: &str| serde_json::json!({"alg": alg, "typ": typ, "kid": kid});
        let ok = custom(header("EdDSA", ADMISSION_JWT_TYPE, &did(&k)), &body, &k);
        assert!(verify(&ok, &did(&k), NOW).is_ok(), "legacy EdDSA with an Ed25519 key");
        for bad in [
            header("none", ADMISSION_JWT_TYPE, &did(&k)),
            header("ES256", ADMISSION_JWT_TYPE, &did(&k)),
            header("Ed448", ADMISSION_JWT_TYPE, &did(&k)),
            header(ADMISSION_ALG, "JWT", &did(&k)),
            header(ADMISSION_ALG, ADMISSION_JWT_TYPE, &did(&key(2))),
        ] {
            assert_eq!(verify(&custom(bad, &body, &k), &did(&k), NOW), Err(AdmissionDeny::BadProof));
        }
        let embedded = serde_json::json!({"alg": ADMISSION_ALG, "typ": ADMISSION_JWT_TYPE, "kid": did(&k),
            "jwk": {"kty": "OKP", "crv": "Ed25519", "x": "AA"}});
        assert_eq!(verify(&custom(embedded, &body, &k), &did(&k), NOW), Err(AdmissionDeny::BadProof));
        let url = serde_json::json!({"alg": ADMISSION_ALG, "typ": ADMISSION_JWT_TYPE, "kid": did(&k), "jku": "https://x.test/keys"});
        assert_eq!(verify(&custom(url, &body, &k), &did(&k), NOW), Err(AdmissionDeny::BadProof));
    }

    #[test]
    fn altered_payload_or_unknown_claims_fail() {
        let k = key(1);
        let token = sign_admission_token(&claims(), &k);
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let mut changed = claims();
        changed.lease_revision = 3;
        parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&changed).unwrap());
        assert_eq!(verify(&parts.join("."), &did(&k), NOW), Err(AdmissionDeny::BadProof));
        let mut extra = serde_json::to_value(claims()).unwrap();
        extra["task"] = "send".into();
        let header = serde_json::json!({"alg": ADMISSION_ALG, "typ": ADMISSION_JWT_TYPE, "kid": did(&k)});
        assert_eq!(verify(&custom(header, &extra, &k), &did(&k), NOW), Err(AdmissionDeny::BadProof));
        assert_eq!(verify("a.b", &did(&k), NOW), Err(AdmissionDeny::BadProof));
    }

    #[test]
    fn proof_window_and_skew() {
        let k = key(1);
        let mut long = claims();
        long.exp = long.iat + 61;
        assert_eq!(verify(&sign_admission_token(&long, &k), &did(&k), NOW), Err(AdmissionDeny::StaleDeadline));
        let token = sign_admission_token(&claims(), &k);
        assert_eq!(verify(&token, &did(&k), NOW + 60), Err(AdmissionDeny::StaleDeadline));
        let mut future = claims();
        future.iat = NOW + 5;
        future.exp = NOW + 30;
        assert!(verify(&sign_admission_token(&future, &k), &did(&k), NOW).is_ok());
        future.iat = NOW + 6;
        assert_eq!(verify(&sign_admission_token(&future, &k), &did(&k), NOW), Err(AdmissionDeny::StaleDeadline));
    }

    fn facts(lease: &OpaqueId) -> AdmissionFacts<'_> {
        AdmissionFacts {
            now: NOW + 1,
            verified_key_revision: 4,
            bound_key_revision: 4,
            nonce_already_used: false,
            source_withdrawn: false,
            relationship_ready: true,
            grant_allows_operation: true,
            current_lease_id: lease,
            current_lease_revision: 2,
            lease_expires_at: None,
            other_deadlines: &[],
        }
    }

    #[test]
    fn stream_deadline_is_at_most_300_seconds_and_never_past_the_lease() {
        let lease = OpaqueId::new("lease-1").unwrap();
        let c = claims();
        assert_eq!(evaluate_admission(&c, &facts(&lease)), AdmissionDecision::Allow { deadline: NOW + 1 + 300 });
        let mut short = facts(&lease);
        short.lease_expires_at = Some(NOW + 100);
        assert_eq!(evaluate_admission(&c, &short), AdmissionDecision::Allow { deadline: NOW + 100 });
        let mut month = facts(&lease);
        month.lease_expires_at = Some(NOW + 30 * 86_400);
        assert_eq!(evaluate_admission(&c, &month), AdmissionDecision::Allow { deadline: NOW + 1 + 300 });
        let mut expired = facts(&lease);
        expired.lease_expires_at = Some(NOW + 1);
        assert_eq!(evaluate_admission(&c, &expired), AdmissionDecision::Deny(AdmissionDeny::StaleDeadline));
    }

    #[test]
    fn platform_checks_deny_in_the_atomic_step() {
        let lease = OpaqueId::new("lease-1").unwrap();
        let other_lease = OpaqueId::new("lease-2").unwrap();
        let c = claims();
        type Case = (fn(&mut AdmissionFacts), AdmissionDeny);
        let cases: [Case; 6] = [
            (|f| f.bound_key_revision = 5, AdmissionDeny::KeyRevisionChanged),
            (|f| f.nonce_already_used = true, AdmissionDeny::ReusedNonce),
            (|f| f.source_withdrawn = true, AdmissionDeny::SourceWithdrawn),
            (|f| f.relationship_ready = false, AdmissionDeny::NotReady),
            (|f| f.grant_allows_operation = false, AdmissionDeny::GrantDenied),
            (|f| f.current_lease_revision = 3, AdmissionDeny::GrantDenied),
        ];
        for (change, reason) in cases {
            let mut f = facts(&lease);
            change(&mut f);
            assert_eq!(evaluate_admission(&c, &f), AdmissionDecision::Deny(reason));
        }
        let mut moved = facts(&other_lease);
        moved.current_lease_id = &other_lease;
        assert_eq!(evaluate_admission(&c, &moved), AdmissionDecision::Deny(AdmissionDeny::GrantDenied));
    }

    #[test]
    fn known_answer_vector_is_reproduced_and_verifies() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/live-admission-v3-vectors.json")).unwrap();
        let seed: [u8; 32] = crate::encoding::decode_hex32(vector["seed_hex"].as_str().unwrap()).unwrap();
        let key = SigningKey::from_bytes(&seed);
        assert_eq!(did(&key), vector["kid"]);
        let claims: AdmissionClaims = serde_json::from_value(vector["claims"].clone()).unwrap();
        let token = sign_admission_token(&claims, &key);
        assert_eq!(token, vector["token"]);
        let peer = PlatformId::new("provider-a").unwrap();
        assert_eq!(
            verify_admission_token(&token, vector["kid"].as_str().unwrap(), &peer, AUDIENCE, true, claims.iat + 1),
            Ok(claims)
        );
    }

    #[test]
    fn frame_and_response_wire() {
        let k = key(1);
        let frame = serde_json::json!({"schema": ADMISSION_SCHEMA, "token": sign_admission_token(&claims(), &k),
            "destination_address": "0123456789abcdef.provider-b.test", "relationship_id": "relationship-1"});
        let bytes = serde_json::to_vec(&frame).unwrap();
        assert!(parse_admission_frame(&bytes).is_ok());
        let mut extra = frame.clone();
        extra["task"] = "send".into();
        assert_eq!(parse_admission_frame(&serde_json::to_vec(&extra).unwrap()), Err(AdmissionParseError::InvalidJson));
        let mut old = frame.clone();
        old["schema"] = "live-admission/v2".into();
        assert_eq!(parse_admission_frame(&serde_json::to_vec(&old).unwrap()), Err(AdmissionParseError::InvalidSchema));
        assert!(admission_response_json(&AdmissionDecision::Allow { deadline: 180 }).contains("\"result\":\"ALLOW\""));
        assert!(admission_response_json(&AdmissionDecision::Deny(AdmissionDeny::ReusedNonce)).contains("REUSED_NONCE"));
        let schema: serde_json::Value = serde_json::from_str(include_str!("../../../schemas/live-admission-v3.json")).unwrap();
        crate::schema_check::matches(&schema, &schema["$defs"]["frame"], &frame, "frame");
        crate::schema_check::matches(&schema, &schema["$defs"]["claims"], &serde_json::to_value(claims()).unwrap(), "claims");
        let reasons: Vec<&str> = schema["$defs"]["response"]["properties"]["reason"]["enum"]
            .as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        for reason in [AdmissionDeny::BadProof, AdmissionDeny::WrongAudience, AdmissionDeny::WrongIssuer,
            AdmissionDeny::PeerNotActive, AdmissionDeny::StaleDeadline, AdmissionDeny::KeyRevisionChanged,
            AdmissionDeny::ReusedNonce, AdmissionDeny::GrantDenied, AdmissionDeny::NotReady, AdmissionDeny::SourceWithdrawn] {
            assert!(reasons.contains(&deny_reason(reason)), "{reason:?}");
        }
        assert_eq!(reasons.len(), 10);
    }
}
