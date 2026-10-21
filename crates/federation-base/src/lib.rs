//! Host-neutral PTPAN Base policy types.
//!
//! This crate does not implement AGNTCY Directory, OASF, SPIFFE, host grants, or
//! A2A. Those mechanisms cross explicit integration boundaries. The types here
//! describe the Base-owned relationship and peer-policy rules.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub mod address;
pub mod control_event;
pub mod encoding;
pub mod identity_evidence;
pub mod peer_control;
pub mod peer_routes;
pub mod peer_transitions;
pub mod provider_manifest;
pub mod live_admission;
pub mod relationship_lifecycle;
pub mod time;

const MAX_JCS_INTEGER: u64 = 9_007_199_254_740_991;

/// Protocol versions this Base implements, as listed in a manifest (D2).
pub const SUPPORTED_PROTOCOLS: [&str; 4] = [
    "federation-peer/v2",
    "federation-control/v3",
    "live-admission/v3",
    "FRL/1",
];

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct PlatformId(String);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct OpaqueId(String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelError {
    EmptyId,
    EmptyPermissions,
    InvalidTime,
    InvalidLeaseMode,
    WrongDestinationIssuer,
    WrongRelationship,
    WrongRequest,
    ScopeBroadened,
    LifetimeBroadened,
    LeaseRevisionNotAdvanced,
    PeerNotApproved,
    WrongAuthenticatedPeer,
    RequestExpired,
    InvalidRevision,
    InvalidTermsDigest,
    Canonicalization,
    InvalidJson,
    InvalidTargetAddress,
    InvalidRequesterReference,
    InvalidName,
    MessageTooLarge,
}

impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ModelError {}

impl PlatformId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ModelError::EmptyId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl OpaqueId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ModelError::EmptyId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An agent as another platform sees it: its platform and an address
/// (`<opaque part>.<provider domain>`) issued and resolved only by that
/// platform (D5, D10). For the requester this is its requester reference.
/// No internal account or agent ID crosses platforms.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Participant {
    pub platform_id: PlatformId,
    pub address: String,
}

/// A human's name taken from their own platform's account record (D6). It is
/// identity information for the other human, never routing or authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonName {
    pub given_name: String,
    pub family_name: String,
}

/// Maximum bytes of one name part.
pub const MAX_NAME_BYTES: usize = 128;

impl PersonName {
    /// Plain text only: non-empty, at most `MAX_NAME_BYTES`, Unicode NFC, no
    /// surrounding whitespace, and no control or bidirectional-formatting
    /// characters.
    pub fn validate(&self) -> Result<(), ModelError> {
        fn part(value: &str) -> bool {
            !value.is_empty()
                && value.len() <= MAX_NAME_BYTES
                && value.trim() == value
                && unicode_normalization::is_nfc(value)
                && !value.chars().any(|c| {
                    c.is_control()
                        || matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
                })
        }
        if part(&self.given_name) && part(&self.family_name) {
            Ok(())
        } else {
            Err(ModelError::InvalidName)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum LifetimeRequest {
    SingleTask { expires_at: u64 },
    Fixed { expires_at: u64 },
    UntilRevoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestKind {
    Establish,
    Renew,
    Modify,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipRequest {
    pub relationship_id: OpaqueId,
    pub request_id: OpaqueId,
    /// The requesting agent: the source platform and its requester reference.
    pub source: Participant,
    pub source_ownership_revision: u64,
    pub requester_name: PersonName,
    pub request_kind: RequestKind,
    pub request_revision: u64,
    pub base_lease_revision: Option<u64>,
    pub application_protocol: String,
    pub transport: String,
    /// The address the requester entered, carried byte for byte. The request
    /// names no destination platform: the source platform never needs to
    /// know other platforms (principle 3); the adapter routes by domain and
    /// names the destination in the event envelope.
    pub target_address: String,
    pub requested_permissions: BTreeSet<String>,
    pub requested_lifetime: LifetimeRequest,
    pub created_at: u64,
    pub request_expires_at: u64,
}

impl RelationshipRequest {
    pub fn validate(&self) -> Result<(), ModelError> {
        for value in [
            self.relationship_id.as_str(),
            self.request_id.as_str(),
            self.source.platform_id.as_str(),
        ] {
            if value.trim().is_empty() {
                return Err(ModelError::EmptyId);
            }
        }
        if !address::valid_address(&self.source.address) {
            return Err(ModelError::InvalidRequesterReference);
        }
        if !address::valid_address(&self.target_address) {
            return Err(ModelError::InvalidTargetAddress);
        }
        self.requester_name.validate()?;
        if self.application_protocol.trim().is_empty() || self.transport.trim().is_empty() {
            return Err(ModelError::EmptyId);
        }
        if self.source_ownership_revision == 0
            || self.request_revision == 0
            || self.source_ownership_revision > MAX_JCS_INTEGER
            || self.request_revision > MAX_JCS_INTEGER
            || self
                .base_lease_revision
                .is_some_and(|revision| revision == 0 || revision > MAX_JCS_INTEGER)
            || (matches!(self.request_kind, RequestKind::Establish)
                != self.base_lease_revision.is_none())
        {
            return Err(ModelError::InvalidRevision);
        }
        if self.created_at > MAX_JCS_INTEGER || self.request_expires_at > MAX_JCS_INTEGER {
            return Err(ModelError::InvalidTime);
        }
        if self.requested_permissions.is_empty()
            || self
                .requested_permissions
                .iter()
                .any(|p| p.trim().is_empty())
        {
            return Err(ModelError::EmptyPermissions);
        }
        if self.request_expires_at <= self.created_at {
            return Err(ModelError::InvalidTime);
        }
        match self.requested_lifetime {
            LifetimeRequest::SingleTask { expires_at } | LifetimeRequest::Fixed { expires_at }
                if expires_at > MAX_JCS_INTEGER =>
            {
                Err(ModelError::InvalidTime)
            }
            LifetimeRequest::SingleTask { expires_at } | LifetimeRequest::Fixed { expires_at }
                if expires_at <= self.created_at =>
            {
                Err(ModelError::InvalidTime)
            }
            _ => Ok(()),
        }
    }

    /// Digest of only the source's immutable requested terms. The destination
    /// owner is intentionally absent until its own host resolves the address.
    pub fn request_terms_digest(&self) -> Result<[u8; 32], ModelError> {
        Ok(encoding::sha256(&self.canonical_requested_terms()?))
    }

    pub fn canonical_requested_terms(&self) -> Result<Vec<u8>, ModelError> {
        self.validate()?;
        canonical_bytes(self)
    }

    /// The destination agent as the source names it: the issuing platform
    /// and the address its user entered, unchanged.
    pub fn destination(&self, destination_platform: &PlatformId) -> Participant {
        Participant {
            platform_id: destination_platform.clone(),
            address: self.target_address.clone(),
        }
    }
}

/// Parses only the bounded typed relationship-request payload. The full
/// control-event envelope, authenticated sender binding, and receipt store
/// are separate required layers; this parser alone never admits a request.
pub fn parse_relationship_request_json(bytes: &[u8]) -> Result<RelationshipRequest, ModelError> {
    if bytes.len() > 32 * 1024 {
        return Err(ModelError::MessageTooLarge);
    }
    let request: RelationshipRequest =
        serde_json::from_slice(bytes).map_err(|_| ModelError::InvalidJson)?;
    request.validate()?;
    Ok(request)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LeaseMode {
    SingleTask,
    Fixed,
    UntilRevoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationshipLease {
    pub lease_id: OpaqueId,
    pub relationship_id: OpaqueId,
    pub lease_revision: u64,
    pub mode: LeaseMode,
    pub effective_from: u64,
    pub expires_at: Option<u64>,
    pub max_tasks: Option<u32>,
    pub granted_by_platform_id: PlatformId,
    pub decision_id: OpaqueId,
    pub request_id: OpaqueId,
    pub effective_permissions: BTreeSet<String>,
    /// Computed by the executable JCS wire profile; this type never invents it.
    pub terms_digest: [u8; 32],
}

/// The destination owner's chosen terms; the input to `ComputeLease` (D1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerTerms {
    pub lease_id: OpaqueId,
    pub lease_revision: u64,
    pub decision_id: OpaqueId,
    pub mode: LeaseMode,
    pub effective_from: u64,
    pub expires_at: Option<u64>,
    pub effective_permissions: BTreeSet<String>,
}

impl RelationshipLease {
    /// `ComputeLease` (D1): build the FRL/1 lease from the owner's terms,
    /// validate it against the request (narrower only) and compute its terms
    /// digest. The platform stores the result and stays the authority.
    pub fn issue(
        request: &RelationshipRequest,
        destination_platform: &PlatformId,
        terms: OwnerTerms,
        destination_ownership_revision: u64,
        destination_owner_name: &PersonName,
    ) -> Result<Self, ModelError> {
        let max_tasks = (terms.mode == LeaseMode::SingleTask).then_some(1);
        let mut lease = Self {
            lease_id: terms.lease_id,
            relationship_id: request.relationship_id.clone(),
            lease_revision: terms.lease_revision,
            mode: terms.mode,
            effective_from: terms.effective_from,
            expires_at: terms.expires_at,
            max_tasks,
            granted_by_platform_id: destination_platform.clone(),
            decision_id: terms.decision_id,
            request_id: request.request_id.clone(),
            effective_permissions: terms.effective_permissions,
            terms_digest: [0; 32],
        };
        lease.terms_digest =
            lease.compute_terms_digest(request, destination_ownership_revision, destination_owner_name)?;
        Ok(lease)
    }

    pub fn validate_against(&self, request: &RelationshipRequest) -> Result<(), ModelError> {
        request.validate()?;
        if self.relationship_id != request.relationship_id {
            return Err(ModelError::WrongRelationship);
        }
        if self.request_id != request.request_id {
            return Err(ModelError::WrongRequest);
        }
        if self.granted_by_platform_id == request.source.platform_id {
            return Err(ModelError::WrongDestinationIssuer);
        }
        if self.effective_permissions.is_empty()
            || !self
                .effective_permissions
                .is_subset(&request.requested_permissions)
        {
            return Err(ModelError::ScopeBroadened);
        }
        if self.lease_revision == 0
            || self.lease_revision > MAX_JCS_INTEGER
            || self.effective_from > MAX_JCS_INTEGER
            || self
                .expires_at
                .is_some_and(|expiry| expiry > MAX_JCS_INTEGER)
            || self.effective_from < request.created_at
            || self.effective_from >= request.request_expires_at
        {
            return Err(ModelError::InvalidTime);
        }
        match (&request.requested_lifetime, &self.mode) {
            (
                LifetimeRequest::SingleTask {
                    expires_at: requested,
                },
                LeaseMode::SingleTask,
            ) => {
                if self.max_tasks != Some(1) || self.expires_at.is_none() {
                    return Err(ModelError::InvalidLeaseMode);
                }
                self.check_finite_expiry(*requested)
            }
            (
                LifetimeRequest::Fixed {
                    expires_at: requested,
                },
                LeaseMode::Fixed,
            ) => {
                if self.max_tasks.is_some() || self.expires_at.is_none() {
                    return Err(ModelError::InvalidLeaseMode);
                }
                self.check_finite_expiry(*requested)
            }
            (
                LifetimeRequest::Fixed {
                    expires_at: requested,
                },
                LeaseMode::SingleTask,
            ) => {
                if self.max_tasks != Some(1) || self.expires_at.is_none() {
                    return Err(ModelError::InvalidLeaseMode);
                }
                self.check_finite_expiry(*requested)
            }
            (LifetimeRequest::UntilRevoked, LeaseMode::UntilRevoked) => {
                if self.max_tasks.is_some() || self.expires_at.is_some() {
                    return Err(ModelError::InvalidLeaseMode);
                }
                Ok(())
            }
            (LifetimeRequest::UntilRevoked, LeaseMode::Fixed) => {
                if self.max_tasks.is_some() || self.expires_at.is_none() {
                    return Err(ModelError::InvalidLeaseMode);
                }
                self.check_finite_expiry(u64::MAX)
            }
            (LifetimeRequest::UntilRevoked, LeaseMode::SingleTask) => {
                if self.max_tasks != Some(1) || self.expires_at.is_none() {
                    return Err(ModelError::InvalidLeaseMode);
                }
                self.check_finite_expiry(u64::MAX)
            }
            _ => Err(ModelError::LifetimeBroadened),
        }
    }

    /// The destination computes this after its owner decided. It binds both
    /// addresses, both humans' names and the destination's ownership
    /// revision, and differs from the request digest whenever terms differ.
    pub fn compute_terms_digest(
        &self,
        request: &RelationshipRequest,
        destination_ownership_revision: u64,
        destination_owner_name: &PersonName,
    ) -> Result<[u8; 32], ModelError> {
        Ok(encoding::sha256(&self.canonical_effective_terms(
            request,
            destination_ownership_revision,
            destination_owner_name,
        )?))
    }

    pub fn canonical_effective_terms(
        &self,
        request: &RelationshipRequest,
        destination_ownership_revision: u64,
        destination_owner_name: &PersonName,
    ) -> Result<Vec<u8>, ModelError> {
        self.validate_against(request)?;
        destination_owner_name.validate()?;
        if destination_ownership_revision == 0 || destination_ownership_revision > MAX_JCS_INTEGER {
            return Err(ModelError::InvalidRevision);
        }
        #[derive(Serialize)]
        struct EffectiveTerms<'a> {
            relationship_id: &'a OpaqueId,
            source: &'a Participant,
            source_ownership_revision: u64,
            requester_name: &'a PersonName,
            destination: &'a Participant,
            destination_ownership_revision: u64,
            destination_owner_name: &'a PersonName,
            lease_id: &'a OpaqueId,
            lease_revision: u64,
            mode: &'a LeaseMode,
            effective_from: u64,
            expires_at: Option<u64>,
            max_tasks: Option<u32>,
            granted_by_platform_id: &'a PlatformId,
            decision_id: &'a OpaqueId,
            request_id: &'a OpaqueId,
            effective_permissions: &'a BTreeSet<String>,
            application_protocol: &'a str,
            transport: &'a str,
        }
        canonical_bytes(&EffectiveTerms {
            relationship_id: &self.relationship_id,
            source: &request.source,
            source_ownership_revision: request.source_ownership_revision,
            requester_name: &request.requester_name,
            destination: &request.destination(&self.granted_by_platform_id),
            destination_ownership_revision,
            destination_owner_name,
            lease_id: &self.lease_id,
            lease_revision: self.lease_revision,
            mode: &self.mode,
            effective_from: self.effective_from,
            expires_at: self.expires_at,
            max_tasks: self.max_tasks,
            granted_by_platform_id: &self.granted_by_platform_id,
            decision_id: &self.decision_id,
            request_id: &self.request_id,
            effective_permissions: &self.effective_permissions,
            application_protocol: &request.application_protocol,
            transport: &request.transport,
        })
    }

    pub fn verify_terms_digest(
        &self,
        request: &RelationshipRequest,
        destination_ownership_revision: u64,
        destination_owner_name: &PersonName,
    ) -> Result<(), ModelError> {
        if self.terms_digest
            != self.compute_terms_digest(
                request,
                destination_ownership_revision,
                destination_owner_name,
            )?
        {
            return Err(ModelError::InvalidTermsDigest);
        }
        Ok(())
    }

    fn check_finite_expiry(&self, requested: u64) -> Result<(), ModelError> {
        let approved = self.expires_at.expect("checked before call");
        if approved <= self.effective_from {
            return Err(ModelError::InvalidTime);
        }
        if approved > requested {
            return Err(ModelError::LifetimeBroadened);
        }
        Ok(())
    }

    pub fn is_effective_at(&self, now: u64) -> bool {
        now >= self.effective_from && self.expires_at.is_none_or(|end| now < end)
    }

    pub fn admission_deadline(&self, now: u64, other_deadlines: &[u64]) -> Option<u64> {
        if !self.is_effective_at(now) {
            return None;
        }
        let deadline = self
            .expires_at
            .into_iter()
            .chain(other_deadlines.iter().copied())
            .min()?;
        (deadline > now).then_some(deadline)
    }
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, ModelError> {
    encoding::canonical_json(value).ok_or(ModelError::Canonicalization)
}

pub fn check_next_lease_revision(
    previous: &RelationshipLease,
    next: &RelationshipLease,
) -> Result<(), ModelError> {
    if previous.relationship_id != next.relationship_id {
        return Err(ModelError::WrongRelationship);
    }
    if previous.granted_by_platform_id != next.granted_by_platform_id {
        return Err(ModelError::WrongDestinationIssuer);
    }
    if next.lease_revision <= previous.lease_revision {
        return Err(ModelError::LeaseRevisionNotAdvanced);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerState {
    Pending,
    Active,
    Suspended,
    Removing,
    Removed,
}

impl PeerState {
    pub fn permits_new_authority(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// A provider relationship permits bounded request delivery only after both
/// operators approved the exact peer and the current control service was
/// authenticated. Account access is a separate destination-host decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerRequestGate {
    pub state: PeerState,
    pub local_operator_approved: bool,
    pub remote_operator_approval_confirmed: bool,
    pub peer_identity_verified: bool,
    pub exact_service_authenticated: bool,
}

impl PeerRequestGate {
    pub fn permits_request_delivery(&self) -> bool {
        self.state.permits_new_authority()
            && self.local_operator_approved
            && self.remote_operator_approval_confirmed
            && self.peer_identity_verified
            && self.exact_service_authenticated
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestDeliveryResult {
    QueuedForLocalOwner,
    AddressNotRecognized,
}

/// Checks an inbound request before its address is handed to the destination
/// platform's internal resolver. `peer_domain` is the authenticated peer's
/// verified provider domain and `local_domain` this platform's own. The
/// opaque part is never inspected here (principle 3, D10).
pub fn check_inbound_request(
    request: &RelationshipRequest,
    authenticated_peer: &PlatformId,
    peer_domain: &str,
    local_domain: &str,
    gate: &PeerRequestGate,
    now: u64,
) -> Result<(), ModelError> {
    request.validate()?;
    if &request.source.platform_id != authenticated_peer {
        return Err(ModelError::WrongAuthenticatedPeer);
    }
    if !gate.permits_request_delivery() {
        return Err(ModelError::PeerNotApproved);
    }
    if now >= request.request_expires_at {
        return Err(ModelError::RequestExpired);
    }
    if !address::address_in_domain(&request.source.address, peer_domain) {
        return Err(ModelError::InvalidRequesterReference);
    }
    if !address::address_in_domain(&request.target_address, local_domain) {
        return Err(ModelError::InvalidTargetAddress);
    }
    Ok(())
}

/// Test helper: every object in a serialized Rust value must carry all of
/// the schema's required keys and only declared keys, recursively. This keeps
/// the checked-in JSON Schemas in step with the Rust wire types.
#[cfg(test)]
pub(crate) mod schema_check {
    use serde_json::Value;

    fn resolve<'a>(root: &'a Value, node: &'a Value) -> &'a Value {
        match node.get("$ref").and_then(Value::as_str) {
            Some(path) => {
                let mut current = root;
                for part in path.trim_start_matches("#/").split('/') {
                    current = &current[part];
                }
                resolve(root, current)
            }
            None => node,
        }
    }

    pub(crate) fn matches(root: &Value, node: &Value, value: &Value, path: &str) {
        let node = resolve(root, node);
        if let Some(branches) = node.get("oneOf").and_then(Value::as_array) {
            if value.is_null() {
                return;
            }
            let branch = branches
                .iter()
                .map(|b| resolve(root, b))
                .find(|b| b.get("type").and_then(Value::as_str) != Some("null"))
                .expect("non-null branch");
            return matches(root, branch, value, path);
        }
        match value {
            Value::Object(map) => {
                let properties = node["properties"]
                    .as_object()
                    .unwrap_or_else(|| panic!("{path}: no properties"));
                let required = node["required"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{path}: no required"));
                for key in required {
                    assert!(map.contains_key(key.as_str().unwrap()), "{path}: missing {key}");
                }
                for key in map.keys() {
                    assert!(properties.contains_key(key), "{path}: undeclared {key}");
                }
                assert_eq!(node["additionalProperties"], false, "{path}: open object");
                for (key, child) in map {
                    matches(root, &properties[key.as_str()], child, &format!("{path}.{key}"));
                }
            }
            Value::Array(items) => {
                if let Some(items_schema) = node.get("items") {
                    for item in items {
                        matches(root, items_schema, item, path);
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).unwrap()
    }

    fn platform(value: &str) -> PlatformId {
        PlatformId::new(value).unwrap()
    }

    fn name(given: &str, family: &str) -> PersonName {
        PersonName {
            given_name: given.into(),
            family_name: family.into(),
        }
    }

    fn request() -> RelationshipRequest {
        RelationshipRequest {
            relationship_id: id("relationship-a-b"),
            request_id: id("request-1"),
            source: Participant {
                platform_id: platform("a"),
                address: "Requester.7.providera.example".into(),
            },
            source_ownership_revision: 1,
            requester_name: name("Ada", "Lovelace"),
            request_kind: RequestKind::Establish,
            request_revision: 1,
            base_lease_revision: None,
            application_protocol: "a2a".into(),
            transport: "https".into(),
            target_address: "0123456789abcdef.providerb.example".into(),
            requested_permissions: BTreeSet::from(["a2a.invoke".into()]),
            requested_lifetime: LifetimeRequest::Fixed { expires_at: 3000 },
            created_at: 1000,
            request_expires_at: 1200,
        }
    }

    /// The test request as wire JSON, for schema checks in other modules.
    pub(crate) fn request_value() -> serde_json::Value {
        serde_json::to_value(request()).unwrap()
    }

    fn owner() -> PersonName {
        name("Grace", "Hopper")
    }

    fn lease() -> RelationshipLease {
        RelationshipLease {
            lease_id: id("lease-b-1"),
            relationship_id: id("relationship-a-b"),
            lease_revision: 1,
            mode: LeaseMode::Fixed,
            effective_from: 1100,
            expires_at: Some(1160),
            max_tasks: None,
            granted_by_platform_id: platform("b"),
            decision_id: id("decision-b-1"),
            request_id: id("request-1"),
            effective_permissions: BTreeSet::from(["a2a.invoke".into()]),
            terms_digest: [1; 32],
        }
    }

    #[test]
    fn issue_builds_a_validated_lease_with_its_digest() {
        let request = request();
        let terms = OwnerTerms {
            lease_id: id("lease-b-1"),
            lease_revision: 1,
            decision_id: id("decision-b-1"),
            mode: LeaseMode::SingleTask,
            effective_from: 1100,
            expires_at: Some(1160),
            effective_permissions: BTreeSet::from(["a2a.invoke".into()]),
        };
        let lease = RelationshipLease::issue(&request, &platform("b"), terms.clone(), 1, &owner()).unwrap();
        assert_eq!(lease.max_tasks, Some(1));
        assert_eq!(lease.granted_by_platform_id, platform("b"));
        assert_eq!(lease.verify_terms_digest(&request, 1, &owner()), Ok(()));
        let mut broader = terms;
        broader.effective_permissions.insert("account.read".into());
        assert_eq!(
            RelationshipLease::issue(&request, &platform("b"), broader, 1, &owner()),
            Err(ModelError::ScopeBroadened)
        );
    }

    #[test]
    fn destination_can_narrow_but_not_broaden() {
        let request = request();
        let mut lease = lease();
        assert_eq!(lease.validate_against(&request), Ok(()));
        lease.expires_at = Some(3001);
        assert_eq!(
            lease.validate_against(&request),
            Err(ModelError::LifetimeBroadened)
        );
        lease.expires_at = Some(1160);
        lease.effective_permissions.insert("account.read".into());
        assert_eq!(
            lease.validate_against(&request),
            Err(ModelError::ScopeBroadened)
        );
    }

    #[test]
    fn canonical_request_and_effective_digests_bind_codes_and_names() {
        let request = request();
        let mut lease = lease();
        let request_digest = request.request_terms_digest().unwrap();
        lease.terms_digest = lease.compute_terms_digest(&request, 1, &owner()).unwrap();
        assert_ne!(request_digest, lease.terms_digest);
        assert_eq!(lease.verify_terms_digest(&request, 1, &owner()), Ok(()));
        assert_eq!(
            lease.verify_terms_digest(&request, 2, &owner()),
            Err(ModelError::InvalidTermsDigest)
        );
        assert_eq!(
            lease.verify_terms_digest(&request, 1, &name("Grace", "Murray")),
            Err(ModelError::InvalidTermsDigest)
        );
        let mut changed = request.clone();
        changed.target_address = "0123456789ABCDEF.providerb.example".into();
        assert_ne!(request_digest, changed.request_terms_digest().unwrap());
        let mut renamed = request.clone();
        renamed.requester_name.family_name = "Byron".into();
        assert_ne!(request_digest, renamed.request_terms_digest().unwrap());
        let effective = String::from_utf8(
            lease.canonical_effective_terms(&request, 1, &owner()).unwrap(),
        )
        .unwrap();
        assert!(effective.contains("\"address\":\"0123456789abcdef.providerb.example\""));
        assert!(effective.contains("\"destination_owner_name\""));
        assert!(!effective.contains("subject_id") && !effective.contains("resource_id"));
    }

    #[test]
    fn request_carries_addresses_and_names_but_no_internal_ids() {
        let raw = String::from_utf8(request().canonical_requested_terms().unwrap()).unwrap();
        assert!(raw.contains("\"address\":\"Requester.7.providera.example\""));
        assert!(raw.contains("\"requester_name\":{\"family_name\":\"Lovelace\",\"given_name\":\"Ada\"}"));
        assert!(!raw.contains("subject_id") && !raw.contains("resource_id"));
        let legacy = raw.replace(
            "\"address\":\"Requester.7.providera.example\"",
            "\"address\":\"Requester.7.providera.example\",\"subject_id\":\"account\"",
        );
        assert_eq!(
            parse_relationship_request_json(legacy.as_bytes()),
            Err(ModelError::InvalidJson)
        );
    }

    #[test]
    fn typed_request_parser_rejects_bad_addresses_names_and_input() {
        let raw = String::from_utf8(request().canonical_requested_terms().unwrap()).unwrap();
        assert_eq!(
            parse_relationship_request_json(raw.as_bytes()).unwrap(),
            request()
        );
        let bad_target = raw.replace("0123456789abcdef.providerb.example", "Calendar_1.providerb.example");
        assert_eq!(
            parse_relationship_request_json(bad_target.as_bytes()),
            Err(ModelError::InvalidTargetAddress)
        );
        let bad_source = raw.replace("Requester.7.providera.example", "account-7");
        assert_eq!(
            parse_relationship_request_json(bad_source.as_bytes()),
            Err(ModelError::InvalidRequesterReference)
        );
        let bad_name = raw.replace("\"Ada\"", "\"Ada\\u202e\"");
        assert_eq!(
            parse_relationship_request_json(bad_name.as_bytes()),
            Err(ModelError::InvalidName)
        );
        let duplicate = raw.replacen(
            "\"request_id\":\"request-1\",",
            "\"request_id\":\"request-1\",\"request_id\":\"other\",",
            1,
        );
        assert_eq!(
            parse_relationship_request_json(duplicate.as_bytes()),
            Err(ModelError::InvalidJson)
        );
        let unknown = format!("{{\"surprise\":true,{}", &raw[1..]);
        assert_eq!(
            parse_relationship_request_json(unknown.as_bytes()),
            Err(ModelError::InvalidJson)
        );
        assert_eq!(
            parse_relationship_request_json(&vec![b' '; 32 * 1024 + 1]),
            Err(ModelError::MessageTooLarge)
        );
    }

    #[test]
    fn names_are_plain_normalized_text() {
        assert_eq!(name("José", "Núñez").validate(), Ok(()));
        for bad in [
            name("", "x"),
            name(" Ada", "Lovelace"),
            name("Ada", "Lovelace\n"),
            name("Ada\u{200f}", "Lovelace"),
            name("Jose\u{301}", "Nunez"),
            name(&"a".repeat(MAX_NAME_BYTES + 1), "x"),
        ] {
            assert_eq!(bad.validate(), Err(ModelError::InvalidName), "{bad:?}");
        }
    }

    #[test]
    fn source_cannot_issue_destination_lease() {
        let mut lease = lease();
        lease.granted_by_platform_id = platform("a");
        assert_eq!(
            lease.validate_against(&request()),
            Err(ModelError::WrongDestinationIssuer)
        );
    }

    #[test]
    fn fixed_expiry_and_shorter_deadline_apply_without_status_event() {
        let lease = lease();
        assert_eq!(lease.admission_deadline(1100, &[1150, 1200]), Some(1150));
        assert_eq!(lease.admission_deadline(1160, &[1200]), None);
    }

    #[test]
    fn one_task_requires_finite_expiry_and_one_task_limit() {
        let mut request = request();
        request.requested_lifetime = LifetimeRequest::SingleTask { expires_at: 3000 };
        let mut lease = lease();
        lease.mode = LeaseMode::SingleTask;
        lease.max_tasks = Some(1);
        assert_eq!(lease.validate_against(&request), Ok(()));
        lease.max_tasks = None;
        assert_eq!(
            lease.validate_against(&request),
            Err(ModelError::InvalidLeaseMode)
        );
    }

    #[test]
    fn destination_may_choose_a_stricter_lifetime_mode() {
        let mut request = request();
        request.requested_lifetime = LifetimeRequest::UntilRevoked;
        assert_eq!(lease().validate_against(&request), Ok(()));
        let mut one_task = lease();
        one_task.mode = LeaseMode::SingleTask;
        one_task.max_tasks = Some(1);
        assert_eq!(one_task.validate_against(&request), Ok(()));

        request.requested_lifetime = LifetimeRequest::Fixed { expires_at: 3000 };
        assert_eq!(one_task.validate_against(&request), Ok(()));
        request.requested_lifetime = LifetimeRequest::SingleTask { expires_at: 3000 };
        assert_eq!(
            lease().validate_against(&request),
            Err(ModelError::LifetimeBroadened)
        );
    }

    #[test]
    fn approval_after_pending_request_expiry_is_invalid() {
        let mut expired_decision = lease();
        expired_decision.effective_from = request().request_expires_at;
        assert_eq!(
            expired_decision.validate_against(&request()),
            Err(ModelError::InvalidTime)
        );
    }

    #[test]
    fn non_active_peer_never_permits_new_authority() {
        for state in [
            PeerState::Pending,
            PeerState::Suspended,
            PeerState::Removing,
            PeerState::Removed,
        ] {
            assert!(!state.permits_new_authority());
        }
        assert!(PeerState::Active.permits_new_authority());
    }

    fn approved_gate() -> PeerRequestGate {
        PeerRequestGate {
            state: PeerState::Active,
            local_operator_approved: true,
            remote_operator_approval_confirmed: true,
            peer_identity_verified: true,
            exact_service_authenticated: true,
        }
    }

    #[test]
    fn provider_trust_requires_both_approvals_and_exact_service() {
        let mut gate = approved_gate();
        assert!(gate.permits_request_delivery());
        gate.remote_operator_approval_confirmed = false;
        assert!(!gate.permits_request_delivery());
        gate.remote_operator_approval_confirmed = true;
        gate.exact_service_authenticated = false;
        assert!(!gate.permits_request_delivery());
    }

    #[test]
    fn inbound_check_binds_addresses_to_verified_domains() {
        let request = request();
        let a = platform("a");
        let check = |peer: &PlatformId, peer_domain: &str, local_domain: &str, gate: &PeerRequestGate, now| {
            check_inbound_request(&request, peer, peer_domain, local_domain, gate, now)
        };
        let gate = approved_gate();
        assert_eq!(check(&a, "providera.example", "providerb.example", &gate, 1100), Ok(()));
        assert_eq!(check(&a, "PROVIDERA.example", "providerb.EXAMPLE", &gate, 1100), Ok(()));
        assert_eq!(
            check(&platform("c"), "providera.example", "providerb.example", &gate, 1100),
            Err(ModelError::WrongAuthenticatedPeer)
        );
        assert_eq!(
            check(&a, "providerc.example", "providerb.example", &gate, 1100),
            Err(ModelError::InvalidRequesterReference)
        );
        assert_eq!(
            check(&a, "providera.example", "providerc.example", &gate, 1100),
            Err(ModelError::InvalidTargetAddress)
        );
        assert_eq!(
            check(&a, "providera.example", "providerb.example", &gate, 1200),
            Err(ModelError::RequestExpired)
        );
        let mut closed = approved_gate();
        closed.peer_identity_verified = false;
        assert_eq!(
            check(&a, "providera.example", "providerb.example", &closed, 1100),
            Err(ModelError::PeerNotApproved)
        );
    }
}
