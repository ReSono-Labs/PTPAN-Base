//! Host-neutral Federation Base policy types.
//!
//! This crate does not implement AGNTCY Directory, OASF, SPIFFE, host grants, or
//! A2A. Those mechanisms cross explicit integration boundaries. The types here
//! describe the Base-owned relationship and peer-policy rules.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub mod control_event;
pub mod identity_evidence;
pub mod peer_control;
pub mod peer_routes;
pub mod peer_transitions;
pub mod provider_manifest;
pub mod relationship_exchange;
pub mod live_admission;
pub mod relationship_lifecycle;

const MAX_JCS_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct PlatformId(String);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct OpaqueId(String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelError {
    EmptyId,
    SameProvider,
    EmptyPermissions,
    InvalidTime,
    InvalidLeaseMode,
    WrongDestinationIssuer,
    WrongRelationship,
    WrongRequest,
    ScopeBroadened,
    LifetimeBroadened,
    WrongDirection,
    LeaseRevisionNotAdvanced,
    PeerNotApproved,
    WrongAuthenticatedPeer,
    RequestExpired,
    InvalidLocalOwner,
    InvalidRevision,
    InvalidTermsDigest,
    Canonicalization,
    InvalidJson,
    InvalidTargetAddress,
    MessageTooLarge,
}

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Participant {
    pub platform_id: PlatformId,
    pub subject_id: OpaqueId,
    pub resource_id: OpaqueId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Direction {
    pub source_platform_id: PlatformId,
    pub destination_platform_id: PlatformId,
}

impl Direction {
    pub fn new(source: PlatformId, destination: PlatformId) -> Result<Self, ModelError> {
        if source == destination {
            return Err(ModelError::SameProvider);
        }
        Ok(Self {
            source_platform_id: source,
            destination_platform_id: destination,
        })
    }

    pub fn reverse(&self) -> Self {
        Self {
            source_platform_id: self.destination_platform_id.clone(),
            destination_platform_id: self.source_platform_id.clone(),
        }
    }
}

/// The source knows only the destination platform and a user-supplied exact
/// agent address at request time. The destination host resolves its own owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingTarget {
    pub destination_platform_id: PlatformId,
    pub full_agent_address: String,
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
    pub direction: Direction,
    pub source: Participant,
    pub source_ownership_revision: u64,
    pub request_kind: RequestKind,
    pub request_revision: u64,
    pub base_lease_revision: Option<u64>,
    pub application_protocol: String,
    pub transport: String,
    pub target: PendingTarget,
    pub requested_permissions: BTreeSet<String>,
    pub requested_lifetime: LifetimeRequest,
    pub created_at: u64,
    pub request_expires_at: u64,
}

impl RelationshipRequest {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.direction.source_platform_id == self.direction.destination_platform_id {
            return Err(ModelError::SameProvider);
        }
        for value in [
            self.relationship_id.as_str(),
            self.request_id.as_str(),
            self.source.platform_id.as_str(),
            self.source.subject_id.as_str(),
            self.source.resource_id.as_str(),
            self.target.destination_platform_id.as_str(),
        ] {
            if value.trim().is_empty() {
                return Err(ModelError::EmptyId);
            }
        }
        if self.source.platform_id != self.direction.source_platform_id
            || self.target.destination_platform_id != self.direction.destination_platform_id
        {
            return Err(ModelError::WrongDirection);
        }
        if self.target.full_agent_address.trim().is_empty() {
            return Err(ModelError::EmptyId);
        }
        if !identity_evidence::valid_private_short_address(&self.target.full_agent_address) {
            return Err(ModelError::InvalidTargetAddress);
        }
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
        Ok(Sha256::digest(self.canonical_requested_terms()?).into())
    }

    pub fn canonical_requested_terms(&self) -> Result<Vec<u8>, ModelError> {
        self.validate()?;
        canonical_bytes(self)
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

impl RelationshipLease {
    pub fn validate_against(
        &self,
        request: &RelationshipRequest,
        destination: &Participant,
    ) -> Result<(), ModelError> {
        request.validate()?;
        if self.relationship_id != request.relationship_id {
            return Err(ModelError::WrongRelationship);
        }
        if self.request_id != request.request_id {
            return Err(ModelError::WrongRequest);
        }
        if self.granted_by_platform_id != request.direction.destination_platform_id
            || destination.platform_id != request.direction.destination_platform_id
        {
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

    /// The destination computes this from one resolved owner binding. It is
    /// distinct from the request digest whenever effective terms differ.
    pub fn compute_terms_digest(
        &self,
        request: &RelationshipRequest,
        destination: &Participant,
        destination_ownership_revision: u64,
    ) -> Result<[u8; 32], ModelError> {
        Ok(Sha256::digest(self.canonical_effective_terms(
            request,
            destination,
            destination_ownership_revision,
        )?)
        .into())
    }

    pub fn canonical_effective_terms(
        &self,
        request: &RelationshipRequest,
        destination: &Participant,
        destination_ownership_revision: u64,
    ) -> Result<Vec<u8>, ModelError> {
        self.validate_against(request, destination)?;
        if destination_ownership_revision == 0 || destination_ownership_revision > MAX_JCS_INTEGER {
            return Err(ModelError::InvalidRevision);
        }
        #[derive(Serialize)]
        struct EffectiveTerms<'a> {
            relationship_id: &'a OpaqueId,
            source: &'a Participant,
            source_ownership_revision: u64,
            destination: &'a Participant,
            destination_ownership_revision: u64,
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
            destination,
            destination_ownership_revision,
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
        destination: &Participant,
        destination_ownership_revision: u64,
    ) -> Result<(), ModelError> {
        if self.terms_digest
            != self.compute_terms_digest(request, destination, destination_ownership_revision)?
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
    serde_json_canonicalizer::to_vec(value).map_err(|_| ModelError::Canonicalization)
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

/// The destination host alone returns this result after checking its own
/// address authority and current account/resource ownership. It never came
/// from Directory or from a source-supplied destination account ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalAddressResolution {
    Found {
        destination: Participant,
        ownership_revision: u64,
    },
    NotRecognized,
}

/// This result stays inside the receiving provider. The owner binding is used
/// for its local Inbox and is never copied into the delivery receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalIngressResult {
    PendingForOwner {
        destination: Participant,
        ownership_revision: u64,
    },
    AddressNotRecognized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestDeliveryResult {
    QueuedForLocalOwner,
    AddressNotRecognized,
}

impl LocalIngressResult {
    pub fn delivery_result(&self) -> RequestDeliveryResult {
        match self {
            Self::PendingForOwner { .. } => RequestDeliveryResult::QueuedForLocalOwner,
            Self::AddressNotRecognized => RequestDeliveryResult::AddressNotRecognized,
        }
    }
}

pub fn classify_inbound_request(
    request: &RelationshipRequest,
    authenticated_peer: &PlatformId,
    local_platform: &PlatformId,
    gate: &PeerRequestGate,
    now: u64,
    resolution: LocalAddressResolution,
) -> Result<LocalIngressResult, ModelError> {
    request.validate()?;
    if &request.direction.source_platform_id != authenticated_peer {
        return Err(ModelError::WrongAuthenticatedPeer);
    }
    if &request.direction.destination_platform_id != local_platform {
        return Err(ModelError::WrongDirection);
    }
    if !gate.permits_request_delivery() {
        return Err(ModelError::PeerNotApproved);
    }
    if now >= request.request_expires_at {
        return Err(ModelError::RequestExpired);
    }
    match resolution {
        LocalAddressResolution::Found {
            destination,
            ownership_revision,
        } if &destination.platform_id == local_platform && ownership_revision > 0 => {
            Ok(LocalIngressResult::PendingForOwner {
                destination,
                ownership_revision,
            })
        }
        LocalAddressResolution::Found { .. } => Err(ModelError::InvalidLocalOwner),
        LocalAddressResolution::NotRecognized => Ok(LocalIngressResult::AddressNotRecognized),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).unwrap()
    }

    fn platform(value: &str) -> PlatformId {
        PlatformId::new(value).unwrap()
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

    fn destination() -> Participant {
        Participant {
            platform_id: platform("b"),
            subject_id: id("b-account"),
            resource_id: id("b-agent"),
        }
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
    fn destination_can_narrow_but_not_broaden() {
        let request = request();
        let mut lease = lease();
        assert_eq!(lease.validate_against(&request, &destination()), Ok(()));
        lease.expires_at = Some(3001);
        assert_eq!(
            lease.validate_against(&request, &destination()),
            Err(ModelError::LifetimeBroadened)
        );
        lease.expires_at = Some(1160);
        lease.effective_permissions.insert("account.read".into());
        assert_eq!(
            lease.validate_against(&request, &destination()),
            Err(ModelError::ScopeBroadened)
        );
    }

    #[test]
    fn canonical_request_and_effective_digests_bind_distinct_terms() {
        let request = request();
        let mut lease = lease();
        let request_digest = request.request_terms_digest().unwrap();
        lease.terms_digest = lease
            .compute_terms_digest(&request, &destination(), 1)
            .unwrap();
        assert_ne!(request_digest, lease.terms_digest);
        assert_eq!(
            lease.verify_terms_digest(&request, &destination(), 1),
            Ok(())
        );
        assert_eq!(
            lease.verify_terms_digest(&request, &destination(), 2),
            Err(ModelError::InvalidTermsDigest)
        );
        let mut changed_request = request.clone();
        changed_request.target.full_agent_address.push_str(".wrong");
        assert_ne!(
            request_digest,
            changed_request.request_terms_digest().unwrap()
        );
        let mut changed_lease = lease.clone();
        changed_lease
            .effective_permissions
            .insert("account.read".into());
        assert!(changed_lease
            .verify_terms_digest(&request, &destination(), 1)
            .is_err());
    }

    #[test]
    fn typed_request_parser_rejects_duplicate_unknown_and_oversized_input() {
        let raw = String::from_utf8(request().canonical_requested_terms().unwrap()).unwrap();
        let parsed = parse_relationship_request_json(raw.as_bytes()).unwrap();
        assert_eq!(parsed.request_id.as_str(), "request-1");
        let long_address = raw.replace("0123456789abcdef.providerb.example", "calendar.someuser.providerb.example");
        assert_eq!(parse_relationship_request_json(long_address.as_bytes()), Err(ModelError::InvalidTargetAddress));
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
        let same_provider = raw.replace("\"destination_platform_id\":\"b\"", "\"destination_platform_id\":\"a\"");
        assert_eq!(
            parse_relationship_request_json(same_provider.as_bytes()),
            Err(ModelError::SameProvider)
        );
    }

    #[test]
    fn source_cannot_issue_destination_lease() {
        let mut lease = lease();
        lease.granted_by_platform_id = platform("a");
        assert_eq!(
            lease.validate_against(&request(), &destination()),
            Err(ModelError::WrongDestinationIssuer)
        );
    }

    #[test]
    fn reverse_relationship_is_independent() {
        let request = request();
        let reverse = request.direction.reverse();
        assert_eq!(reverse.source_platform_id, platform("b"));
        assert_eq!(reverse.destination_platform_id, platform("a"));
        assert_ne!(reverse, request.direction);
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
        assert_eq!(lease.validate_against(&request, &destination()), Ok(()));
        lease.max_tasks = None;
        assert_eq!(
            lease.validate_against(&request, &destination()),
            Err(ModelError::InvalidLeaseMode)
        );
    }

    #[test]
    fn destination_may_choose_a_stricter_lifetime_mode() {
        let mut request = request();
        request.requested_lifetime = LifetimeRequest::UntilRevoked;
        assert_eq!(lease().validate_against(&request, &destination()), Ok(()));
        let mut one_task = lease();
        one_task.mode = LeaseMode::SingleTask;
        one_task.max_tasks = Some(1);
        assert_eq!(one_task.validate_against(&request, &destination()), Ok(()));

        request.requested_lifetime = LifetimeRequest::Fixed { expires_at: 3000 };
        assert_eq!(one_task.validate_against(&request, &destination()), Ok(()));
        request.requested_lifetime = LifetimeRequest::SingleTask { expires_at: 3000 };
        assert_eq!(
            lease().validate_against(&request, &destination()),
            Err(ModelError::LifetimeBroadened)
        );
    }

    #[test]
    fn approval_after_pending_request_expiry_is_invalid() {
        let mut expired_decision = lease();
        expired_decision.effective_from = request().request_expires_at;
        assert_eq!(
            expired_decision.validate_against(&request(), &destination()),
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
    fn private_address_resolution_stays_local_and_unknown_has_no_owner() {
        let request = request();
        let gate = approved_gate();
        let local = platform("b");
        let peer = platform("a");
        let found = classify_inbound_request(
            &request,
            &peer,
            &local,
            &gate,
            1100,
            LocalAddressResolution::Found {
                destination: destination(),
                ownership_revision: 3,
            },
        )
        .unwrap();
        assert_eq!(
            found.delivery_result(),
            RequestDeliveryResult::QueuedForLocalOwner
        );
        let unknown = classify_inbound_request(
            &request,
            &peer,
            &local,
            &gate,
            1100,
            LocalAddressResolution::NotRecognized,
        )
        .unwrap();
        assert_eq!(
            unknown.delivery_result(),
            RequestDeliveryResult::AddressNotRecognized
        );
    }

    #[test]
    fn inbound_request_rejects_unapproved_or_wrong_peer_before_account_routing() {
        let request = request();
        let local = platform("b");
        let found = LocalAddressResolution::Found {
            destination: destination(),
            ownership_revision: 3,
        };
        assert_eq!(
            classify_inbound_request(
                &request,
                &platform("c"),
                &local,
                &approved_gate(),
                1100,
                found.clone()
            ),
            Err(ModelError::WrongAuthenticatedPeer)
        );
        let mut gate = approved_gate();
        gate.local_operator_approved = false;
        assert_eq!(
            classify_inbound_request(&request, &platform("a"), &local, &gate, 1100, found),
            Err(ModelError::PeerNotApproved)
        );
    }
}
