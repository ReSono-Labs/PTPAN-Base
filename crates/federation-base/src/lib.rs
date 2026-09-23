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
