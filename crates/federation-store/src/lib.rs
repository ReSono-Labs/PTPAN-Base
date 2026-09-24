//! Storage contracts for provider-owned Federation Base adapters.
//!
//! This crate has no database driver, tables, migrations, connection string,
//! or assumption that two providers use the same persistence technology.

use federation_base::control_event::{ControlReceipt, ParsedControlEvent};
use federation_base::live_admission::{
    AdmissionDecision, AdmissionRequest, SourceChallenge,
};
use federation_base::identity_evidence::{FieldObservation, VerifiedProviderBinding};
use federation_base::peer_control::ParsedPeerMessage;
use federation_base::{
    OpaqueId, Participant, PeerRequestGate, PlatformId, RelationshipLease, RelationshipRequest,
    RequestDeliveryResult,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerProposal<'a> {
    pub peer: &'a PlatformId,
    pub manifest_revision: u64,
    pub manifest_digest: [u8; 32],
    pub expected_service_id: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerBinding {
    pub manifest_revision: u64,
    pub manifest_digest: [u8; 32],
    pub expected_service_id: String,
    pub generation: u64,
}

/// Account-scoped result of a completed source request. The notice contains
/// no destination account, agent, address suggestions, or lookup details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceRequestNoticeKind {
    AddressNotRecognized,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRequestNotice {
    pub request_id: OpaqueId,
    pub peer: PlatformId,
    pub kind: SourceRequestNoticeKind,
}

/// Required private lookup index for the destination adapter. A provider may
/// implement this with SQL, a KV store, or its existing account service. The
/// key is the entire provider-scoped short address, never a public DNS query.
/// The result is local-only and must be rechecked against current ownership
/// before an Inbox item is created. Retired keys must not resolve.
pub trait ShortAddressResolutionStore {
    type Error;

    /// Issue a provider-scoped, unpredictable 80-bit handle. Keep the full
    /// mapping private and retain issued labels after retirement so they can
    /// never be assigned to a different resource.
    fn issue_short_address(
        &self,
        agent_id: &OpaqueId,
        now: u64,
    ) -> Result<String, Self::Error>;

    /// Stop resolution of exactly this agent's handle. Retirement does not
    /// transfer an existing relationship to a different agent or owner.
    fn retire_short_address(
        &self,
        agent_id: &OpaqueId,
        short_address: &str,
        now: u64,
    ) -> Result<(), Self::Error>;

    fn resolve_current_short_address(
        &self,
        short_address: &str,
    ) -> Result<Option<(Participant, u64)>, Self::Error>;
}

/// A provider adapter must persist these transitions atomically within its
/// own security boundary. The authenticated service observation and verified
/// identity evidence must come from the upstream bridge/verification path;
/// a caller-provided platform ID alone is never evidence.
pub trait PeerPolicyStore {
    type Error;

    fn save_candidate(&mut self, candidate: PeerProposal<'_>) -> Result<(), Self::Error>;
    fn record_request(
        &self,
        request_id: &str,
        peer: &PlatformId,
        digest: [u8; 32],
        inbound: bool,
    ) -> Result<(), Self::Error>;
    fn decide_inbound(&mut self, request_id: &str, approve: bool) -> Result<(), Self::Error>;
    fn approve_outbound_peer(
        &mut self,
        peer: &PlatformId,
        digest: [u8; 32],
    ) -> Result<(), Self::Error>;
    fn record_authenticated_service(
        &mut self,
        peer: &PlatformId,
        observed_service_id: &str,
        digest: [u8; 32],
    ) -> Result<(), Self::Error>;
    fn record_verified_identity(
        &mut self,
        report: &VerifiedProviderBinding,
    ) -> Result<(), Self::Error>;
    fn confirm_remote_approval(
        &mut self,
        request_id: &str,
        peer: &PlatformId,
        observed_service_id: &str,
        digest: [u8; 32],
    ) -> Result<(), Self::Error>;
    fn reject_outbound(
        &mut self,
        request_id: &str,
        peer: &PlatformId,
        observed_service_id: &str,
        digest: [u8; 32],
    ) -> Result<(), Self::Error>;
    fn suspend(&self, peer: &PlatformId) -> Result<(), Self::Error>;
    fn remove(&mut self, peer: &PlatformId) -> Result<(), Self::Error>;
    fn begin_regrant(&mut self, candidate: PeerProposal<'_>) -> Result<(), Self::Error>;
    fn gate(&self, peer: &PlatformId) -> Result<PeerRequestGate, Self::Error>;
    fn binding(&self, peer: &PlatformId) -> Result<PeerBinding, Self::Error>;
}

/// Destination provider adapter for private request delivery and enforceable
/// grants. The provider supplies its own account and grant implementation.
pub trait DestinationHostPort {
    type Error;

    fn receive_request(
        &mut self,
        request: &RelationshipRequest,
        authenticated_peer: &PlatformId,
        gate: &PeerRequestGate,
        now: u64,
    ) -> Result<RequestDeliveryResult, Self::Error>;
    fn decide_pending(
        &mut self,
        actor_account: &OpaqueId,
        request_id: &OpaqueId,
        decision_id: &OpaqueId,
        approve: bool,
        now: u64,
    ) -> Result<(), Self::Error>;
    fn install_grant(
        &mut self,
        request: &RelationshipRequest,
        lease: &RelationshipLease,
        grant_id: &OpaqueId,
        now: u64,
    ) -> Result<(), Self::Error>;
    fn check_grant(
        &self,
        grant_id: &OpaqueId,
        request: &RelationshipRequest,
        lease: &RelationshipLease,
        destination: &Participant,
        ownership_revision: u64,
        permission: &str,
        now: u64,
    ) -> Result<bool, Self::Error>;
    fn revoke_grant(&self, grant_id: &OpaqueId) -> Result<bool, Self::Error>;
}

/// Source-side account authority and Sent projection. The provider adapter
/// authenticates its own actor before Base creates any outbound request.
pub trait SourceHostPort {
    type Error;

    fn authorize_source(
        &self,
        actor_account: &OpaqueId,
        resource_id: &OpaqueId,
    ) -> Result<(Participant, u64), Self::Error>;
    fn record_sent(
        &mut self,
        actor_account: &OpaqueId,
        request: &RelationshipRequest,
        ownership_revision: u64,
    ) -> Result<(), Self::Error>;
    fn sent_count(&self, actor_account: &OpaqueId) -> Result<u64, Self::Error>;
    /// Read only the authenticated requester's own durable correction notice.
    /// `commit_control_receipt` creates it atomically with the Sent state.
    fn request_notice(
        &self,
        actor_account: &OpaqueId,
        request_id: &OpaqueId,
    ) -> Result<Option<SourceRequestNotice>, Self::Error>;
}

/// Durable peer inbox. The adapter commits the transition from
/// `federation_base::peer_transitions` and the exact message bytes together.
/// The same sender, message, and bytes return the saved result. Altered bytes
/// under the same ID conflict.
pub trait DurablePeerInbox {
    type Error;

    fn apply_authenticated_peer_message(
        &mut self,
        parsed: &ParsedPeerMessage,
        local: &PlatformId,
        expected_peer: &PlatformId,
        authenticated_service_id: &str,
        expected_service_id: &str,
        own_manifest_digest: [u8; 32],
    ) -> Result<String, Self::Error>;
}

/// Durable relationship inbox, outbox, and source decision. The adapter
/// applies `federation_base::relationship_exchange` inside its own transaction.
/// Account rows, ownership, and grants stay on the provider host port.
pub trait DurableRelationshipExchange {
    type Error;

    fn record_sent_control(
        &mut self,
        actor_account: &OpaqueId,
        request: &RelationshipRequest,
        ownership_revision: u64,
        event: &ParsedControlEvent,
        peer_generation: u64,
    ) -> Result<(), Self::Error>;
    fn commit_control_receipt(
        &mut self,
        receipt: &ControlReceipt,
        peer_generation: u64,
    ) -> Result<(), Self::Error>;
    fn receive_control_request(
        &mut self,
        event: &ParsedControlEvent,
        authenticated_peer: &PlatformId,
        gate: &PeerRequestGate,
        peer_generation: u64,
        now: u64,
    ) -> Result<RequestDeliveryResult, Self::Error>;
    fn approve_fixed_decision_atomic(
        &mut self,
        actor_account: &OpaqueId,
        request: &RelationshipRequest,
        destination: &Participant,
        ownership_revision: u64,
        lease: &RelationshipLease,
        grant_id: &OpaqueId,
        event: &ParsedControlEvent,
        peer_generation: u64,
        now: u64,
    ) -> Result<(), Self::Error>;
    fn deny_decision_atomic(
        &mut self,
        actor_account: &OpaqueId,
        request: &RelationshipRequest,
        event: &ParsedControlEvent,
        peer_generation: u64,
        now: u64,
    ) -> Result<(), Self::Error>;
    fn commit_destination_decision_receipt(
        &mut self,
        receipt: &ControlReceipt,
        peer_generation: u64,
    ) -> Result<(), Self::Error>;
    fn receive_control_decision(
        &mut self,
        event: &ParsedControlEvent,
        authenticated_peer: &PlatformId,
        gate: &PeerRequestGate,
        peer_generation: u64,
    ) -> Result<(), Self::Error>;
    fn apply_durable_lifecycle(
        &mut self,
        event: &ParsedControlEvent,
        authenticated_peer: &PlatformId,
        gate: &PeerRequestGate,
        peer_generation: u64,
    ) -> Result<(), Self::Error>;
}

/// Destination test admission. The nonce record is single-use and is not a
/// lifecycle outbox row. The decision does not issue a destination credential.
pub trait TestAdmissionPort {
    type Error;

    fn issue_test_admission(
        &mut self,
        request: &AdmissionRequest,
        challenge: Option<&SourceChallenge>,
        grant_id: &OpaqueId,
        relationship_request: &RelationshipRequest,
        lease: &RelationshipLease,
        destination: &Participant,
        ownership_revision: u64,
        operation: &str,
        gate: &PeerRequestGate,
        now: u64,
    ) -> Result<AdmissionDecision, Self::Error>;
}

/// Persists receiver field observations for a rejected identity evaluation.
/// This port must not set identity verification.
pub trait IdentityObservationStore {
    type Error;

    fn record_field_observations(
        &mut self,
        peer: &PlatformId,
        manifest_digest: [u8; 32],
        observations: &[FieldObservation],
    ) -> Result<(), Self::Error>;
}
