//! Peer trust state machine (principles 10–11, D8, D14). The adapter keeps
//! one `PeerRecord` per trusted peer platform in its peer store, applies these
//! functions to it, and persists the result. Nothing here reads accounts.
//!
//! A peer is open for request delivery only when the operator has not
//! suspended or removed it, the peer has not suspended us, the identity check
//! passed for the manifest it currently uses, the local operator approved
//! exactly that manifest, and the peer approved our current manifest.

use crate::identity_evidence::BootstrapAuthority;
use crate::peer_control::TrustDecisionResult;
use crate::{PeerRequestGate, PeerState};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The only capability a provider approval grants (requests may enter; no
/// account discovery).
pub const REQUEST_DELIVERY: &str = "REQUEST_DELIVERY";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRuleError {
    InvalidTransition,
    ManifestMismatch,
    ServiceMismatch,
    NotVerified,
    Removed,
}

/// The operator's own setting for the peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OperatorState {
    Enabled,
    Suspended,
    Removed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceivedManifest {
    pub revision: u64,
    pub digest: [u8; 32],
    pub exact_bytes: Vec<u8>,
}

/// A planned revision the peer announced (D8).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PendingRevision {
    pub manifest: ReceivedManifest,
    pub effective_at: u64,
    pub locally_approved: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerRecord {
    pub bootstrap: BootstrapAuthority,
    /// Bumps whenever the operator replaces the bootstrap; messages from an
    /// older generation are ignored.
    pub generation: u64,
    pub operator: OperatorState,
    pub remote_suspended: bool,
    pub current: Option<ReceivedManifest>,
    /// Digest of `current` whose identity check passed, if any, and when
    /// its domain proof was fetched (unix seconds).
    pub verified_digest: Option<[u8; 32]>,
    pub verified_at: Option<u64>,
    pub local_approved_digest: Option<[u8; 32]>,
    /// Digests of our own manifest that the peer approved.
    pub remote_approved_digests: BTreeSet<[u8; 32]>,
    pub pending: Option<PendingRevision>,
}

impl PeerRecord {
    pub fn new(bootstrap: BootstrapAuthority) -> Self {
        Self {
            bootstrap,
            generation: 1,
            operator: OperatorState::Enabled,
            remote_suspended: false,
            current: None,
            verified_digest: None,
            verified_at: None,
            local_approved_digest: None,
            remote_approved_digests: BTreeSet::new(),
            pending: None,
        }
    }

    fn current_digest(&self) -> Option<[u8; 32]> {
        self.current.as_ref().map(|m| m.digest)
    }

    /// The request gate for one moment, given our own current manifest
    /// digest and the service authenticated on the connection.
    pub fn gate(&self, own_digest: &[u8; 32], authenticated_service: Option<&str>) -> PeerRequestGate {
        let verified = self.current_digest().is_some() && self.verified_digest == self.current_digest();
        let local = self.local_approved_digest.is_some() && self.local_approved_digest == self.current_digest();
        let remote = self.remote_approved_digests.contains(own_digest);
        let service = authenticated_service.is_none_or(|s| s == self.bootstrap.expected_control_service_id);
        let state = match self.operator {
            OperatorState::Removed => PeerState::Removed,
            OperatorState::Suspended => PeerState::Suspended,
            OperatorState::Enabled if self.remote_suspended => PeerState::Suspended,
            OperatorState::Enabled if verified && local && remote => PeerState::Active,
            OperatorState::Enabled => PeerState::Pending,
        };
        PeerRequestGate {
            state,
            local_operator_approved: local,
            remote_operator_approval_confirmed: remote,
            peer_identity_verified: verified,
            exact_service_authenticated: service,
        }
    }

    /// Operator replaced the bootstrap: everything learned under the old one
    /// is discarded and the generation advances.
    pub fn replace_bootstrap(&mut self, bootstrap: BootstrapAuthority) -> Result<(), PeerRuleError> {
        if self.operator == OperatorState::Removed {
            return Err(PeerRuleError::Removed);
        }
        let generation = self.generation + 1;
        let operator = self.operator;
        *self = Self::new(bootstrap);
        self.generation = generation;
        self.operator = operator;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelloOutcome {
    /// Same manifest as before; nothing changed.
    Unchanged,
    /// A new manifest replaced the current one. It must pass the identity
    /// check again. `approval_kept` is true only for an announced revision the
    /// operator approved in advance (D8); otherwise traffic stops until the
    /// operator approves again.
    Replaced { approval_kept: bool },
}

/// The peer presented its manifest on a hello, authenticated as
/// `authenticated_service`.
pub fn receive_hello(
    record: &mut PeerRecord,
    manifest: ReceivedManifest,
    authenticated_service: &str,
) -> Result<HelloOutcome, PeerRuleError> {
    if record.operator == OperatorState::Removed {
        return Err(PeerRuleError::Removed);
    }
    if authenticated_service != record.bootstrap.expected_control_service_id {
        return Err(PeerRuleError::ServiceMismatch);
    }
    if let Some(current) = &record.current {
        if manifest.revision < current.revision {
            return Err(PeerRuleError::InvalidTransition);
        }
        if manifest.revision == current.revision {
            return if manifest.digest == current.digest && manifest.exact_bytes == current.exact_bytes {
                Ok(HelloOutcome::Unchanged)
            } else {
                Err(PeerRuleError::ManifestMismatch)
            };
        }
    }
    let announced = record.pending.take().filter(|pending| {
        pending.locally_approved && pending.manifest.digest == manifest.digest
    });
    let approval_kept = announced.is_some();
    record.local_approved_digest = approval_kept.then_some(manifest.digest);
    record.verified_digest = None;
    record.verified_at = None;
    record.current = Some(manifest);
    Ok(HelloOutcome::Replaced { approval_kept })
}

/// Record the identity check result for `digest` (identity_evidence),
/// with the time its domain proof was fetched.
pub fn record_identity(record: &mut PeerRecord, digest: [u8; 32], verified_at: Option<u64>) {
    if record.current_digest() == Some(digest) {
        record.verified_digest = verified_at.map(|_| digest);
        record.verified_at = verified_at;
    }
}

/// True when the identity check is missing or older than the bootstrap's
/// freshness limit, so the adapter must fetch the domain proof again.
pub fn identity_needs_refresh(record: &PeerRecord, now: u64) -> bool {
    let limit = u64::try_from(record.bootstrap.max_evidence_age_seconds).unwrap_or(0);
    match (record.verified_digest, record.verified_at) {
        (Some(_), Some(at)) => now.saturating_sub(at) >= limit / 2,
        _ => record.current.is_some(),
    }
}

/// The local operator approves the peer's current, verified manifest.
pub fn approve_locally(record: &mut PeerRecord) -> Result<[u8; 32], PeerRuleError> {
    if record.operator == OperatorState::Removed {
        return Err(PeerRuleError::Removed);
    }
    let digest = record.current_digest().ok_or(PeerRuleError::NotVerified)?;
    if record.verified_digest != Some(digest) {
        return Err(PeerRuleError::NotVerified);
    }
    record.local_approved_digest = Some(digest);
    Ok(digest)
}

/// The peer's decision about our manifest. `sender_digest` is the peer's own
/// manifest it was looking at; it must be its current or announced one.
pub fn receive_trust_decision(
    record: &mut PeerRecord,
    sender_digest: [u8; 32],
    our_digest: [u8; 32],
    result: TrustDecisionResult,
    capabilities: &BTreeSet<String>,
) -> Result<(), PeerRuleError> {
    let known = record.current_digest() == Some(sender_digest)
        || record.pending.as_ref().is_some_and(|p| p.manifest.digest == sender_digest);
    if !known {
        return Err(PeerRuleError::ManifestMismatch);
    }
    match result {
        TrustDecisionResult::Approved
            if capabilities.len() == 1 && capabilities.contains(REQUEST_DELIVERY) =>
        {
            record.remote_approved_digests.insert(our_digest);
            record.remote_suspended = false;
            Ok(())
        }
        TrustDecisionResult::Rejected if capabilities.is_empty() => {
            record.remote_approved_digests.remove(&our_digest);
            Ok(())
        }
        _ => Err(PeerRuleError::InvalidTransition),
    }
}

/// The peer announced a planned revision (D8). A newer announcement replaces
/// an older one and needs its own approval.
pub fn receive_pending(
    record: &mut PeerRecord,
    manifest: ReceivedManifest,
    effective_at: u64,
) -> Result<(), PeerRuleError> {
    if record.operator == OperatorState::Removed {
        return Err(PeerRuleError::Removed);
    }
    if record.current.as_ref().is_some_and(|c| manifest.revision <= c.revision) {
        return Err(PeerRuleError::InvalidTransition);
    }
    if let Some(prior) = &record.pending {
        if prior.manifest.revision == manifest.revision && prior.manifest.digest == manifest.digest {
            return Ok(());
        }
        if manifest.revision < prior.manifest.revision {
            return Err(PeerRuleError::InvalidTransition);
        }
    }
    record.pending = Some(PendingRevision { manifest, effective_at, locally_approved: false });
    Ok(())
}

/// The local operator approves the announced revision in advance.
pub fn approve_pending(record: &mut PeerRecord) -> Result<[u8; 32], PeerRuleError> {
    let pending = record.pending.as_mut().ok_or(PeerRuleError::InvalidTransition)?;
    pending.locally_approved = true;
    Ok(pending.manifest.digest)
}

/// Restrictive operator actions. They take effect at once and are sent to
/// the peer; revoke, block, withdrawal and suspension still flow afterwards.
pub fn suspend(record: &mut PeerRecord) -> Result<(), PeerRuleError> {
    match record.operator {
        OperatorState::Removed => Err(PeerRuleError::Removed),
        _ => {
            record.operator = OperatorState::Suspended;
            Ok(())
        }
    }
}

pub fn resume(record: &mut PeerRecord) -> Result<(), PeerRuleError> {
    match record.operator {
        OperatorState::Suspended => {
            record.operator = OperatorState::Enabled;
            Ok(())
        }
        _ => Err(PeerRuleError::InvalidTransition),
    }
}

pub fn remove(record: &mut PeerRecord) {
    record.operator = OperatorState::Removed;
    record.local_approved_digest = None;
}

/// The peer suspended or removed us.
pub fn receive_restriction(record: &mut PeerRecord) {
    record.remote_suspended = true;
}

pub fn stored_peer_state(value: &str) -> Option<PeerState> {
    match value {
        "pending" => Some(PeerState::Pending),
        "active" => Some(PeerState::Active),
        "suspended" => Some(PeerState::Suspended),
        "removing" => Some(PeerState::Removing),
        "removed" => Some(PeerState::Removed),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PlatformId;

    const CONTROL: &str = "spiffe://provider-b.test/federation/control";
    const OURS: [u8; 32] = [7; 32];

    fn bootstrap() -> BootstrapAuthority {
        BootstrapAuthority {
            peer: PlatformId::new("provider-b").unwrap(),
            provider_domain: "provider-b.test".into(),
            expected_control_service_id: CONTROL.into(),
            expected_control_endpoint: "https://control.provider-b.test/control".into(),
            expected_edge_service_id: "spiffe://provider-b.test/federation/edge".into(),
            expected_edge_endpoint: "edge.provider-b.test:8443".into(),
            expected_bundle_endpoint: "https://bundle.provider-b.test".into(),
            expected_bundle_profile: "https_spiffe".into(),
            max_evidence_age_seconds: 3600,
        }
    }

    fn manifest(revision: u64, digest: u8) -> ReceivedManifest {
        ReceivedManifest { revision, digest: [digest; 32], exact_bytes: vec![digest; 4] }
    }

    fn delivery() -> BTreeSet<String> {
        BTreeSet::from([REQUEST_DELIVERY.to_string()])
    }

    fn active() -> PeerRecord {
        let mut record = PeerRecord::new(bootstrap());
        receive_hello(&mut record, manifest(1, 1), CONTROL).unwrap();
        record_identity(&mut record, [1; 32], Some(1));
        approve_locally(&mut record).unwrap();
        receive_trust_decision(&mut record, [1; 32], OURS, TrustDecisionResult::Approved, &delivery()).unwrap();
        record
    }

    #[test]
    fn every_peer_state_reads_back_from_storage() {
        for (text, state) in [
            ("pending", PeerState::Pending),
            ("active", PeerState::Active),
            ("suspended", PeerState::Suspended),
            ("removing", PeerState::Removing),
            ("removed", PeerState::Removed),
        ] {
            assert_eq!(stored_peer_state(text), Some(state));
        }
        assert_eq!(stored_peer_state("ACTIVE"), None);
    }

    #[test]
    fn gate_opens_only_with_identity_and_both_approvals() {
        let mut record = PeerRecord::new(bootstrap());
        assert_eq!(record.gate(&OURS, None).state, PeerState::Pending);
        receive_hello(&mut record, manifest(1, 1), CONTROL).unwrap();
        assert_eq!(approve_locally(&mut record), Err(PeerRuleError::NotVerified));
        record_identity(&mut record, [1; 32], Some(1));
        approve_locally(&mut record).unwrap();
        assert!(!record.gate(&OURS, None).permits_request_delivery());
        receive_trust_decision(&mut record, [1; 32], OURS, TrustDecisionResult::Approved, &delivery()).unwrap();
        assert!(record.gate(&OURS, Some(CONTROL)).permits_request_delivery());
        assert!(!record.gate(&OURS, Some("spiffe://provider-b.test/other")).permits_request_delivery());
        assert!(!record.gate(&[8; 32], None).permits_request_delivery(), "peer has not approved our new manifest");
    }

    #[test]
    fn unannounced_manifest_change_cuts_off_until_revalidated_and_approved() {
        let mut record = active();
        assert_eq!(receive_hello(&mut record, manifest(2, 2), CONTROL), Ok(HelloOutcome::Replaced { approval_kept: false }));
        assert!(!record.gate(&OURS, None).permits_request_delivery());
        record_identity(&mut record, [2; 32], Some(1));
        assert!(!record.gate(&OURS, None).permits_request_delivery());
        approve_locally(&mut record).unwrap();
        assert!(record.gate(&OURS, None).permits_request_delivery());
    }

    #[test]
    fn announced_and_approved_change_switches_after_its_identity_check() {
        let mut record = active();
        receive_pending(&mut record, manifest(2, 2), 5_000).unwrap();
        assert!(record.gate(&OURS, None).permits_request_delivery(), "announcement alone changes nothing");
        approve_pending(&mut record).unwrap();
        assert_eq!(receive_hello(&mut record, manifest(2, 2), CONTROL), Ok(HelloOutcome::Replaced { approval_kept: true }));
        assert!(!record.gate(&OURS, None).permits_request_delivery(), "identity is checked again");
        record_identity(&mut record, [2; 32], Some(1));
        assert!(record.gate(&OURS, None).permits_request_delivery());
        let mut other = active();
        receive_pending(&mut other, manifest(2, 2), 5_000).unwrap();
        approve_pending(&mut other).unwrap();
        assert_eq!(receive_hello(&mut other, manifest(2, 3), CONTROL), Ok(HelloOutcome::Replaced { approval_kept: false }));
    }

    #[test]
    fn replays_conflicts_and_old_revisions() {
        let mut record = active();
        assert_eq!(receive_hello(&mut record, manifest(1, 1), CONTROL), Ok(HelloOutcome::Unchanged));
        assert_eq!(receive_hello(&mut record, manifest(1, 9), CONTROL), Err(PeerRuleError::ManifestMismatch));
        assert_eq!(receive_hello(&mut record, manifest(1, 1), "spiffe://provider-b.test/x"), Err(PeerRuleError::ServiceMismatch));
        assert_eq!(receive_pending(&mut record, manifest(1, 4), 9), Err(PeerRuleError::InvalidTransition));
        assert!(record.gate(&OURS, None).permits_request_delivery());
        assert_eq!(
            receive_trust_decision(&mut record, [9; 32], OURS, TrustDecisionResult::Approved, &delivery()),
            Err(PeerRuleError::ManifestMismatch)
        );
        let wider = BTreeSet::from([REQUEST_DELIVERY.to_string(), "ACCOUNT_LIST".to_string()]);
        assert_eq!(
            receive_trust_decision(&mut record, [1; 32], OURS, TrustDecisionResult::Approved, &wider),
            Err(PeerRuleError::InvalidTransition)
        );
    }

    #[test]
    fn suspension_and_removal_close_the_gate() {
        let mut record = active();
        suspend(&mut record).unwrap();
        assert_eq!(record.gate(&OURS, None).state, PeerState::Suspended);
        resume(&mut record).unwrap();
        assert!(record.gate(&OURS, None).permits_request_delivery());
        receive_restriction(&mut record);
        assert_eq!(record.gate(&OURS, None).state, PeerState::Suspended);
        receive_trust_decision(&mut record, [1; 32], OURS, TrustDecisionResult::Approved, &delivery()).unwrap();
        assert!(record.gate(&OURS, None).permits_request_delivery());
        remove(&mut record);
        assert_eq!(record.gate(&OURS, None).state, PeerState::Removed);
        assert_eq!(receive_hello(&mut record, manifest(2, 2), CONTROL), Err(PeerRuleError::Removed));
        assert_eq!(resume(&mut record), Err(PeerRuleError::InvalidTransition));
    }

    #[test]
    fn identity_is_refreshed_at_half_the_freshness_limit() {
        let mut record = active();
        assert!(!identity_needs_refresh(&record, 1_000));
        assert!(identity_needs_refresh(&record, 1 + 1_800));
        record_identity(&mut record, [1; 32], None);
        assert!(!record.gate(&OURS, None).permits_request_delivery());
        assert!(identity_needs_refresh(&record, 2));
    }

    #[test]
    fn replacing_the_bootstrap_forgets_learned_state() {
        let mut record = active();
        record.replace_bootstrap(bootstrap()).unwrap();
        assert_eq!(record.generation, 2);
        assert!(record.current.is_none() && record.remote_approved_digests.is_empty());
        assert!(!record.gate(&OURS, None).permits_request_delivery());
    }
}
