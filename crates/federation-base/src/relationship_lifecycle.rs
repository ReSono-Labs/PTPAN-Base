//! Restrictive relationship lifecycle. These rules decide local authority.
//! A provider adapter loads facts and stores the result. A status report,
//! a durable `AUTHORIZED` hint, or an unblock never creates consent.

use crate::control_event::{
    ActorSide, ConfigAckPayload, PairBlockState, RelationshipState, RevokePayload,
    SourceAuthorization, SourceAuthorizationPayload, StatusPayload,
};
use crate::{LeaseMode, PeerState};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    StaleRevision,
    StaleAcknowledgment,
    RevokedIsTerminal,
    RenewalDoesNotExtend,
}

/// One superseded lease revision kept so a replay cannot become current.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditedRevision {
    pub lease_revision: u64,
    pub terms_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskBindError {
    EmptyTaskId,
    DifferentTask,
    NotSingleTaskMode,
}

/// One pair block (D7). The destination platform keys it by (source
/// platform, requester reference, destination address); the source platform
/// keeps the same record keyed by (its own account, destination address) to
/// enforce the block for the whole account. Platforms own the records; this
/// type and `apply_pair_block` are the shared rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairBlockRecord {
    pub state: PairBlockState,
    pub block_revision: u64,
}

/// Apply a block or unblock at `revision`. Revisions only move forward; the
/// same revision with the same state is an idempotent replay. An unblock
/// changes only this record: it never creates consent and never revives a
/// relationship (new consent requires a new request).
pub fn apply_pair_block(
    current: Option<PairBlockRecord>,
    state: PairBlockState,
    revision: u64,
) -> Result<PairBlockRecord, LifecycleError> {
    let next = PairBlockRecord { state, block_revision: revision };
    match current {
        Some(existing) if existing == next => Ok(existing),
        Some(existing) if revision <= existing.block_revision => Err(LifecycleError::StaleRevision),
        _ if revision == 0 => Err(LifecycleError::StaleRevision),
        _ => Ok(next),
    }
}

/// A block makes every affected relationship permanently unusable. The
/// relationship is also revoked through the normal revoke event.
pub fn block_relationship(record: &mut LifecycleRecord) {
    record.grant_usable = false;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableSourceAuthorization {
    None,
    /// Reconciliation hint only. It is not fresh positive proof.
    Hint { revision: u64 },
    Withdrawn { revision: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleRecord {
    pub lease_revision: u64,
    pub local_terms_digest: [u8; 32],
    pub remote_terms_digest: Option<[u8; 32]>,
    pub source_authorization: DurableSourceAuthorization,
    pub destination_owner_current: bool,
    pub grant_usable: bool,
    pub provenance_current: bool,
    pub configuration_revision: u64,
    pub acknowledged_configuration_revision: Option<u64>,
    pub key_purpose_revision: u64,
    pub acknowledged_key_purpose_revision: Option<u64>,
    pub revoked: bool,
    pub prior_revisions: Vec<AuditedRevision>,
    pub bound_task_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AffirmativeTraffic {
    NewRelationship,
    Admission,
    CleanupOrRevoke,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadinessInput<'a> {
    pub peer: PeerState,
    pub record: &'a LifecycleRecord,
    /// The platform's pair-block record for this relationship's pair.
    pub pair_block: PairBlockState,
    /// The source host's own current authorization. A durable `AUTHORIZED`
    /// event must not be passed here as if it were this fact.
    pub host_source_authorization_current: bool,
    pub now: u64,
    /// `None` is `UNTIL_REVOKED`: no lease clock. A finite expiry denies at
    /// `now` even when no `EXPIRED` status event arrived.
    pub lease_expires_at: Option<u64>,
}

pub fn peer_allows(peer: PeerState, traffic: AffirmativeTraffic) -> bool {
    match (peer, traffic) {
        (PeerState::Active, _) => true,
        (PeerState::Suspended, AffirmativeTraffic::CleanupOrRevoke) => true,
        (
            PeerState::Pending
            | PeerState::Suspended
            | PeerState::Removing
            | PeerState::Removed,
            AffirmativeTraffic::NewRelationship | AffirmativeTraffic::Admission,
        ) => false,
        (
            PeerState::Pending | PeerState::Removing | PeerState::Removed,
            AffirmativeTraffic::CleanupOrRevoke,
        ) => false,
    }
}

pub fn apply_revoke(
    record: &mut LifecycleRecord,
    payload: &RevokePayload,
) -> Result<(), LifecycleError> {
    if payload.lease_revision != record.lease_revision {
        return Err(LifecycleError::StaleRevision);
    }
    if record.revoked {
        return Ok(());
    }
    record.revoked = true;
    record.grant_usable = false;
    Ok(())
}

/// A status observation never grants, renews, extends, or clears a revoke.
/// Every reported state, including `READY`, leaves the local record unchanged.
pub fn apply_status(
    record: &LifecycleRecord,
    payload: &StatusPayload,
) -> Result<(), LifecycleError> {
    if payload.lease_revision > record.lease_revision {
        return Err(LifecycleError::RenewalDoesNotExtend);
    }
    if payload.lease_revision < record.lease_revision {
        return Err(LifecycleError::StaleRevision);
    }
    match payload.state {
        RelationshipState::Configuring
        | RelationshipState::Ready
        | RelationshipState::Revoked
        | RelationshipState::Expired
        | RelationshipState::Consumed
        | RelationshipState::Suspended => Ok(()),
    }
}

pub fn apply_source_authorization(
    record: &mut LifecycleRecord,
    actor: ActorSide,
    payload: &SourceAuthorizationPayload,
) -> Result<(), LifecycleError> {
    if actor != ActorSide::Source || payload.lease_revision != record.lease_revision {
        return Err(LifecycleError::StaleRevision);
    }
    if record.revoked {
        return Err(LifecycleError::RevokedIsTerminal);
    }
    let current = authorization_revision(record.source_authorization);
    if payload.authorization_revision < current {
        return Err(LifecycleError::StaleRevision);
    }
    if payload.authorization_revision == current {
        let same_status = matches!(
            (record.source_authorization, &payload.status),
            (DurableSourceAuthorization::Hint { .. }, SourceAuthorization::Authorized)
                | (DurableSourceAuthorization::Withdrawn { .. }, SourceAuthorization::Withdrawn)
        );
        if current != 0 && !same_status {
            return Err(LifecycleError::StaleRevision);
        }
    }
    record.source_authorization = match payload.status {
        SourceAuthorization::Withdrawn => {
            record.grant_usable = false;
            DurableSourceAuthorization::Withdrawn {
                revision: payload.authorization_revision,
            }
        }
        SourceAuthorization::Authorized => DurableSourceAuthorization::Hint {
            revision: payload.authorization_revision,
        },
    };
    Ok(())
}

pub fn apply_config_ack(
    record: &mut LifecycleRecord,
    payload: &ConfigAckPayload,
) -> Result<(), LifecycleError> {
    if record.revoked {
        return Err(LifecycleError::RevokedIsTerminal);
    }
    if payload.lease_revision != record.lease_revision
        || payload.configuration_revision != record.configuration_revision
        || payload.key_purpose_revision != record.key_purpose_revision
    {
        return Err(LifecycleError::StaleAcknowledgment);
    }
    record.acknowledged_configuration_revision = Some(payload.configuration_revision);
    record.acknowledged_key_purpose_revision = Some(payload.key_purpose_revision);
    Ok(())
}

/// A pending renewal is a new request. It does not extend the current lease.
pub fn pending_renewal_extends_current_lease() -> bool {
    false
}

/// `None` has no lease timestamp. A stored expiry denies at that timestamp
/// without an `EXPIRED` status event.
pub fn finite_lease_still_effective(expires_at: Option<u64>, now: u64) -> bool {
    expires_at.is_none_or(|expiry| now < expiry)
}

/// Records a new destination decision on the same relationship. The previous
/// revision stays in `prior_revisions`. The new revision is not usable until
/// the host proves the new grant and the counterpart stores the new digest.
pub fn apply_renewal(
    record: &mut LifecycleRecord,
    new_revision: u64,
    new_local_digest: [u8; 32],
) -> Result<(), LifecycleError> {
    if record.revoked {
        return Err(LifecycleError::RevokedIsTerminal);
    }
    if new_revision <= record.lease_revision
        || record
            .prior_revisions
            .iter()
            .any(|prior| prior.lease_revision == new_revision)
    {
        return Err(LifecycleError::StaleRevision);
    }
    record.prior_revisions.push(AuditedRevision {
        lease_revision: record.lease_revision,
        terms_digest: record.local_terms_digest,
    });
    record.lease_revision = new_revision;
    record.local_terms_digest = new_local_digest;
    record.remote_terms_digest = None;
    record.grant_usable = false;
    record.acknowledged_configuration_revision = None;
    record.acknowledged_key_purpose_revision = None;
    record.bound_task_id = None;
    Ok(())
}

/// Binds the first logical task id for `SINGLE_TASK`. The same id may retry.
/// A different id is denied. This records the portable rule. It does not see
/// an A2A payload.
pub fn bind_single_task(
    bound_task_id: &mut Option<String>,
    mode: LeaseMode,
    task_id: &str,
) -> Result<(), TaskBindError> {
    if mode != LeaseMode::SingleTask {
        return Err(TaskBindError::NotSingleTaskMode);
    }
    if task_id.is_empty() {
        return Err(TaskBindError::EmptyTaskId);
    }
    match bound_task_id {
        None => {
            *bound_task_id = Some(task_id.to_owned());
            Ok(())
        }
        Some(bound) if bound == task_id => Ok(()),
        Some(_) => Err(TaskBindError::DifferentTask),
    }
}

pub fn derive_ready(input: ReadinessInput<'_>) -> bool {
    let record = input.record;
    finite_lease_still_effective(input.lease_expires_at, input.now)
        && input.peer == PeerState::Active
        && !record.revoked
        && input.pair_block == PairBlockState::Open
        && record.remote_terms_digest == Some(record.local_terms_digest)
        && input.host_source_authorization_current
        && !matches!(
            record.source_authorization,
            DurableSourceAuthorization::Withdrawn { .. }
        )
        && record.destination_owner_current
        && record.grant_usable
        && record.provenance_current
        && record.acknowledged_configuration_revision == Some(record.configuration_revision)
        && record.acknowledged_key_purpose_revision == Some(record.key_purpose_revision)
}

fn authorization_revision(authorization: DurableSourceAuthorization) -> u64 {
    match authorization {
        DurableSourceAuthorization::None => 0,
        DurableSourceAuthorization::Hint { revision }
        | DurableSourceAuthorization::Withdrawn { revision } => revision,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OpaqueId;

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).unwrap()
    }

    fn record() -> LifecycleRecord {
        LifecycleRecord {
            lease_revision: 2,
            local_terms_digest: [4; 32],
            remote_terms_digest: Some([4; 32]),
            source_authorization: DurableSourceAuthorization::None,
            destination_owner_current: true,
            grant_usable: true,
            provenance_current: true,
            configuration_revision: 3,
            acknowledged_configuration_revision: None,
            key_purpose_revision: 5,
            acknowledged_key_purpose_revision: None,
            revoked: false,
            prior_revisions: Vec::new(),
            bound_task_id: None,
        }
    }

    fn revoke(revision: u64) -> RevokePayload {
        RevokePayload {
            revocation_id: id("rev-1"),
            lease_id: id("lease-1"),
            lease_revision: revision,
            reason_code: "owner".into(),
            effective_at: "2026-09-23T08:00:00Z".into(),
        }
    }

    fn ready_input(record: &LifecycleRecord) -> ReadinessInput<'_> {
        ReadinessInput {
            peer: PeerState::Active,
            record,
            pair_block: PairBlockState::Open,
            host_source_authorization_current: true,
            now: 1,
            lease_expires_at: None,
        }
    }

    #[test]
    fn revoke_is_terminal_and_status_cannot_restore_it() {
        let mut record = record();
        apply_revoke(&mut record, &revoke(2)).unwrap();
        assert!(record.revoked);
        assert!(!record.grant_usable);
        apply_status(
            &record,
            &StatusPayload {
                lease_id: id("lease-1"),
                lease_revision: 2,
                state: RelationshipState::Ready,
                observed_at: "2026-09-23T08:01:00Z".into(),
            },
        )
        .unwrap();
        assert!(record.revoked);
        assert!(!derive_ready(ready_input(&record)));
        assert_eq!(apply_revoke(&mut record, &revoke(1)), Err(LifecycleError::StaleRevision));
        assert!(record.revoked);
    }

    #[test]
    fn older_revoke_does_not_replace_the_current_lease() {
        let mut record = record();
        assert_eq!(
            apply_revoke(&mut record, &revoke(1)),
            Err(LifecycleError::StaleRevision)
        );
        assert!(!record.revoked);
        assert!(record.grant_usable);
    }

    #[test]
    fn authorized_hint_is_not_admission_proof_and_withdrawal_restricts() {
        let mut record = record();
        apply_source_authorization(
            &mut record,
            ActorSide::Source,
            &SourceAuthorizationPayload {
                lease_id: id("lease-1"),
                lease_revision: 2,
                authorization_revision: 1,
                status: SourceAuthorization::Authorized,
                effective_at: "2026-09-23T08:00:00Z".into(),
            },
        )
        .unwrap();
        assert_eq!(
            record.source_authorization,
            DurableSourceAuthorization::Hint { revision: 1 }
        );
        let mut without_host = ready_input(&record);
        without_host.host_source_authorization_current = false;
        assert!(!derive_ready(without_host));
        apply_source_authorization(
            &mut record,
            ActorSide::Source,
            &SourceAuthorizationPayload {
                lease_id: id("lease-1"),
                lease_revision: 2,
                authorization_revision: 2,
                status: SourceAuthorization::Withdrawn,
                effective_at: "2026-09-23T08:02:00Z".into(),
            },
        )
        .unwrap();
        assert!(!derive_ready(ready_input(&record)));
        assert_eq!(
            apply_source_authorization(
                &mut record,
                ActorSide::Source,
                &SourceAuthorizationPayload {
                    lease_id: id("lease-1"),
                    lease_revision: 2,
                    authorization_revision: 1,
                    status: SourceAuthorization::Authorized,
                    effective_at: "2026-09-23T08:03:00Z".into(),
                }
            ),
            Err(LifecycleError::StaleRevision)
        );
    }

    #[test]
    fn stale_config_ack_cannot_become_ready() {
        let mut record = record();
        assert_eq!(
            apply_config_ack(
                &mut record,
                &ConfigAckPayload {
                    lease_id: id("lease-1"),
                    lease_revision: 2,
                    configuration_revision: 2,
                    key_purpose_revision: 5,
                    acknowledged_at: "2026-09-23T08:00:00Z".into(),
                    source_key: None,
                }
            ),
            Err(LifecycleError::StaleAcknowledgment)
        );
        assert!(!derive_ready(ready_input(&record)));
        apply_config_ack(
            &mut record,
            &ConfigAckPayload {
                lease_id: id("lease-1"),
                lease_revision: 2,
                configuration_revision: 3,
                key_purpose_revision: 5,
                acknowledged_at: "2026-09-23T08:00:00Z".into(),
                source_key: None,
            },
        )
        .unwrap();
        assert!(derive_ready(ready_input(&record)));
    }

    #[test]
    fn unblock_does_not_resurrect_a_blocked_relationship() {
        let mut record = record();
        record.acknowledged_configuration_revision = Some(3);
        record.acknowledged_key_purpose_revision = Some(5);
        assert!(derive_ready(ready_input(&record)));
        let blocked = apply_pair_block(None, PairBlockState::Blocked, 1).unwrap();
        block_relationship(&mut record);
        apply_revoke(&mut record, &revoke(2)).unwrap();
        let mut input = ready_input(&record);
        input.pair_block = blocked.state;
        assert!(!derive_ready(input));
        let open = apply_pair_block(Some(blocked), PairBlockState::Open, 2).unwrap();
        let mut input = ready_input(&record);
        input.pair_block = open.state;
        assert!(record.revoked && !record.grant_usable);
        assert!(!derive_ready(input));
    }

    #[test]
    fn pair_block_revisions_only_move_forward() {
        let blocked = apply_pair_block(None, PairBlockState::Blocked, 3).unwrap();
        assert_eq!(apply_pair_block(Some(blocked), PairBlockState::Blocked, 3), Ok(blocked));
        assert_eq!(
            apply_pair_block(Some(blocked), PairBlockState::Open, 3),
            Err(LifecycleError::StaleRevision)
        );
        assert_eq!(
            apply_pair_block(Some(blocked), PairBlockState::Open, 2),
            Err(LifecycleError::StaleRevision)
        );
        assert_eq!(apply_pair_block(None, PairBlockState::Blocked, 0), Err(LifecycleError::StaleRevision));
        let open = apply_pair_block(Some(blocked), PairBlockState::Open, 4).unwrap();
        assert_eq!(open.state, PairBlockState::Open);
    }

    #[test]
    fn suspended_peer_allows_cleanup_but_not_new_authority() {
        assert!(!peer_allows(
            PeerState::Suspended,
            AffirmativeTraffic::NewRelationship
        ));
        assert!(!peer_allows(PeerState::Suspended, AffirmativeTraffic::Admission));
        assert!(peer_allows(
            PeerState::Suspended,
            AffirmativeTraffic::CleanupOrRevoke
        ));
        assert!(!pending_renewal_extends_current_lease());
    }

    #[test]
    fn status_on_the_current_lease_does_not_change_authority() {
        let record = record();
        apply_status(
            &record,
            &StatusPayload {
                lease_id: id("lease-1"),
                lease_revision: 2,
                state: RelationshipState::Configuring,
                observed_at: "2026-09-23T08:00:00Z".into(),
            },
        )
        .unwrap();
        assert_eq!(record.lease_revision, 2);
        assert!(!derive_ready(ready_input(&record)));
    }

    #[test]
    fn finite_expiry_denies_without_an_expired_status_event() {
        let mut record = record();
        record.acknowledged_configuration_revision = Some(3);
        record.acknowledged_key_purpose_revision = Some(5);
        let mut current = ready_input(&record);
        current.lease_expires_at = Some(10);
        current.now = 9;
        assert!(derive_ready(current));
        current.now = 10;
        assert!(!derive_ready(current));
        apply_status(
            &record,
            &StatusPayload {
                lease_id: id("lease-1"),
                lease_revision: 2,
                state: RelationshipState::Expired,
                observed_at: "2026-09-23T08:00:00Z".into(),
            },
        )
        .unwrap();
        assert_eq!(record.lease_revision, 2);
        assert!(record.grant_usable);
    }

    #[test]
    fn renewal_archives_the_old_revision_and_does_not_stay_ready() {
        let mut record = record();
        record.acknowledged_configuration_revision = Some(3);
        record.acknowledged_key_purpose_revision = Some(5);
        record.bound_task_id = Some("task-1".into());
        assert!(derive_ready(ready_input(&record)));
        apply_renewal(&mut record, 3, [9; 32]).unwrap();
        assert_eq!(
            record.prior_revisions,
            vec![AuditedRevision {
                lease_revision: 2,
                terms_digest: [4; 32],
            }]
        );
        assert_eq!(record.lease_revision, 3);
        assert!(record.remote_terms_digest.is_none());
        assert!(!record.grant_usable);
        assert!(record.bound_task_id.is_none());
        assert!(!derive_ready(ready_input(&record)));
        assert_eq!(
            apply_renewal(&mut record, 2, [4; 32]),
            Err(LifecycleError::StaleRevision)
        );
        assert_eq!(record.lease_revision, 3);
    }

    #[test]
    fn single_task_binds_one_logical_id() {
        let mut bound = None;
        assert_eq!(
            bind_single_task(&mut bound, LeaseMode::Fixed, "task-1"),
            Err(TaskBindError::NotSingleTaskMode)
        );
        assert_eq!(
            bind_single_task(&mut bound, LeaseMode::SingleTask, ""),
            Err(TaskBindError::EmptyTaskId)
        );
        bind_single_task(&mut bound, LeaseMode::SingleTask, "task-1").unwrap();
        bind_single_task(&mut bound, LeaseMode::SingleTask, "task-1").unwrap();
        assert_eq!(
            bind_single_task(&mut bound, LeaseMode::SingleTask, "task-2"),
            Err(TaskBindError::DifferentTask)
        );
        assert_eq!(bound.as_deref(), Some("task-1"));
    }
}
