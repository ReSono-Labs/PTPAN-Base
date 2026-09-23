//! Restrictive relationship lifecycle. These rules decide local authority.
//! A provider adapter loads facts and stores the result. A status report,
//! a durable `AUTHORIZED` hint, or an unblock never creates consent.

use crate::control_event::{
    ActorSide, ConfigAckPayload, RelationshipState, RevokePayload, SourceAuthorization,
    SourceAuthorizationPayload, StatusPayload,
};
use crate::{LeaseMode, PeerState};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    StaleRevision,
    StaleAcknowledgment,
    RevokedIsTerminal,
    UnblockDoesNotRevive,
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

/// Local pair policy. A block is not a revoke, and clearing it does not
/// restore a relationship that was already revoked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairBlock {
    Open,
    Blocked,
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
    pub block: PairBlock,
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

pub fn apply_block(record: &mut LifecycleRecord) {
    record.block = PairBlock::Blocked;
    record.grant_usable = false;
}

pub fn apply_unblock(record: &mut LifecycleRecord) -> Result<(), LifecycleError> {
    if record.revoked {
        return Err(LifecycleError::UnblockDoesNotRevive);
    }
    record.block = PairBlock::Open;
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
        && record.block == PairBlock::Open
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
