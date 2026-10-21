//! `PlatformService` for the reference platform: the adapter's only way in.

use crate::store::Db;
use crate::{Platform, Relationship};
use federation_base::control_event::{
    ConfigAckPayload, DecisionPayload, DecisionResult, LeaseWire, PairBlockStatusPayload, RevokePayload,
    SourceAuthorization, SourceAuthorizationPayload,
};
use federation_base::encoding::{decode_hex, decode_hex32, hex_lower};
use federation_base::live_admission::{
    deny_reason, did_key_from_ed25519, evaluate_admission, AdmissionClaims, AdmissionDecision, AdmissionFacts,
};
use federation_base::relationship_lifecycle::{apply_pair_block, PairBlockRecord};
use federation_base::time::{format_utc, now_unix};
use federation_base::{parse_relationship_request_json, OpaqueId, PlatformId, RelationshipRequest};
use ptpan_platform_api::v1 as api;
use ptpan_platform_api::v1::platform_service_server::PlatformService;
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct Service(pub Arc<Platform>);

fn internal(e: impl std::fmt::Display) -> Status {
    Status::internal(e.to_string())
}

fn applied(ok: bool) -> Response<api::ApplyResponse> {
    let result = if ok { api::ApplyResult::Applied } else { api::ApplyResult::Rejected };
    Response::new(api::ApplyResponse { result: result as i32 })
}

/// Replay of an inbound event returns its first result (H8).
fn seen(c: &Connection, source: &str, event: &str) -> crate::Result<Option<i32>> {
    Ok(c.query_row(
        "SELECT result FROM inbound_events WHERE source_platform_id = ?1 AND event_id = ?2",
        params![source, event],
        |r| r.get(0),
    )
    .optional()?)
}

fn remember(c: &Connection, source: &str, event: &str, result: i32) -> crate::Result<()> {
    c.execute("INSERT INTO inbound_events VALUES (?1, ?2, ?3)", params![source, event, result])?;
    Ok(())
}

impl Platform {
    /// Source side: the destination accepted our configuration.
    fn source_config_ack(&self, c: &Connection, r: &Relationship, payload: &ConfigAckPayload) -> crate::Result<bool> {
        let lease: LeaseWire = serde_json::from_str(&r.lease_json)?;
        if payload.lease_id != lease.lease_id || payload.lease_revision != lease.lease_revision || payload.source_key.is_some() {
            return Ok(false);
        }
        c.execute("UPDATE relationships SET acknowledged_configuration = 1 WHERE relationship_id = ?1", [&r.relationship_id])?;
        Ok(true)
    }

    /// Destination side: bind the requesting agent's key to our grant and
    /// acknowledge our own configuration back (H9, H10).
    fn destination_config_ack(&self, c: &Connection, r: &Relationship, payload: &ConfigAckPayload) -> crate::Result<bool> {
        let request: RelationshipRequest = serde_json::from_str(&r.request_json)?;
        let lease: LeaseWire = serde_json::from_str(&r.lease_json)?;
        let Some(binding) = &payload.source_key else { return Ok(false) };
        let terms = decode_hex32(&binding.terms_digest).ok_or("digest")?;
        if payload.lease_id != lease.lease_id
            || payload.lease_revision != lease.lease_revision
            || binding.requester_reference != request.source.address
            || binding.destination_address != request.target_address
            || terms != r.local_terms_digest
        {
            return Ok(false);
        }
        let key: [u8; 32] = decode_hex(&binding.public_key).ok_or("key")?.try_into().map_err(|_| "key")?;
        c.execute(
            "UPDATE relationships SET foreign_key_did = ?2, foreign_key_revision = ?3, key_revision = ?3,
                 remote_terms_digest = ?4, acknowledged_configuration = 1, grant_usable = 1
             WHERE relationship_id = ?1 AND revoked = 0",
            params![r.relationship_id, did_key_from_ed25519(&key), payload.key_purpose_revision as i64, terms.as_slice()],
        )?;
        let now = now_unix();
        let ack = serde_json::json!({
            "lease_id": lease.lease_id, "lease_revision": lease.lease_revision, "configuration_revision": 1,
            "key_purpose_revision": payload.key_purpose_revision, "acknowledged_at": format_utc(now),
        });
        Db::handoff(c, &format!("ho-ack-{}", r.relationship_id), api::ControlKind::ConfigAck as i32, &r.peer_platform_id,
            &r.relationship_id, "", &ack, api::ActorSide::Destination as i32, &format_utc(now))?;
        Ok(true)
    }
}

#[tonic::async_trait]
impl PlatformService for Service {
    async fn get_platform_info(&self, _: Request<api::GetPlatformInfoRequest>) -> Result<Response<api::PlatformInfo>, Status> {
        Ok(Response::new(api::PlatformInfo {
            platform_id: self.0.config.platform_id.as_str().into(),
            provider_domain: self.0.config.provider_domain.clone(),
            api_majors: vec![ptpan_platform_api::API_MAJOR],
            features: vec![],
        }))
    }

    async fn read_handoff(&self, request: Request<api::ReadHandoffRequest>) -> Result<Response<api::ReadHandoffResponse>, Status> {
        let r = request.into_inner();
        let records = self
            .0
            .db
            .with(|c| {
                let mut stmt = c.prepare(
                    "SELECT handoff_id, cursor, kind, peer_platform_id, relationship_id, request_id, payload_json, committed_at, actor_side
                     FROM handoff WHERE acked = 0 AND cursor > ?1 ORDER BY cursor LIMIT ?2",
                )?;
                let rows = stmt.query_map(params![r.after_cursor as i64, r.limit.max(1) as i64], |row| {
                    Ok(api::HandoffRecord {
                        handoff_id: row.get(0)?,
                        cursor: row.get::<_, i64>(1)? as u64,
                        kind: row.get(2)?,
                        peer_platform_id: row.get(3)?,
                        relationship_id: row.get(4)?,
                        request_id: row.get(5)?,
                        payload_json: row.get::<_, String>(6)?.into_bytes(),
                        committed_at: row.get(7)?,
                        actor_side: row.get(8)?,
                    })
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .map_err(internal)?;
        Ok(Response::new(api::ReadHandoffResponse { records }))
    }

    async fn ack_handoff(&self, request: Request<api::AckHandoffRequest>) -> Result<Response<api::AckHandoffResponse>, Status> {
        self.0
            .db
            .with(|c| {
                c.execute("UPDATE handoff SET acked = 1 WHERE handoff_id = ?1", [&request.get_ref().handoff_id])?;
                Ok(())
            })
            .map_err(internal)?;
        Ok(Response::new(api::AckHandoffResponse {}))
    }

    async fn authorize_source(&self, request: Request<api::AuthorizeSourceRequest>) -> Result<Response<api::AuthorizeSourceResponse>, Status> {
        let (authorized, revision) = self
            .0
            .db
            .with(|c| {
                let row: Option<(String, String)> = c
                    .query_row("SELECT account_id, agent_id FROM sent WHERE request_id = ?1", [&request.get_ref().request_id], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                    .optional()?;
                Ok(match row {
                    Some((account, agent)) => match Db::current_owner(c, &agent)? {
                        Some((owner, revision)) if owner == account => (true, revision),
                        _ => (false, 0),
                    },
                    None => (false, 0),
                })
            })
            .map_err(internal)?;
        Ok(Response::new(api::AuthorizeSourceResponse { authorized, ownership_revision: revision }))
    }

    async fn deliver_inbound(&self, request: Request<api::DeliverInboundRequest>) -> Result<Response<api::DeliverInboundResponse>, Status> {
        let r = request.into_inner();
        let result = self
            .0
            .db
            .tx(|c| {
                if let Some(result) = seen(c, &r.source_platform_id, &r.event_id)? {
                    return Ok(result);
                }
                let request = parse_relationship_request_json(&r.request_json)?;
                let blocked: Option<String> = c
                    .query_row(
                        "SELECT state FROM pair_blocks WHERE source_platform_id = ?1 AND requester_reference = ?2 AND destination_address = ?3",
                        params![r.source_platform_id, request.source.address, request.target_address],
                        |row| row.get(0),
                    )
                    .optional()?;
                let target = Db::resolve(c, &request.target_address)?;
                let result = match (target, blocked.as_deref()) {
                    // Unknown, retired and blocked look the same (review 12.5).
                    (None, _) | (_, Some("BLOCKED")) => api::DeliveryResult::AddressNotRecognized,
                    (Some((agent, account, revision)), _) => {
                        c.execute(
                            "INSERT INTO inbox (source_platform_id, request_id, request_json, account_id, agent_id, ownership_revision, state)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending') ON CONFLICT DO NOTHING",
                            params![r.source_platform_id, request.request_id.as_str(), serde_json::to_string(&request)?, account, agent, revision as i64],
                        )?;
                        api::DeliveryResult::QueuedForLocalOwner
                    }
                } as i32;
                remember(c, &r.source_platform_id, &r.event_id, result)?;
                Ok(result)
            })
            .map_err(internal)?;
        Ok(Response::new(api::DeliverInboundResponse { result }))
    }

    async fn apply_decision(&self, request: Request<api::ApplyDecisionRequest>) -> Result<Response<api::ApplyResponse>, Status> {
        let r = request.into_inner();
        let platform = &self.0;
        let ok = platform
            .db
            .tx(|c| {
                if let Some(result) = seen(c, &r.source_platform_id, &r.event_id)? {
                    return Ok(result == 1);
                }
                let row: Option<(String, String, String, String)> = c
                    .query_row("SELECT account_id, agent_id, request_json, state FROM sent WHERE request_id = ?1", [&r.request_id], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                    })
                    .optional()?;
                let Some((account, agent, request_json, _state)) = row else {
                    remember(c, &r.source_platform_id, &r.event_id, 0)?;
                    return Ok(false);
                };
                let request: RelationshipRequest = serde_json::from_str(&request_json)?;
                let payload: DecisionPayload = serde_json::from_slice(&r.decision_json)?;
                let issuer = PlatformId::new(r.source_platform_id.clone())?;
                let ok = match payload.result {
                    DecisionResult::Approved => {
                        let lease = Platform::lease_of(&request, &payload, &issuer)?;
                        let owner = payload.destination_owner_name.clone().ok_or("owner name")?;
                        let (seed, key_revision): (Vec<u8>, i64) = c.query_row(
                            "SELECT key_seed, key_revision FROM agents WHERE agent_id = ?1",
                            [&agent],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )?;
                        c.execute(
                            "INSERT INTO relationships (relationship_id, side, peer_platform_id, account_id, agent_id, ownership_revision,
                                 request_json, lease_json, local_terms_digest, remote_terms_digest, owner_given_name, owner_family_name,
                                 peer_ca_root, peer_edge_service_id, grant_usable, key_revision)
                             VALUES (?1, 'source', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, ?11, ?12, 1, ?13)",
                            params![request.relationship_id.as_str(), r.source_platform_id, account, agent,
                                request.source_ownership_revision as i64, request_json,
                                serde_json::to_string(&LeaseWire::from_lease(&lease))?, lease.terms_digest.as_slice(),
                                owner.given_name, owner.family_name, r.peer_agent_ca_root, r.peer_edge_service_id, key_revision],
                        )?;
                        c.execute("UPDATE sent SET state = 'approved' WHERE request_id = ?1", [&r.request_id])?;
                        let key = ed25519_dalek::SigningKey::from_bytes(&seed.try_into().map_err(|_| "seed")?);
                        let (did, revision) = (hex_lower(key.verifying_key().as_bytes()), key_revision);
                        let now = now_unix();
                        let ack = serde_json::json!({
                            "lease_id": lease.lease_id, "lease_revision": lease.lease_revision, "configuration_revision": 1,
                            "key_purpose_revision": revision, "acknowledged_at": format_utc(now),
                            "source_key": {"requester_reference": request.source.address, "destination_address": request.target_address,
                                "terms_digest": hex_lower(&lease.terms_digest), "key_purpose": "ed25519_admission", "public_key": did},
                        });
                        Db::handoff(c, &format!("ho-ack-{}", request.relationship_id.as_str()), api::ControlKind::ConfigAck as i32,
                            &r.source_platform_id, request.relationship_id.as_str(), "", &ack, api::ActorSide::Source as i32, &format_utc(now))?;
                        true
                    }
                    DecisionResult::Denied | DecisionResult::Blocked => {
                        // A block is shown exactly like a denial (D7).
                        c.execute("UPDATE sent SET state = 'denied' WHERE request_id = ?1", [&r.request_id])?;
                        if payload.result == DecisionResult::Blocked {
                            c.execute(
                                "INSERT INTO block_enforcement VALUES (?1, ?2, 'BLOCKED', 0) ON CONFLICT DO NOTHING",
                                params![account, request.target_address],
                            )?;
                        }
                        true
                    }
                };
                remember(c, &r.source_platform_id, &r.event_id, i32::from(ok))?;
                Ok(ok)
            })
            .map_err(internal)?;
        Ok(applied(ok))
    }

    async fn apply_lifecycle(&self, request: Request<api::ApplyLifecycleRequest>) -> Result<Response<api::ApplyResponse>, Status> {
        let r = request.into_inner();
        let platform = &self.0;
        let kind = api::ControlKind::try_from(r.kind).map_err(|_| Status::invalid_argument("kind"))?;
        let ok = platform
            .db
            .tx(|c| {
                if let Some(result) = seen(c, &r.peer_platform_id, &r.event_id)? {
                    return Ok(result == 1);
                }
                let relationship = Db::relationship(c, &r.relationship_id)?
                    .filter(|rel| rel.peer_platform_id == r.peer_platform_id);
                let ok = match (kind, relationship) {
                    (api::ControlKind::RelationshipRevoke, Some(rel)) if rel.side == "source" => {
                        let payload: RevokePayload = serde_json::from_slice(&r.payload_json)?;
                        let lease: LeaseWire = serde_json::from_str(&rel.lease_json)?;
                        let matches = payload.lease_revision == lease.lease_revision;
                        if matches {
                            c.execute("UPDATE relationships SET revoked = 1, grant_usable = 0 WHERE relationship_id = ?1", [&rel.relationship_id])?;
                        }
                        matches
                    }
                    (api::ControlKind::SourceAuthorizationStatus, Some(rel)) if rel.side == "destination" => {
                        let payload: SourceAuthorizationPayload = serde_json::from_slice(&r.payload_json)?;
                        if payload.status == SourceAuthorization::Withdrawn {
                            c.execute("UPDATE relationships SET source_withdrawn = 1, grant_usable = 0 WHERE relationship_id = ?1", [&rel.relationship_id])?;
                        }
                        true
                    }
                    (api::ControlKind::ConfigAck, Some(rel)) => {
                        let payload: ConfigAckPayload = serde_json::from_slice(&r.payload_json)?;
                        if rel.side == "destination" {
                            platform.destination_config_ack(c, &rel, &payload)?
                        } else {
                            platform.source_config_ack(c, &rel, &payload)?
                        }
                    }
                    (api::ControlKind::RelationshipStatus, Some(_)) => true,
                    (api::ControlKind::PairBlockStatus, _) => {
                        // We are the requester's platform: enforce for the
                        // whole account that owns the requester reference.
                        let payload: PairBlockStatusPayload = serde_json::from_slice(&r.payload_json)?;
                        match Db::resolve(c, &payload.requester_reference)? {
                            Some((_, account, _)) => {
                                let current: Option<(String, i64)> = c
                                    .query_row(
                                        "SELECT state, block_revision FROM block_enforcement WHERE account_id = ?1 AND destination_address = ?2",
                                        params![account, payload.destination_address],
                                        |row| Ok((row.get(0)?, row.get(1)?)),
                                    )
                                    .optional()?;
                                let current = current.map(|(s, rev)| PairBlockRecord {
                                    state: if s == "BLOCKED" { federation_base::control_event::PairBlockState::Blocked } else { federation_base::control_event::PairBlockState::Open },
                                    block_revision: rev as u64,
                                });
                                match apply_pair_block(current, payload.state, payload.block_revision) {
                                    Ok(next) => {
                                        let text = if next.state == federation_base::control_event::PairBlockState::Blocked { "BLOCKED" } else { "OPEN" };
                                        c.execute(
                                            "INSERT INTO block_enforcement VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO UPDATE SET state = ?3, block_revision = ?4",
                                            params![account, payload.destination_address, text, next.block_revision as i64],
                                        )?;
                                        true
                                    }
                                    Err(_) => false,
                                }
                            }
                            None => false,
                        }
                    }
                    _ => false,
                };
                remember(c, &r.peer_platform_id, &r.event_id, i32::from(ok))?;
                Ok(ok)
            })
            .map_err(internal)?;
        Ok(applied(ok))
    }

    async fn confirm_receipt(&self, request: Request<api::ConfirmReceiptRequest>) -> Result<Response<api::ConfirmReceiptResponse>, Status> {
        let r = request.into_inner();
        self.0
            .db
            .with(|c| {
                let row: Option<(i32, String)> = c
                    .query_row("SELECT kind, request_id FROM handoff WHERE handoff_id = ?1", [&r.handoff_id], |row| Ok((row.get(0)?, row.get(1)?)))
                    .optional()?;
                if let Some((kind, request_id)) = row {
                    if kind == api::ControlKind::RelationshipRequest as i32 {
                        let state = if r.result == api::ReceiptResult::QueuedForLocalOwner as i32 { "delivered" } else { "not_recognized" };
                        c.execute("UPDATE sent SET state = ?2 WHERE request_id = ?1 AND state = 'waiting_for_delivery'", params![request_id, state])?;
                    }
                }
                Ok(())
            })
            .map_err(internal)?;
        Ok(Response::new(api::ConfirmReceiptResponse {}))
    }

    async fn record_notice(&self, request: Request<api::RecordNoticeRequest>) -> Result<Response<api::RecordNoticeResponse>, Status> {
        let r = request.into_inner();
        let state = match api::NoticeKind::try_from(r.kind) {
            Ok(api::NoticeKind::WaitingForDelivery) => "waiting_for_delivery",
            Ok(api::NoticeKind::Delivered) => "delivered",
            Ok(api::NoticeKind::NotRecognized) => "not_recognized",
            Ok(api::NoticeKind::UnknownProvider) => "unknown_provider",
            Ok(api::NoticeKind::PeerNotActive) => "peer_not_active",
            Ok(api::NoticeKind::ExpiredUndelivered) => "expired_undelivered",
            Ok(api::NoticeKind::SourceNotAuthorized) => "source_not_authorized",
            _ => return Err(Status::invalid_argument("notice kind")),
        };
        self.0
            .db
            .with(|c| {
                // A later state never goes back to "waiting".
                c.execute(
                    "UPDATE sent SET state = ?2 WHERE request_id = ?1 AND (state = 'waiting_for_delivery' OR ?2 != 'waiting_for_delivery')",
                    params![r.request_id, state],
                )?;
                Ok(())
            })
            .map_err(internal)?;
        Ok(Response::new(api::RecordNoticeResponse {}))
    }

    async fn get_bound_key(&self, request: Request<api::GetBoundKeyRequest>) -> Result<Response<api::GetBoundKeyResponse>, Status> {
        let found = self
            .0
            .db
            .with(|c| Db::relationship(c, &request.get_ref().relationship_id))
            .map_err(internal)?
            .filter(|r| r.side == "destination")
            .and_then(|r| Some((r.foreign_key_did?, r.foreign_key_revision?)));
        Ok(Response::new(match found {
            Some((did, revision)) => api::GetBoundKeyResponse { found: true, did_key: did, key_revision: revision },
            None => api::GetBoundKeyResponse { found: false, did_key: String::new(), key_revision: 0 },
        }))
    }

    async fn admit_call(&self, request: Request<api::AdmitCallRequest>) -> Result<Response<api::AdmitCallResponse>, Status> {
        let r = request.into_inner();
        let claims: AdmissionClaims = serde_json::from_slice(&r.claims_json).map_err(|_| Status::invalid_argument("claims"))?;
        let platform = &self.0;
        let decision = platform
            .db
            .tx(|c| {
                let Some(rel) = Db::relationship(c, &r.relationship_id)?.filter(|rel| rel.side == "destination") else {
                    return Ok(AdmissionDecision::Deny(federation_base::live_admission::AdmissionDeny::GrantDenied));
                };
                let now = now_unix();
                let fresh = c.execute(
                    "INSERT INTO nonces VALUES (?1, ?2) ON CONFLICT DO NOTHING",
                    params![claims.jti, r.relationship_id],
                )? == 1;
                let lease: LeaseWire = serde_json::from_str(&rel.lease_json)?;
                let lease_id = OpaqueId::new(lease.lease_id.as_str())?;
                let ready = platform.ready(c, &rel, now)?;
                let facts = AdmissionFacts {
                    now,
                    verified_key_revision: r.verified_key_revision,
                    bound_key_revision: rel.foreign_key_revision.unwrap_or(0),
                    nonce_already_used: !fresh,
                    source_withdrawn: rel.source_withdrawn,
                    relationship_ready: ready,
                    grant_allows_operation: rel.grant_usable && lease.effective_permissions.contains(&claims.operation),
                    current_lease_id: &lease_id,
                    current_lease_revision: lease.lease_revision,
                    lease_expires_at: lease.expires_at,
                    other_deadlines: &[],
                };
                Ok(evaluate_admission(&claims, &facts))
            })
            .map_err(internal)?;
        Ok(Response::new(match decision {
            AdmissionDecision::Allow { deadline } => api::AdmitCallResponse { allowed: true, deadline, reason: String::new() },
            AdmissionDecision::Deny(reason) => api::AdmitCallResponse { allowed: false, deadline: 0, reason: deny_reason(reason).into() },
        }))
    }
}
