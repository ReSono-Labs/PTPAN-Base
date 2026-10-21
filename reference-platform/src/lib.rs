//! PTPAN reference platform. A fixture and conformance target: it shows one
//! way a platform meets review section 14 behind `PlatformService`, on its
//! own SQLite record, calling Base for every PTPAN rule. It is not a
//! production platform and is not shipped in the public package.

pub mod service;
pub mod store;
pub mod streams;

use crate::store::{Db, Relationship};
use federation_base::control_event::{
    ActorSide, DecisionPayload, DecisionResult, LeaseWire, PairBlockState, RequestPayload,
};
use federation_base::encoding::{decode_hex32, hex_lower};
use federation_base::live_admission::did_key_from_ed25519;
use federation_base::relationship_lifecycle::{
    derive_ready, DurableSourceAuthorization, LifecycleRecord, ReadinessInput,
};
use federation_base::time::{format_utc, now_unix};
use federation_base::{
    LifetimeRequest, OpaqueId, Participant, PeerState, PersonName, PlatformId, RelationshipLease, RelationshipRequest,
    RequestKind,
};
use ptpan_platform_api::v1 as api;
use rusqlite::{params, OptionalExtension};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::PathBuf;

pub use store::{Error, Result};

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub platform_id: PlatformId,
    pub provider_domain: String,
    pub database_path: PathBuf,
    /// `PlatformService`, served here for the adapter.
    pub platform_socket: PathBuf,
    /// `AdapterService`, served by the adapter.
    pub adapter_socket: PathBuf,
    pub adapter_uid: u32,
    /// Agent stream sockets: egress is the bridge's, ingress is served here.
    pub egress_socket: PathBuf,
    pub ingress_socket: PathBuf,
    pub bridge_uid: u32,
}

pub struct Platform {
    pub config: Config,
    pub db: Db,
}

/// Random lowercase Crockford base32 of `bytes` random bytes. This fixture's
/// address labels use 10 bytes (16 characters); D10 leaves the format to the
/// platform.
pub fn random_label(bytes: usize) -> Result<String> {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut raw = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut raw)?;
    let (mut out, mut bits, mut available) = (String::new(), 0u32, 0u32);
    for byte in raw {
        bits = (bits << 8) | u32::from(byte);
        available += 8;
        while available >= 5 {
            available -= 5;
            out.push(ALPHABET[((bits >> available) & 31) as usize] as char);
        }
    }
    Ok(out)
}

fn kind(k: api::ControlKind) -> i32 {
    k as i32
}

fn side(s: ActorSide) -> i32 {
    match s {
        ActorSide::Source => api::ActorSide::Source as i32,
        ActorSide::Destination => api::ActorSide::Destination as i32,
    }
}

/// Owner's chosen terms for an approval (stored as the durable intent).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ApprovalTerms {
    pub permissions: Vec<String>,
    /// `FIXED`, `SINGLE_TASK` or `UNTIL_REVOKED`.
    pub mode: String,
    /// Seconds from approval; ignored for `UNTIL_REVOKED`.
    pub lifetime_seconds: u64,
}

impl Platform {
    pub fn open(config: Config) -> Result<Self> {
        Ok(Self { db: Db::open(&config.database_path)?, config })
    }

    /// Serve `PlatformService` (adapter only), the ingress socket (bridge
    /// only) and the intent-completion loop until one of them fails.
    pub async fn serve(self: std::sync::Arc<Self>) -> Result<()> {
        use ptpan_platform_api::v1::platform_service_server::PlatformServiceServer;
        let listener = ptpan_platform_api::transport::bind(&self.config.platform_socket)?;
        let uid = self.config.adapter_uid;
        let ingress = tokio::spawn(self.clone().serve_ingress());
        let intents = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = intents.complete_intents().await {
                    eprintln!("approval intents: {e}");
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        });
        eprintln!("PLATFORM_READY {}", self.config.platform_id.as_str());
        let server = tonic::transport::Server::builder()
            .add_service(PlatformServiceServer::new(service::Service(self)))
            .serve_with_incoming(ptpan_platform_api::transport::incoming(listener, uid));
        tokio::select! {
            r = server => r?,
            r = ingress => r??,
        }
        Ok(())
    }

    fn platform_id(&self) -> &PlatformId {
        &self.config.platform_id
    }

    // --- Accounts, agents, addresses (H2, H3) ---------------------------------

    pub fn add_account(&self, account_id: &str, given_name: &str, family_name: &str) -> Result<()> {
        PersonName { given_name: given_name.into(), family_name: family_name.into() }.validate()?;
        self.db.with(|c| {
            c.execute("INSERT INTO accounts VALUES (?1, ?2, ?3)", params![account_id, given_name, family_name])?;
            Ok(())
        })
    }

    /// A new agent with its own Ed25519 admission key and one address.
    pub fn add_agent(&self, agent_id: &str, account_id: &str) -> Result<String> {
        let mut seed = [0u8; 32];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
        let address = format!("{}.{}", random_label(10)?, self.config.provider_domain);
        self.db.tx(|c| {
            c.execute(
                "INSERT INTO agents VALUES (?1, ?2, 1, ?3, 1)",
                params![agent_id, account_id, seed.as_slice()],
            )?;
            c.execute("INSERT INTO addresses (address, agent_id) VALUES (?1, ?2)", params![address, agent_id])?;
            Ok(())
        })?;
        Ok(address)
    }

    /// Retire an address: it stops new requests only; existing relationships
    /// keep working; it is never reassigned (H2).
    pub fn retire_address(&self, address: &str) -> Result<()> {
        self.db.with(|c| {
            c.execute("UPDATE addresses SET retired = 1 WHERE address = ?1", [address])?;
            Ok(())
        })
    }

    fn agent_address(c: &rusqlite::Connection, agent_id: &str) -> Result<String> {
        Ok(c.query_row(
            "SELECT address FROM addresses WHERE agent_id = ?1 AND retired = 0 ORDER BY rowid LIMIT 1",
            [agent_id],
            |r| r.get(0),
        )?)
    }

    // --- Source: a user asks to connect one of its agents (H4, H5) ----------

    /// Commit the Sent row and the hand-off record together. Works while the
    /// adapter is down; the request is shown as waiting (principle 11).
    pub fn create_request(&self, account_id: &str, agent_id: &str, target_address: &str, terms: &ApprovalTerms) -> Result<String> {
        let now = now_unix();
        let request_id = format!("req-{}", random_label(10)?);
        let relationship_id = format!("rel-{}", random_label(10)?);
        self.db.tx(|c| {
            let (owner, revision) = Db::current_owner(c, agent_id)?.ok_or("unknown agent")?;
            if owner != account_id {
                return Err("the account does not own this agent".into());
            }
            let (given, family) = Db::name(c, account_id)?;
            let requested_lifetime = match terms.mode.as_str() {
                "UNTIL_REVOKED" => LifetimeRequest::UntilRevoked,
                "SINGLE_TASK" => LifetimeRequest::SingleTask { expires_at: now + terms.lifetime_seconds },
                _ => LifetimeRequest::Fixed { expires_at: now + terms.lifetime_seconds },
            };
            let request = RelationshipRequest {
                relationship_id: OpaqueId::new(relationship_id.clone())?,
                request_id: OpaqueId::new(request_id.clone())?,
                source: Participant { platform_id: self.platform_id().clone(), address: Self::agent_address(c, agent_id)? },
                source_ownership_revision: revision,
                requester_name: PersonName { given_name: given, family_name: family },
                request_kind: RequestKind::Establish,
                request_revision: 1,
                base_lease_revision: None,
                application_protocol: "a2a".into(),
                transport: "tls13".into(),
                target_address: target_address.into(),
                requested_permissions: terms.permissions.iter().cloned().collect(),
                requested_lifetime,
                created_at: now,
                request_expires_at: now + 7 * 86_400,
            };
            let digest = hex_lower(&request.request_terms_digest()?);
            let blocked: Option<String> = c
                .query_row(
                    "SELECT state FROM block_enforcement WHERE account_id = ?1 AND destination_address = ?2",
                    params![account_id, target_address],
                    |r| r.get(0),
                )
                .optional()?;
            let request_json = serde_json::to_string(&request)?;
            if blocked.as_deref() == Some("BLOCKED") {
                // Enforced here for the whole account (D7); the user sees the
                // same "not recognized" notice as for any unknown address.
                c.execute(
                    "INSERT INTO sent VALUES (?1, ?2, ?3, ?4, 'not_recognized')",
                    params![request_id, account_id, agent_id, request_json],
                )?;
                return Ok(());
            }
            c.execute(
                "INSERT INTO sent VALUES (?1, ?2, ?3, ?4, 'waiting_for_delivery')",
                params![request_id, account_id, agent_id, request_json],
            )?;
            let payload = serde_json::to_value(RequestPayload { request, request_terms_digest: digest })?;
            Db::handoff(c, &format!("ho-{request_id}"), kind(api::ControlKind::RelationshipRequest), "",
                &relationship_id, &request_id, &payload, side(ActorSide::Source), &format_utc(now))
        })?;
        Ok(request_id)
    }

    // --- Destination: the owner decides (H6, H7) ------------------------------

    /// Record the owner's approval as a durable intent. `complete_intents`
    /// turns it into lease, grant and decision in one transaction when the
    /// adapter's `ComputeLease` is reachable (D1, WB-03.2).
    pub fn approve(&self, actor_account: &str, source_platform: &str, request_id: &str, terms: &ApprovalTerms) -> Result<()> {
        self.db.tx(|c| {
            let owner: String = c.query_row(
                "SELECT account_id FROM inbox WHERE source_platform_id = ?1 AND request_id = ?2 AND state = 'pending'",
                params![source_platform, request_id],
                |r| r.get(0),
            )?;
            if owner != actor_account {
                return Err("only the owning account decides".into());
            }
            c.execute(
                "UPDATE inbox SET state = 'approved', intent_json = ?3 WHERE source_platform_id = ?1 AND request_id = ?2",
                params![source_platform, request_id, serde_json::to_string(terms)?],
            )?;
            Ok(())
        })
    }

    /// Deny or block: committed locally at once with the decision hand-off.
    pub fn deny(&self, actor_account: &str, source_platform: &str, request_id: &str, block: bool) -> Result<()> {
        let now = now_unix();
        self.db.tx(|c| {
            let (owner, request_json): (String, String) = c.query_row(
                "SELECT account_id, request_json FROM inbox WHERE source_platform_id = ?1 AND request_id = ?2 AND state = 'pending'",
                params![source_platform, request_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if owner != actor_account {
                return Err("only the owning account decides".into());
            }
            let request: RelationshipRequest = serde_json::from_str(&request_json)?;
            let state = if block { "blocked" } else { "denied" };
            c.execute(
                "UPDATE inbox SET state = ?3 WHERE source_platform_id = ?1 AND request_id = ?2",
                params![source_platform, request_id, state],
            )?;
            if block {
                Self::set_pair_block(c, source_platform, &request.source.address, &request.target_address, PairBlockState::Blocked)?;
            }
            let payload = DecisionPayload {
                decision_id: OpaqueId::new(format!("dec-{request_id}"))?,
                result: if block { DecisionResult::Blocked } else { DecisionResult::Denied },
                bound_request_revision: request.request_revision,
                request_terms_digest: hex_lower(&request.request_terms_digest()?),
                destination_ownership_revision: None,
                destination_owner_name: None,
                lease: None,
            };
            Db::handoff(c, &format!("ho-dec-{request_id}"), kind(api::ControlKind::RelationshipDecision), source_platform,
                request.relationship_id.as_str(), request_id, &serde_json::to_value(payload)?, side(ActorSide::Destination), &format_utc(now))
        })
    }

    /// Next pair-block revision; returns it.
    fn set_pair_block(c: &rusqlite::Connection, source: &str, reference: &str, address: &str, state: PairBlockState) -> Result<u64> {
        let current: Option<(String, i64)> = c
            .query_row(
                "SELECT state, block_revision FROM pair_blocks WHERE source_platform_id = ?1 AND requester_reference = ?2 AND destination_address = ?3",
                params![source, reference, address],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let current = current.map(|(s, rev)| federation_base::relationship_lifecycle::PairBlockRecord {
            state: if s == "BLOCKED" { PairBlockState::Blocked } else { PairBlockState::Open },
            block_revision: rev as u64,
        });
        let revision = current.map_or(1, |r| r.block_revision + 1);
        let next = federation_base::relationship_lifecycle::apply_pair_block(current, state, revision).map_err(|e| format!("{e:?}"))?;
        let text = if next.state == PairBlockState::Blocked { "BLOCKED" } else { "OPEN" };
        c.execute(
            "INSERT INTO pair_blocks VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT DO UPDATE SET state = ?4, block_revision = ?5",
            params![source, reference, address, text, next.block_revision as i64],
        )?;
        Ok(next.block_revision)
    }

    /// Block (or unblock) a requester reference against one of our addresses
    /// after the fact (D7). A block also revokes every relationship of the pair.
    pub fn set_block(&self, source_platform: &str, requester_reference: &str, destination_address: &str, blocked: bool) -> Result<()> {
        let now = now_unix();
        let state = if blocked { PairBlockState::Blocked } else { PairBlockState::Open };
        let affected = self.db.with(|c| {
            let mut stmt = c.prepare("SELECT relationship_id, request_json FROM relationships WHERE side = 'destination' AND peer_platform_id = ?1 AND revoked = 0")?;
            let rows = stmt.query_map([source_platform], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
            let mut out = Vec::new();
            for row in rows {
                let (id, json) = row?;
                let request: RelationshipRequest = serde_json::from_str(&json)?;
                if request.source.address == requester_reference && request.target_address == destination_address {
                    out.push(id);
                }
            }
            Ok(out)
        })?;
        if blocked {
            for id in &affected {
                self.revoke(id, "PAIR_BLOCKED")?;
            }
        }
        self.db.tx(|c| {
            let revision = Self::set_pair_block(c, source_platform, requester_reference, destination_address, state)?;
            let payload = serde_json::json!({
                "requester_reference": requester_reference, "destination_address": destination_address,
                "state": state, "block_revision": revision, "effective_at": format_utc(now),
            });
            Db::handoff(c, &format!("ho-block-{}", random_label(8)?), kind(api::ControlKind::PairBlockStatus), source_platform,
                "", "", &payload, side(ActorSide::Destination), &format_utc(now))
        })
    }

    /// Local cutoff first, then the revoke goes out (H13).
    pub fn revoke(&self, relationship_id: &str, reason: &str) -> Result<()> {
        let now = now_unix();
        self.db.tx(|c| {
            let r = Db::relationship(c, relationship_id)?.ok_or("unknown relationship")?;
            let lease: LeaseWire = serde_json::from_str(&r.lease_json)?;
            c.execute("UPDATE relationships SET revoked = 1, grant_usable = 0 WHERE relationship_id = ?1", [relationship_id])?;
            let (kind_value, payload, actor) = if r.side == "destination" {
                (api::ControlKind::RelationshipRevoke, serde_json::json!({
                    "revocation_id": format!("rev-{relationship_id}"), "lease_id": lease.lease_id,
                    "lease_revision": lease.lease_revision, "reason_code": reason, "effective_at": format_utc(now)}), ActorSide::Destination)
            } else {
                (api::ControlKind::SourceAuthorizationStatus, serde_json::json!({
                    "lease_id": lease.lease_id, "lease_revision": lease.lease_revision, "authorization_revision": 1,
                    "status": "WITHDRAWN", "effective_at": format_utc(now)}), ActorSide::Source)
            };
            Db::handoff(c, &format!("ho-revoke-{relationship_id}"), kind(kind_value), &r.peer_platform_id, relationship_id, "",
                &payload, side(actor), &format_utc(now))
        })
    }

    /// Turn approved intents into lease, grant and decision (H7). Needs the
    /// adapter's `ComputeLease`; while it is down, intents wait.
    pub async fn complete_intents(&self) -> Result<usize> {
        let pending: Vec<(String, String, String, String, String, u64, String)> = self.db.with(|c| {
            let mut stmt = c.prepare(
                "SELECT source_platform_id, request_id, request_json, account_id, agent_id, ownership_revision, intent_json
                 FROM inbox WHERE state = 'approved'",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get::<_, i64>(5)? as u64, r.get(6)?))
            })?;
            Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
        })?;
        let mut done = 0;
        for (source, request_id, request_json, account, agent, revision, intent) in pending {
            let terms: ApprovalTerms = serde_json::from_str(&intent)?;
            let (given, family) = self.db.with(|c| Db::name(c, &account))?;
            let now = now_unix();
            let parsed: RelationshipRequest = serde_json::from_str(&request_json)?;
            // The owner may only narrow: a finite approval never outlasts
            // the expiry the requester asked for.
            let expires_at = match (terms.mode.as_str(), &parsed.requested_lifetime) {
                ("UNTIL_REVOKED", _) => 0,
                (_, federation_base::LifetimeRequest::Fixed { expires_at } | federation_base::LifetimeRequest::SingleTask { expires_at }) => {
                    (now + terms.lifetime_seconds).min(*expires_at)
                }
                (_, federation_base::LifetimeRequest::UntilRevoked) => now + terms.lifetime_seconds,
            };
            let mut client = self.adapter_client().await?;
            let response = client
                .compute_lease(api::ComputeLeaseRequest {
                    request_json: request_json.clone().into_bytes(),
                    lease_id: format!("lease-{request_id}"),
                    lease_revision: 1,
                    decision_id: format!("dec-{request_id}"),
                    mode: terms.mode.clone(),
                    effective_from: now,
                    expires_at,
                    effective_permissions: terms.permissions.clone(),
                    destination_ownership_revision: revision,
                    destination_owner_name: Some(api::PersonName { given_name: given.clone(), family_name: family.clone() }),
                })
                .await?
                .into_inner();
            if !response.error.is_empty() {
                return Err(format!("ComputeLease: {}", response.error).into());
            }
            let lease: LeaseWire = serde_json::from_slice(&response.lease_json)?;
            let request: RelationshipRequest = serde_json::from_str(&request_json)?;
            let terms_digest = decode_hex32(&lease.terms_digest).ok_or("terms digest")?;
            let key_revision: i64 = 1;
            self.db.tx(|c| {
                c.execute(
                    "UPDATE inbox SET state = 'configuring' WHERE source_platform_id = ?1 AND request_id = ?2 AND state = 'approved'",
                    params![source, request_id],
                )?;
                c.execute(
                    "INSERT INTO relationships (relationship_id, side, peer_platform_id, account_id, agent_id, ownership_revision,
                         request_json, lease_json, local_terms_digest, owner_given_name, owner_family_name, key_revision)
                     VALUES (?1, 'destination', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    params![request.relationship_id.as_str(), source, account, agent, revision as i64, request_json,
                        serde_json::to_string(&lease)?, terms_digest.as_slice(), given, family, key_revision],
                )?;
                let payload = DecisionPayload {
                    decision_id: OpaqueId::new(format!("dec-{request_id}"))?,
                    result: DecisionResult::Approved,
                    bound_request_revision: request.request_revision,
                    request_terms_digest: hex_lower(&request.request_terms_digest()?),
                    destination_ownership_revision: Some(revision),
                    destination_owner_name: Some(PersonName { given_name: given.clone(), family_name: family.clone() }),
                    lease: Some(lease.clone()),
                };
                Db::handoff(c, &format!("ho-dec-{request_id}"), kind(api::ControlKind::RelationshipDecision), &source,
                    request.relationship_id.as_str(), &request_id, &serde_json::to_value(payload)?, side(ActorSide::Destination),
                    &format_utc(now))
            })?;
            done += 1;
        }
        Ok(done)
    }

    pub async fn adapter_client(
        &self,
    ) -> Result<ptpan_platform_api::v1::adapter_service_client::AdapterServiceClient<tonic::transport::Channel>> {
        let channel = ptpan_platform_api::transport::connect(&self.config.adapter_socket, self.config.adapter_uid).await?;
        Ok(ptpan_platform_api::v1::adapter_service_client::AdapterServiceClient::new(channel))
    }

    // --- Readiness (H10, H11) -------------------------------------------------

    /// Base's readiness rule over this platform's record.
    pub fn ready(&self, c: &rusqlite::Connection, r: &Relationship, now: u64) -> Result<bool> {
        let lease: LeaseWire = serde_json::from_str(&r.lease_json)?;
        let owner_current = Db::current_owner(c, &r.agent_id)?
            .is_some_and(|(account, revision)| account == r.account_id && revision == r.ownership_revision);
        let request: RelationshipRequest = serde_json::from_str(&r.request_json)?;
        let pair_block = if r.side == "destination" {
            let state: Option<String> = c
                .query_row(
                    "SELECT state FROM pair_blocks WHERE source_platform_id = ?1 AND requester_reference = ?2 AND destination_address = ?3",
                    params![r.peer_platform_id, request.source.address, request.target_address],
                    |row| row.get(0),
                )
                .optional()?;
            if state.as_deref() == Some("BLOCKED") { PairBlockState::Blocked } else { PairBlockState::Open }
        } else {
            PairBlockState::Open
        };
        let key_ack = if r.side == "destination" { r.foreign_key_revision } else { Some(r.key_revision) };
        let record = LifecycleRecord {
            lease_revision: lease.lease_revision,
            local_terms_digest: r.local_terms_digest,
            remote_terms_digest: r.remote_terms_digest,
            source_authorization: if r.source_withdrawn {
                DurableSourceAuthorization::Withdrawn { revision: 1 }
            } else {
                DurableSourceAuthorization::None
            },
            destination_owner_current: owner_current,
            grant_usable: r.grant_usable,
            provenance_current: true,
            configuration_revision: 1,
            acknowledged_configuration_revision: r.acknowledged_configuration.then_some(1),
            key_purpose_revision: r.key_revision,
            acknowledged_key_purpose_revision: key_ack,
            revoked: r.revoked,
            prior_revisions: Vec::new(),
            bound_task_id: None,
        };
        Ok(derive_ready(ReadinessInput {
            peer: PeerState::Active,
            record: &record,
            pair_block,
            host_source_authorization_current: true,
            now,
            lease_expires_at: lease.expires_at,
        }))
    }

    /// The source agent's public admission key as a `did:key`.
    pub fn agent_did(&self, agent_id: &str) -> Result<(String, u64)> {
        self.db.with(|c| {
            let (seed, revision): (Vec<u8>, i64) =
                c.query_row("SELECT key_seed, key_revision FROM agents WHERE agent_id = ?1", [agent_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
            let key = ed25519_dalek::SigningKey::from_bytes(&seed.try_into().map_err(|_| "seed")?);
            Ok((did_key_from_ed25519(key.verifying_key().as_bytes()), revision as u64))
        })
    }

    pub fn agent_key(&self, agent_id: &str) -> Result<ed25519_dalek::SigningKey> {
        self.db.with(|c| {
            let seed: Vec<u8> = c.query_row("SELECT key_seed FROM agents WHERE agent_id = ?1", [agent_id], |r| r.get(0))?;
            Ok(ed25519_dalek::SigningKey::from_bytes(&seed.try_into().map_err(|_| "seed")?))
        })
    }

    pub fn sent_state(&self, request_id: &str) -> Result<Option<String>> {
        self.db.with(|c| Ok(c.query_row("SELECT state FROM sent WHERE request_id = ?1", [request_id], |r| r.get(0)).optional()?))
    }

    pub fn relationship_of(&self, request_id: &str) -> Result<Option<String>> {
        self.db.with(|c| {
            let json: Option<String> = c.query_row("SELECT request_json FROM sent WHERE request_id = ?1", [request_id], |r| r.get(0)).optional()?;
            Ok(json
                .map(|j| serde_json::from_str::<RelationshipRequest>(&j).map(|r| r.relationship_id.as_str().to_owned()))
                .transpose()?)
        })
    }

    pub fn inbox(&self) -> Result<Vec<serde_json::Value>> {
        self.db.with(|c| {
            let mut stmt = c.prepare("SELECT source_platform_id, request_id, request_json, account_id, state FROM inbox")?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (source, id, json, account, state) = row?;
                let request: RelationshipRequest = serde_json::from_str(&json)?;
                out.push(serde_json::json!({
                    "source_platform_id": source, "request_id": id, "account_id": account, "state": state,
                    "requester_name": request.requester_name, "requester_reference": request.source.address,
                    "target_address": request.target_address, "requested_permissions": request.requested_permissions,
                }));
            }
            Ok(out)
        })
    }

    pub fn is_ready(&self, relationship_id: &str) -> Result<bool> {
        self.db.with(|c| match Db::relationship(c, relationship_id)? {
            Some(r) => self.ready(c, &r, now_unix()),
            None => Ok(false),
        })
    }

    /// Permissions granted by a relationship's lease.
    pub fn lease_permissions(r: &Relationship) -> Result<BTreeSet<String>> {
        Ok(serde_json::from_str::<LeaseWire>(&r.lease_json)?.effective_permissions)
    }

    /// The validated lease of a relationship (source side, from the decision).
    pub fn lease_of(request: &RelationshipRequest, payload: &DecisionPayload, issuer: &PlatformId) -> Result<RelationshipLease> {
        Ok(payload.lease_against(request, issuer).map_err(|e| format!("{e:?}"))?)
    }
}
