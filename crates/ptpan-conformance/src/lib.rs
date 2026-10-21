//! Black-box conformance checks for a platform's `PlatformService`
//! (review 11.8). The suite stands in for the platform's adapter: it serves
//! `AdapterService` (policy calls from Base) and calls `PlatformService` as a
//! peer's events would arrive. A platform supplies a `Driver` for the user and
//! owner actions the API does not carry (accounts, requests, decisions).
//!
//! Each check names the requirement it covers (review section 14, section 12,
//! decisions D1–D14).

use ed25519_dalek::SigningKey;
use federation_base::address::{address_in_domain, valid_provider_domain};
use federation_base::control_event::{
    ConfigAckPayload, DecisionPayload, DecisionResult, LeaseWire, RequestPayload,
};
use federation_base::encoding::{decode_hex32, hex_lower};
use federation_base::live_admission::{did_key_from_ed25519, AdmissionClaims};
use federation_base::time::{format_utc, now_unix};
use federation_base::{
    LifetimeRequest, OpaqueId, OwnerTerms, Participant, PersonName, PlatformId, RelationshipLease, RelationshipRequest,
    RequestKind,
};
use ptpan_platform_api::v1 as api;
use ptpan_platform_api::v1::adapter_service_server::{AdapterService, AdapterServiceServer};
use ptpan_platform_api::v1::platform_service_client::PlatformServiceClient;
use std::collections::BTreeSet;
use std::path::PathBuf;
use tonic::transport::Channel;
use tonic::{Request, Response, Status};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// The user and owner actions a platform performs through its own product.
#[tonic::async_trait]
pub trait Driver: Send + Sync {
    async fn add_account(&self, account: &str, given_name: &str, family_name: &str) -> Result<(), Error>;
    /// Create an agent owned by `account`; return an address it can be
    /// reached at and use as its requester reference.
    async fn add_agent(&self, agent: &str, account: &str) -> Result<String, Error>;
    async fn retire_address(&self, address: &str) -> Result<(), Error>;
    /// A user asks to connect `agent` to `target`; returns the request ID.
    async fn create_request(&self, account: &str, agent: &str, target: &str) -> Result<String, Error>;
    async fn approve(&self, account: &str, source_platform: &str, request_id: &str) -> Result<(), Error>;
    async fn block(&self, account: &str, source_platform: &str, request_id: &str) -> Result<(), Error>;
    async fn revoke(&self, relationship_id: &str) -> Result<(), Error>;
}

pub struct Target {
    pub platform_socket: PathBuf,
    pub platform_uid: u32,
    /// The suite serves `AdapterService` here for the platform.
    pub adapter_socket: PathBuf,
}

#[derive(Debug)]
pub struct CheckResult {
    pub name: &'static str,
    pub covers: &'static str,
    pub outcome: Result<(), String>,
}

pub const PEER: &str = "conformance-peer";
pub const PEER_DOMAIN: &str = "conformance-peer.test";
const PEER_EDGE: &str = "spiffe://conformance-peer.test/federation/edge";

struct StandIn {
    platform_id: PlatformId,
}

#[tonic::async_trait]
impl AdapterService for StandIn {
    async fn wake(&self, _: Request<api::WakeRequest>) -> Result<Response<api::WakeResponse>, Status> {
        Ok(Response::new(api::WakeResponse {}))
    }
    async fn get_health(&self, _: Request<api::GetHealthRequest>) -> Result<Response<api::Health>, Status> {
        Ok(Response::new(api::Health { components: vec![], peers: vec![] }))
    }
    async fn resolve_address(&self, _: Request<api::ResolveAddressRequest>) -> Result<Response<api::ResolveAddressResponse>, Status> {
        Ok(Response::new(api::ResolveAddressResponse { result: api::ResolveResult::UnknownProvider as i32, ..Default::default() }))
    }
    async fn validate_request(&self, r: Request<api::ValidateRequestRequest>) -> Result<Response<api::ValidateRequestResponse>, Status> {
        Ok(Response::new(ptpan_platform_api::policy::validate_request(r.get_ref())))
    }
    async fn compute_terms_digest(&self, r: Request<api::ComputeTermsDigestRequest>) -> Result<Response<api::ComputeTermsDigestResponse>, Status> {
        Ok(Response::new(ptpan_platform_api::policy::compute_terms_digest(r.get_ref())))
    }
    async fn compute_lease(&self, r: Request<api::ComputeLeaseRequest>) -> Result<Response<api::ComputeLeaseResponse>, Status> {
        Ok(Response::new(ptpan_platform_api::policy::compute_lease(&self.platform_id, r.into_inner())))
    }
}

struct Run<'a> {
    driver: &'a dyn Driver,
    client: PlatformServiceClient<Channel>,
    platform_id: PlatformId,
    domain: String,
    results: Vec<CheckResult>,
}

fn ensure(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn s(e: impl std::fmt::Display) -> String {
    e.to_string()
}

impl Run<'_> {
    fn record(&mut self, name: &'static str, covers: &'static str, outcome: Result<(), String>) {
        self.results.push(CheckResult { name, covers, outcome });
    }

    async fn handoffs(&mut self) -> Result<Vec<api::HandoffRecord>, String> {
        Ok(self.client.read_handoff(api::ReadHandoffRequest { after_cursor: 0, limit: 100 }).await.map_err(s)?.into_inner().records)
    }

    /// Wait up to 15 s for an unacknowledged record of `kind` matching `pick`.
    async fn wait_handoff(&mut self, kind: api::ControlKind, pick: impl Fn(&api::HandoffRecord) -> bool) -> Result<api::HandoffRecord, String> {
        for _ in 0..75 {
            if let Some(record) = self.handoffs().await?.into_iter().find(|h| h.kind == kind as i32 && pick(h)) {
                return Ok(record);
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        Err(format!("no {kind:?} hand-off record appeared"))
    }

    async fn ack(&mut self, record: &api::HandoffRecord) -> Result<(), String> {
        self.client.ack_handoff(api::AckHandoffRequest { handoff_id: record.handoff_id.clone() }).await.map_err(s)?;
        Ok(())
    }

    async fn deliver(&mut self, event: &str, request: &RelationshipRequest) -> Result<i32, String> {
        Ok(self
            .client
            .deliver_inbound(api::DeliverInboundRequest {
                source_platform_id: PEER.into(),
                event_id: event.into(),
                request_json: serde_json::to_vec(request).map_err(s)?,
            })
            .await
            .map_err(s)?
            .into_inner()
            .result)
    }

    fn peer_request(&self, id: &str, requester: &str, target: &str) -> RelationshipRequest {
        let now = now_unix();
        RelationshipRequest {
            relationship_id: OpaqueId::new(format!("rel-{id}")).unwrap(),
            request_id: OpaqueId::new(id).unwrap(),
            source: Participant { platform_id: PlatformId::new(PEER).unwrap(), address: requester.into() },
            source_ownership_revision: 1,
            requester_name: PersonName { given_name: "Conformance".into(), family_name: "Peer".into() },
            request_kind: RequestKind::Establish,
            request_revision: 1,
            base_lease_revision: None,
            application_protocol: "a2a".into(),
            transport: "tls13".into(),
            target_address: target.into(),
            requested_permissions: BTreeSet::from(["a2a.invoke".to_string()]),
            requested_lifetime: LifetimeRequest::UntilRevoked,
            created_at: now - 1,
            request_expires_at: now + 3600,
        }
    }
}

/// Run every check against `target`. A failed check does not stop the rest
/// unless a later check depends on its result.
pub async fn run(driver: &dyn Driver, target: &Target) -> Result<Vec<CheckResult>, Error> {
    let channel = ptpan_platform_api::transport::connect(&target.platform_socket, target.platform_uid).await?;
    let mut client = PlatformServiceClient::new(channel);
    let info = client
        .get_platform_info(api::GetPlatformInfoRequest { adapter_api_majors: vec![ptpan_platform_api::API_MAJOR], adapter_features: vec![] })
        .await?
        .into_inner();
    let platform_id = PlatformId::new(info.platform_id.clone())?;
    let listener = ptpan_platform_api::transport::bind(&target.adapter_socket)?;
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(AdapterServiceServer::new(StandIn { platform_id: platform_id.clone() }))
            .serve_with_incoming(ptpan_platform_api::transport::incoming(listener, target.platform_uid)),
    );
    let mut run = Run { driver, client, platform_id, domain: info.provider_domain.clone(), results: Vec::new() };
    run.record("platform info", "H1, D2", ensure(
        valid_provider_domain(&info.provider_domain) && info.api_majors.contains(&ptpan_platform_api::API_MAJOR),
        "provider domain must be lowercase ASCII and API major 1 must be offered",
    ));
    let source = source_checks(&mut run).await;
    run.record("source side", "H4, H5, H9, H15, D5, D6, D7", source);
    let destination = destination_checks(&mut run).await;
    run.record("destination side", "H3, H6, H7, H8, H9, H11, H13, D1, D4, D7, D12, review 12.5", destination);
    server.abort();
    Ok(run.results)
}

async fn source_checks(run: &mut Run<'_>) -> Result<(), String> {
    let d = run.driver;
    d.add_account("conf-alice", "Ada", "Lovelace").await.map_err(s)?;
    let a1 = d.add_agent("conf-a1", "conf-alice").await.map_err(s)?;
    d.add_agent("conf-a2", "conf-alice").await.map_err(s)?;
    ensure(address_in_domain(&a1, &run.domain), "an issued address must end in the platform's own domain (D10)")?;
    let target = format!("agent-x.{PEER_DOMAIN}");
    let request_id = d.create_request("conf-alice", "conf-a1", &target).await.map_err(s)?;
    let record = run.wait_handoff(api::ControlKind::RelationshipRequest, |h| h.request_id == request_id).await?;
    let again = run.handoffs().await?;
    ensure(again.iter().any(|h| h.handoff_id == record.handoff_id), "a hand-off record stays until acknowledged (H15)")?;
    let text = String::from_utf8(record.payload_json.clone()).map_err(s)?;
    for internal in ["conf-alice", "conf-a1", "subject_id", "resource_id"] {
        ensure(!text.contains(internal), "no internal account or agent ID may cross platforms (D5)")?;
    }
    let payload: RequestPayload = serde_json::from_slice(&record.payload_json).map_err(s)?;
    payload.request.validate().map_err(s)?;
    ensure(payload.request_terms_digest == hex_lower(&payload.request.request_terms_digest().map_err(s)?), "request digest")?;
    ensure(payload.request.source.address == a1, "the requester reference is the requesting agent's address (D5)")?;
    ensure(payload.request.requester_name.given_name == "Ada", "the requester's account name is carried (D6)")?;
    let authorized = run
        .client
        .authorize_source(api::AuthorizeSourceRequest { request_id: request_id.clone() })
        .await
        .map_err(s)?
        .into_inner();
    ensure(authorized.authorized, "the requesting account still owns the agent (H4)")?;
    run.ack(&record).await?;
    ensure(!run.handoffs().await?.iter().any(|h| h.handoff_id == record.handoff_id), "an acknowledged record is gone (H15)")?;

    // The peer approves; the platform applies it and acknowledges with the key.
    let request = payload.request;
    let issuer = PlatformId::new(PEER).map_err(s)?;
    let now = now_unix();
    let owner = PersonName { given_name: "Grace".into(), family_name: "Hopper".into() };
    let lease = RelationshipLease::issue(&request, &issuer, OwnerTerms {
        lease_id: OpaqueId::new("conf-lease-1").map_err(s)?,
        lease_revision: 1,
        decision_id: OpaqueId::new("conf-dec-1").map_err(s)?,
        mode: federation_base::LeaseMode::UntilRevoked,
        effective_from: now,
        expires_at: None,
        effective_permissions: BTreeSet::from(["a2a.invoke".to_string()]),
    }, 1, &owner).map_err(s)?;
    let decision = DecisionPayload {
        decision_id: OpaqueId::new("conf-dec-1").map_err(s)?,
        result: DecisionResult::Approved,
        bound_request_revision: 1,
        request_terms_digest: hex_lower(&request.request_terms_digest().map_err(s)?),
        destination_ownership_revision: Some(1),
        destination_owner_name: Some(owner),
        lease: Some(LeaseWire::from_lease(&lease)),
    };
    let apply = api::ApplyDecisionRequest {
        source_platform_id: PEER.into(),
        event_id: "conf-ev-decision-1".into(),
        request_id: request_id.clone(),
        decision_json: serde_json::to_vec(&decision).map_err(s)?,
        peer_agent_ca_root: String::new(),
        peer_edge_service_id: PEER_EDGE.into(),
    };
    let first = run.client.apply_decision(apply.clone()).await.map_err(s)?.into_inner().result;
    let replay = run.client.apply_decision(apply).await.map_err(s)?.into_inner().result;
    ensure(first == api::ApplyResult::Applied as i32 && replay == first, "a decision applies once and its replay returns the same result (H8)")?;
    let ack = run.wait_handoff(api::ControlKind::ConfigAck, |h| h.relationship_id == request.relationship_id.as_str()).await?;
    let ack_payload: ConfigAckPayload = serde_json::from_slice(&ack.payload_json).map_err(s)?;
    let binding = ack_payload.source_key.ok_or("the source acknowledgment carries the admission key (H9)")?;
    ensure(binding.requester_reference == a1 && binding.destination_address == target
        && decode_hex32(&binding.terms_digest) == Some(lease.terms_digest), "the key binding names both addresses and the lease terms (D5)")?;
    run.ack(&ack).await?;

    // A block on that destination address is enforced for the whole account.
    let block = serde_json::json!({"requester_reference": a1, "destination_address": target, "state": "BLOCKED",
        "block_revision": 1, "effective_at": format_utc(now)});
    let applied = run
        .client
        .apply_lifecycle(api::ApplyLifecycleRequest {
            peer_platform_id: PEER.into(),
            event_id: "conf-ev-block-1".into(),
            kind: api::ControlKind::PairBlockStatus as i32,
            relationship_id: String::new(),
            payload_json: serde_json::to_vec(&block).map_err(s)?,
        })
        .await
        .map_err(s)?
        .into_inner()
        .result;
    ensure(applied == api::ApplyResult::Applied as i32, "a pair block for our requester reference applies (D7)")?;
    let blocked_request = d.create_request("conf-alice", "conf-a2", &target).await.map_err(s)?;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    ensure(
        !run.handoffs().await?.iter().any(|h| h.request_id == blocked_request),
        "a block is enforced for every agent of the account; no request is sent (D7)",
    )?;
    Ok(())
}

async fn destination_checks(run: &mut Run<'_>) -> Result<(), String> {
    let d = run.driver;
    d.add_account("conf-bob", "Grace", "Hopper").await.map_err(s)?;
    let b1 = d.add_agent("conf-b1", "conf-bob").await.map_err(s)?;
    let b2 = d.add_agent("conf-b2", "conf-bob").await.map_err(s)?;
    let requester = format!("requester-1.{PEER_DOMAIN}");
    let request = run.peer_request("conf-req-in-1", &requester, &b1);
    let queued = api::DeliveryResult::QueuedForLocalOwner as i32;
    let unknown = api::DeliveryResult::AddressNotRecognized as i32;
    ensure(run.deliver("conf-ev-in-1", &request).await? == queued, "a known address reaches its owner's inbox (H3, H6)")?;
    ensure(run.deliver("conf-ev-in-1", &request).await? == queued, "a replayed event returns the same result (H8)")?;
    let nobody = run.peer_request("conf-req-in-2", &requester, &format!("nobody.{}", run.domain));
    ensure(run.deliver("conf-ev-in-2", &nobody).await? == unknown, "an unknown address is not recognized (H3)")?;
    d.retire_address(&b2).await.map_err(s)?;
    let retired = run.peer_request("conf-req-in-3", &requester, &b2);
    ensure(run.deliver("conf-ev-in-3", &retired).await? == unknown, "a retired address is not recognized (H2, 12.5)")?;

    // Approval: lease, grant and decision through ComputeLease (D1, H7).
    d.approve("conf-bob", PEER, "conf-req-in-1").await.map_err(s)?;
    let record = run.wait_handoff(api::ControlKind::RelationshipDecision, |h| h.request_id == "conf-req-in-1").await?;
    let decision: DecisionPayload = serde_json::from_slice(&record.payload_json).map_err(s)?;
    ensure(decision.result == DecisionResult::Approved, "approved")?;
    let lease = decision.lease_against(&request, &run.platform_id).map_err(|e| format!("{e:?}"))?;
    ensure(decision.destination_owner_name.as_ref().is_some_and(|n| n.validate().is_ok()), "an approval carries the owner's name (D6)")?;
    run.ack(&record).await?;

    // The requesting agent's key arrives; the platform binds it and acknowledges.
    let key = SigningKey::from_bytes(&[7; 32]);
    let ack = serde_json::json!({"lease_id": lease.lease_id, "lease_revision": 1, "configuration_revision": 1,
        "key_purpose_revision": 1, "acknowledged_at": format_utc(now_unix()),
        "source_key": {"requester_reference": requester, "destination_address": b1, "terms_digest": hex_lower(&lease.terms_digest),
            "key_purpose": "ed25519_admission", "public_key": hex_lower(key.verifying_key().as_bytes())}});
    let applied = run
        .client
        .apply_lifecycle(api::ApplyLifecycleRequest {
            peer_platform_id: PEER.into(),
            event_id: "conf-ev-ack-1".into(),
            kind: api::ControlKind::ConfigAck as i32,
            relationship_id: request.relationship_id.as_str().into(),
            payload_json: serde_json::to_vec(&ack).map_err(s)?,
        })
        .await
        .map_err(s)?
        .into_inner()
        .result;
    ensure(applied == api::ApplyResult::Applied as i32, "the key binding applies (H9)")?;
    let own_ack = run.wait_handoff(api::ControlKind::ConfigAck, |h| h.relationship_id == request.relationship_id.as_str()).await?;
    run.ack(&own_ack).await?;
    let bound = run
        .client
        .get_bound_key(api::GetBoundKeyRequest { relationship_id: request.relationship_id.as_str().into() })
        .await
        .map_err(s)?
        .into_inner();
    ensure(bound.found && bound.did_key == did_key_from_ed25519(key.verifying_key().as_bytes()), "GetBoundKey returns the bound key (D4)")?;

    // Admission: atomic nonce, key revision recheck, 300-second cap.
    let now = now_unix();
    let claims = |jti: &str| AdmissionClaims {
        iss: PlatformId::new(PEER).unwrap(),
        sub: requester.clone(),
        aud: "spiffe://conformance.test/federation/edge".into(),
        iat: now,
        exp: now + 30,
        jti: jti.into(),
        relationship_id: request.relationship_id.clone(),
        lease_id: lease.lease_id.clone(),
        lease_revision: 1,
        operation: "a2a.invoke".into(),
        destination_address: b1.clone(),
        key_revision: bound.key_revision,
    };
    let admit = |jti: &str, revision: u64| api::AdmitCallRequest {
        relationship_id: request.relationship_id.as_str().into(),
        claims_json: serde_json::to_vec(&claims(jti)).unwrap(),
        verified_key_revision: revision,
    };
    let allowed = run.client.admit_call(admit("conf-n1", bound.key_revision)).await.map_err(s)?.into_inner();
    ensure(allowed.allowed && allowed.deadline > now && allowed.deadline <= now + 301, "a ready relationship admits one stream for at most 300 s (D12)")?;
    let replay = run.client.admit_call(admit("conf-n1", bound.key_revision)).await.map_err(s)?.into_inner();
    ensure(!replay.allowed && replay.reason == "REUSED_NONCE", "a nonce is single-use (H11)")?;
    let rotated = run.client.admit_call(admit("conf-n2", bound.key_revision + 1)).await.map_err(s)?.into_inner();
    ensure(!rotated.allowed && rotated.reason == "KEY_REVISION_CHANGED", "the key revision is rechecked atomically (D4)")?;

    // Revoke: local cutoff first, then the event.
    d.revoke(request.relationship_id.as_str()).await.map_err(s)?;
    let revoke = run.wait_handoff(api::ControlKind::RelationshipRevoke, |h| h.relationship_id == request.relationship_id.as_str()).await?;
    run.ack(&revoke).await?;
    let after = run.client.admit_call(admit("conf-n3", bound.key_revision)).await.map_err(s)?.into_inner();
    ensure(!after.allowed, "a revoked relationship admits nothing (H13)")?;

    // Block: the decision says BLOCKED; later requests are not recognized.
    let second = run.peer_request("conf-req-in-4", &requester, &b1);
    ensure(run.deliver("conf-ev-in-4", &second).await? == queued, "second request queued")?;
    d.block("conf-bob", PEER, "conf-req-in-4").await.map_err(s)?;
    let blocked = run.wait_handoff(api::ControlKind::RelationshipDecision, |h| h.request_id == "conf-req-in-4").await?;
    let blocked_decision: DecisionPayload = serde_json::from_slice(&blocked.payload_json).map_err(s)?;
    ensure(blocked_decision.result == DecisionResult::Blocked && blocked_decision.destination_owner_name.is_none(),
        "a block decision carries no name or lease (D6, D7)")?;
    run.ack(&blocked).await?;
    let third = run.peer_request("conf-req-in-5", &requester, &b1);
    ensure(run.deliver("conf-ev-in-5", &third).await? == unknown, "a blocked pair is not recognized, like an unknown address (12.5)")?;
    Ok(())
}
