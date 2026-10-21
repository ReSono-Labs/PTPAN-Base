//! End-to-end exchange between two adapters (A and B), each with its own
//! PostgreSQL database, an in-memory fake platform and an in-process fake
//! bridge that joins A's sends to B's runtime socket and serves domain
//! proofs. Run with:
//!
//!   PTPAN_TEST_PG="host=127.0.0.1 port=5432 user=postgres password=..." \
//!     cargo test -p ptpan-adapter -- --ignored
//!
//! The test creates and drops its own databases.

use federation_base::control_event::RequestPayload;
use federation_base::encoding::hex_lower;
use federation_base::identity_evidence::EvidenceProfile;
use federation_base::live_admission::{sign_admission_token, did_key_from_ed25519, AdmissionClaims};
use federation_base::time::{format_utc, now_unix};
use federation_base::{
    LifetimeRequest, OpaqueId, Participant, PeerState, PersonName, PlatformId, RelationshipRequest, RequestKind,
};
use ptpan_test_support::{create_database, drop_database, uid, wait_for, Network, Provider, RemoveOnDrop, Side as BridgeSide};
use ptpan_adapter::config::Config;
use ptpan_adapter::Adapter;
use ptpan_platform_api::v1 as api;
use ptpan_platform_api::v1::platform_service_server::{PlatformService, PlatformServiceServer};
use std::collections::{BTreeSet, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tonic::{Request as GrpcRequest, Response as GrpcResponse, Status};

// --- Fake platform ----------------------------------------------------------

#[derive(Default)]
struct FakePlatform {
    platform_id: String,
    domain: String,
    handoff: Mutex<Vec<api::HandoffRecord>>,
    next_cursor: AtomicU64,
    fail_next_ack: AtomicBool,
    down: AtomicBool,
    delivered: Mutex<Vec<(String, Vec<u8>)>>,
    lifecycle: Mutex<Vec<(i32, String)>>,
    receipts: Mutex<Vec<(String, i32)>>,
    notices: Mutex<Vec<(String, i32)>>,
    bound_key: Mutex<Option<(String, u64)>>,
    nonces: Mutex<HashSet<String>>,
}

impl FakePlatform {
    fn push(&self, mut record: api::HandoffRecord) {
        record.cursor = self.next_cursor.fetch_add(1, Ordering::SeqCst) + 1;
        self.handoff.lock().unwrap().push(record);
    }
    fn check_up(&self) -> Result<(), Status> {
        if self.down.load(Ordering::SeqCst) {
            Err(Status::unavailable("platform down"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone)]
struct FakeService(Arc<FakePlatform>);

#[tonic::async_trait]
impl PlatformService for FakeService {
    async fn get_platform_info(&self, _: GrpcRequest<api::GetPlatformInfoRequest>) -> Result<GrpcResponse<api::PlatformInfo>, Status> {
        Ok(GrpcResponse::new(api::PlatformInfo {
            platform_id: self.0.platform_id.clone(),
            provider_domain: self.0.domain.clone(),
            api_majors: vec![1],
            features: vec![],
        }))
    }
    async fn read_handoff(&self, r: GrpcRequest<api::ReadHandoffRequest>) -> Result<GrpcResponse<api::ReadHandoffResponse>, Status> {
        self.0.check_up()?;
        let after = r.get_ref().after_cursor;
        let records = self.0.handoff.lock().unwrap().iter().filter(|h| h.cursor > after).cloned().collect();
        Ok(GrpcResponse::new(api::ReadHandoffResponse { records }))
    }
    async fn ack_handoff(&self, r: GrpcRequest<api::AckHandoffRequest>) -> Result<GrpcResponse<api::AckHandoffResponse>, Status> {
        self.0.check_up()?;
        if self.0.fail_next_ack.swap(false, Ordering::SeqCst) {
            return Err(Status::unavailable("simulated crash before ack"));
        }
        self.0.handoff.lock().unwrap().retain(|h| h.handoff_id != r.get_ref().handoff_id);
        Ok(GrpcResponse::new(api::AckHandoffResponse {}))
    }
    async fn authorize_source(&self, _: GrpcRequest<api::AuthorizeSourceRequest>) -> Result<GrpcResponse<api::AuthorizeSourceResponse>, Status> {
        Ok(GrpcResponse::new(api::AuthorizeSourceResponse { authorized: true, ownership_revision: 1 }))
    }
    async fn deliver_inbound(&self, r: GrpcRequest<api::DeliverInboundRequest>) -> Result<GrpcResponse<api::DeliverInboundResponse>, Status> {
        self.0.check_up()?;
        let r = r.into_inner();
        let request: RelationshipRequest = serde_json::from_slice(&r.request_json).unwrap();
        self.0.delivered.lock().unwrap().push((r.event_id, r.request_json));
        let known = request.target_address.starts_with("agent1.");
        let result = if known { api::DeliveryResult::QueuedForLocalOwner } else { api::DeliveryResult::AddressNotRecognized };
        Ok(GrpcResponse::new(api::DeliverInboundResponse { result: result as i32 }))
    }
    async fn apply_decision(&self, _: GrpcRequest<api::ApplyDecisionRequest>) -> Result<GrpcResponse<api::ApplyResponse>, Status> {
        Ok(GrpcResponse::new(api::ApplyResponse { result: api::ApplyResult::Applied as i32 }))
    }
    async fn apply_lifecycle(&self, r: GrpcRequest<api::ApplyLifecycleRequest>) -> Result<GrpcResponse<api::ApplyResponse>, Status> {
        self.0.check_up()?;
        let r = r.into_inner();
        self.0.lifecycle.lock().unwrap().push((r.kind, r.relationship_id));
        Ok(GrpcResponse::new(api::ApplyResponse { result: api::ApplyResult::Applied as i32 }))
    }
    async fn confirm_receipt(&self, r: GrpcRequest<api::ConfirmReceiptRequest>) -> Result<GrpcResponse<api::ConfirmReceiptResponse>, Status> {
        self.0.check_up()?;
        let r = r.into_inner();
        self.0.receipts.lock().unwrap().push((r.handoff_id, r.result));
        Ok(GrpcResponse::new(api::ConfirmReceiptResponse {}))
    }
    async fn record_notice(&self, r: GrpcRequest<api::RecordNoticeRequest>) -> Result<GrpcResponse<api::RecordNoticeResponse>, Status> {
        let r = r.into_inner();
        self.0.notices.lock().unwrap().push((r.request_id, r.kind));
        Ok(GrpcResponse::new(api::RecordNoticeResponse {}))
    }
    async fn get_bound_key(&self, _: GrpcRequest<api::GetBoundKeyRequest>) -> Result<GrpcResponse<api::GetBoundKeyResponse>, Status> {
        let key = self.0.bound_key.lock().unwrap().clone();
        Ok(GrpcResponse::new(match key {
            Some((did, revision)) => api::GetBoundKeyResponse { found: true, did_key: did, key_revision: revision },
            None => api::GetBoundKeyResponse { found: false, did_key: String::new(), key_revision: 0 },
        }))
    }
    async fn admit_call(&self, r: GrpcRequest<api::AdmitCallRequest>) -> Result<GrpcResponse<api::AdmitCallResponse>, Status> {
        let r = r.into_inner();
        let claims: AdmissionClaims = serde_json::from_slice(&r.claims_json).unwrap();
        let bound = self.0.bound_key.lock().unwrap().as_ref().map(|k| k.1);
        let fresh = self.0.nonces.lock().unwrap().insert(claims.jti.clone());
        let (allowed, reason) = match (bound == Some(r.verified_key_revision), fresh) {
            (false, _) => (false, "KEY_REVISION_CHANGED"),
            (_, false) => (false, "REUSED_NONCE"),
            _ => (true, ""),
        };
        Ok(GrpcResponse::new(api::AdmitCallResponse {
            allowed,
            deadline: if allowed { now_unix() + 300 } else { 0 },
            reason: reason.into(),
        }))
    }
}

struct Node {
    adapter: Arc<Adapter>,
    task: tokio::task::JoinHandle<()>,
    config: Config,
}




async fn start(config: Config, platform: Arc<FakePlatform>) -> Node {
    let listener = ptpan_platform_api::transport::bind(&config.platform_socket).unwrap();
    let service = FakeService(platform.clone());
    let uid = config.platform_uid;
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(PlatformServiceServer::new(service))
            .serve_with_incoming(ptpan_platform_api::transport::incoming(listener, uid)),
    );
    let adapter = Adapter::new(config.clone()).await.unwrap();
    let runner = adapter.clone();
    let task = tokio::spawn(async move {
        let _ = runner.run().await;
    });
    Node { adapter, task, config }
}


async fn peer_state(node: &Node, peer: &str) -> Option<PeerState> {
    node.adapter
        .peer_states(now_unix())
        .await
        .unwrap()
        .into_iter()
        .find(|(id, _, _)| id.as_str() == peer)
        .map(|(_, state, _)| state)
}

fn request_handoff(handoff_id: &str, request_id: &str, target: &str) -> api::HandoffRecord {
    let now = now_unix();
    let request = RelationshipRequest {
        relationship_id: OpaqueId::new(format!("rel-{request_id}")).unwrap(),
        request_id: OpaqueId::new(request_id).unwrap(),
        source: Participant { platform_id: PlatformId::new("provider-a").unwrap(), address: "Requester.1.provider-a.test".into() },
        source_ownership_revision: 1,
        requester_name: PersonName { given_name: "Ada".into(), family_name: "Lovelace".into() },
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
    };
    let digest = hex_lower(&request.request_terms_digest().unwrap());
    let payload = RequestPayload { request: request.clone(), request_terms_digest: digest };
    api::HandoffRecord {
        handoff_id: handoff_id.into(),
        cursor: 0,
        kind: api::ControlKind::RelationshipRequest as i32,
        peer_platform_id: String::new(),
        relationship_id: request.relationship_id.as_str().into(),
        request_id: request_id.into(),
        payload_json: serde_json::to_vec(&payload).unwrap(),
        committed_at: format_utc(now),
        actor_side: api::ActorSide::Source as i32,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs PostgreSQL: set PTPAN_TEST_PG"]
async fn two_adapters_onboard_exchange_recover_and_change_manifests() {
    let base = std::env::var("PTPAN_TEST_PG").expect("PTPAN_TEST_PG");
    let dir = std::env::temp_dir().join(format!("ptpan-adapter-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = RemoveOnDrop(dir.clone());
    let me = uid(&dir);
    let tag = std::process::id();
    let (a, b) = (Provider::new("provider-a", 1), Provider::new("provider-b", 2));
    let dbs = [format!("ptpan_e2e_a_{tag}"), format!("ptpan_e2e_b_{tag}")];
    for db in &dbs {
        create_database(&base, db).await;
    }

    let network = Network::default();
    network.proofs.lock().unwrap().insert(a.proof_url(), a.domain_doc());
    network.proofs.lock().unwrap().insert(b.proof_url(), b.domain_doc());

    let mut configs = Vec::new();
    for (side, db) in [(&a, &dbs[0]), (&b, &dbs[1])] {
        let path = |name: &str| dir.join(format!("{}-{name}", side.id));
        std::fs::write(path("manifest.json"), serde_json::to_vec(&side.manifest(1)).unwrap()).unwrap();
        let config = Config {
            platform_id: PlatformId::new(side.id.clone()).unwrap(),
            provider_domain: side.domain.clone(),
            control_service_id: side.control.clone(),
            edge_service_id: side.edge.clone(),
            database_url: format!("{base} dbname={db}"),
            platform_socket: path("platform.sock"),
            adapter_socket: path("adapter.sock"),
            platform_uid: me,
            runtime_socket: path("runtime.sock"),
            bridge_socket: path("bridge.sock"),
            bridge_uid: me,
            manifest_path: path("manifest.json"),
            evidence_profile: EvidenceProfile::LocalHttpTest,
            worker_id: format!("{}-copy-1", side.id),
        };
        let bridge = BridgeSide {
            control_service: side.control.clone(),
            edge_service: side.edge.clone(),
            runtime_socket: path("runtime.sock"),
            bridge_socket: path("bridge.sock"),
            egress_socket: path("egress.sock"),
            ingress_socket: path("ingress.sock"),
        };
        network.register(&bridge);
        network.start_bridge(&bridge, me);
        configs.push(config);
    }
    let platform_a = Arc::new(FakePlatform { platform_id: a.id.clone(), domain: a.domain.clone(), ..Default::default() });
    let platform_b = Arc::new(FakePlatform { platform_id: b.id.clone(), domain: b.domain.clone(), ..Default::default() });
    let node_a = start(configs[0].clone(), platform_a.clone()).await;
    let node_b = start(configs[1].clone(), platform_b.clone()).await;

    // Onboarding: bootstrap, hello, domain proof, both approvals.
    let now = now_unix();
    node_a.adapter.add_peer(b.bootstrap(), now).await.unwrap();
    node_b.adapter.add_peer(a.bootstrap(), now).await.unwrap();
    let (pa, pb) = (PlatformId::new(a.id.clone()).unwrap(), PlatformId::new(b.id.clone()).unwrap());
    wait_for("both identities verified", || async {
        let ra = node_a.adapter.store.peer(&pb).await.unwrap().unwrap();
        let rb = node_b.adapter.store.peer(&pa).await.unwrap().unwrap();
        ra.verified_digest.is_some() && rb.verified_digest.is_some()
    })
    .await;
    assert_eq!(peer_state(&node_a, &b.id).await, Some(PeerState::Pending), "no approval yet");
    node_a.adapter.approve_peer(&pb, now_unix()).await.unwrap();
    node_b.adapter.approve_peer(&pa, now_unix()).await.unwrap();
    wait_for("both peers active", || async {
        peer_state(&node_a, &b.id).await == Some(PeerState::Active) && peer_state(&node_b, &a.id).await == Some(PeerState::Active)
    })
    .await;

    // A request crosses once even though the first hand-off ack fails.
    platform_a.fail_next_ack.store(true, Ordering::SeqCst);
    platform_a.push(request_handoff("h1", "req-1", "agent1.provider-b.test"));
    node_a.adapter.wake.notify_one();
    wait_for("receipt confirmed on A", || async { platform_a.receipts.lock().unwrap().iter().any(|(h, _)| h == "h1") }).await;
    assert_eq!(platform_b.delivered.lock().unwrap().len(), 1, "delivered exactly once");
    assert_eq!(
        platform_a.receipts.lock().unwrap().iter().find(|(h, _)| h == "h1").unwrap().1,
        api::ReceiptResult::QueuedForLocalOwner as i32
    );
    let delivered = platform_b.delivered.lock().unwrap()[0].1.clone();
    let text = String::from_utf8(delivered).unwrap();
    assert!(text.contains("\"target_address\":\"agent1.provider-b.test\"") && !text.contains("subject_id"));

    // Unknown provider: refused locally with a notice; nothing is sent.
    platform_a.push(request_handoff("h2", "req-2", "agent9.unknown.test"));
    node_a.adapter.wake.notify_one();
    wait_for("unknown provider notice", || async {
        platform_a.notices.lock().unwrap().iter().any(|(r, k)| r == "req-2" && *k == api::NoticeKind::UnknownProvider as i32)
    })
    .await;

    // Destination platform down: the event waits and is delivered once B is back.
    platform_b.down.store(true, Ordering::SeqCst);
    platform_a.push(request_handoff("h3", "req-3", "unknown-label.provider-b.test"));
    node_a.adapter.wake.notify_one();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(platform_b.delivered.lock().unwrap().len(), 1);
    assert!(!platform_a.receipts.lock().unwrap().iter().any(|(h, _)| h == "h3"));
    platform_b.down.store(false, Ordering::SeqCst);
    wait_for("delivery after recovery", || async { platform_a.receipts.lock().unwrap().iter().any(|(h, _)| h == "h3") }).await;
    assert_eq!(
        platform_a.receipts.lock().unwrap().iter().find(|(h, _)| h == "h3").unwrap().1,
        api::ReceiptResult::AddressNotRecognized as i32
    );

    // Restart A with the same database: nothing is redone.
    node_a.task.abort();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let restarted = Adapter::new(node_a.config.clone()).await.unwrap();
    let runner = restarted.clone();
    let task_a = tokio::spawn(async move {
        let _ = runner.run().await;
    });
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(platform_b.delivered.lock().unwrap().len(), 2, "no event delivered twice after restart");

    // Fenced delivery: one copy holds a peer's lease until it lapses.
    let store = &restarted.store;
    let fenced = PlatformId::new("provider-z").unwrap();
    let lease_now = now_unix();
    assert!(store.acquire_peer_lease(&fenced, "copy-x", lease_now, 15).await.unwrap());
    assert!(store.acquire_peer_lease(&fenced, "copy-x", lease_now + 5, 15).await.unwrap(), "owner renews");
    assert!(!store.acquire_peer_lease(&fenced, "copy-y", lease_now + 5, 15).await.unwrap());
    assert!(store.acquire_peer_lease(&fenced, "copy-y", lease_now + 21, 15).await.unwrap(), "takeover after lapse");

    // Edge admission on B: verify with the bound key, then the platform decides.
    let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    *platform_b.bound_key.lock().unwrap() = Some((did_key_from_ed25519(key.verifying_key().as_bytes()), 1));
    let claims = AdmissionClaims {
        iss: pa.clone(),
        sub: "Requester.1.provider-a.test".into(),
        aud: b.edge.clone(),
        iat: now_unix(),
        exp: now_unix() + 30,
        jti: "nonce-1".into(),
        relationship_id: OpaqueId::new("rel-req-1").unwrap(),
        lease_id: OpaqueId::new("lease-1").unwrap(),
        lease_revision: 1,
        operation: "a2a.invoke".into(),
        destination_address: "agent1.provider-b.test".into(),
        key_revision: 1,
    };
    let frame = serde_json::to_vec(&serde_json::json!({
        "schema": "live-admission/v3", "token": sign_admission_token(&claims, &key),
        "destination_address": "agent1.provider-b.test", "relationship_id": "rel-req-1"
    }))
    .unwrap();
    let allowed = node_b.adapter.admit(&a.edge, &frame).await.unwrap();
    assert!(allowed.allow && allowed.deadline > now_unix());
    let replay = node_b.adapter.admit(&a.edge, &frame).await.unwrap();
    assert!(!replay.allow && String::from_utf8(replay.response).unwrap().contains("REUSED_NONCE"));
    let wrong_edge = node_b.adapter.admit("spiffe://provider-c.test/federation/edge", &frame).await.unwrap();
    assert!(!wrong_edge.allow);

    // Announced and approved manifest change on B: no outage on A.
    let effective = now_unix() + 4;
    node_b
        .adapter
        .propose_manifest(&serde_json::to_vec(&b.manifest(2)).unwrap(), effective, now_unix())
        .await
        .unwrap();
    wait_for("A received B's pending manifest", || async {
        restarted.store.peer(&pb).await.unwrap().unwrap().pending.is_some()
    })
    .await;
    restarted.approve_pending(&pb, now_unix()).await.unwrap();
    wait_for("B has A's approval of its pending manifest", || async {
        node_b.adapter.store.peer(&pa).await.unwrap().unwrap().remote_approved_digests.len() >= 2
    })
    .await;
    wait_for("A switched to B's revision 2 and stayed active", || async {
        let record = restarted.store.peer(&pb).await.unwrap().unwrap();
        record.current.as_ref().is_some_and(|m| m.revision == 2) && peer_state_of(&restarted, &b.id).await == Some(PeerState::Active)
    })
    .await;

    // Unannounced change on B: A cuts off until its operator approves again.
    std::fs::write(&configs[1].manifest_path, serde_json::to_vec(&b.manifest(3)).unwrap()).unwrap();
    wait_for("A cut off B after an unannounced change", || async {
        let record = restarted.store.peer(&pb).await.unwrap().unwrap();
        record.current.as_ref().is_some_and(|m| m.revision == 3) && peer_state_of(&restarted, &b.id).await == Some(PeerState::Pending)
    })
    .await;

    // Removal without restart: B removes A; A sees the restriction.
    node_b.adapter.remove_peer(&pa, now_unix()).await.unwrap();
    wait_for("A sees B's removal", || async {
        restarted.store.peer(&pb).await.unwrap().unwrap().remote_suspended
    })
    .await;
    assert_eq!(peer_state(&node_b, &a.id).await, Some(PeerState::Removed));

    task_a.abort();
    node_b.task.abort();
    tokio::time::sleep(Duration::from_millis(300)).await;
    for db in &dbs {
        drop_database(&base, db).await;
    }
}

async fn peer_state_of(adapter: &Adapter, peer: &str) -> Option<PeerState> {
    adapter
        .peer_states(now_unix())
        .await
        .unwrap()
        .into_iter()
        .find(|(id, _, _)| id.as_str() == peer)
        .map(|(_, state, _)| state)
}
