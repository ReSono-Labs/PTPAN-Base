//! Two reference platforms, each with its own adapter, exchange database and
//! fake bridge (ptpan-test-support), go through the whole relationship
//! lifecycle. Run with:
//!
//!   PTPAN_TEST_PG="host=127.0.0.1 port=5432 user=postgres password=..." \
//!     cargo test -p ptpan-reference-platform -- --ignored

use federation_base::identity_evidence::EvidenceProfile;
use federation_base::time::now_unix;
use federation_base::{PeerState, PlatformId};
use ptpan_adapter::config::Config as AdapterConfig;
use ptpan_adapter::Adapter;
use ptpan_reference_platform::{ApprovalTerms, Config, Platform};
use ptpan_test_support::{create_database, drop_database, uid, wait_for, Network, Provider, RemoveOnDrop, Side};
use std::path::PathBuf;
use std::sync::Arc;

struct Node {
    platform: Arc<Platform>,
    adapter: Arc<Adapter>,
    adapter_task: tokio::task::JoinHandle<()>,
    adapter_config: AdapterConfig,
}

async fn start_platform(platform: Arc<Platform>) {
    tokio::spawn(async move {
        let _ = platform.serve().await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

async fn start_adapter(config: AdapterConfig) -> (Arc<Adapter>, tokio::task::JoinHandle<()>) {
    let adapter = Adapter::new(config).await.unwrap();
    let runner = adapter.clone();
    (adapter, tokio::spawn(async move {
        let _ = runner.run().await;
    }))
}

fn terms(mode: &str) -> ApprovalTerms {
    ApprovalTerms { permissions: vec!["a2a.invoke".into()], mode: mode.into(), lifetime_seconds: 3600 }
}

async fn state(platform: &Platform, request_id: &str) -> String {
    platform.sent_state(request_id).unwrap().unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "needs PostgreSQL: set PTPAN_TEST_PG"]
async fn relationship_lifecycle_between_two_reference_platforms() {
    let base = std::env::var("PTPAN_TEST_PG").expect("PTPAN_TEST_PG");
    let dir = std::env::temp_dir().join(format!("ptpan-reference-flow-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = RemoveOnDrop(dir.clone());
    let me = uid(&dir);
    let tag = std::process::id();
    let (pa, pb) = (Provider::new("provider-a", 1), Provider::new("provider-b", 2));
    let dbs = [format!("ptpan_flow_a_{tag}"), format!("ptpan_flow_b_{tag}")];
    for db in &dbs {
        create_database(&base, db).await;
    }
    let network = Network::default();
    let mut nodes = Vec::new();
    for (provider, db) in [(&pa, &dbs[0]), (&pb, &dbs[1])] {
        let path = |name: &str| -> PathBuf { dir.join(format!("{}-{name}", provider.id)) };
        network.proofs.lock().unwrap().insert(provider.proof_url(), provider.domain_doc());
        std::fs::write(path("manifest.json"), serde_json::to_vec(&provider.manifest(1)).unwrap()).unwrap();
        let side = Side {
            control_service: provider.control.clone(),
            edge_service: provider.edge.clone(),
            runtime_socket: path("runtime.sock"),
            bridge_socket: path("bridge.sock"),
            egress_socket: path("egress.sock"),
            ingress_socket: path("ingress.sock"),
        };
        network.register(&side);
        network.start_bridge(&side, me);
        let platform = Arc::new(
            Platform::open(Config {
                platform_id: PlatformId::new(provider.id.clone()).unwrap(),
                provider_domain: provider.domain.clone(),
                database_path: path("platform.sqlite"),
                platform_socket: path("platform.sock"),
                adapter_socket: path("adapter.sock"),
                adapter_uid: me,
                egress_socket: path("egress.sock"),
                ingress_socket: path("ingress.sock"),
                bridge_uid: me,
            })
            .unwrap(),
        );
        start_platform(platform.clone()).await;
        let adapter_config = AdapterConfig {
            platform_id: PlatformId::new(provider.id.clone()).unwrap(),
            provider_domain: provider.domain.clone(),
            control_service_id: provider.control.clone(),
            edge_service_id: provider.edge.clone(),
            database_url: format!("{base} dbname={db}"),
            platform_socket: path("platform.sock"),
            adapter_socket: path("adapter.sock"),
            platform_uid: me,
            runtime_socket: path("runtime.sock"),
            bridge_socket: path("bridge.sock"),
            bridge_uid: me,
            manifest_path: path("manifest.json"),
            evidence_profile: EvidenceProfile::LocalHttpTest,
            worker_id: format!("{}-1", provider.id),
        };
        let (adapter, adapter_task) = start_adapter(adapter_config.clone()).await;
        nodes.push(Node { platform, adapter, adapter_task, adapter_config });
    }
    let (a, b) = (&nodes[0], &nodes[1]);
    let (id_a, id_b) = (PlatformId::new("provider-a").unwrap(), PlatformId::new("provider-b").unwrap());

    // Operators onboard each other.
    a.adapter.add_peer(pb.bootstrap(), now_unix()).await.unwrap();
    b.adapter.add_peer(pa.bootstrap(), now_unix()).await.unwrap();
    wait_for("identities verified", || async {
        a.adapter.store.peer(&id_b).await.unwrap().unwrap().verified_digest.is_some()
            && b.adapter.store.peer(&id_a).await.unwrap().unwrap().verified_digest.is_some()
    })
    .await;
    a.adapter.approve_peer(&id_b, now_unix()).await.unwrap();
    b.adapter.approve_peer(&id_a, now_unix()).await.unwrap();
    wait_for("peers active", || async {
        let sa = a.adapter.peer_states(now_unix()).await.unwrap();
        let sb = b.adapter.peer_states(now_unix()).await.unwrap();
        sa.iter().any(|(_, s, _)| *s == PeerState::Active) && sb.iter().any(|(_, s, _)| *s == PeerState::Active)
    })
    .await;

    // Accounts and agents on each platform.
    a.platform.add_account("alice", "Ada", "Lovelace").unwrap();
    for agent in ["a1", "a2", "a3"] {
        a.platform.add_agent(agent, "alice").unwrap();
    }
    b.platform.add_account("bob", "Grace", "Hopper").unwrap();
    let b1 = b.platform.add_agent("b1", "bob").unwrap();
    let b2 = b.platform.add_agent("b2", "bob").unwrap();

    // A request reaches only the owning account's inbox, with the name.
    let r1 = a.platform.create_request("alice", "a1", &b1, &terms("UNTIL_REVOKED")).unwrap();
    wait_for("request delivered", || async { state(&a.platform, &r1).await == "delivered" }).await;
    let inbox = b.platform.inbox().unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0]["account_id"], "bob");
    assert_eq!(inbox[0]["requester_name"]["given_name"], "Ada");
    assert_eq!(inbox[0]["target_address"], b1.as_str());

    // Unknown and retired addresses look the same: not recognized, no inbox.
    let unknown = a.platform.create_request("alice", "a1", "zzzzzzzzzzzzzzzz.provider-b.test", &terms("FIXED")).unwrap();
    b.platform.retire_address(&b2).unwrap();
    let retired = a.platform.create_request("alice", "a1", &b2, &terms("FIXED")).unwrap();
    wait_for("not recognized", || async {
        state(&a.platform, &unknown).await == "not_recognized" && state(&a.platform, &retired).await == "not_recognized"
    })
    .await;
    assert_eq!(b.platform.inbox().unwrap().len(), 1);

    // Approval while B's adapter is down waits as an intent, then completes.
    b.adapter_task.abort();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let source = "provider-a";
    b.platform.approve("bob", source, &r1, &terms("FIXED")).unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert_eq!(b.platform.inbox().unwrap()[0]["state"], "approved", "intent waits for the adapter");
    let (b_adapter, _b_task) = start_adapter(b.adapter_config.clone()).await;
    let rel1 = a.platform.relationship_of(&r1).unwrap().unwrap();
    wait_for("both sides ready", || async {
        a.platform.is_ready(&rel1).unwrap() && b.platform.is_ready(&rel1).unwrap()
    })
    .await;
    assert_eq!(state(&a.platform, &r1).await, "approved");

    // An agent call is admitted once per stream and carries opaque bytes.
    let (response, echo) = a.platform.call_agent(&rel1, b"hello across platforms").await.unwrap();
    assert_eq!(response["result"], "ALLOW", "{response}");
    assert_eq!(echo, b"hello across platforms");

    // Revoke on B: local cutoff, propagated to A; calls stop.
    b.platform.revoke(&rel1, "OWNER_REVOKED").unwrap();
    wait_for("A sees the revoke", || async { !a.platform.is_ready(&rel1).unwrap() }).await;
    assert!(a.platform.call_agent(&rel1, b"after revoke").await.is_err());

    // Block on a decision: A shows a denial and enforces it for the account.
    let r2 = a.platform.create_request("alice", "a2", &b1, &terms("FIXED")).unwrap();
    wait_for("second request delivered", || async { state(&a.platform, &r2).await == "delivered" }).await;
    b.platform.deny("bob", source, &r2, true).unwrap();
    wait_for("block shown as denied", || async { state(&a.platform, &r2).await == "denied" }).await;
    let r3 = a.platform.create_request("alice", "a3", &b1, &terms("FIXED")).unwrap();
    assert_eq!(state(&a.platform, &r3).await, "not_recognized", "account-wide enforcement, no request sent");

    // Unblock travels as PAIR_BLOCK_STATUS and lifts the enforcement.
    let a2_reference = serde_json::from_str::<federation_base::RelationshipRequest>(
        &a.platform.db.with(|c| Ok(c.query_row("SELECT request_json FROM sent WHERE request_id = ?1", [&r2], |r| r.get::<_, String>(0))?)).unwrap(),
    )
    .unwrap()
    .source
    .address;
    b.platform.set_block(source, &a2_reference, &b1, false).unwrap();
    wait_for("enforcement lifted", || async {
        let r4 = a.platform.create_request("alice", "a3", &b1, &terms("FIXED")).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        state(&a.platform, &r4).await != "not_recognized"
    })
    .await;

    b_adapter.store.peers().await.unwrap();
    a.adapter_task.abort();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    for db in &dbs {
        drop_database(&base, db).await;
    }
}
