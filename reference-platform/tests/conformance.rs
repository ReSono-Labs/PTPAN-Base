//! The reference platform passes the black-box conformance suite.

use federation_base::PlatformId;
use ptpan_conformance::{run, Driver, Error, Target};
use ptpan_reference_platform::{ApprovalTerms, Config, Platform};
use ptpan_test_support::{uid, RemoveOnDrop};
use std::sync::Arc;

struct Reference(Arc<Platform>);

fn terms() -> ApprovalTerms {
    ApprovalTerms { permissions: vec!["a2a.invoke".into()], mode: "UNTIL_REVOKED".into(), lifetime_seconds: 0 }
}

#[tonic::async_trait]
impl Driver for Reference {
    async fn add_account(&self, account: &str, given: &str, family: &str) -> Result<(), Error> {
        self.0.add_account(account, given, family)
    }
    async fn add_agent(&self, agent: &str, account: &str) -> Result<String, Error> {
        self.0.add_agent(agent, account)
    }
    async fn retire_address(&self, address: &str) -> Result<(), Error> {
        self.0.retire_address(address)
    }
    async fn create_request(&self, account: &str, agent: &str, target: &str) -> Result<String, Error> {
        self.0.create_request(account, agent, target, &terms())
    }
    async fn approve(&self, account: &str, source: &str, request_id: &str) -> Result<(), Error> {
        self.0.approve(account, source, request_id, &terms())
    }
    async fn block(&self, account: &str, source: &str, request_id: &str) -> Result<(), Error> {
        self.0.deny(account, source, request_id, true)
    }
    async fn revoke(&self, relationship_id: &str) -> Result<(), Error> {
        self.0.revoke(relationship_id, "OWNER_REVOKED")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reference_platform_passes_the_conformance_suite() {
    let dir = std::env::temp_dir().join(format!("ptpan-conformance-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = RemoveOnDrop(dir.clone());
    let me = uid(&dir);
    let platform = Arc::new(
        Platform::open(Config {
            platform_id: PlatformId::new("provider-r").unwrap(),
            provider_domain: "provider-r.test".into(),
            database_path: dir.join("platform.sqlite"),
            platform_socket: dir.join("platform.sock"),
            adapter_socket: dir.join("adapter.sock"),
            adapter_uid: me,
            egress_socket: dir.join("egress.sock"),
            ingress_socket: dir.join("ingress.sock"),
            bridge_uid: me,
        })
        .unwrap(),
    );
    let serving = platform.clone();
    tokio::spawn(async move {
        let _ = serving.serve().await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let target = Target { platform_socket: dir.join("platform.sock"), platform_uid: me, adapter_socket: dir.join("adapter.sock") };
    let results = run(&Reference(platform), &target).await.unwrap();
    for result in &results {
        eprintln!("{:<18} {:<70} {:?}", result.name, result.covers, result.outcome);
    }
    assert!(results.iter().all(|r| r.outcome.is_ok()), "{results:#?}");
    assert_eq!(results.len(), 3);
}
