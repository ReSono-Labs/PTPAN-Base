//! Test-only stand-ins. `FakeBridge` does what the Go bridge does for one
//! platform, without SPIRE: it joins the runtime's sends to the peer
//! runtime's socket (as mutual TLS would, naming the sender's control service
//! as the authenticated peer), serves domain proofs from memory, and carries
//! agent streams from the platform's egress socket through the peer's ADMIT
//! decision to the peer platform's ingress socket. The real bridge is tested
//! separately in Go and in the Docker ladder.

use federation_base::time::{format_utc, now_unix};
use federation_ipc::{
    AdmitReply, DomainProofReply, FetchDomainProofBody, Handler, Operation, Request, Response, RouteEgressReply,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Everything the fake bridges of one test share: runtime sockets by control
/// and edge service, and domain documents by URL.
#[derive(Clone, Default)]
pub struct Network {
    pub runtime_by_control: Arc<Mutex<HashMap<String, PathBuf>>>,
    pub runtime_by_edge: Arc<Mutex<HashMap<String, (PathBuf, PathBuf)>>>,
    pub proofs: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

pub struct Side {
    pub control_service: String,
    pub edge_service: String,
    pub runtime_socket: PathBuf,
    pub bridge_socket: PathBuf,
    pub egress_socket: PathBuf,
    pub ingress_socket: PathBuf,
}

impl Network {
    pub fn register(&self, side: &Side) {
        self.runtime_by_control.lock().unwrap().insert(side.control_service.clone(), side.runtime_socket.clone());
        self.runtime_by_edge
            .lock()
            .unwrap()
            .insert(side.edge_service.clone(), (side.runtime_socket.clone(), side.ingress_socket.clone()));
    }

    /// Start one platform's fake bridge (IPC server and egress socket).
    pub fn start_bridge(&self, side: &Side, uid: u32) {
        let net = self.clone();
        let own_control = side.control_service.clone();
        let listener = federation_ipc::bind(&side.bridge_socket).unwrap();
        let handler: Handler = Arc::new(move |request: Request| match request.operation {
            Operation::SendControl => {
                let Some(target) = net.runtime_by_control.lock().unwrap().get(&request.service_id).cloned() else {
                    return Response::error("PEER_NOT_AUTHORIZED");
                };
                let inbound = Request::new(Operation::ReceiveControl, &own_control, request.body);
                match federation_ipc::call(&target, uid, &inbound) {
                    Ok(reply) if reply.error_code.is_empty() => Response::ok(reply.body),
                    Ok(reply) => Response::error(&reply.error_code),
                    Err(_) => Response::error("PEER_DELIVERY_FAILED"),
                }
            }
            Operation::FetchDomainProof => {
                let body: FetchDomainProofBody = serde_json::from_slice(&request.body).unwrap();
                match net.proofs.lock().unwrap().get(&body.url) {
                    Some(doc) => Response::ok(
                        serde_json::to_vec(&DomainProofReply { url: body.url, fetched_at: format_utc(now_unix()), body: doc.clone() })
                            .unwrap(),
                    ),
                    None => Response::error("FETCH_FAILED"),
                }
            }
            Operation::SetPeers | Operation::CloseStreams => Response::ok(b"{}".to_vec()),
            _ => Response::error("UNSUPPORTED"),
        });
        std::thread::spawn(move || federation_ipc::serve(listener, uid, handler));
        let net = self.clone();
        let runtime = side.runtime_socket.clone();
        let own_edge = side.edge_service.clone();
        let egress = side.egress_socket.clone();
        tokio::spawn(async move { net.serve_egress(&egress, runtime, own_edge, uid).await });
    }

    async fn serve_egress(&self, socket: &Path, runtime: PathBuf, own_edge: String, uid: u32) {
        let _ = std::fs::remove_file(socket);
        let listener = tokio::net::UnixListener::bind(socket).unwrap();
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let net = self.clone();
            let runtime = runtime.clone();
            let own_edge = own_edge.clone();
            tokio::spawn(async move {
                let _ = net.relay(stream, runtime, own_edge, uid).await;
            });
        }
    }

    async fn relay(&self, mut local: UnixStream, runtime: PathBuf, own_edge: String, uid: u32) -> std::io::Result<()> {
        let frame = read_frame(&mut local).await?;
        let route = blocking_call(&runtime, uid, Request::new(Operation::RouteEgress, "", frame.clone())).await;
        let Some(route) = route.and_then(|b| serde_json::from_slice::<RouteEgressReply>(&b).ok()) else { return Ok(()) };
        let Some((peer_runtime, peer_ingress)) = self.runtime_by_edge.lock().unwrap().get(&route.edge_service_id).cloned() else {
            return Ok(());
        };
        let admit = blocking_call(&peer_runtime, uid, Request::new(Operation::Admit, &own_edge, frame)).await;
        let Some(reply) = admit.and_then(|b| serde_json::from_slice::<AdmitReply>(&b).ok()) else { return Ok(()) };
        write_frame(&mut local, &reply.response).await?;
        if !reply.allow {
            return Ok(());
        }
        let mut remote = UnixStream::connect(&peer_ingress).await?;
        let header = serde_json::json!({"schema": "ptpan-ingress/1", "relationship_id": reply.relationship_id,
            "destination_address": reply.destination_address, "deadline": reply.deadline});
        write_frame(&mut remote, &serde_json::to_vec(&header).unwrap()).await?;
        let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
        Ok(())
    }
}

async fn blocking_call(socket: &Path, uid: u32, request: Request) -> Option<Vec<u8>> {
    let socket = socket.to_owned();
    let reply = tokio::task::spawn_blocking(move || federation_ipc::call(&socket, uid, &request)).await.ok()?.ok()?;
    reply.error_code.is_empty().then_some(reply.body)
}

pub async fn write_frame(stream: &mut UnixStream, body: &[u8]) -> std::io::Result<()> {
    stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
    stream.write_all(body).await
}

pub async fn read_frame(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let mut body = vec![0u8; u32::from_be_bytes(header) as usize];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

/// Create a fresh database; the caller drops it with `drop_database`.
pub async fn create_database(base: &str, name: &str) {
    let (client, connection) = tokio_postgres::connect(&format!("{base} dbname=postgres"), tokio_postgres::NoTls).await.unwrap();
    tokio::spawn(connection);
    client.batch_execute(&format!("DROP DATABASE IF EXISTS {name}")).await.unwrap();
    client.batch_execute(&format!("CREATE DATABASE {name}")).await.unwrap();
}

pub async fn drop_database(base: &str, name: &str) {
    if let Ok((client, connection)) = tokio_postgres::connect(&format!("{base} dbname=postgres"), tokio_postgres::NoTls).await {
        tokio::spawn(connection);
        let _ = client.batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)")).await;
    }
}

/// This process's user ID, read from a directory it created.
pub fn uid(dir: &Path) -> u32 {
    std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(dir).unwrap())
}

/// Removes a test directory even when an assertion fails.
pub struct RemoveOnDrop(pub PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Poll `check` every 200 ms for up to 30 s.
pub async fn wait_for<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..150 {
        if check().await {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    panic!("timed out waiting for {what}");
}

/// A placeholder agent CA root with the shape Base accepts (DER sequence).
pub fn ca_root(seed: u8) -> String {
    let mut der = vec![0x30, 0x82, 0x01, 0x00];
    der.resize(200, seed);
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der)
}

/// Provider identity fixtures for one test platform.
pub struct Provider {
    pub id: String,
    pub domain: String,
    pub control: String,
    pub edge: String,
    pub ca_seed: u8,
}

impl Provider {
    pub fn new(id: &str, ca_seed: u8) -> Self {
        let domain = format!("{id}.test");
        Self {
            id: id.into(),
            control: format!("spiffe://{domain}/federation/control"),
            edge: format!("spiffe://{domain}/federation/edge"),
            domain,
            ca_seed,
        }
    }

    pub fn manifest(&self, revision: u64) -> serde_json::Value {
        serde_json::json!({
            "schema": "federation-provider/2", "manifest_id": format!("m-{}-{revision}", self.id), "revision": revision,
            "generated_at": "2026-10-21T12:00:00Z",
            "platform": {"platform_id": self.id, "display_name": self.id, "display_name_source": "LOCAL_METADATA",
                "operator_name": "Operator", "website": format!("https://{}", self.domain), "documentation_url": null,
                "logo_url": null, "provider_domain": self.domain},
            "workload_trust": {"trust_domain": self.domain, "bundle_endpoint": format!("https://bundle.{}", self.domain),
                "bundle_profile": "https_spiffe", "control_service_identity": self.control, "control_service_role": "CONTROL",
                "edge_service_identity": self.edge, "edge_service_role": "EDGE"},
            "federation": {"control_endpoint": format!("https://control.{}/control", self.domain),
                "edge_endpoint": format!("edge.{}:8443", self.domain),
                "protocols": federation_base::SUPPORTED_PROTOCOLS, "base_capabilities": []},
            "agent_trust": {"ca_root": ca_root(self.ca_seed)},
            "directory": null, "application_protocols": ["a2a/1"], "transports": ["tls13"]
        })
    }

    pub fn domain_doc(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": "ptpan-provider-domain/1", "platform_id": self.id, "control_service_identity": self.control,
            "edge_service_identity": self.edge, "agent_ca_root": ca_root(self.ca_seed)
        }))
        .unwrap()
    }

    pub fn proof_url(&self) -> String {
        format!("http://{}/.well-known/ptpan-provider.json", self.domain)
    }

    pub fn bootstrap(&self) -> federation_base::identity_evidence::BootstrapAuthority {
        federation_base::identity_evidence::BootstrapAuthority {
            peer: federation_base::PlatformId::new(self.id.clone()).unwrap(),
            provider_domain: self.domain.clone(),
            expected_control_service_id: self.control.clone(),
            expected_control_endpoint: format!("https://control.{}/control", self.domain),
            expected_edge_service_id: self.edge.clone(),
            expected_edge_endpoint: format!("edge.{}:8443", self.domain),
            expected_bundle_endpoint: format!("https://bundle.{}", self.domain),
            expected_bundle_profile: "https_spiffe".into(),
            max_evidence_age_seconds: 3600,
        }
    }
}
