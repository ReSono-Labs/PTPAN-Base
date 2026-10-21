//! `AdapterService` (D1, D2): served on a private socket for the platform
//! only. Policy calls are stateless and backed by Base; the adapter keeps
//! nothing from them.

use crate::peers::Resolution;
use crate::Adapter;
use ptpan_platform_api::policy;
use ptpan_platform_api::v1 as api;
use ptpan_platform_api::v1::adapter_service_server::{AdapterService, AdapterServiceServer};
use ptpan_platform_api::transport;
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct Service(pub Arc<Adapter>);

pub async fn serve(adapter: Arc<Adapter>) -> Result<(), crate::Error> {
    let listener = transport::bind(&adapter.config.adapter_socket)?;
    let uid = adapter.config.platform_uid;
    tonic::transport::Server::builder()
        .add_service(AdapterServiceServer::new(Service(adapter)))
        .serve_with_incoming(transport::incoming(listener, uid))
        .await?;
    Ok(())
}

fn internal(e: impl std::fmt::Display) -> Status {
    Status::internal(e.to_string())
}

#[tonic::async_trait]
impl AdapterService for Service {
    async fn wake(&self, _: Request<api::WakeRequest>) -> Result<Response<api::WakeResponse>, Status> {
        self.0.wake.notify_one();
        Ok(Response::new(api::WakeResponse {}))
    }

    async fn get_health(&self, _: Request<api::GetHealthRequest>) -> Result<Response<api::Health>, Status> {
        let adapter = &self.0;
        let state = |up: bool| if up { api::ComponentState::Up } else { api::ComponentState::Down } as i32;
        let components = vec![
            api::ComponentHealth { component: "runtime".into(), state: state(true), detail: String::new() },
            api::ComponentHealth { component: "platform".into(), state: state(adapter.platform_reachable()), detail: String::new() },
            api::ComponentHealth { component: "bridge".into(), state: state(adapter.bridge_reachable()), detail: String::new() },
        ];
        let now = federation_base::time::now_unix();
        let peers = adapter
            .peer_states(now)
            .await
            .map_err(internal)?
            .into_iter()
            .map(|(id, state, queued)| api::PeerHealth {
                peer_platform_id: id.as_str().into(),
                peer_state: format!("{state:?}").to_uppercase(),
                reachable: adapter.bridge_reachable(),
                queued_events: queued,
            })
            .collect();
        Ok(Response::new(api::Health { components, peers }))
    }

    async fn resolve_address(
        &self,
        request: Request<api::ResolveAddressRequest>,
    ) -> Result<Response<api::ResolveAddressResponse>, Status> {
        use api::ResolveResult as R;
        let resolution = self.0.resolve_address(&request.get_ref().address).await.map_err(internal)?;
        let (result, peer, ca_root) = match resolution {
            Resolution::Peer(id, record) => {
                let ca_root = record
                    .current
                    .as_ref()
                    .and_then(|m| federation_base::provider_manifest::parse_manifest(&m.exact_bytes).ok())
                    .map(|s| s.manifest.agent_trust.ca_root)
                    .unwrap_or_default();
                (R::Peer, id.as_str().to_owned(), ca_root)
            }
            Resolution::BadSyntax => (R::BadSyntax, String::new(), String::new()),
            Resolution::UnknownProvider => (R::UnknownProvider, String::new(), String::new()),
            Resolution::PeerNotActive(id) => (R::PeerNotActive, id.as_str().to_owned(), String::new()),
            Resolution::OwnPlatform => (R::OwnPlatform, String::new(), String::new()),
        };
        Ok(Response::new(api::ResolveAddressResponse { result: result as i32, peer_platform_id: peer, agent_ca_root: ca_root }))
    }

    async fn validate_request(
        &self,
        request: Request<api::ValidateRequestRequest>,
    ) -> Result<Response<api::ValidateRequestResponse>, Status> {
        Ok(Response::new(policy::validate_request(request.get_ref())))
    }

    async fn compute_terms_digest(
        &self,
        request: Request<api::ComputeTermsDigestRequest>,
    ) -> Result<Response<api::ComputeTermsDigestResponse>, Status> {
        Ok(Response::new(policy::compute_terms_digest(request.get_ref())))
    }

    async fn compute_lease(
        &self,
        request: Request<api::ComputeLeaseRequest>,
    ) -> Result<Response<api::ComputeLeaseResponse>, Status> {
        Ok(Response::new(policy::compute_lease(&self.0.config.platform_id, request.into_inner())))
    }
}
