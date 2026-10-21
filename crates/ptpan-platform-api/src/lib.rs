//! The PTPAN adapter–platform API (`ptpan.platform.v1`, decision D2) as
//! generated Rust bindings, plus the one local transport both sides use: a
//! Unix socket on which each side checks the other's user ID. A platform in
//! another language generates its own bindings from the same proto file.

pub mod policy;

pub mod v1 {
    tonic::include_proto!("ptpan.platform.v1");
}

/// The API major this crate implements.
pub const API_MAJOR: u32 = 1;

/// Highest API major both sides declare. `None` means no common major: the
/// adapter pauses cross-platform features and reports why; the platform's own
/// features are unaffected (principle 9).
pub fn negotiate_major(local: &[u32], remote: &[u32]) -> Option<u32> {
    local.iter().copied().filter(|major| remote.contains(major)).max()
}

/// Local Unix-socket transport with peer user-ID checks on both sides.
pub mod transport {
    use hyper_util::rt::TokioIo;
    use std::io;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use tokio::net::{UnixListener, UnixStream};
    use tokio_stream::wrappers::UnixListenerStream;
    use tokio_stream::{Stream, StreamExt};
    use tonic::transport::{Channel, Endpoint};

    fn peer_is(stream: &UnixStream, expected_uid: u32) -> bool {
        stream
            .peer_cred()
            .map(|cred| cred.uid() == expected_uid)
            .unwrap_or(false)
    }

    /// Bind a local socket with mode 0660 (one dedicated group; each side
    /// checks the other's exact user ID). An existing socket file at `path`
    /// is replaced; any other kind of file is an error.
    pub fn bind(path: &Path) -> io::Result<UnixListener> {
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if !meta.file_type().is_socket() {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "path exists and is not a socket"));
            }
            std::fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        Ok(listener)
    }

    /// Accepted connections whose peer runs as `expected_uid`; all others are
    /// closed before any request is read.
    pub fn incoming(
        listener: UnixListener,
        expected_uid: u32,
    ) -> impl Stream<Item = io::Result<UnixStream>> {
        UnixListenerStream::new(listener).filter(move |accepted| match accepted {
            Ok(stream) => peer_is(stream, expected_uid),
            Err(_) => true,
        })
    }

    /// A channel to the socket at `path` whose server must run as
    /// `expected_uid`.
    pub async fn connect(path: &Path, expected_uid: u32) -> Result<Channel, tonic::transport::Error> {
        let path: PathBuf = path.to_owned();
        Endpoint::from_static("http://local.ptpan")
            .connect_with_connector(tower::service_fn(move |_| {
                let path = path.clone();
                async move {
                    let stream = UnixStream::connect(&path).await?;
                    if !peer_is(&stream, expected_uid) {
                        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unexpected socket owner"));
                    }
                    Ok::<_, io::Error>(TokioIo::new(stream))
                }
            }))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::v1::platform_service_client::PlatformServiceClient;
    use super::v1::platform_service_server::{PlatformService, PlatformServiceServer};
    use super::v1::*;
    use super::*;
    use tonic::{Request, Response, Status};

    #[test]
    fn negotiation_picks_the_highest_common_major() {
        assert_eq!(negotiate_major(&[1, 2], &[1]), Some(1));
        assert_eq!(negotiate_major(&[1, 2], &[2, 3]), Some(2));
        assert_eq!(negotiate_major(&[1], &[2]), None);
        assert_eq!(negotiate_major(&[], &[1]), None);
    }

    struct Fixture;

    fn unimplemented<T>() -> Result<Response<T>, Status> {
        Err(Status::unimplemented("fixture"))
    }

    #[tonic::async_trait]
    impl PlatformService for Fixture {
        async fn get_platform_info(&self, request: Request<GetPlatformInfoRequest>) -> Result<Response<PlatformInfo>, Status> {
            let majors = vec![API_MAJOR];
            if negotiate_major(&majors, &request.get_ref().adapter_api_majors).is_none() {
                return Err(Status::failed_precondition("no common API major"));
            }
            Ok(Response::new(PlatformInfo {
                platform_id: "provider-a".into(),
                provider_domain: "provider-a.test".into(),
                api_majors: majors,
                features: vec![],
            }))
        }
        async fn read_handoff(&self, _: Request<ReadHandoffRequest>) -> Result<Response<ReadHandoffResponse>, Status> { unimplemented() }
        async fn ack_handoff(&self, _: Request<AckHandoffRequest>) -> Result<Response<AckHandoffResponse>, Status> { unimplemented() }
        async fn authorize_source(&self, _: Request<AuthorizeSourceRequest>) -> Result<Response<AuthorizeSourceResponse>, Status> { unimplemented() }
        async fn deliver_inbound(&self, _: Request<DeliverInboundRequest>) -> Result<Response<DeliverInboundResponse>, Status> { unimplemented() }
        async fn apply_decision(&self, _: Request<ApplyDecisionRequest>) -> Result<Response<ApplyResponse>, Status> { unimplemented() }
        async fn apply_lifecycle(&self, _: Request<ApplyLifecycleRequest>) -> Result<Response<ApplyResponse>, Status> { unimplemented() }
        async fn confirm_receipt(&self, _: Request<ConfirmReceiptRequest>) -> Result<Response<ConfirmReceiptResponse>, Status> { unimplemented() }
        async fn record_notice(&self, _: Request<RecordNoticeRequest>) -> Result<Response<RecordNoticeResponse>, Status> { unimplemented() }
        async fn get_bound_key(&self, _: Request<GetBoundKeyRequest>) -> Result<Response<GetBoundKeyResponse>, Status> { unimplemented() }
        async fn admit_call(&self, _: Request<AdmitCallRequest>) -> Result<Response<AdmitCallResponse>, Status> { unimplemented() }
    }

    /// This process's user ID, read from a file it just created.
    fn uid(dir: &std::path::Path) -> u32 {
        std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(dir).unwrap())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn round_trip_over_a_private_socket_negotiates_the_major() {
        let dir = std::env::temp_dir().join(format!("ptpan-api-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("platform.sock");
        let listener = transport::bind(&path).unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&path).unwrap().permissions());
        assert_eq!(mode & 0o777, 0o660);
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(PlatformServiceServer::new(Fixture))
                .serve_with_incoming(transport::incoming(listener, uid(&dir))),
        );
        let channel = transport::connect(&path, uid(&dir)).await.unwrap();
        let mut client = PlatformServiceClient::new(channel);
        let info = client
            .get_platform_info(GetPlatformInfoRequest { adapter_api_majors: vec![1], adapter_features: vec![] })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(info.provider_domain, "provider-a.test");
        let refused = client
            .get_platform_info(GetPlatformInfoRequest { adapter_api_majors: vec![2], adapter_features: vec![] })
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert!(transport::connect(&path, uid(&dir) + 1).await.is_err(), "wrong server owner is refused");
        server.abort();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
