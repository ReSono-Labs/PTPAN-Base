//! Private length-framed Unix socket between the adapter runtime (Rust) and
//! the bridge (Go), schema `base-bridge-ipc/v2`. Each side checks the other's
//! user ID. Service IDs on inbound calls are the ones the bridge took from
//! the peer's certificate after go-spiffe mutual TLS, never a claimed value.
//!
//! Runtime → bridge: `SEND_CONTROL`, `SET_PEERS`, `FETCH_DOMAIN_PROOF`,
//! `CLOSE_STREAMS`. Bridge → runtime: `RECEIVE_CONTROL`, `ADMIT`,
//! `ROUTE_EGRESS`. The bridge never decides trust: it asks the runtime.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub const SCHEMA: &str = "base-bridge-ipc/v2";
pub const MAX_FRAME_BYTES: usize = 128 << 10;
pub const MAX_BODY_BYTES: usize = 72 << 10;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Operation {
    SendControl,
    ReceiveControl,
    SetPeers,
    FetchDomainProof,
    CloseStreams,
    Admit,
    RouteEgress,
}

impl Operation {
    /// Operations that name a peer service: the runtime's choice of
    /// destination (send) or the bridge's authenticated peer (inbound).
    fn names_service(self) -> bool {
        matches!(self, Self::SendControl | Self::ReceiveControl | Self::Admit)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub operation: Operation,
    pub service_id: String,
    #[serde(with = "base64_bytes")]
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub schema: String,
    #[serde(with = "base64_bytes")]
    pub body: Vec<u8>,
    pub error_code: String,
}

impl Response {
    pub fn ok(body: Vec<u8>) -> Self {
        Self { schema: SCHEMA.into(), body, error_code: String::new() }
    }
    pub fn error(code: &str) -> Self {
        Self { schema: SCHEMA.into(), body: Vec::new(), error_code: code.into() }
    }
}

/// One trusted peer's routes, as the runtime publishes them (principle 10).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRoute {
    pub control_service_id: String,
    pub control_endpoint: String,
    pub edge_service_id: String,
    pub edge_endpoint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetPeersBody {
    /// Increases with every change; the bridge ignores an older set.
    pub version: u64,
    pub routes: Vec<PeerRoute>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchDomainProofBody {
    pub url: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainProofReply {
    pub url: String,
    pub fetched_at: String,
    #[serde(with = "base64_bytes")]
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseStreamsBody {
    /// Close streams of this relationship, or every stream of `peer_service_id`.
    pub relationship_id: Option<String>,
    pub peer_service_id: Option<String>,
}

/// The runtime's answer to `ADMIT`. `response` goes back to the source relay
/// unchanged; the other fields tell the bridge where and how long to carry
/// the stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmitReply {
    #[serde(with = "base64_bytes")]
    pub response: Vec<u8>,
    pub allow: bool,
    pub deadline: u64,
    pub relationship_id: String,
    pub destination_address: String,
}

/// The runtime's answer to `ROUTE_EGRESS` (platform resolver result).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteEgressReply {
    pub edge_service_id: String,
    pub edge_endpoint: String,
    pub relationship_id: String,
}

#[derive(Debug)]
pub enum IpcError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidFrame,
    WrongUid,
    InvalidMessage,
}
impl From<std::io::Error> for IpcError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<serde_json::Error> for IpcError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl Request {
    pub fn new(operation: Operation, service_id: &str, body: Vec<u8>) -> Self {
        Self { schema: SCHEMA.into(), operation, service_id: service_id.into(), body }
    }

    pub fn validate(&self) -> Result<(), IpcError> {
        if self.schema != SCHEMA
            || self.body.is_empty()
            || self.body.len() > MAX_BODY_BYTES
            || self.operation.names_service() == self.service_id.is_empty()
        {
            return Err(IpcError::InvalidMessage);
        }
        Ok(())
    }
}

/// Bind a local socket with mode 0660: the adapter, bridge and platform run
/// as different users in one dedicated group, and each side checks the other's
/// exact user ID on every connection. An existing socket at `path` is
/// replaced; any other kind of file is an error.
pub fn bind(path: &Path) -> Result<UnixListener, IpcError> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            return Err(IpcError::InvalidMessage);
        }
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

pub type Handler = Arc<dyn Fn(Request) -> Response + Send + Sync>;

/// Serve one framed request per connection, each on its own thread, until
/// the listener fails. Connections from any other user are closed unread.
pub fn serve(listener: UnixListener, expected_peer_uid: u32, handler: Handler) -> Result<(), IpcError> {
    loop {
        let (stream, _) = listener.accept()?;
        let handler = handler.clone();
        std::thread::spawn(move || {
            let _ = serve_one(stream, expected_peer_uid, &handler);
        });
    }
}

fn serve_one(mut stream: UnixStream, expected_peer_uid: u32, handler: &Handler) -> Result<(), IpcError> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    if peer_uid(&stream)? != expected_peer_uid {
        return Err(IpcError::WrongUid);
    }
    let request: Request = read_frame(&mut stream)?;
    let mut response = match request.validate() {
        Ok(()) => handler(request),
        Err(_) => Response::error("INVALID_REQUEST"),
    };
    response.schema = SCHEMA.to_owned();
    write_frame(&mut stream, &response)
}

pub fn call(path: &Path, expected_peer_uid: u32, request: &Request) -> Result<Response, IpcError> {
    request.validate()?;
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    if peer_uid(&stream)? != expected_peer_uid {
        return Err(IpcError::WrongUid);
    }
    write_frame(&mut stream, request)?;
    let response: Response = read_frame(&mut stream)?;
    if response.schema != SCHEMA
        || response.body.len() > MAX_BODY_BYTES
        || (response.error_code.is_empty() && response.body.is_empty())
    {
        return Err(IpcError::InvalidMessage);
    }
    Ok(response)
}

fn peer_uid(stream: &UnixStream) -> Result<u32, IpcError> {
    let mut credential: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: SO_PEERCRED writes at most `len` bytes into `credential`.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credential as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(IpcError::Io(std::io::Error::last_os_error()));
    }
    if len as usize != std::mem::size_of::<libc::ucred>() {
        return Err(IpcError::InvalidFrame);
    }
    Ok(credential.uid)
}

fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), IpcError> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(IpcError::InvalidFrame);
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    Ok(())
}

fn read_frame<T: for<'a> Deserialize<'a>>(stream: &mut UnixStream) -> Result<T, IpcError> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err(IpcError::InvalidFrame);
    }
    let mut bytes = vec![0u8; size];
    stream.read_exact(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        STANDARD.decode(value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_wire_matches_go_encoding_and_rejects_extra_fields() {
        let request = Request::new(Operation::ReceiveControl, "spiffe://a.test/control", b"{\"x\":1}".to_vec());
        let encoded = serde_json::to_string(&request).unwrap();
        assert!(encoded.contains("\"body\":\"eyJ4IjoxfQ==\""));
        assert_eq!(serde_json::from_str::<Request>(&encoded).unwrap(), request);
        assert!(serde_json::from_str::<Request>(&encoded.replace("\"schema\":", "\"forged\":true,\"schema\":")).is_err());
    }

    #[test]
    fn service_id_is_present_exactly_for_peer_naming_operations() {
        for operation in [Operation::SendControl, Operation::ReceiveControl, Operation::Admit] {
            assert!(Request::new(operation, "spiffe://a.test/x", b"x".to_vec()).validate().is_ok());
            assert!(Request::new(operation, "", b"x".to_vec()).validate().is_err());
        }
        for operation in [Operation::SetPeers, Operation::FetchDomainProof, Operation::CloseStreams, Operation::RouteEgress] {
            assert!(Request::new(operation, "", b"x".to_vec()).validate().is_ok());
            assert!(Request::new(operation, "spiffe://a.test/x", b"x".to_vec()).validate().is_err());
        }
        let mut old = Request::new(Operation::SetPeers, "", b"x".to_vec());
        old.schema = "base-bridge-ipc/v1".into();
        assert!(old.validate().is_err());
        assert!(serde_json::from_str::<Operation>("\"RESOLVE_NAME_EVIDENCE\"").is_err());
    }

    #[test]
    fn unix_peer_credentials_gate_roundtrip() {
        let path = std::env::temp_dir().join(format!("federation-ipc-test-{}.sock", std::process::id()));
        let listener = bind(&path).unwrap();
        let uid = unsafe { libc::geteuid() };
        let handler: Handler = Arc::new(|request: Request| Response::ok(request.body));
        std::thread::spawn(move || serve(listener, uid, handler));
        let request = Request::new(Operation::SendControl, "spiffe://b.test/federation/control", b"hello".to_vec());
        assert_eq!(call(&path, uid, &request).unwrap().body, b"hello");
        assert_eq!(call(&path, uid, &request).unwrap().body, b"hello", "serves more than one connection");
        assert!(matches!(call(&path, uid + 1, &request), Err(IpcError::WrongUid)));
        fs::remove_file(path).unwrap();
    }
}
