//! Private length-framed Unix socket for the Rust Base and Go SDK bridge.
//! The verified service ID is supplied by the bridge after go-spiffe mTLS,
//! never by a network header or claimed JSON platform ID.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

pub const SCHEMA: &str = "base-bridge-ipc/v1";
pub const MAX_FRAME_BYTES: usize = 128 << 10;
pub const MAX_BODY_BYTES: usize = 72 << 10;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Operation {
    SendControl,
    ReceiveControl,
    ResolveNameEvidence,
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
    pub fn validate(&self) -> Result<(), IpcError> {
        if self.schema != SCHEMA || self.body.is_empty() || self.body.len() > MAX_BODY_BYTES {
            return Err(IpcError::InvalidMessage);
        }
        match self.operation {
            Operation::ResolveNameEvidence if !self.service_id.is_empty() => {
                Err(IpcError::InvalidMessage)
            }
            // Base selects the exact locally approved service for a send.
            // The bridge independently checks that service against its
            // configured peer routes before opening mTLS.
            Operation::SendControl if self.service_id.is_empty() => {
                Err(IpcError::InvalidMessage)
            }
            Operation::ReceiveControl if self.service_id.is_empty() => {
                Err(IpcError::InvalidMessage)
            }
            _ => Ok(()),
        }
    }
}

pub fn bind(path: &Path) -> Result<UnixListener, IpcError> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub fn accept_one<F>(
    listener: &UnixListener,
    expected_bridge_uid: u32,
    handle: F,
) -> Result<(), IpcError>
where
    F: FnOnce(Request) -> Response,
{
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    if peer_uid(&stream)? != expected_bridge_uid {
        return Err(IpcError::WrongUid);
    }
    let request: Request = read_frame(&mut stream)?;
    request.validate()?;
    let mut response = handle(request);
    response.schema = SCHEMA.to_owned();
    write_frame(&mut stream, &response)?;
    Ok(())
}

pub fn call(
    path: &Path,
    expected_bridge_uid: u32,
    request: &Request,
) -> Result<Response, IpcError> {
    request.validate()?;
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    if peer_uid(&stream)? != expected_bridge_uid {
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
        let request = Request {
            schema: SCHEMA.into(),
            operation: Operation::ReceiveControl,
            service_id: "spiffe://a.test/control".into(),
            body: b"{\"x\":1}".to_vec(),
        };
        let encoded = serde_json::to_string(&request).unwrap();
        assert!(encoded.contains("\"body\":\"eyJ4IjoxfQ==\""));
        assert_eq!(serde_json::from_str::<Request>(&encoded).unwrap(), request);
        assert!(serde_json::from_str::<Request>(
            &encoded.replace("\"schema\":", "\"forged\":true,\"schema\":")
        )
        .is_err());
    }
    #[test]
    fn unix_peer_credentials_gate_roundtrip() {
        let path = std::env::temp_dir().join(format!(
            "federation-ipc-test-{}-{}.sock",
            std::process::id(),
            1
        ));
        let listener = bind(&path).unwrap();
        let uid = unsafe { libc::geteuid() };
        let worker = std::thread::spawn(move || {
            accept_one(&listener, uid, |request| Response {
                schema: String::new(),
                body: request.body,
                error_code: String::new(),
            })
            .unwrap()
        });
        let request = Request {
            schema: SCHEMA.into(),
            operation: Operation::SendControl,
            service_id: "spiffe://b.test/federation/control".into(),
            body: b"hello".to_vec(),
        };
        let reply = call(&path, uid, &request).unwrap();
        assert_eq!(reply.body, b"hello");
        worker.join().unwrap();
        fs::remove_file(path).unwrap();
    }
}
