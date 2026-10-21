//! Async wrappers around the runtime-to-bridge IPC (`base-bridge-ipc/v2`).
//! The IPC itself is a blocking framed socket, so each call runs on the
//! blocking pool.

use federation_ipc::{
    call, CloseStreamsBody, DomainProofReply, FetchDomainProofBody, Operation, Request, SetPeersBody,
};
use std::path::PathBuf;

#[derive(Clone)]
pub struct Bridge {
    pub socket: PathBuf,
    pub uid: u32,
}

#[derive(Debug)]
pub enum BridgeError {
    Unavailable(String),
    Refused(String),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(e) => write!(f, "bridge unavailable: {e}"),
            Self::Refused(code) => write!(f, "bridge refused: {code}"),
        }
    }
}

impl std::error::Error for BridgeError {}

impl Bridge {
    async fn call(&self, operation: Operation, service_id: &str, body: Vec<u8>) -> Result<Vec<u8>, BridgeError> {
        let request = Request::new(operation, service_id, body);
        let socket = self.socket.clone();
        let uid = self.uid;
        let response = tokio::task::spawn_blocking(move || call(&socket, uid, &request))
            .await
            .map_err(|e| BridgeError::Unavailable(e.to_string()))?
            .map_err(|e| BridgeError::Unavailable(format!("{e:?}")))?;
        if response.error_code.is_empty() {
            Ok(response.body)
        } else {
            Err(BridgeError::Refused(response.error_code))
        }
    }

    /// Deliver exact bytes to a peer's control service; returns its receipt.
    pub async fn send(&self, control_service_id: &str, bytes: Vec<u8>) -> Result<Vec<u8>, BridgeError> {
        self.call(Operation::SendControl, control_service_id, bytes).await
    }

    pub async fn set_peers(&self, body: &SetPeersBody) -> Result<(), BridgeError> {
        self.call(Operation::SetPeers, "", serde_json::to_vec(body).expect("peers")).await.map(|_| ())
    }

    pub async fn fetch_domain_proof(&self, url: &str) -> Result<DomainProofReply, BridgeError> {
        let body = serde_json::to_vec(&FetchDomainProofBody { url: url.into() }).expect("fetch body");
        let reply = self.call(Operation::FetchDomainProof, "", body).await?;
        serde_json::from_slice(&reply).map_err(|e| BridgeError::Unavailable(e.to_string()))
    }

    pub async fn close_streams(&self, body: &CloseStreamsBody) -> Result<(), BridgeError> {
        self.call(Operation::CloseStreams, "", serde_json::to_vec(body).expect("close body")).await.map(|_| ())
    }
}
