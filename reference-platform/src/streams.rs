//! Agent streams (H12a, H12b) over the local sockets with the D11 framing:
//! a 4-byte big-endian length and the frame, then opaque bytes. The fixture
//! "agent" behind every address echoes what it receives; a real platform
//! connects the stream to the agent the address resolves to.

use crate::store::Db;
use crate::Platform;
use federation_base::live_admission::{sign_admission_token, AdmissionClaims, ADMISSION_SCHEMA};
use federation_base::time::now_unix;
use federation_base::{OpaqueId, RelationshipRequest};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub const MAX_FRAME_BYTES: usize = 8 << 10;

pub async fn write_frame(stream: &mut UnixStream, body: &[u8]) -> crate::Result<()> {
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err("frame size".into());
    }
    stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}

pub async fn read_frame(stream: &mut UnixStream) -> crate::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err("frame size".into());
    }
    let mut body = vec![0u8; size];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

fn peer_is(stream: &UnixStream, uid: u32) -> bool {
    stream.peer_cred().map(|c| c.uid() == uid).unwrap_or(false)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IngressHeader {
    schema: String,
    relationship_id: String,
    destination_address: String,
    deadline: u64,
}

impl Platform {
    /// Serve inbound agent streams from the local bridge only (H12b).
    pub async fn serve_ingress(self: Arc<Self>) -> crate::Result<()> {
        let listener = ptpan_platform_api::transport::bind(&self.config.ingress_socket)?;
        loop {
            let (stream, _) = listener.accept().await?;
            if !peer_is(&stream, self.config.bridge_uid) {
                continue;
            }
            let platform = self.clone();
            tokio::spawn(async move {
                let _ = platform.ingress(stream).await;
            });
        }
    }

    async fn ingress(&self, mut stream: UnixStream) -> crate::Result<()> {
        let header: IngressHeader = serde_json::from_slice(&read_frame(&mut stream).await?)?;
        if header.schema != "ptpan-ingress/1" {
            return Err("ingress schema".into());
        }
        let allowed = self.db.with(|c| {
            let Some((agent, _, _)) = Db::resolve(c, &header.destination_address)? else { return Ok(false) };
            let Some(r) = Db::relationship(c, &header.relationship_id)? else { return Ok(false) };
            Ok(r.side == "destination" && r.agent_id == agent && self.ready(c, &r, now_unix())?)
        })?;
        if !allowed {
            return Ok(());
        }
        let remaining = header.deadline.saturating_sub(now_unix());
        let echo = async {
            let mut buffer = [0u8; 4096];
            loop {
                let n = stream.read(&mut buffer).await?;
                if n == 0 {
                    return Ok::<_, std::io::Error>(());
                }
                stream.write_all(&buffer[..n]).await?;
            }
        };
        let _ = tokio::time::timeout(std::time::Duration::from_secs(remaining), echo).await;
        Ok(())
    }

    /// Open an agent stream on a ready source relationship (H12a): sign a
    /// fresh admission proof with the agent's key, send it through the local
    /// bridge, then exchange `payload`. Returns the edge's response JSON and
    /// the bytes the destination agent sent back.
    /// Open an admitted agent stream: sign a fresh admission token, send it
    /// on the egress socket and return the decision and the stream.
    async fn open_agent_stream(&self, relationship_id: &str) -> crate::Result<(serde_json::Value, UnixStream)> {
        let now = now_unix();
        let (r, request) = self.db.with(|c| {
            let r = Db::relationship(c, relationship_id)?.ok_or("unknown relationship")?;
            if r.side != "source" || !self.ready(c, &r, now)? {
                return Err("relationship is not ready".into());
            }
            let request: RelationshipRequest = serde_json::from_str(&r.request_json)?;
            Ok((r, request))
        })?;
        let lease: federation_base::control_event::LeaseWire = serde_json::from_str(&r.lease_json)?;
        let key = self.agent_key(&r.agent_id)?;
        let mut jti = [0u8; 16];
        std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut jti)?;
        let claims = AdmissionClaims {
            iss: self.config.platform_id.clone(),
            sub: request.source.address.clone(),
            aud: r.peer_edge_service_id.clone(),
            iat: now,
            exp: now + 30,
            jti: federation_base::encoding::hex_lower(&jti),
            relationship_id: OpaqueId::new(relationship_id)?,
            lease_id: lease.lease_id.clone(),
            lease_revision: lease.lease_revision,
            operation: "a2a.invoke".into(),
            destination_address: request.target_address.clone(),
            key_revision: r.key_revision,
        };
        let frame = serde_json::to_vec(&serde_json::json!({
            "schema": ADMISSION_SCHEMA, "token": sign_admission_token(&claims, &key),
            "destination_address": request.target_address, "relationship_id": relationship_id,
        }))?;
        let mut stream = UnixStream::connect(&self.config.egress_socket).await?;
        if !peer_is(&stream, self.config.bridge_uid) {
            return Err("unexpected egress socket owner".into());
        }
        write_frame(&mut stream, &frame).await?;
        let response: serde_json::Value = serde_json::from_slice(&read_frame(&mut stream).await?)?;
        Ok((response, stream))
    }

    /// One admitted call: send `payload`, read the echo.
    pub async fn call_agent(&self, relationship_id: &str, payload: &[u8]) -> crate::Result<(serde_json::Value, Vec<u8>)> {
        let (response, mut stream) = self.open_agent_stream(relationship_id).await?;
        if response["result"] != "ALLOW" {
            return Ok((response, Vec::new()));
        }
        stream.write_all(payload).await?;
        let mut echoed = vec![0u8; payload.len()];
        stream.read_exact(&mut echoed).await?;
        Ok((response, echoed))
    }

    /// Keep an admitted stream open, exchanging one byte a second, until the
    /// far side closes it or `max_seconds` pass. Returns the decision and the
    /// seconds the stream stayed open (used to check revoke cutoff, D12).
    pub async fn hold_agent(&self, relationship_id: &str, max_seconds: u64) -> crate::Result<(serde_json::Value, u64)> {
        let (response, mut stream) = self.open_agent_stream(relationship_id).await?;
        if response["result"] != "ALLOW" {
            return Ok((response, 0));
        }
        let started = std::time::Instant::now();
        let mut byte = [0u8; 1];
        while started.elapsed().as_secs() < max_seconds {
            if stream.write_all(b".").await.is_err() {
                break;
            }
            match tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut byte)).await {
                Ok(Ok(1)) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
                _ => break,
            }
        }
        Ok((response, started.elapsed().as_secs()))
    }
}
