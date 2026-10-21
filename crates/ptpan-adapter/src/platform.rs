//! The adapter's client for its own platform's `PlatformService`. The
//! channel reconnects on its own; when the platform is down, calls fail and
//! the caller keeps its work queued (principle 11).

use ptpan_platform_api::transport;
use ptpan_platform_api::v1::platform_service_client::PlatformServiceClient;
use std::path::PathBuf;
use tokio::sync::Mutex;
use tonic::transport::Channel;

pub struct Platform {
    socket: PathBuf,
    uid: u32,
    channel: Mutex<Option<Channel>>,
}

impl Platform {
    pub fn new(socket: PathBuf, uid: u32) -> Self {
        Self { socket, uid, channel: Mutex::new(None) }
    }

    /// A client on the cached channel, connecting first if needed.
    pub async fn client(&self) -> Result<PlatformServiceClient<Channel>, tonic::Status> {
        let mut guard = self.channel.lock().await;
        if guard.is_none() {
            let channel = transport::connect(&self.socket, self.uid)
                .await
                .map_err(|e| tonic::Status::unavailable(format!("platform: {e}")))?;
            *guard = Some(channel);
        }
        Ok(PlatformServiceClient::new(guard.clone().expect("channel set")))
    }

    /// Drop the cached channel after a transport failure.
    pub async fn reset(&self) {
        *self.channel.lock().await = None;
    }
}
