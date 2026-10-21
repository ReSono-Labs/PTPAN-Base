//! Adapter configuration. Every value is local operator input; nothing here
//! comes from a peer.

use federation_base::identity_evidence::EvidenceProfile;
use federation_base::PlatformId;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub platform_id: PlatformId,
    /// Lowercase ASCII provider domain of every address this platform issues.
    pub provider_domain: String,
    /// This adapter's own control and edge SPIFFE IDs (as in its manifest).
    pub control_service_id: String,
    pub edge_service_id: String,
    /// PostgreSQL connection string for the exchange store.
    pub database_url: String,
    /// `PlatformService`, served by the platform.
    pub platform_socket: PathBuf,
    /// `AdapterService`, served here for the platform.
    pub adapter_socket: PathBuf,
    /// User ID the platform process runs as.
    pub platform_uid: u32,
    /// IPC served here for the bridge, and the bridge's own IPC socket.
    pub runtime_socket: PathBuf,
    pub bridge_socket: PathBuf,
    pub bridge_uid: u32,
    /// This platform's own current provider manifest (`federation-provider/2`).
    pub manifest_path: PathBuf,
    pub evidence_profile: EvidenceProfile,
    /// Unique per adapter copy; fences outbox workers per peer.
    pub worker_id: String,
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let config: Self = serde_json::from_slice(&bytes).map_err(|e| format!("config: {e}"))?;
        if !federation_base::address::valid_provider_domain(&config.provider_domain) {
            return Err("config: provider_domain must be lowercase ASCII with at least two labels".into());
        }
        if config.worker_id.is_empty() {
            return Err("config: worker_id is required".into());
        }
        Ok(config)
    }
}
