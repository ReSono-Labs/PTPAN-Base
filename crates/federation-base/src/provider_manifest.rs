//! Project-owned provider identity snapshot (`federation-provider/2`). It
//! describes the provider only, never its customers. Every business field is
//! a claim until the receiver's own checks verify it (identity_evidence).

use crate::encoding::{bounded_text, canonical_digest};
use crate::address::valid_provider_domain;
use crate::time::parse_utc;
use crate::{PlatformId, MAX_JCS_INTEGER};
use base64::Engine;
use http::uri::Authority;
use http::Uri;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_MANIFEST_BYTES: usize = 64 << 10;
pub const MANIFEST_SCHEMA: &str = "federation-provider/2";
/// Largest accepted agent CA root certificate (DER bytes).
pub const MAX_CA_ROOT_DER_BYTES: usize = 8 << 10;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimSource {
    LocalMetadata,
    AiCatalog,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPlatform {
    pub platform_id: PlatformId,
    pub display_name: String,
    pub display_name_source: ClaimSource,
    pub operator_name: String,
    pub website: String,
    pub documentation_url: Option<String>,
    pub logo_url: Option<String>,
    /// The verified provider domain: the suffix of every address this
    /// platform issues (D10) and the host of its domain proof (D14).
    pub provider_domain: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadTrust {
    pub trust_domain: String,
    pub bundle_endpoint: String,
    pub bundle_profile: String,
    pub control_service_identity: String,
    pub control_service_role: String,
    pub edge_service_identity: String,
    pub edge_service_role: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationEndpoint {
    pub control_endpoint: String,
    /// `host:port` of the agent-traffic edge (D11).
    pub edge_endpoint: String,
    /// Supported protocol versions, one entry per version, for example
    /// `federation-control/v3` or `FRL/1` (D2).
    pub protocols: Vec<String>,
    pub base_capabilities: Vec<String>,
}

/// Trust anchor for the platform's agent certificates (D13).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTrust {
    /// Base64 (standard alphabet, padded) DER of the private CA root.
    pub ca_root: String,
}

/// Optional AGNTCY Directory evidence (D14: additional, never required).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEvidence {
    pub endpoint: String,
    pub profile: String,
    pub record_cids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderManifest {
    pub schema: String,
    pub manifest_id: String,
    pub revision: u64,
    pub generated_at: String,
    pub platform: ProviderPlatform,
    pub workload_trust: WorkloadTrust,
    pub federation: FederationEndpoint,
    pub agent_trust: AgentTrust,
    pub directory: Option<DirectoryEvidence>,
    pub application_protocols: Vec<String>,
    pub transports: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestSnapshot {
    pub manifest: ProviderManifest,
    pub exact_bytes: Vec<u8>,
    pub canonical_bytes: Vec<u8>,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestError {
    TooLarge,
    InvalidJson,
    InvalidSchema,
    InvalidField(&'static str),
    InvalidTime,
    InvalidRevision,
    WrongPlatform,
    WrongService,
    Canonicalization,
}

pub fn parse_manifest(bytes: &[u8]) -> Result<ManifestSnapshot, ManifestError> {
    if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::TooLarge);
    }
    let manifest: ProviderManifest =
        serde_json::from_slice(bytes).map_err(|_| ManifestError::InvalidJson)?;
    manifest.validate()?;
    let (canonical_bytes, digest) =
        canonical_digest(&manifest).ok_or(ManifestError::Canonicalization)?;
    Ok(ManifestSnapshot {
        manifest,
        exact_bytes: bytes.to_vec(),
        canonical_bytes,
        digest,
    })
}

/// Decode an agent CA root: padded standard base64 of a DER structure.
pub fn decode_ca_root(value: &str) -> Option<Vec<u8>> {
    let der = base64::engine::general_purpose::STANDARD.decode(value).ok()?;
    (der.len() >= 64 && der.len() <= MAX_CA_ROOT_DER_BYTES && der[0] == 0x30).then_some(der)
}

/// `name/version` with an optional `v`, for example `federation-peer/v2`.
fn protocol_entry(value: &str) -> Option<(&str, u32)> {
    let (name, version) = value.split_once('/')?;
    let digits = version.strip_prefix('v').unwrap_or(version);
    let valid_name = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if !valid_name || digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((name, digits.parse().ok()?))
}

/// Highest common version for every protocol family in `local` (D2). Fails
/// with the first family the peer does not share.
pub fn negotiate_protocols<'a>(
    local: &[&'a str],
    remote: &[String],
) -> Result<Vec<&'a str>, &'a str> {
    let mut families: Vec<&str> = Vec::new();
    for entry in local {
        if let Some((name, _)) = protocol_entry(entry) {
            if !families.contains(&name) {
                families.push(name);
            }
        }
    }
    let mut selected = Vec::new();
    for family in families {
        let best = local
            .iter()
            .filter(|entry| protocol_entry(entry).is_some_and(|(name, _)| name == family))
            .filter(|entry| remote.iter().any(|r| r == **entry))
            .max_by_key(|entry| protocol_entry(entry).map(|(_, v)| v));
        match best {
            Some(entry) => selected.push(*entry),
            None => return Err(family),
        }
    }
    Ok(selected)
}

impl ProviderManifest {
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema != MANIFEST_SCHEMA {
            return Err(ManifestError::InvalidSchema);
        }
        if self.revision == 0 || self.revision > MAX_JCS_INTEGER {
            return Err(ManifestError::InvalidRevision);
        }
        bounded(&self.manifest_id, "manifest_id")?;
        bounded(self.platform.platform_id.as_str(), "platform.platform_id")?;
        bounded(&self.platform.display_name, "platform.display_name")?;
        bounded(&self.platform.operator_name, "platform.operator_name")?;
        https_url(&self.platform.website, "platform.website")?;
        optional_url(&self.platform.documentation_url, "platform.documentation_url")?;
        optional_url(&self.platform.logo_url, "platform.logo_url")?;
        if !valid_provider_domain(&self.platform.provider_domain) {
            return Err(ManifestError::InvalidField("platform.provider_domain"));
        }
        let trust = &self.workload_trust;
        bounded(&trust.trust_domain, "workload_trust.trust_domain")?;
        https_url(&trust.bundle_endpoint, "workload_trust.bundle_endpoint")?;
        bounded(&trust.bundle_profile, "workload_trust.bundle_profile")?;
        bounded(&trust.control_service_identity, "workload_trust.control_service_identity")?;
        bounded(&trust.control_service_role, "workload_trust.control_service_role")?;
        bounded(&trust.edge_service_identity, "workload_trust.edge_service_identity")?;
        bounded(&trust.edge_service_role, "workload_trust.edge_service_role")?;
        if trust.edge_service_identity == trust.control_service_identity {
            return Err(ManifestError::InvalidField("workload_trust.edge_service_identity"));
        }
        https_url(&self.federation.control_endpoint, "federation.control_endpoint")?;
        host_port(&self.federation.edge_endpoint, "federation.edge_endpoint")?;
        list(&self.federation.protocols, "federation.protocols", true)?;
        if self.federation.protocols.iter().any(|p| protocol_entry(p).is_none()) {
            return Err(ManifestError::InvalidField("federation.protocols"));
        }
        list(&self.federation.base_capabilities, "federation.base_capabilities", false)?;
        if decode_ca_root(&self.agent_trust.ca_root).is_none() {
            return Err(ManifestError::InvalidField("agent_trust.ca_root"));
        }
        if let Some(directory) = &self.directory {
            https_url(&directory.endpoint, "directory.endpoint")?;
            bounded(&directory.profile, "directory.profile")?;
            if directory.record_cids.len() > 32 {
                return Err(ManifestError::InvalidField("directory.record_cids"));
            }
            list(&directory.record_cids, "directory.record_cids", false)?;
        }
        list(&self.application_protocols, "application_protocols", false)?;
        list(&self.transports, "transports", false)?;
        parse_utc(&self.generated_at).ok_or(ManifestError::InvalidTime)?;
        Ok(())
    }

    /// Transport evidence comes from go-spiffe, never the JSON sender claim.
    pub fn check_authenticated_binding(
        &self,
        expected_platform: &PlatformId,
        authenticated_service: &str,
    ) -> Result<(), ManifestError> {
        if &self.platform.platform_id != expected_platform {
            return Err(ManifestError::WrongPlatform);
        }
        if self.workload_trust.control_service_identity != authenticated_service {
            return Err(ManifestError::WrongService);
        }
        Ok(())
    }
}

fn host_port(value: &str, field: &'static str) -> Result<(), ManifestError> {
    let authority: Authority = value.parse().map_err(|_| ManifestError::InvalidField(field))?;
    if authority.as_str() != value
        || authority.as_str().contains('@')
        || authority.host().is_empty()
        || authority.port_u16().is_none_or(|port| port == 0)
    {
        return Err(ManifestError::InvalidField(field));
    }
    Ok(())
}

fn bounded(value: &str, field: &'static str) -> Result<(), ManifestError> {
    if bounded_text(value) {
        Ok(())
    } else {
        Err(ManifestError::InvalidField(field))
    }
}
fn https_url(value: &str, field: &'static str) -> Result<(), ManifestError> {
    let parsed: Uri = value
        .parse()
        .map_err(|_| ManifestError::InvalidField(field))?;
    if parsed.scheme_str() != Some("https")
        || parsed
            .authority()
            .is_none_or(|a| a.host().is_empty() || a.as_str().contains('@'))
        || value.contains('#')
    {
        return Err(ManifestError::InvalidField(field));
    }
    Ok(())
}
fn optional_url(value: &Option<String>, field: &'static str) -> Result<(), ManifestError> {
    if let Some(value) = value {
        https_url(value, field)?;
    }
    Ok(())
}
fn list(values: &[String], field: &'static str, required: bool) -> Result<(), ManifestError> {
    if values.len() > 64 || (required && values.is_empty()) {
        return Err(ManifestError::InvalidField(field));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        bounded(value, field)?;
        if !seen.insert(value) {
            return Err(ManifestError::InvalidField(field));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A DER-shaped placeholder for the agent CA root (structure only).
    pub(crate) fn test_ca_root() -> String {
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.resize(260, 0x5a);
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    pub(crate) fn valid() -> ProviderManifest {
        ProviderManifest {
            schema: MANIFEST_SCHEMA.into(),
            manifest_id: "manifest-b-1".into(),
            revision: 1,
            generated_at: "2026-09-23T08:00:00Z".into(),
            platform: ProviderPlatform {
                platform_id: PlatformId::new("provider-b").unwrap(),
                display_name: "Provider B".into(),
                display_name_source: ClaimSource::LocalMetadata,
                operator_name: "B Example LLC".into(),
                website: "https://provider-b.test".into(),
                documentation_url: None,
                logo_url: None,
                provider_domain: "provider-b.test".into(),
            },
            workload_trust: WorkloadTrust {
                trust_domain: "provider-b.test".into(),
                bundle_endpoint: "https://bundle.provider-b.test".into(),
                bundle_profile: "https_spiffe".into(),
                control_service_identity: "spiffe://provider-b.test/federation/control".into(),
                control_service_role: "CONTROL".into(),
                edge_service_identity: "spiffe://provider-b.test/federation/edge".into(),
                edge_service_role: "EDGE".into(),
            },
            federation: FederationEndpoint {
                control_endpoint: "https://control.provider-b.test/control".into(),
                edge_endpoint: "edge.provider-b.test:8443".into(),
                protocols: crate::SUPPORTED_PROTOCOLS.map(String::from).to_vec(),
                base_capabilities: vec![],
            },
            agent_trust: AgentTrust { ca_root: test_ca_root() },
            directory: None,
            application_protocols: vec!["a2a/1".into()],
            transports: vec!["tls13".into()],
        }
    }

    #[test]
    fn exact_bytes_digest_and_transport_binding() {
        let raw = serde_json::to_vec(&valid()).unwrap();
        let snapshot = parse_manifest(&raw).unwrap();
        assert_eq!(snapshot.exact_bytes, raw);
        assert_ne!(snapshot.digest, [0; 32]);
        let b = PlatformId::new("provider-b").unwrap();
        snapshot
            .manifest
            .check_authenticated_binding(&b, "spiffe://provider-b.test/federation/control")
            .unwrap();
        assert_eq!(
            snapshot
                .manifest
                .check_authenticated_binding(&b, "spiffe://provider-b.test/federation/edge"),
            Err(ManifestError::WrongService)
        );
    }

    #[test]
    fn duplicate_unknown_customer_field_and_malformed_claims_fail() {
        let raw = serde_json::to_string(&valid()).unwrap();
        assert_eq!(
            parse_manifest(raw.replace("\"revision\":1", "\"revision\":1,\"revision\":2").as_bytes()),
            Err(ManifestError::InvalidJson)
        );
        assert_eq!(
            parse_manifest(raw.replace("\"operator_name\":", "\"account_inventory\":[],\"operator_name\":").as_bytes()),
            Err(ManifestError::InvalidJson)
        );
        assert_eq!(
            parse_manifest(raw.replace(MANIFEST_SCHEMA, "federation-provider/1").as_bytes()),
            Err(ManifestError::InvalidSchema)
        );
        type Case = (fn(&mut ProviderManifest), ManifestError);
        let cases: [Case; 7] = [
            (|m| m.generated_at = "2026-09-23T04:00:00-04:00".into(), ManifestError::InvalidTime),
            (|m| m.federation.edge_endpoint = "https://edge.provider-b.test:8443".into(), ManifestError::InvalidField("federation.edge_endpoint")),
            (|m| m.federation.edge_endpoint = "edge.provider-b.test".into(), ManifestError::InvalidField("federation.edge_endpoint")),
            (|m| m.federation.protocols = vec!["federation-control".into()], ManifestError::InvalidField("federation.protocols")),
            (|m| m.agent_trust.ca_root = "bm90IGEgY2VydA==".into(), ManifestError::InvalidField("agent_trust.ca_root")),
            (|m| m.platform.provider_domain = "Provider-B.test".into(), ManifestError::InvalidField("platform.provider_domain")),
            (|m| m.workload_trust.edge_service_identity = m.workload_trust.control_service_identity.clone(), ManifestError::InvalidField("workload_trust.edge_service_identity")),
        ];
        for (change, error) in cases {
            let mut bad = valid();
            change(&mut bad);
            assert_eq!(bad.validate(), Err(error));
        }
        let mut with_directory = valid();
        with_directory.directory = Some(DirectoryEvidence {
            endpoint: "http://directory.provider-b.test".into(),
            profile: "SPIRE_X509".into(),
            record_cids: vec![],
        });
        assert_eq!(with_directory.validate(), Err(ManifestError::InvalidField("directory.endpoint")));
    }

    #[test]
    fn checked_in_schema_matches_the_wire_type() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/provider-manifest-v2.json")).unwrap();
        assert_eq!(schema["$id"], MANIFEST_SCHEMA);
        let mut with_directory = valid();
        with_directory.directory = Some(DirectoryEvidence {
            endpoint: "https://directory.provider-b.test".into(),
            profile: "SPIRE_X509".into(),
            record_cids: vec!["bafy".into()],
        });
        for manifest in [valid(), with_directory] {
            let value = serde_json::to_value(&manifest).unwrap();
            crate::schema_check::matches(&schema, &schema, &value, "manifest");
        }
    }

    #[test]
    fn negotiation_picks_the_highest_common_version_per_family() {
        let local = ["federation-control/v3", "federation-control/v4", "FRL/1"];
        let remote = vec!["federation-control/v3".to_string(), "federation-control/v4".into(), "FRL/1".into()];
        assert_eq!(negotiate_protocols(&local, &remote), Ok(vec!["federation-control/v4", "FRL/1"]));
        let older = vec!["federation-control/v3".to_string(), "FRL/1".into()];
        assert_eq!(negotiate_protocols(&local, &older), Ok(vec!["federation-control/v3", "FRL/1"]));
        let missing = vec!["federation-control/v2".to_string(), "FRL/1".into()];
        assert_eq!(negotiate_protocols(&local, &missing), Err("federation-control"));
    }
}
