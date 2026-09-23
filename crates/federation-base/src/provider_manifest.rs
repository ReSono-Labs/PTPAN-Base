//! Project-owned provider identity snapshot. AGNTCY Directory publishes
//! records and routing metadata; it does not define provider business consent.
//! Every remote business field remains a claim until local evidence verifies it.

use crate::{PlatformId, MAX_JCS_INTEGER};
use http::Uri;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_MANIFEST_BYTES: usize = 64 << 10;

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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDiscovery {
    pub ai_catalog_url: String,
    pub host_identifier: Option<String>,
    pub host_trust_manifest_ref: Option<String>,
    pub directory_endpoint: String,
    pub directory_profile: String,
    pub publisher_name_ref: Option<String>,
    pub record_cids: Vec<String>,
    pub domain_proof_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadTrust {
    pub trust_domain: String,
    pub bundle_endpoint: String,
    pub bundle_profile: String,
    pub control_service_identity: String,
    pub control_service_role: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationEndpoint {
    pub control_endpoint: String,
    pub control_protocols: Vec<String>,
    pub relationship_lease_profiles: Vec<String>,
    pub base_capabilities: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSourceRefs {
    pub identity_evidence: Vec<String>,
    pub agent_card: Vec<String>,
    pub ans: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderManifest {
    pub schema: String,
    pub manifest_id: String,
    pub revision: u64,
    pub generated_at: String,
    pub platform: ProviderPlatform,
    pub discovery: ProviderDiscovery,
    pub workload_trust: WorkloadTrust,
    pub federation: FederationEndpoint,
    pub application_protocols: Vec<String>,
    pub transports: Vec<String>,
    pub source_refs: ProviderSourceRefs,
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
    let canonical_bytes =
        serde_json_canonicalizer::to_vec(&manifest).map_err(|_| ManifestError::Canonicalization)?;
    let digest = Sha256::digest(&canonical_bytes).into();
    Ok(ManifestSnapshot {
        manifest,
        exact_bytes: bytes.to_vec(),
        canonical_bytes,
        digest,
    })
}

impl ProviderManifest {
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema != "federation-provider/1" {
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
        optional_url(
            &self.platform.documentation_url,
            "platform.documentation_url",
        )?;
        optional_url(&self.platform.logo_url, "platform.logo_url")?;
        https_url(&self.discovery.ai_catalog_url, "discovery.ai_catalog_url")?;
        https_url(
            &self.discovery.directory_endpoint,
            "discovery.directory_endpoint",
        )?;
        bounded(
            &self.discovery.directory_profile,
            "discovery.directory_profile",
        )?;
        optional_bounded(&self.discovery.host_identifier, "discovery.host_identifier")?;
        optional_bounded(
            &self.discovery.host_trust_manifest_ref,
            "discovery.host_trust_manifest_ref",
        )?;
        optional_bounded(
            &self.discovery.publisher_name_ref,
            "discovery.publisher_name_ref",
        )?;
        optional_bounded(
            &self.discovery.domain_proof_ref,
            "discovery.domain_proof_ref",
        )?;
        if self.discovery.record_cids.len() > 32 {
            return Err(ManifestError::InvalidField("discovery.record_cids"));
        }
        for value in &self.discovery.record_cids {
            bounded(value, "discovery.record_cids")?;
        }
        bounded(
            &self.workload_trust.trust_domain,
            "workload_trust.trust_domain",
        )?;
        https_url(
            &self.workload_trust.bundle_endpoint,
            "workload_trust.bundle_endpoint",
        )?;
        bounded(
            &self.workload_trust.bundle_profile,
            "workload_trust.bundle_profile",
        )?;
        bounded(
            &self.workload_trust.control_service_identity,
            "workload_trust.control_service_identity",
        )?;
        bounded(
            &self.workload_trust.control_service_role,
            "workload_trust.control_service_role",
        )?;
        https_url(
            &self.federation.control_endpoint,
            "federation.control_endpoint",
        )?;
        list(
            &self.federation.control_protocols,
            "federation.control_protocols",
            true,
        )?;
        list(
            &self.federation.relationship_lease_profiles,
            "federation.relationship_lease_profiles",
            true,
        )?;
        list(
            &self.federation.base_capabilities,
            "federation.base_capabilities",
            false,
        )?;
        list(&self.application_protocols, "application_protocols", false)?;
        list(&self.transports, "transports", false)?;
        list(
            &self.source_refs.identity_evidence,
            "source_refs.identity_evidence",
            false,
        )?;
        list(
            &self.source_refs.agent_card,
            "source_refs.agent_card",
            false,
        )?;
        list(&self.source_refs.ans, "source_refs.ans", false)?;
        if self.source_refs.identity_evidence.len()
            + self.source_refs.agent_card.len()
            + self.source_refs.ans.len()
            > 32
        {
            return Err(ManifestError::InvalidField("source_refs"));
        }
        utc_timestamp(&self.generated_at)?;
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

fn bounded(value: &str, field: &'static str) -> Result<(), ManifestError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err(ManifestError::InvalidField(field))
    } else {
        Ok(())
    }
}
fn optional_bounded(value: &Option<String>, field: &'static str) -> Result<(), ManifestError> {
    if let Some(value) = value {
        bounded(value, field)?;
    }
    Ok(())
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct UtcInstant(
    pub u32,
    pub u32,
    pub u32,
    pub u32,
    pub u32,
    pub u32,
    pub u32,
);

pub(crate) fn utc_timestamp(value: &str) -> Result<UtcInstant, ManifestError> {
    let b = value.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || *b.last().unwrap() != b'Z'
    {
        return Err(ManifestError::InvalidTime);
    }
    for (index, byte) in b.iter().enumerate() {
        if matches!(index, 4 | 7 | 10 | 13 | 16)
            || index == b.len() - 1
            || (b.len() > 20 && index == 19)
        {
            continue;
        }
        if !byte.is_ascii_digit() {
            return Err(ManifestError::InvalidTime);
        }
    }
    if b.len() > 20 && (b[19] != b'.' || b.len() > 30 || b.len() < 22) {
        return Err(ManifestError::InvalidTime);
    }
    let part = |range: std::ops::Range<usize>| -> Result<u32, ManifestError> {
        std::str::from_utf8(&b[range])
            .map_err(|_| ManifestError::InvalidTime)?
            .parse()
            .map_err(|_| ManifestError::InvalidTime)
    };
    let year = part(0..4)?;
    let month = part(5..7)?;
    let day = part(8..10)?;
    let hour = part(11..13)?;
    let minute = part(14..16)?;
    let second = part(17..19)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return Err(ManifestError::InvalidTime);
    }
    let fraction = if b.len() > 20 {
        let digits = &value[20..value.len() - 1];
        let parsed: u32 = digits.parse().map_err(|_| ManifestError::InvalidTime)?;
        parsed * 10u32.pow(9 - digits.len() as u32)
    } else {
        0
    };
    Ok(UtcInstant(year, month, day, hour, minute, second, fraction))
}
