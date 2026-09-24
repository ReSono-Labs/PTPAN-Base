//! Locally computed provider authority checks. Directory naming verifies a
//! record's domain key and go-spiffe verifies a workload service. Neither
//! alone verifies a legal business or grants operator trust.

use crate::provider_manifest::{utc_timestamp, ManifestSnapshot};
use crate::PlatformId;
use http::Uri;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceProfile {
    ProductionHttps,
    LocalHttpTest,
}

/// The Go bridge must populate this from the selected Directory SDK's
/// GetVerificationInfo and Pull on an exact-ID authenticated connection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryNameEvidence {
    pub record_cid: String,
    pub record_name: String,
    pub verified: bool,
    pub domain: String,
    pub method: String,
    pub key_id: String,
    pub verified_at: String,
    pub source_directory_service_id: String,
}

/// Independently provisioned local operator bootstrap expectations. These
/// values must not be copied from the remote manifest being checked.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapAuthority {
    pub peer: PlatformId,
    pub provider_domain: String,
    pub expected_control_service_id: String,
    pub expected_control_endpoint: String,
    pub expected_directory_endpoint: String,
    pub expected_local_directory_service_id: String,
    pub expected_bundle_endpoint: String,
    pub expected_bundle_profile: String,
    pub max_evidence_age_seconds: i64,
}

impl BootstrapAuthority {
    pub fn digest(&self) -> [u8; 32] {
        let bytes =
            serde_json_canonicalizer::to_vec(self).expect("bootstrap authority serialization");
        Sha256::digest(&bytes).into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityError {
    WrongPeer,
    WrongService,
    WrongDomain,
    WrongEndpoint,
    WrongDirectory,
    WrongBundle,
    WrongRecord,
    UnverifiedName,
    StaleOrInvalidEvidence,
    UnsupportedProfile,
}

/// Receiver-owned result for one manifest or evidence field. `VERIFIED` names
/// the property that was checked. It is not a verified-provider flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationResult {
    SelfDeclared,
    Verified,
    Mismatch,
    Unavailable,
    ReviewRequired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FieldObservation {
    pub field_path: String,
    pub observed_value: String,
    pub source: String,
    pub observed_at: String,
    pub evidence_revision: u64,
    pub freshness_seconds: Option<i64>,
    pub result: ObservationResult,
    pub verified_property: Option<String>,
    pub reason: String,
}

pub struct IdentityEvaluation {
    pub observations: Vec<FieldObservation>,
    pub binding: Result<VerifiedProviderBinding, IdentityError>,
}

/// The fields are private so persistence can only receive a value returned
/// by the evaluator, instead of a caller-provided boolean.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedProviderBinding {
    peer: PlatformId,
    manifest_revision: u64,
    manifest_digest: [u8; 32],
    observed_control_service_id: String,
    verified_domain: String,
    record_cid: String,
    key_id: String,
    source_directory_service_id: String,
    verified_at: String,
    profile: EvidenceProfile,
    bootstrap_digest: [u8; 32],
    observations: Vec<FieldObservation>,
}

impl VerifiedProviderBinding {
    pub fn peer(&self) -> &PlatformId {
        &self.peer
    }
    pub fn manifest_revision(&self) -> u64 {
        self.manifest_revision
    }
    pub fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }
    pub fn observed_control_service_id(&self) -> &str {
        &self.observed_control_service_id
    }
    pub fn verified_domain(&self) -> &str {
        &self.verified_domain
    }
    pub fn record_cid(&self) -> &str {
        &self.record_cid
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn source_directory_service_id(&self) -> &str {
        &self.source_directory_service_id
    }
    pub fn verified_at(&self) -> &str {
        &self.verified_at
    }
    pub fn profile(&self) -> EvidenceProfile {
        self.profile
    }
    pub fn bootstrap_digest(&self) -> [u8; 32] {
        self.bootstrap_digest
    }
    pub fn observations(&self) -> &[FieldObservation] {
        &self.observations
    }
}

pub fn verify_provider_binding(
    snapshot: &ManifestSnapshot,
    bootstrap: &BootstrapAuthority,
    observed_control_service_id: &str,
    evidence: &DirectoryNameEvidence,
    profile: EvidenceProfile,
    now_unix_seconds: i64,
) -> Result<VerifiedProviderBinding, IdentityError> {
    evaluate_provider_identity(
        snapshot,
        bootstrap,
        observed_control_service_id,
        evidence,
        profile,
        now_unix_seconds,
    )
    .binding
}

/// Field observations are produced even when the binding is rejected. A later
/// failed check does not mark unchecked fields verified.
pub fn evaluate_provider_identity(
    snapshot: &ManifestSnapshot,
    bootstrap: &BootstrapAuthority,
    observed_control_service_id: &str,
    evidence: &DirectoryNameEvidence,
    profile: EvidenceProfile,
    now_unix_seconds: i64,
) -> IdentityEvaluation {
    let manifest = &snapshot.manifest;
    let revision = manifest.revision;
    let claimed_at = manifest.generated_at.as_str();
    let mut observations = Vec::new();
    note(
        &mut observations,
        "platform.operator_name",
        &manifest.platform.operator_name,
        "manifest",
        claimed_at,
        revision,
        None,
        ObservationResult::SelfDeclared,
        None,
        "local operator name is a claim, not independent identity proof",
    );
    match manifest.platform.display_name_source {
        crate::provider_manifest::ClaimSource::LocalMetadata => note(
            &mut observations,
            "platform.display_name",
            &manifest.platform.display_name,
            "manifest",
            claimed_at,
            revision,
            None,
            ObservationResult::SelfDeclared,
            None,
            "display name is local metadata",
        ),
        crate::provider_manifest::ClaimSource::AiCatalog => note(
            &mut observations,
            "platform.display_name",
            &manifest.platform.display_name,
            "ai-catalog",
            claimed_at,
            revision,
            None,
            ObservationResult::ReviewRequired,
            None,
            "catalog display name is not operator identity",
        ),
    }
    if manifest.platform.platform_id != bootstrap.peer {
        note(
            &mut observations,
            "platform.platform_id",
            manifest.platform.platform_id.as_str(),
            "local-bootstrap",
            claimed_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "manifest platform id does not match the bootstrap peer",
        );
        return IdentityEvaluation {
            observations,
            binding: Err(IdentityError::WrongPeer),
        };
    }
    note(
        &mut observations,
        "platform.platform_id",
        manifest.platform.platform_id.as_str(),
        "local-bootstrap",
        claimed_at,
        revision,
        None,
        ObservationResult::Verified,
        Some("platform-binding"),
        "manifest platform id matches the local bootstrap peer",
    );

    let mut error = None;
    let service_prefix = format!("spiffe://{}/", bootstrap.provider_domain);
    if observed_control_service_id != bootstrap.expected_control_service_id
        || !observed_control_service_id.starts_with(&service_prefix)
    {
        note(
            &mut observations,
            "authenticated_control_service",
            observed_control_service_id,
            "authenticated-service",
            claimed_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "authenticated service is not the bootstrap control service in its provider domain",
        );
        error = Some(IdentityError::WrongService);
    } else {
        note(
            &mut observations,
            "authenticated_control_service",
            observed_control_service_id,
            "authenticated-service",
            claimed_at,
            revision,
            None,
            ObservationResult::Verified,
            Some("exact-service-authentication"),
            "authenticated SPIFFE ID matches the bootstrap control service",
        );
    }
    if manifest.workload_trust.control_service_identity != bootstrap.expected_control_service_id {
        note(
            &mut observations,
            "workload_trust.control_service_identity",
            &manifest.workload_trust.control_service_identity,
            "local-bootstrap",
            claimed_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "manifest control service does not match the bootstrap service",
        );
        let _ = error.get_or_insert(IdentityError::WrongService);
    } else if error.is_none() {
        note(
            &mut observations,
            "workload_trust.control_service_identity",
            &manifest.workload_trust.control_service_identity,
            "manifest",
            claimed_at,
            revision,
            None,
            ObservationResult::Verified,
            Some("exact-service-authentication"),
            "manifest control service matches the bootstrap service",
        );
    }
    if manifest.workload_trust.control_service_role != "CONTROL" {
        note(
            &mut observations,
            "workload_trust.control_service_role",
            &manifest.workload_trust.control_service_role,
            "manifest",
            claimed_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "control service role is not CONTROL",
        );
        let _ = error.get_or_insert(IdentityError::WrongService);
    } else if error.is_none() {
        note(
            &mut observations,
            "workload_trust.control_service_role",
            &manifest.workload_trust.control_service_role,
            "manifest",
            claimed_at,
            revision,
            None,
            ObservationResult::Verified,
            Some("control-role"),
            "manifest role is CONTROL",
        );
    }
    if error.is_some() {
        return IdentityEvaluation {
            observations,
            binding: Err(error.unwrap()),
        };
    }

    if manifest.workload_trust.trust_domain != bootstrap.provider_domain {
        note(
            &mut observations,
            "workload_trust.trust_domain",
            &manifest.workload_trust.trust_domain,
            "local-bootstrap",
            claimed_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "trust domain does not match the bootstrap provider domain",
        );
        error = Some(IdentityError::WrongDomain);
    } else {
        note(
            &mut observations,
            "workload_trust.trust_domain",
            &manifest.workload_trust.trust_domain,
            "local-bootstrap",
            claimed_at,
            revision,
            None,
            ObservationResult::Verified,
            Some("trust-domain"),
            "trust domain matches the bootstrap provider domain",
        );
    }
    let website_host = uri_host(&manifest.platform.website);
    if website_host.as_deref() != Some(bootstrap.provider_domain.as_str()) {
        note(
            &mut observations,
            "platform.website",
            &manifest.platform.website,
            "local-bootstrap",
            claimed_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "website host does not match the bootstrap provider domain",
        );
        let _ = error.get_or_insert(IdentityError::WrongDomain);
    } else if error.is_none() {
        note(
            &mut observations,
            "platform.website",
            &manifest.platform.website,
            "local-bootstrap",
            claimed_at,
            revision,
            None,
            ObservationResult::Verified,
            Some("domain-authority"),
            "website host matches the bootstrap provider domain",
        );
    }
    if error.is_some() {
        return IdentityEvaluation {
            observations,
            binding: Err(error.unwrap()),
        };
    }

    if manifest.federation.control_endpoint != bootstrap.expected_control_endpoint {
        note(
            &mut observations,
            "federation.control_endpoint",
            &manifest.federation.control_endpoint,
            "local-bootstrap",
            claimed_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "control endpoint does not match the bootstrap endpoint",
        );
        error = Some(IdentityError::WrongEndpoint);
    } else {
        note(
            &mut observations,
            "federation.control_endpoint",
            &manifest.federation.control_endpoint,
            "local-bootstrap",
            claimed_at,
            revision,
            None,
            ObservationResult::Verified,
            Some("control-endpoint"),
            "control endpoint matches the bootstrap endpoint",
        );
    }
    let protocols = manifest.federation.control_protocols.iter().cloned().collect::<Vec<_>>().join(",");
    if !manifest.federation.control_protocols.iter().any(|value| value == "federation-peer/v1")
        || !manifest.federation.control_protocols.iter().any(|value| value == "federation-control/v1")
    {
        note(
            &mut observations,
            "federation.control_protocols",
            &protocols,
            "manifest",
            claimed_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "control protocols do not include the peer and relationship schemas",
        );
        let _ = error.get_or_insert(IdentityError::WrongEndpoint);
    } else if error.is_none() {
        note(
            &mut observations,
            "federation.control_protocols",
            &protocols,
            "manifest",
            claimed_at,
            revision,
            None,
            ObservationResult::Verified,
            Some("schema-compatibility"),
            "peer and relationship control schemas are present",
        );
    }
    let leases = manifest.federation.relationship_lease_profiles.iter().cloned().collect::<Vec<_>>().join(",");
    if !manifest.federation.relationship_lease_profiles.iter().any(|value| value == "FRL/1") {
        note(
            &mut observations,
            "federation.relationship_lease_profiles",
            &leases,
            "manifest",
            claimed_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "FRL/1 is not an offered lease profile",
        );
        let _ = error.get_or_insert(IdentityError::WrongEndpoint);
    } else if error.is_none() {
        note(
            &mut observations,
            "federation.relationship_lease_profiles",
            &leases,
            "manifest",
            claimed_at,
            revision,
            None,
            ObservationResult::Verified,
            Some("schema-compatibility"),
            "FRL/1 is an offered lease profile",
        );
    }
    if error.is_some() {
        return IdentityEvaluation {
            observations,
            binding: Err(error.unwrap()),
        };
    }

    if manifest.discovery.directory_endpoint != bootstrap.expected_directory_endpoint {
        note(
            &mut observations,
            "discovery.directory_endpoint",
            &manifest.discovery.directory_endpoint,
            "local-bootstrap",
            claimed_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "directory endpoint does not match the bootstrap endpoint",
        );
        error = Some(IdentityError::WrongDirectory);
    } else {
        note(
            &mut observations,
            "discovery.directory_endpoint",
            &manifest.discovery.directory_endpoint,
            "local-bootstrap",
            claimed_at,
            revision,
            None,
            ObservationResult::Verified,
            Some("directory-endpoint"),
            "directory endpoint matches the bootstrap endpoint",
        );
    }
    if evidence.source_directory_service_id != bootstrap.expected_local_directory_service_id {
        note(
            &mut observations,
            "directory_name.source_directory_service_id",
            &evidence.source_directory_service_id,
            "directory-name-evidence",
            &evidence.verified_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "Directory evidence did not come from the bootstrap Directory service",
        );
        let _ = error.get_or_insert(IdentityError::WrongDirectory);
    } else if error.is_none() {
        note(
            &mut observations,
            "directory_name.source_directory_service_id",
            &evidence.source_directory_service_id,
            "directory-name-evidence",
            &evidence.verified_at,
            revision,
            None,
            ObservationResult::Verified,
            Some("directory-service"),
            "Directory evidence came from the bootstrap Directory service",
        );
    }
    if error.is_some() {
        return IdentityEvaluation {
            observations,
            binding: Err(error.unwrap()),
        };
    }

    if manifest.workload_trust.bundle_endpoint != bootstrap.expected_bundle_endpoint {
        note(
            &mut observations,
            "workload_trust.bundle_endpoint",
            &manifest.workload_trust.bundle_endpoint,
            "local-bootstrap",
            claimed_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "bundle endpoint does not match the bootstrap endpoint",
        );
        error = Some(IdentityError::WrongBundle);
    } else {
        note(
            &mut observations,
            "workload_trust.bundle_endpoint",
            &manifest.workload_trust.bundle_endpoint,
            "local-bootstrap",
            claimed_at,
            revision,
            None,
            ObservationResult::Verified,
            Some("bundle-endpoint"),
            "bundle endpoint matches the bootstrap endpoint",
        );
    }
    if manifest.workload_trust.bundle_profile != bootstrap.expected_bundle_profile {
        note(
            &mut observations,
            "workload_trust.bundle_profile",
            &manifest.workload_trust.bundle_profile,
            "local-bootstrap",
            claimed_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "bundle profile does not match the bootstrap profile",
        );
        let _ = error.get_or_insert(IdentityError::WrongBundle);
    } else if error.is_none() {
        note(
            &mut observations,
            "workload_trust.bundle_profile",
            &manifest.workload_trust.bundle_profile,
            "local-bootstrap",
            claimed_at,
            revision,
            None,
            ObservationResult::Verified,
            Some("bundle-profile"),
            "bundle profile matches the bootstrap profile",
        );
    }
    if error.is_some() {
        return IdentityEvaluation {
            observations,
            binding: Err(error.unwrap()),
        };
    }

    let name: Uri = match evidence.record_name.parse() {
        Ok(name) => name,
        Err(_) => {
            note(
                &mut observations,
                "directory_name.record_name",
                &evidence.record_name,
                "directory-name-evidence",
                &evidence.verified_at,
                revision,
                None,
                ObservationResult::Unavailable,
                None,
                "Directory record name is not a URI",
            );
            return IdentityEvaluation {
                observations,
                binding: Err(IdentityError::WrongRecord),
            };
        }
    };
    let Some(scheme) = name.scheme_str() else {
        note(
            &mut observations,
            "directory_name.record_name",
            &evidence.record_name,
            "directory-name-evidence",
            &evidence.verified_at,
            revision,
            None,
            ObservationResult::Unavailable,
            None,
            "Directory record name has no URI scheme",
        );
        return IdentityEvaluation {
            observations,
            binding: Err(IdentityError::WrongRecord),
        };
    };
    if !matches!(
        (profile, scheme),
        (EvidenceProfile::ProductionHttps, "https") | (EvidenceProfile::LocalHttpTest, "http")
    ) {
        note(
            &mut observations,
            "directory_name.record_name",
            &evidence.record_name,
            "directory-name-evidence",
            &evidence.verified_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "record name scheme does not match the selected evidence profile",
        );
        return IdentityEvaluation {
            observations,
            binding: Err(IdentityError::UnsupportedProfile),
        };
    }
    let Some(authority) = name.authority() else {
        note(
            &mut observations,
            "directory_name.record_name",
            &evidence.record_name,
            "directory-name-evidence",
            &evidence.verified_at,
            revision,
            None,
            ObservationResult::Unavailable,
            None,
            "Directory record name has no authority",
        );
        return IdentityEvaluation {
            observations,
            binding: Err(IdentityError::WrongRecord),
        };
    };
    if authority.host() != bootstrap.provider_domain
        || evidence.domain != authority.as_str()
        || manifest.discovery.domain_proof_ref.as_deref() != Some(evidence.record_name.as_str())
        || manifest.discovery.publisher_name_ref.as_deref() != Some(evidence.record_name.as_str())
        || !manifest.discovery.record_cids.contains(&evidence.record_cid)
    {
        note(
            &mut observations,
            "discovery.domain_proof_ref",
            manifest.discovery.domain_proof_ref.as_deref().unwrap_or(""),
            "directory-name-evidence",
            &evidence.verified_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "Directory name evidence does not match the manifest domain proof, publisher, or selected CID",
        );
        return IdentityEvaluation {
            observations,
            binding: Err(IdentityError::WrongRecord),
        };
    }
    note(
        &mut observations,
        "discovery.domain_proof_ref",
        evidence.record_name.as_str(),
        "directory-name-evidence",
        &evidence.verified_at,
        revision,
        None,
        ObservationResult::Verified,
        Some("selected-record"),
        "Directory name matches the manifest domain proof and selected CID",
    );
    if !evidence.verified || evidence.method != "wellknown" || evidence.key_id.is_empty() {
        note(
            &mut observations,
            "directory_name.key_id",
            &evidence.key_id,
            "directory-name-evidence",
            &evidence.verified_at,
            revision,
            None,
            ObservationResult::Mismatch,
            None,
            "Directory name is not a verified well-known domain key",
        );
        return IdentityEvaluation {
            observations,
            binding: Err(IdentityError::UnverifiedName),
        };
    }
    note(
        &mut observations,
        "directory_name.key_id",
        &evidence.key_id,
        "directory-name-evidence",
        &evidence.verified_at,
        revision,
        None,
        ObservationResult::Verified,
        Some("domain-key-control"),
        "Directory well-known check verified the publisher domain key",
    );

    let parsed_verified_at = utc_timestamp(&evidence.verified_at).ok().map(unix_seconds);
    let freshness = parsed_verified_at.map(|verified_at| now_unix_seconds.saturating_sub(verified_at));
    let fresh = match parsed_verified_at {
        Some(verified_at) => {
            bootstrap.max_evidence_age_seconds > 0
                && bootstrap.max_evidence_age_seconds <= 604800
                && verified_at <= now_unix_seconds + 300
                && now_unix_seconds.saturating_sub(verified_at) <= bootstrap.max_evidence_age_seconds
        }
        None => false,
    };
    if !fresh {
        note(
            &mut observations,
            "directory_name.verified_at",
            &evidence.verified_at,
            "directory-name-evidence",
            &evidence.verified_at,
            revision,
            freshness,
            ObservationResult::Mismatch,
            None,
            "Directory evidence is missing, skewed, or older than the bootstrap freshness limit",
        );
        return IdentityEvaluation {
            observations,
            binding: Err(IdentityError::StaleOrInvalidEvidence),
        };
    }
    note(
        &mut observations,
        "directory_name.verified_at",
        &evidence.verified_at,
        "directory-name-evidence",
        &evidence.verified_at,
        revision,
        freshness,
        ObservationResult::Verified,
        Some("evidence-freshness"),
        "Directory evidence is inside the bootstrap freshness limit",
    );
    let observations_for_binding = observations.clone();
    IdentityEvaluation {
        observations,
        binding: Ok(VerifiedProviderBinding {
            peer: bootstrap.peer.clone(),
            manifest_revision: manifest.revision,
            manifest_digest: snapshot.digest,
            observed_control_service_id: observed_control_service_id.to_owned(),
            verified_domain: bootstrap.provider_domain.clone(),
            record_cid: evidence.record_cid.clone(),
            key_id: evidence.key_id.clone(),
            source_directory_service_id: evidence.source_directory_service_id.clone(),
            verified_at: evidence.verified_at.clone(),
            profile,
            bootstrap_digest: bootstrap.digest(),
            observations: observations_for_binding,
        }),
    }
}

fn note(
    observations: &mut Vec<FieldObservation>,
    field_path: &str,
    observed_value: &str,
    source: &str,
    observed_at: &str,
    evidence_revision: u64,
    freshness_seconds: Option<i64>,
    result: ObservationResult,
    verified_property: Option<&str>,
    reason: &str,
) {
    observations.push(FieldObservation {
        field_path: field_path.to_owned(),
        observed_value: observed_value.to_owned(),
        source: source.to_owned(),
        observed_at: observed_at.to_owned(),
        evidence_revision,
        freshness_seconds,
        result,
        verified_property: (result == ObservationResult::Verified).then(|| {
            verified_property
                .expect("verified observation names its property")
                .to_owned()
        }),
        reason: reason.to_owned(),
    });
}

fn uri_host(value: &str) -> Option<String> {
    value
        .parse::<Uri>()
        .ok()?
        .authority()
        .map(|a| a.host().to_owned())
}

fn unix_seconds(value: crate::provider_manifest::UtcInstant) -> i64 {
    let mut year = i64::from(value.0);
    let month = i64::from(value.1);
    let day = i64::from(value.2);
    if month <= 2 {
        year -= 1;
    }
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let year_of_era_day = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146097 + year_of_era_day - 719468;
    days * 86400 + i64::from(value.3) * 3600 + i64::from(value.4) * 60 + i64::from(value.5)
}

pub fn utc_unix_seconds(value: &str) -> Option<i64> {
    Some(unix_seconds(utc_timestamp(value).ok()?))
}

/// A private target address must lie beneath the independently provisioned
/// provider domain. Exact-address ownership is still resolved only by that
/// provider's own host after authenticated delivery.
pub fn target_address_in_provider_domain(address: &str, domain: &str) -> bool {
    fn valid_dns(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 253
            && value.is_ascii()
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
            && value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            })
    }
    valid_dns(address)
        && valid_dns(domain)
        && address
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
}

/// Private provider-scoped short address. Issuers start with 16 base32
/// characters; accepting up to 32 permits longer keys without a schema
/// migration. The provider suffix is an authenticated routing hint, not a
/// public DNS lookup or proof that the target exists.
pub fn short_address_in_provider_domain(address: &str, domain: &str) -> bool {
    let Some(label) = address.strip_suffix(domain).and_then(|prefix| prefix.strip_suffix('.')) else {
        return false;
    };
    (16..=32).contains(&label.len())
        && label.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'h' | b'j'..=b'k' | b'm'..=b'n' | b'p'..=b't' | b'v'..=b'z'))
        && target_address_in_provider_domain(address, domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_manifest::parse_manifest;

    #[test]
    fn provider_scoped_short_handles_allow_length_growth_without_accepting_internal_names() {
        let domain = "provider-b.test";
        for width in [16, 17, 18, 32] {
            let address = format!("{}.{}", "a".repeat(width), domain);
            assert!(short_address_in_provider_domain(&address, domain));
        }
        for invalid in [
            format!("{}.{}", "a".repeat(15), domain),
            format!("{}.{}", "a".repeat(33), domain),
            "calendar.someone.provider-b.test".into(),
            "iiiiiiiiiiiiiiii.provider-b.test".into(),
            "aaaaaaaaaaaaaaaa.provider-c.test".into(),
        ] {
            assert!(!short_address_in_provider_domain(&invalid, domain));
        }
    }

    #[test]
    fn domain_key_service_and_bootstrap_must_all_match() {
        let hello: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/peer/provider-a-hello.json")).unwrap();
        let mut manifest = hello["payload"]["manifest"].clone();
        let name = "http://provider-a.test:8080/providers/test-1";
        manifest["discovery"]["domain_proof_ref"] = serde_json::json!(name);
        manifest["discovery"]["publisher_name_ref"] = serde_json::json!(name);
        manifest["discovery"]["record_cids"] = serde_json::json!(["bafy-test-cid"]);
        let snapshot = parse_manifest(&serde_json::to_vec(&manifest).unwrap()).unwrap();
        let bootstrap = BootstrapAuthority {
            peer: PlatformId::new("provider-a").unwrap(),
            provider_domain: "provider-a.test".into(),
            expected_control_service_id: "spiffe://provider-a.test/federation/control".into(),
            expected_control_endpoint: "https://provider-a-bridge:8444/control".into(),
            expected_directory_endpoint: "https://directory.provider-a.test".into(),
            expected_local_directory_service_id: "spiffe://provider-b.test/directory/server".into(),
            expected_bundle_endpoint: "https://bundle.provider-a.test".into(),
            expected_bundle_profile: "https_spiffe".into(),
            max_evidence_age_seconds: 7200,
        };
        let evidence = DirectoryNameEvidence {
            record_cid: "bafy-test-cid".into(),
            record_name: name.into(),
            verified: true,
            domain: "provider-a.test:8080".into(),
            method: "wellknown".into(),
            key_id: "test-key".into(),
            verified_at: "2026-09-23T08:00:00Z".into(),
            source_directory_service_id: "spiffe://provider-b.test/directory/server".into(),
        };
        let now = unix_seconds(utc_timestamp("2026-09-23T09:00:00Z").unwrap());
        assert_eq!(
            unix_seconds(utc_timestamp("1970-01-01T00:00:00Z").unwrap()),
            0
        );
        let binding = verify_provider_binding(
            &snapshot,
            &bootstrap,
            &bootstrap.expected_control_service_id,
            &evidence,
            EvidenceProfile::LocalHttpTest,
            now,
        )
        .unwrap();
        assert_eq!(binding.manifest_digest(), snapshot.digest);
        assert!(binding.observations().iter().any(|observation| {
            observation.field_path == "platform.operator_name"
                && observation.result == ObservationResult::SelfDeclared
        }));
        assert!(binding.observations().iter().any(|observation| {
            observation.verified_property.as_deref() == Some("domain-key-control")
                && observation.result == ObservationResult::Verified
        }));
        assert!(binding.observations().iter().any(|observation| {
            observation.verified_property.as_deref() == Some("evidence-freshness")
                && observation.result == ObservationResult::Verified
                && observation.freshness_seconds.is_some()
        }));
        assert!(binding.observations().iter().all(|observation| {
            observation.result != ObservationResult::Verified || observation.verified_property.is_some()
        }));
        let rejected = evaluate_provider_identity(
            &snapshot,
            &bootstrap,
            "spiffe://provider-a.test/other",
            &evidence,
            EvidenceProfile::LocalHttpTest,
            now,
        );
        assert_eq!(rejected.binding, Err(IdentityError::WrongService));
        assert!(rejected.observations.iter().any(|observation| {
            observation.field_path == "authenticated_control_service"
                && observation.result == ObservationResult::Mismatch
        }));
        assert!(rejected.observations.iter().all(|observation| {
            observation.verified_property.as_deref() != Some("domain-key-control")
        }));
        assert_eq!(
            verify_provider_binding(
                &snapshot,
                &bootstrap,
                &bootstrap.expected_control_service_id,
                &evidence,
                EvidenceProfile::ProductionHttps,
                now
            ),
            Err(IdentityError::UnsupportedProfile)
        );
        let mut wrong = evidence.clone();
        wrong.verified = false;
        assert_eq!(
            verify_provider_binding(
                &snapshot,
                &bootstrap,
                &bootstrap.expected_control_service_id,
                &wrong,
                EvidenceProfile::LocalHttpTest,
                now
            ),
            Err(IdentityError::UnverifiedName)
        );
        wrong = evidence.clone();
        wrong.key_id = "".into();
        assert_eq!(
            verify_provider_binding(
                &snapshot,
                &bootstrap,
                &bootstrap.expected_control_service_id,
                &wrong,
                EvidenceProfile::LocalHttpTest,
                now
            ),
            Err(IdentityError::UnverifiedName)
        );
        assert_eq!(
            verify_provider_binding(
                &snapshot,
                &bootstrap,
                &bootstrap.expected_control_service_id,
                &evidence,
                EvidenceProfile::LocalHttpTest,
                now + 7201
            ),
            Err(IdentityError::StaleOrInvalidEvidence)
        );
        assert_eq!(
            verify_provider_binding(
                &snapshot,
                &bootstrap,
                "spiffe://provider-a.test/other",
                &evidence,
                EvidenceProfile::LocalHttpTest,
                now
            ),
            Err(IdentityError::WrongService)
        );
    }

    #[test]
    fn private_address_must_be_a_dns_child_of_the_selected_provider() {
        assert!(target_address_in_provider_domain(
            "agent.agents.provider-b.test",
            "provider-b.test"
        ));
        for address in [
            "provider-b.test",
            "agent.provider-b.test.evil",
            "agent.provider-c.test",
            "AGENT.provider-b.test",
            "agent..provider-b.test",
            "-bad.provider-b.test",
        ] {
            assert!(
                !target_address_in_provider_domain(address, "provider-b.test"),
                "{address}"
            );
        }
    }
}
