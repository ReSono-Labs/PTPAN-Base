//! Locally computed provider identity checks (D14). A peer is verified only
//! when the authenticated control service, the provider manifest, the local
//! bootstrap and the provider's HTTPS well-known domain document all agree.
//! A certificate, a document or an operator approval alone never opens trust.

use crate::address::valid_provider_domain;
use crate::encoding::{bounded_text, canonical_digest, sha256};
use crate::provider_manifest::{decode_ca_root, negotiate_protocols, ManifestSnapshot};
use crate::time::{parse_utc, MAX_CLOCK_SKEW_SECONDS};
use crate::PlatformId;
use http::Uri;
use serde::{Deserialize, Serialize};

pub const DOMAIN_DOCUMENT_SCHEMA: &str = "ptpan-provider-domain/1";
pub const WELL_KNOWN_PATH: &str = "/.well-known/ptpan-provider.json";
pub const MAX_DOMAIN_DOCUMENT_BYTES: usize = 16 << 10;
/// Largest accepted bootstrap evidence age (seven days).
pub const MAX_EVIDENCE_AGE_SECONDS: i64 = 604_800;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceProfile {
    /// The document was fetched over HTTPS with WebPKI validation.
    ProductionHttps,
    /// Isolated test stacks only: plain HTTP on a test domain.
    LocalHttpTest,
}

/// The provider's own statement on its domain (D14). It publishes only the
/// platform ID, its two service identities and its agent CA root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDomainDocument {
    pub schema: String,
    pub platform_id: PlatformId,
    pub control_service_identity: String,
    pub edge_service_identity: String,
    pub agent_ca_root: String,
}

/// What the bridge fetched. The bridge performs the HTTPS and WebPKI checks;
/// Base checks the location, the content and freshness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainProofEvidence {
    pub url: String,
    pub fetched_at: String,
    pub body: Vec<u8>,
}

pub fn well_known_url(provider_domain: &str, profile: EvidenceProfile) -> String {
    let scheme = match profile {
        EvidenceProfile::ProductionHttps => "https",
        EvidenceProfile::LocalHttpTest => "http",
    };
    format!("{scheme}://{provider_domain}{WELL_KNOWN_PATH}")
}

pub fn parse_domain_document(bytes: &[u8]) -> Option<ProviderDomainDocument> {
    if bytes.is_empty() || bytes.len() > MAX_DOMAIN_DOCUMENT_BYTES {
        return None;
    }
    let document: ProviderDomainDocument = serde_json::from_slice(bytes).ok()?;
    (document.schema == DOMAIN_DOCUMENT_SCHEMA
        && bounded_text(document.platform_id.as_str())
        && bounded_text(&document.control_service_identity)
        && bounded_text(&document.edge_service_identity)
        && decode_ca_root(&document.agent_ca_root).is_some())
    .then_some(document)
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
    pub expected_edge_service_id: String,
    pub expected_edge_endpoint: String,
    pub expected_bundle_endpoint: String,
    pub expected_bundle_profile: String,
    pub max_evidence_age_seconds: i64,
}

impl BootstrapAuthority {
    pub fn digest(&self) -> [u8; 32] {
        canonical_digest(self)
            .expect("bootstrap authority serialization")
            .1
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityError {
    WrongPeer,
    WrongService,
    WrongDomain,
    WrongEndpoint,
    UnsupportedProtocol,
    WrongBundle,
    WrongDomainDocument,
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
    edge_service_id: String,
    edge_endpoint: String,
    agent_ca_root: String,
    negotiated_protocols: Vec<String>,
    domain_document_digest: [u8; 32],
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
    pub fn edge_service_id(&self) -> &str {
        &self.edge_service_id
    }
    pub fn edge_endpoint(&self) -> &str {
        &self.edge_endpoint
    }
    pub fn agent_ca_root(&self) -> &str {
        &self.agent_ca_root
    }
    pub fn negotiated_protocols(&self) -> &[String] {
        &self.negotiated_protocols
    }
    pub fn domain_document_digest(&self) -> [u8; 32] {
        self.domain_document_digest
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

/// One equality check: field, observed value, expected value, the property a
/// match verifies, and the error a mismatch raises.
struct Check<'a> {
    field: &'static str,
    observed: &'a str,
    matches: bool,
    source: &'static str,
    property: &'static str,
    error: IdentityError,
    reason: &'static str,
}

/// Field observations are produced even when the binding is rejected. Checks
/// run in order and stop at the first mismatch, so a field after a failed
/// check is never marked verified.
pub fn evaluate_provider_identity(
    snapshot: &ManifestSnapshot,
    bootstrap: &BootstrapAuthority,
    observed_control_service_id: &str,
    evidence: &DomainProofEvidence,
    profile: EvidenceProfile,
    local_protocols: &[&str],
    now_unix_seconds: i64,
) -> IdentityEvaluation {
    let manifest = &snapshot.manifest;
    let revision = manifest.revision;
    let claimed_at = manifest.generated_at.as_str();
    let mut observations = Vec::new();
    note(&mut observations, revision, "platform.operator_name", &manifest.platform.operator_name, "manifest", claimed_at, None,
        ObservationResult::SelfDeclared, None, "operator name is a claim, not identity proof");
    let (display_source, display_result, display_reason) = match manifest.platform.display_name_source {
        crate::provider_manifest::ClaimSource::LocalMetadata => ("manifest", ObservationResult::SelfDeclared, "display name is local metadata"),
        crate::provider_manifest::ClaimSource::AiCatalog => ("ai-catalog", ObservationResult::ReviewRequired, "catalog display name is not operator identity"),
    };
    note(&mut observations, revision, "platform.display_name", &manifest.platform.display_name, display_source, claimed_at, None,
        display_result, None, display_reason);

    let trust = &manifest.workload_trust;
    let domain = bootstrap.provider_domain.as_str();
    let service_prefix = format!("spiffe://{domain}/");
    let website_host = uri_host(&manifest.platform.website);
    let negotiated = negotiate_protocols(local_protocols, &manifest.federation.protocols);
    let protocols = manifest.federation.protocols.join(",");
    let document = parse_domain_document(&evidence.body);
    let expected_url = well_known_url(domain, profile);
    let ca_root = manifest.agent_trust.ca_root.as_str();
    let checks = [
        Check { field: "platform.platform_id", observed: manifest.platform.platform_id.as_str(),
            matches: manifest.platform.platform_id == bootstrap.peer, source: "local-bootstrap",
            property: "platform-binding", error: IdentityError::WrongPeer,
            reason: "manifest platform id against the bootstrap peer" },
        Check { field: "authenticated_control_service", observed: observed_control_service_id,
            matches: observed_control_service_id == bootstrap.expected_control_service_id
                && observed_control_service_id.starts_with(&service_prefix),
            source: "authenticated-service", property: "exact-service-authentication",
            error: IdentityError::WrongService,
            reason: "authenticated SPIFFE ID against the bootstrap control service in its domain" },
        Check { field: "workload_trust.control_service_identity", observed: &trust.control_service_identity,
            matches: trust.control_service_identity == bootstrap.expected_control_service_id,
            source: "local-bootstrap", property: "exact-service-authentication",
            error: IdentityError::WrongService, reason: "manifest control service against the bootstrap" },
        Check { field: "workload_trust.control_service_role", observed: &trust.control_service_role,
            matches: trust.control_service_role == "CONTROL", source: "manifest", property: "control-role",
            error: IdentityError::WrongService, reason: "control service role must be CONTROL" },
        Check { field: "workload_trust.edge_service_identity", observed: &trust.edge_service_identity,
            matches: trust.edge_service_identity == bootstrap.expected_edge_service_id
                && trust.edge_service_identity.starts_with(&service_prefix),
            source: "local-bootstrap", property: "edge-service",
            error: IdentityError::WrongService, reason: "manifest edge service against the bootstrap in its domain" },
        Check { field: "workload_trust.edge_service_role", observed: &trust.edge_service_role,
            matches: trust.edge_service_role == "EDGE", source: "manifest", property: "edge-role",
            error: IdentityError::WrongService, reason: "edge service role must be EDGE" },
        Check { field: "platform.provider_domain", observed: &manifest.platform.provider_domain,
            matches: valid_provider_domain(domain) && manifest.platform.provider_domain == domain,
            source: "local-bootstrap", property: "provider-domain",
            error: IdentityError::WrongDomain, reason: "provider domain against the bootstrap" },
        Check { field: "workload_trust.trust_domain", observed: &trust.trust_domain,
            matches: trust.trust_domain == domain, source: "local-bootstrap", property: "trust-domain",
            error: IdentityError::WrongDomain, reason: "SPIFFE trust domain against the provider domain" },
        Check { field: "platform.website", observed: &manifest.platform.website,
            matches: website_host.as_deref() == Some(domain), source: "local-bootstrap",
            property: "domain-authority", error: IdentityError::WrongDomain,
            reason: "website host against the provider domain" },
        Check { field: "federation.control_endpoint", observed: &manifest.federation.control_endpoint,
            matches: manifest.federation.control_endpoint == bootstrap.expected_control_endpoint,
            source: "local-bootstrap", property: "control-endpoint",
            error: IdentityError::WrongEndpoint, reason: "control endpoint against the bootstrap" },
        Check { field: "federation.edge_endpoint", observed: &manifest.federation.edge_endpoint,
            matches: manifest.federation.edge_endpoint == bootstrap.expected_edge_endpoint,
            source: "local-bootstrap", property: "edge-endpoint",
            error: IdentityError::WrongEndpoint, reason: "edge endpoint against the bootstrap" },
        Check { field: "federation.protocols", observed: &protocols, matches: negotiated.is_ok(),
            source: "manifest", property: "protocol-negotiation", error: IdentityError::UnsupportedProtocol,
            reason: "a common version for every local protocol family" },
        Check { field: "workload_trust.bundle_endpoint", observed: &trust.bundle_endpoint,
            matches: trust.bundle_endpoint == bootstrap.expected_bundle_endpoint,
            source: "local-bootstrap", property: "bundle-endpoint",
            error: IdentityError::WrongBundle, reason: "bundle endpoint against the bootstrap" },
        Check { field: "workload_trust.bundle_profile", observed: &trust.bundle_profile,
            matches: trust.bundle_profile == bootstrap.expected_bundle_profile,
            source: "local-bootstrap", property: "bundle-profile",
            error: IdentityError::WrongBundle, reason: "bundle profile against the bootstrap" },
        Check { field: "domain_proof.url", observed: &evidence.url, matches: evidence.url == expected_url,
            source: "domain-proof", property: "domain-proof-location",
            error: IdentityError::UnsupportedProfile, reason: "well-known URL for the provider domain and profile" },
        Check { field: "domain_proof.document", observed: &evidence.url,
            matches: document.as_ref().is_some_and(|d| {
                d.platform_id == bootstrap.peer
                    && d.control_service_identity == bootstrap.expected_control_service_id
                    && d.edge_service_identity == bootstrap.expected_edge_service_id
                    && d.agent_ca_root == ca_root
            }),
            source: "domain-proof", property: "domain-control",
            error: IdentityError::WrongDomainDocument,
            reason: "domain document names this platform, both services and the manifest CA root" },
    ];
    for check in checks {
        if !check.matches {
            note(&mut observations, revision, check.field, check.observed, check.source, claimed_at, None,
                ObservationResult::Mismatch, None, check.reason);
            return IdentityEvaluation { observations, binding: Err(check.error) };
        }
        note(&mut observations, revision, check.field, check.observed, check.source, claimed_at, None,
            ObservationResult::Verified, Some(check.property), check.reason);
    }

    let fetched = parse_utc(&evidence.fetched_at).map(|t| t.unix_seconds());
    let freshness = fetched.map(|at| now_unix_seconds.saturating_sub(at));
    let fresh = fetched.is_some_and(|at| {
        bootstrap.max_evidence_age_seconds > 0
            && bootstrap.max_evidence_age_seconds <= MAX_EVIDENCE_AGE_SECONDS
            && at <= now_unix_seconds + MAX_CLOCK_SKEW_SECONDS as i64
            && now_unix_seconds.saturating_sub(at) <= bootstrap.max_evidence_age_seconds
    });
    if !fresh {
        note(&mut observations, revision, "domain_proof.fetched_at", &evidence.fetched_at, "domain-proof", &evidence.fetched_at,
            freshness, ObservationResult::Mismatch, None,
            "domain proof is missing, skewed, or older than the bootstrap freshness limit");
        return IdentityEvaluation { observations, binding: Err(IdentityError::StaleOrInvalidEvidence) };
    }
    note(&mut observations, revision, "domain_proof.fetched_at", &evidence.fetched_at, "domain-proof", &evidence.fetched_at,
        freshness, ObservationResult::Verified, Some("evidence-freshness"),
        "domain proof is inside the bootstrap freshness limit");

    let binding = VerifiedProviderBinding {
        peer: bootstrap.peer.clone(),
        manifest_revision: revision,
        manifest_digest: snapshot.digest,
        observed_control_service_id: observed_control_service_id.to_owned(),
        verified_domain: domain.to_owned(),
        edge_service_id: trust.edge_service_identity.clone(),
        edge_endpoint: manifest.federation.edge_endpoint.clone(),
        agent_ca_root: ca_root.to_owned(),
        negotiated_protocols: negotiated
            .expect("negotiation checked above")
            .into_iter()
            .map(str::to_owned)
            .collect(),
        domain_document_digest: sha256(&evidence.body),
        verified_at: evidence.fetched_at.clone(),
        profile,
        bootstrap_digest: bootstrap.digest(),
        observations: observations.clone(),
    };
    IdentityEvaluation { observations, binding: Ok(binding) }
}

#[allow(clippy::too_many_arguments)]
fn note(
    observations: &mut Vec<FieldObservation>,
    revision: u64,
    field: &str,
    value: &str,
    source: &str,
    at: &str,
    freshness: Option<i64>,
    result: ObservationResult,
    property: Option<&str>,
    reason: &str,
) {
    observations.push(FieldObservation {
        field_path: field.to_owned(),
        observed_value: value.to_owned(),
        source: source.to_owned(),
        observed_at: at.to_owned(),
        evidence_revision: revision,
        freshness_seconds: freshness,
        result,
        verified_property: (result == ObservationResult::Verified)
            .then(|| property.expect("verified observation names its property").to_owned()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_manifest::{parse_manifest, tests as manifest};

    const LOCAL: [&str; 4] = crate::SUPPORTED_PROTOCOLS;
    const CONTROL: &str = "spiffe://provider-b.test/federation/control";

    fn bootstrap() -> BootstrapAuthority {
        BootstrapAuthority {
            peer: PlatformId::new("provider-b").unwrap(),
            provider_domain: "provider-b.test".into(),
            expected_control_service_id: CONTROL.into(),
            expected_control_endpoint: "https://control.provider-b.test/control".into(),
            expected_edge_service_id: "spiffe://provider-b.test/federation/edge".into(),
            expected_edge_endpoint: "edge.provider-b.test:8443".into(),
            expected_bundle_endpoint: "https://bundle.provider-b.test".into(),
            expected_bundle_profile: "https_spiffe".into(),
            max_evidence_age_seconds: 3600,
        }
    }

    fn document() -> serde_json::Value {
        serde_json::json!({
            "schema": DOMAIN_DOCUMENT_SCHEMA,
            "platform_id": "provider-b",
            "control_service_identity": CONTROL,
            "edge_service_identity": "spiffe://provider-b.test/federation/edge",
            "agent_ca_root": manifest::test_ca_root(),
        })
    }

    fn evidence(body: &serde_json::Value) -> DomainProofEvidence {
        DomainProofEvidence {
            url: "https://provider-b.test/.well-known/ptpan-provider.json".into(),
            fetched_at: "2026-09-21T13:33:20Z".into(),
            body: serde_json::to_vec(body).unwrap(),
        }
    }

    fn evaluate(
        change: impl FnOnce(&mut crate::provider_manifest::ProviderManifest),
        boot: BootstrapAuthority,
        proof: DomainProofEvidence,
        service: &str,
    ) -> IdentityEvaluation {
        let mut m = manifest::valid();
        change(&mut m);
        let snapshot = parse_manifest(&serde_json::to_vec(&m).unwrap()).unwrap();
        let now = crate::time::utc_unix_seconds("2026-09-21T13:40:00Z").unwrap();
        evaluate_provider_identity(&snapshot, &boot, service, &proof, EvidenceProfile::ProductionHttps, &LOCAL, now)
    }

    #[test]
    fn matching_manifest_bootstrap_service_and_domain_document_verify() {
        let result = evaluate(|_| {}, bootstrap(), evidence(&document()), CONTROL);
        let binding = result.binding.unwrap();
        assert_eq!(binding.verified_domain(), "provider-b.test");
        assert_eq!(binding.edge_endpoint(), "edge.provider-b.test:8443");
        assert_eq!(binding.negotiated_protocols().len(), 4);
        assert!(result
            .observations
            .iter()
            .filter(|o| o.result == ObservationResult::Verified)
            .all(|o| o.verified_property.is_some()));
        assert!(result.observations.iter().any(|o| o.field_path == "domain_proof.document"
            && o.result == ObservationResult::Verified));
    }

    #[test]
    fn each_field_mismatch_rejects_without_verifying_later_fields() {
        type Case = (fn(&mut crate::provider_manifest::ProviderManifest), IdentityError, &'static str);
        let cases: [Case; 8] = [
            (|m| m.platform.platform_id = PlatformId::new("provider-c").unwrap(), IdentityError::WrongPeer, "platform.platform_id"),
            (|m| m.workload_trust.control_service_role = "EDGE".into(), IdentityError::WrongService, "workload_trust.control_service_role"),
            (|m| m.workload_trust.edge_service_identity = "spiffe://provider-c.test/federation/edge".into(), IdentityError::WrongService, "workload_trust.edge_service_identity"),
            (|m| m.workload_trust.trust_domain = "provider-c.test".into(), IdentityError::WrongDomain, "workload_trust.trust_domain"),
            (|m| m.platform.website = "https://provider-c.test".into(), IdentityError::WrongDomain, "platform.website"),
            (|m| m.federation.edge_endpoint = "edge.provider-b.test:9443".into(), IdentityError::WrongEndpoint, "federation.edge_endpoint"),
            (|m| m.federation.protocols = vec!["federation-control/v3".into(), "FRL/1".into()], IdentityError::UnsupportedProtocol, "federation.protocols"),
            (|m| m.workload_trust.bundle_profile = "https_web".into(), IdentityError::WrongBundle, "workload_trust.bundle_profile"),
        ];
        for (change, error, field) in cases {
            let result = evaluate(change, bootstrap(), evidence(&document()), CONTROL);
            assert_eq!(result.binding.err(), Some(error), "{field}");
            let last = result.observations.last().unwrap();
            assert_eq!((last.field_path.as_str(), last.result), (field, ObservationResult::Mismatch));
            assert!(!result.observations.iter().any(|o| o.field_path == "domain_proof.document"));
        }
    }

    #[test]
    fn wrong_service_on_the_connection_rejects() {
        let result = evaluate(|_| {}, bootstrap(), evidence(&document()), "spiffe://provider-b.test/other");
        assert_eq!(result.binding.err(), Some(IdentityError::WrongService));
    }

    #[test]
    fn domain_document_must_name_this_platform_services_and_ca_root() {
        for (key, value) in [
            ("platform_id", "provider-c"),
            ("control_service_identity", "spiffe://provider-b.test/x"),
            ("edge_service_identity", "spiffe://provider-b.test/y"),
        ] {
            let mut doc = document();
            doc[key] = value.into();
            let result = evaluate(|_| {}, bootstrap(), evidence(&doc), CONTROL);
            assert_eq!(result.binding.err(), Some(IdentityError::WrongDomainDocument), "{key}");
        }
        let mut other_root = document();
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.resize(260, 0x11);
        other_root["agent_ca_root"] = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der).into();
        assert_eq!(evaluate(|_| {}, bootstrap(), evidence(&other_root), CONTROL).binding.err(), Some(IdentityError::WrongDomainDocument));
        let mut extra = document();
        extra["peers"] = serde_json::json!(["provider-a"]);
        assert_eq!(evaluate(|_| {}, bootstrap(), evidence(&extra), CONTROL).binding.err(), Some(IdentityError::WrongDomainDocument));
    }

    #[test]
    fn proof_location_profile_and_freshness_are_enforced() {
        let mut http = evidence(&document());
        http.url = "http://provider-b.test/.well-known/ptpan-provider.json".into();
        assert_eq!(evaluate(|_| {}, bootstrap(), http, CONTROL).binding.err(), Some(IdentityError::UnsupportedProfile));
        let mut other_host = evidence(&document());
        other_host.url = "https://provider-c.test/.well-known/ptpan-provider.json".into();
        assert_eq!(evaluate(|_| {}, bootstrap(), other_host, CONTROL).binding.err(), Some(IdentityError::UnsupportedProfile));
        let mut stale = evidence(&document());
        stale.fetched_at = "2026-09-21T11:00:00Z".into();
        assert_eq!(evaluate(|_| {}, bootstrap(), stale, CONTROL).binding.err(), Some(IdentityError::StaleOrInvalidEvidence));
        let mut future = evidence(&document());
        future.fetched_at = "2026-09-21T13:40:06Z".into();
        assert_eq!(evaluate(|_| {}, bootstrap(), future, CONTROL).binding.err(), Some(IdentityError::StaleOrInvalidEvidence));
        let mut skewed = evidence(&document());
        skewed.fetched_at = "2026-09-21T13:40:05Z".into();
        assert!(evaluate(|_| {}, bootstrap(), skewed, CONTROL).binding.is_ok());
    }

    #[test]
    fn checked_in_domain_schema_matches_the_document() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/provider-domain-v1.json")).unwrap();
        assert_eq!(schema["$id"], DOMAIN_DOCUMENT_SCHEMA);
        let parsed = parse_domain_document(&serde_json::to_vec(&document()).unwrap()).unwrap();
        crate::schema_check::matches(&schema, &schema, &serde_json::to_value(parsed).unwrap(), "domain");
    }

    #[test]
    fn local_test_profile_uses_http_only_for_its_own_location() {
        assert_eq!(
            well_known_url("provider-b.test", EvidenceProfile::LocalHttpTest),
            "http://provider-b.test/.well-known/ptpan-provider.json"
        );
    }
}
