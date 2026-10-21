//! Peer trust: onboarding, identity checks (D14), approvals, planned manifest
//! changes (D8), suspension and removal, and publishing the live peer set to
//! the bridge (principle 10). The rules are Base's `peer_transitions`; this
//! module loads records, applies them and persists the result.

use crate::store::{Channel, OutboxEvent};
use crate::Adapter;
use federation_base::address::match_domain;
use federation_base::encoding::{hex_lower, sha256};
use federation_base::identity_evidence::{
    evaluate_provider_identity, well_known_url, BootstrapAuthority, DomainProofEvidence,
};
use federation_base::peer_control::{
    parse_peer_message, ParsedPeerMessage, PeerKind, PeerPayload, TrustDecisionResult, PEER_SCHEMA,
};
use federation_base::peer_routes::{select_peer, ServiceRoute};
use federation_base::peer_transitions::{
    self as rules, identity_needs_refresh, HelloOutcome, OperatorState, PeerRecord, ReceivedManifest,
    REQUEST_DELIVERY,
};
use federation_base::provider_manifest::{parse_manifest, ManifestSnapshot};
use federation_base::time::format_utc;
use federation_base::{PeerState, PlatformId, SUPPORTED_PROTOCOLS};
use federation_ipc::{CloseStreamsBody, PeerRoute, SetPeersBody};
use std::collections::BTreeSet;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Peer message delivery deadline: provider messages are retried for a day.
const PEER_MESSAGE_LIFETIME: u64 = 86_400;

fn received(snapshot: &ManifestSnapshot) -> ReceivedManifest {
    ReceivedManifest {
        revision: snapshot.manifest.revision,
        digest: snapshot.digest,
        exact_bytes: snapshot.exact_bytes.clone(),
    }
}

impl Adapter {
    /// The manifest this platform currently uses: the file, or an announced
    /// revision once its effective time has passed (D8).
    pub async fn own_manifest(&self, now: u64) -> Result<ManifestSnapshot> {
        let file = std::fs::read(&self.config.manifest_path)?;
        let current = parse_manifest(&file).map_err(|e| format!("own manifest: {e:?}"))?;
        if let Some((bytes, effective_at)) = self.store.pending_own_manifest().await? {
            let pending = parse_manifest(&bytes).map_err(|e| format!("pending manifest: {e:?}"))?;
            if pending.manifest.revision <= current.manifest.revision {
                self.store.set_pending_own_manifest(None).await?;
            } else if now >= effective_at {
                return Ok(pending);
            }
        }
        Ok(current)
    }

    pub async fn peer_by_control_service(
        &self,
        service: &str,
        claimed: &PlatformId,
    ) -> Result<(PlatformId, PeerRecord)> {
        let peers = self.store.peers().await?;
        let routes: Vec<ServiceRoute> = peers
            .iter()
            .filter(|(_, r)| r.operator != OperatorState::Removed)
            .map(|(id, r)| ServiceRoute {
                service_id: r.bootstrap.expected_control_service_id.clone(),
                platform_id: id.clone(),
            })
            .collect();
        let id = select_peer(service, claimed, &routes).map_err(|e| format!("peer: {e:?}"))?;
        let record = peers.into_iter().find(|(p, _)| *p == id).map(|(_, r)| r).ok_or("peer")?;
        Ok((id, record))
    }

    pub async fn peer_by_edge_service(&self, service: &str) -> Result<Option<(PlatformId, PeerRecord)>> {
        Ok(self
            .store
            .peers()
            .await?
            .into_iter()
            .find(|(_, r)| r.operator != OperatorState::Removed && r.bootstrap.expected_edge_service_id == service))
    }

    /// Platform resolver (review 11.2): the longest verified domain the
    /// address ends in. Never looks at the opaque part, never queries DNS.
    pub async fn resolve_address(&self, address: &str) -> Result<Resolution> {
        if !federation_base::address::valid_address(address) {
            return Ok(Resolution::BadSyntax);
        }
        let peers = self.store.peers().await?;
        let own = self.config.provider_domain.as_str();
        let domains: Vec<&str> = peers
            .iter()
            .filter(|(_, r)| r.operator != OperatorState::Removed)
            .map(|(_, r)| r.bootstrap.provider_domain.as_str())
            .chain(std::iter::once(own))
            .collect();
        let Some(domain) = match_domain(address, domains).map(str::to_owned) else {
            return Ok(Resolution::UnknownProvider);
        };
        if domain == own {
            return Ok(Resolution::OwnPlatform);
        }
        let (id, record) = peers
            .into_iter()
            .find(|(_, r)| r.bootstrap.provider_domain == domain)
            .ok_or("resolver")?;
        let now = federation_base::time::now_unix();
        let own_digest = self.own_manifest(now).await?.digest;
        if record.gate(&own_digest, None).permits_request_delivery() {
            Ok(Resolution::Peer(id, Box::new(record)))
        } else {
            Ok(Resolution::PeerNotActive(id))
        }
    }

    /// Publish every non-removed peer's routes to the bridge, so it follows
    /// the peer store without a restart (principle 10).
    /// A removed peer keeps its route only while messages to it (such as the
    /// removal notice itself) are still queued.
    pub async fn publish_routes(&self, version: u64) -> Result<()> {
        let mut peers = Vec::new();
        for (id, record) in self.store.peers().await? {
            if record.operator != OperatorState::Removed || self.store.queued_count(&id).await? > 0 {
                peers.push(record);
            }
        }
        let routes = peers
            .into_iter()
            .map(|r| PeerRoute {
                control_service_id: r.bootstrap.expected_control_service_id.clone(),
                control_endpoint: r.bootstrap.expected_control_endpoint.clone(),
                edge_service_id: r.bootstrap.expected_edge_service_id.clone(),
                edge_endpoint: r.bootstrap.expected_edge_endpoint.clone(),
            })
            .collect();
        self.bridge.set_peers(&SetPeersBody { version, routes }).await?;
        Ok(())
    }

    // --- Outbound provider messages ---------------------------------------

    async fn enqueue_peer_message(
        &self,
        peer: &PlatformId,
        record: &PeerRecord,
        kind: PeerKind,
        message_id: String,
        payload: serde_json::Value,
        now: u64,
    ) -> Result<()> {
        let body = serde_json::json!({
            "schema": PEER_SCHEMA,
            "message_id": message_id,
            "kind": kind,
            "sender_platform_id": self.config.platform_id,
            "recipient_platform_id": peer,
            "generation": record.generation,
            "sent_at": format_utc(now),
            "payload": payload,
        });
        let bytes = serde_json::to_vec(&body)?;
        let digest = federation_base::encoding::canonical_digest(&body).ok_or("canonical")?.1;
        self.store
            .enqueue(
                &OutboxEvent {
                    event_id: message_id,
                    handoff_id: None,
                    peer: peer.clone(),
                    channel: Channel::Peer,
                    kind: serde_json::to_value(kind)?.as_str().unwrap_or_default().to_owned(),
                    exact_bytes: bytes,
                    body_digest: digest,
                    expires_at: now + PEER_MESSAGE_LIFETIME,
                    attempts: 0,
                },
                now,
            )
            .await?;
        self.outbox_wake.notify_one();
        Ok(())
    }

    /// Send our current manifest. The message ID is derived from the peer,
    /// its bootstrap generation and our digest, so repeating it is harmless.
    pub async fn send_hello(&self, peer: &PlatformId, record: &PeerRecord, own: &ManifestSnapshot, now: u64) -> Result<()> {
        let id = format!("hello-{}-{}-{}", peer.as_str(), record.generation, &hex_lower(&own.digest)[..32]);
        let manifest: serde_json::Value = serde_json::from_slice(&own.exact_bytes)?;
        self.enqueue_peer_message(peer, record, PeerKind::PeerHello, id, serde_json::json!({ "manifest": manifest }), now)
            .await
    }

    async fn send_trust_decision(
        &self,
        peer: &PlatformId,
        record: &PeerRecord,
        own_digest: &[u8; 32],
        their_digest: &[u8; 32],
        now: u64,
    ) -> Result<()> {
        let id = format!("trust-{}-{}-{}", peer.as_str(), &hex_lower(own_digest)[..16], &hex_lower(their_digest)[..16]);
        self.enqueue_peer_message(
            peer,
            record,
            PeerKind::TrustDecision,
            id.clone(),
            serde_json::json!({
                "request_id": id,
                "result": TrustDecisionResult::Approved,
                "sender_manifest_digest": hex_lower(own_digest),
                "recipient_manifest_digest": hex_lower(their_digest),
                "approved_capabilities": [REQUEST_DELIVERY],
                "decided_at": format_utc(now),
            }),
            now,
        )
        .await
    }

    async fn send_restriction(&self, peer: &PlatformId, record: &PeerRecord, kind: PeerKind, now: u64) -> Result<()> {
        let id = format!("restrict-{}-{now}", peer.as_str());
        let reason = if kind == PeerKind::TrustRemove { "OPERATOR_REMOVED" } else { "OPERATOR_SUSPENDED" };
        self.enqueue_peer_message(
            peer,
            record,
            kind,
            id,
            serde_json::json!({ "reason_code": reason, "effective_at": format_utc(now) }),
            now,
        )
        .await
    }

    // --- Inbound provider messages ----------------------------------------

    /// Apply one authenticated provider message; returns the receipt result.
    pub async fn handle_peer_message(&self, bytes: &[u8], service: &str, claimed: &PlatformId) -> Result<(ParsedPeerMessage, &'static str)> {
        let (peer, record) = self.peer_by_control_service(service, claimed).await?;
        let parsed = parse_peer_message(
            bytes,
            &peer,
            &self.config.platform_id,
            service,
            &record.bootstrap.expected_control_service_id,
        )
        .map_err(|e| format!("peer message: {e:?}"))?;
        let now = federation_base::time::now_unix();
        let own = self.own_manifest(now).await?;
        let result = match &parsed.message.payload {
            PeerPayload::Hello(snapshot) => {
                let manifest = received(snapshot);
                let outcome = self
                    .store
                    .update_peer(&peer, now, |r| Ok(rules::receive_hello(r, manifest, service).map_err(|e| format!("{e:?}"))?))
                    .await?;
                if outcome != HelloOutcome::Unchanged {
                    self.verify_identity(&peer, now).await?;
                }
                let record = self.store.peer(&peer).await?.ok_or("peer")?;
                self.send_hello(&peer, &record, &own, now).await?;
                "CANDIDATE_SAVED"
            }
            PeerPayload::Decision(decision) => {
                let sender = federation_base::encoding::decode_hex32(&decision.sender_manifest_digest).ok_or("digest")?;
                let ours = federation_base::encoding::decode_hex32(&decision.recipient_manifest_digest).ok_or("digest")?;
                let capabilities: BTreeSet<String> = decision.approved_capabilities.iter().cloned().collect();
                let result = decision.result.clone();
                self.store
                    .update_peer(&peer, now, |r| {
                        Ok(rules::receive_trust_decision(r, sender, ours, result, &capabilities).map_err(|e| format!("{e:?}"))?)
                    })
                    .await?;
                "DECISION_RECORDED"
            }
            PeerPayload::Suspend(_) | PeerPayload::Remove(_) => {
                self.store.update_peer(&peer, now, |r| {
                    rules::receive_restriction(r);
                    Ok(())
                })
                .await?;
                self.close_peer_streams(&record).await;
                if matches!(parsed.message.payload, PeerPayload::Remove(_)) { "REMOVED" } else { "SUSPENDED" }
            }
            PeerPayload::ManifestPending(pending) => {
                let manifest = received(&pending.manifest);
                let effective = federation_base::time::utc_unix_seconds(&pending.effective_at).ok_or("time")? as u64;
                self.store
                    .update_peer(&peer, now, |r| Ok(rules::receive_pending(r, manifest, effective).map_err(|e| format!("{e:?}"))?))
                    .await?;
                "PENDING_RECORDED"
            }
        };
        Ok((parsed, result))
    }

    /// Fetch the peer's domain proof through the bridge and run the full
    /// identity check against its current manifest (D14).
    pub async fn verify_identity(&self, peer: &PlatformId, now: u64) -> Result<bool> {
        let record = self.store.peer(peer).await?.ok_or("peer")?;
        let Some(current) = &record.current else { return Ok(false) };
        let snapshot = parse_manifest(&current.exact_bytes).map_err(|e| format!("{e:?}"))?;
        let url = well_known_url(&record.bootstrap.provider_domain, self.config.evidence_profile);
        let reply = match self.bridge.fetch_domain_proof(&url).await {
            Ok(reply) => reply,
            Err(_) => {
                // The proof could not be fetched (bridge or provider down).
                // Keep the previous result until it is actually too old.
                let limit = u64::try_from(record.bootstrap.max_evidence_age_seconds).unwrap_or(0);
                let stale = record.verified_at.is_none_or(|at| now.saturating_sub(at) >= limit);
                if stale && record.verified_digest.is_some() {
                    let digest = current.digest;
                    self.store
                        .update_peer(peer, now, |r| {
                            rules::record_identity(r, digest, None);
                            Ok(())
                        })
                        .await?;
                }
                return Ok(false);
            }
        };
        let fetched_at = federation_base::time::utc_unix_seconds(&reply.fetched_at).unwrap_or(0) as u64;
        let evidence = DomainProofEvidence { url: reply.url, fetched_at: reply.fetched_at, body: reply.body };
        let evaluation = evaluate_provider_identity(
            &snapshot,
            &record.bootstrap,
            &record.bootstrap.expected_control_service_id,
            &evidence,
            self.config.evidence_profile,
            &SUPPORTED_PROTOCOLS,
            now as i64,
        );
        self.store.record_observations(peer, &snapshot.digest, &evaluation.observations, now).await?;
        let verified = evaluation.binding.is_ok();
        let digest = snapshot.digest;
        self.store
            .update_peer(peer, now, |r| {
                rules::record_identity(r, digest, verified.then_some(fetched_at));
                Ok(())
            })
            .await?;
        Ok(verified)
    }

    async fn close_peer_streams(&self, record: &PeerRecord) {
        let _ = self
            .bridge
            .close_streams(&CloseStreamsBody {
                relationship_id: None,
                peer_service_id: Some(record.bootstrap.expected_edge_service_id.clone()),
            })
            .await;
    }

    // --- Operator actions ---------------------------------------------------

    pub async fn add_peer(&self, bootstrap: BootstrapAuthority, now: u64) -> Result<()> {
        if !federation_base::address::valid_provider_domain(&bootstrap.provider_domain) {
            return Err("bootstrap provider_domain must be lowercase ASCII".into());
        }
        let id = bootstrap.peer.clone();
        match self.store.peer(&id).await? {
            None => self.store.add_peer(&id, &PeerRecord::new(bootstrap), now).await?,
            Some(_) => {
                self.store
                    .update_peer(&id, now, |r| Ok(r.replace_bootstrap(bootstrap).map_err(|e| format!("{e:?}"))?))
                    .await?
            }
        }
        Ok(())
    }

    pub async fn approve_peer(&self, peer: &PlatformId, now: u64) -> Result<()> {
        let their = self
            .store
            .update_peer(peer, now, |r| Ok(rules::approve_locally(r).map_err(|e| format!("{e:?}"))?))
            .await?;
        let own = self.own_manifest(now).await?;
        let record = self.store.peer(peer).await?.ok_or("peer")?;
        self.send_trust_decision(peer, &record, &own.digest, &their, now).await
    }

    pub async fn approve_pending(&self, peer: &PlatformId, now: u64) -> Result<()> {
        let their = self
            .store
            .update_peer(peer, now, |r| Ok(rules::approve_pending(r).map_err(|e| format!("{e:?}"))?))
            .await?;
        let own = self.own_manifest(now).await?;
        let record = self.store.peer(peer).await?.ok_or("peer")?;
        self.send_trust_decision(peer, &record, &own.digest, &their, now).await
    }

    pub async fn suspend_peer(&self, peer: &PlatformId, now: u64) -> Result<()> {
        self.store.update_peer(peer, now, |r| Ok(rules::suspend(r).map_err(|e| format!("{e:?}"))?)).await?;
        let record = self.store.peer(peer).await?.ok_or("peer")?;
        self.close_peer_streams(&record).await;
        self.send_restriction(peer, &record, PeerKind::TrustSuspend, now).await
    }

    /// Resume a suspended peer and tell it again that we approve it, which
    /// clears the suspension on its side too.
    pub async fn resume_peer(&self, peer: &PlatformId, now: u64) -> Result<()> {
        self.store.update_peer(peer, now, |r| Ok(rules::resume(r).map_err(|e| format!("{e:?}"))?)).await?;
        let record = self.store.peer(peer).await?.ok_or("peer")?;
        if let Some(their) = record.local_approved_digest {
            let own = self.own_manifest(now).await?;
            let id = format!("resume-{}-{now}", peer.as_str());
            self.enqueue_peer_message(
                peer,
                &record,
                PeerKind::TrustDecision,
                id.clone(),
                serde_json::json!({
                    "request_id": id,
                    "result": TrustDecisionResult::Approved,
                    "sender_manifest_digest": hex_lower(&own.digest),
                    "recipient_manifest_digest": hex_lower(&their),
                    "approved_capabilities": [REQUEST_DELIVERY],
                    "decided_at": format_utc(now),
                }),
                now,
            )
            .await?;
        }
        Ok(())
    }

    pub async fn remove_peer(&self, peer: &PlatformId, now: u64) -> Result<()> {
        let before = self.store.peer(peer).await?.ok_or("peer")?;
        self.send_restriction(peer, &before, PeerKind::TrustRemove, now).await?;
        self.store.update_peer(peer, now, |r| {
            rules::remove(r);
            Ok(())
        })
        .await?;
        self.close_peer_streams(&before).await;
        Ok(())
    }

    /// Announce a planned revision of our own manifest to every peer (D8).
    pub async fn propose_manifest(&self, bytes: &[u8], effective_at: u64, now: u64) -> Result<()> {
        let pending = parse_manifest(bytes).map_err(|e| format!("manifest: {e:?}"))?;
        let current = self.own_manifest(now).await?;
        if pending.manifest.revision <= current.manifest.revision || effective_at <= now {
            return Err("a proposed manifest needs a higher revision and a future effective time".into());
        }
        if pending.manifest.platform.platform_id != self.config.platform_id {
            return Err("a proposed manifest must name this platform".into());
        }
        self.store.set_pending_own_manifest(Some((bytes, effective_at))).await?;
        self.announce_pending(now).await
    }

    async fn announce_pending(&self, now: u64) -> Result<()> {
        let Some((bytes, effective_at)) = self.store.pending_own_manifest().await? else { return Ok(()) };
        if now >= effective_at {
            return Ok(());
        }
        let manifest: serde_json::Value = serde_json::from_slice(&bytes)?;
        let tag = &hex_lower(&sha256(&bytes))[..32];
        for (peer, record) in self.store.peers().await? {
            if record.operator == OperatorState::Removed {
                continue;
            }
            let id = format!("pending-{}-{tag}", peer.as_str());
            let payload = serde_json::json!({ "manifest": manifest, "effective_at": format_utc(effective_at) });
            self.enqueue_peer_message(&peer, &record, PeerKind::ManifestPending, id, payload, now).await?;
        }
        Ok(())
    }

    /// Periodic upkeep: hello every peer with our current manifest, refresh
    /// identity checks before they go stale, and announce a pending revision.
    pub async fn maintain_peers(&self, now: u64) -> Result<()> {
        let own = self.own_manifest(now).await?;
        for (peer, record) in self.store.peers().await? {
            if record.operator == OperatorState::Removed {
                continue;
            }
            self.send_hello(&peer, &record, &own, now).await?;
            if identity_needs_refresh(&record, now) {
                self.verify_identity(&peer, now).await?;
            }
        }
        self.announce_pending(now).await
    }

    /// Peer summary for health output.
    pub async fn peer_states(&self, now: u64) -> Result<Vec<(PlatformId, PeerState, u64)>> {
        let own = self.own_manifest(now).await?;
        let mut out = Vec::new();
        for (peer, record) in self.store.peers().await? {
            let queued = self.store.queued_count(&peer).await?;
            out.push((peer, record.gate(&own.digest, None).state, queued));
        }
        Ok(out)
    }
}

/// The platform resolver's answer for one address.
pub enum Resolution {
    Peer(PlatformId, Box<PeerRecord>),
    BadSyntax,
    UnknownProvider,
    PeerNotActive(PlatformId),
    OwnPlatform,
}
