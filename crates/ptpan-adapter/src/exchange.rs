//! Exchange with peers (D1): hand-off records become exact control events,
//! the outbox delivers them with retries and per-peer fencing, and inbound
//! events are checked and handed to the platform. Event bytes are written
//! once and retried unchanged (WB-04.4).

use crate::peers::Resolution;
use crate::store::{Channel, OutboxEvent};
use crate::Adapter;
use federation_base::address::address_in_domain;
use federation_base::control_event::{
    parse_control_event, parse_receipt, ActorSide, ControlPayload, ControlReceipt, ReceiptResult,
    RequestPayload, CONTROL_SCHEMA,
};
use federation_base::peer_control::{parse_peer_message, parse_peer_receipt};
use federation_base::relationship_lifecycle::{peer_allows, AffirmativeTraffic};
use federation_base::time::{format_utc, now_unix};
use federation_base::{check_inbound_request, PlatformId};
use federation_ipc::CloseStreamsBody;
use ptpan_platform_api::v1 as api;
use ptpan_platform_api::v1::platform_service_client::PlatformServiceClient;
use tonic::transport::Channel as GrpcChannel;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Delivery deadline for events other than requests (which carry their own).
const LIFECYCLE_LIFETIME: u64 = 30 * 86_400;
const BATCH: u32 = 50;

fn kind_name(kind: api::ControlKind) -> Option<&'static str> {
    use api::ControlKind as K;
    Some(match kind {
        K::RelationshipRequest => "RELATIONSHIP_REQUEST",
        K::RelationshipDecision => "RELATIONSHIP_DECISION",
        K::RelationshipRevoke => "RELATIONSHIP_REVOKE",
        K::RelationshipStatus => "RELATIONSHIP_STATUS",
        K::SourceAuthorizationStatus => "SOURCE_AUTHORIZATION_STATUS",
        K::ConfigAck => "CONFIG_ACK",
        K::PairBlockStatus => "PAIR_BLOCK_STATUS",
        K::Unspecified => return None,
    })
}

fn api_kind(payload: &ControlPayload) -> api::ControlKind {
    use api::ControlKind as K;
    match payload {
        ControlPayload::Request(_) => K::RelationshipRequest,
        ControlPayload::Decision(_) => K::RelationshipDecision,
        ControlPayload::Revoke(_) => K::RelationshipRevoke,
        ControlPayload::Status(_) => K::RelationshipStatus,
        ControlPayload::SourceAuthorization(_) => K::SourceAuthorizationStatus,
        ControlPayload::ConfigAck(_) => K::ConfigAck,
        ControlPayload::PairBlockStatus(_) => K::PairBlockStatus,
    }
}

/// Restrictive events still flow to a suspended peer; everything else needs
/// an active peer (principle 11, D8).
fn traffic(kind: &str) -> AffirmativeTraffic {
    match kind {
        "RELATIONSHIP_REVOKE" | "PAIR_BLOCK_STATUS" | "SOURCE_AUTHORIZATION_STATUS" => AffirmativeTraffic::CleanupOrRevoke,
        "RELATIONSHIP_REQUEST" => AffirmativeTraffic::NewRelationship,
        _ => AffirmativeTraffic::Admission,
    }
}

impl Adapter {
    async fn client(&self) -> Result<PlatformServiceClient<GrpcChannel>> {
        match self.platform.client().await {
            Ok(client) => {
                self.set_platform_reachable(true);
                Ok(client)
            }
            Err(e) => {
                self.set_platform_reachable(false);
                Err(e.into())
            }
        }
    }

    /// Platform call failed: forget the channel so the next call reconnects.
    async fn platform_failed(&self, error: tonic::Status) -> Box<dyn std::error::Error + Send + Sync> {
        if error.code() == tonic::Code::Unavailable {
            self.set_platform_reachable(false);
            self.platform.reset().await;
        }
        error.into()
    }

    async fn notice(&self, client: &mut PlatformServiceClient<GrpcChannel>, request_id: &str, kind: api::NoticeKind) -> Result<()> {
        client
            .record_notice(api::RecordNoticeRequest { request_id: request_id.into(), kind: kind as i32 })
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // --- Hand-off -----------------------------------------------------------

    /// Read one batch of hand-off records and turn each into an outbox event.
    /// Returns true when it processed anything.
    pub async fn consume_handoff(&self) -> Result<bool> {
        let mut client = self.client().await?;
        let records = match client.read_handoff(api::ReadHandoffRequest { after_cursor: 0, limit: BATCH }).await {
            Ok(response) => response.into_inner().records,
            Err(e) => return Err(self.platform_failed(e).await),
        };
        let any = !records.is_empty();
        for record in records {
            self.take_handoff(&mut client, record).await?;
        }
        Ok(any)
    }

    async fn ack(&self, client: &mut PlatformServiceClient<GrpcChannel>, handoff_id: &str) -> Result<()> {
        client
            .ack_handoff(api::AckHandoffRequest { handoff_id: handoff_id.into() })
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn take_handoff(&self, client: &mut PlatformServiceClient<GrpcChannel>, record: api::HandoffRecord) -> Result<()> {
        if self.store.handoff_stored(&record.handoff_id).await? {
            return self.ack(client, &record.handoff_id).await;
        }
        let now = now_unix();
        let Some(kind) = api::ControlKind::try_from(record.kind).ok().and_then(kind_name) else {
            eprintln!("hand-off {}: unknown kind; dropped", record.handoff_id);
            return self.ack(client, &record.handoff_id).await;
        };
        let payload: serde_json::Value = match serde_json::from_slice(&record.payload_json) {
            Ok(value) => value,
            Err(_) => {
                eprintln!("hand-off {}: payload is not JSON; dropped", record.handoff_id);
                return self.ack(client, &record.handoff_id).await;
            }
        };
        let local = self.config.platform_id.clone();
        let (peer, expires_at) = if kind == "RELATIONSHIP_REQUEST" {
            let request: RequestPayload = match serde_json::from_value(payload.clone()) {
                Ok(request) => request,
                Err(_) => {
                    eprintln!("hand-off {}: invalid request; dropped", record.handoff_id);
                    return self.ack(client, &record.handoff_id).await;
                }
            };
            let refusal = match self.resolve_address(&request.request.target_address).await? {
                Resolution::Peer(id, _) => {
                    let authorized = client
                        .authorize_source(api::AuthorizeSourceRequest { request_id: record.request_id.clone() })
                        .await
                        .map_err(|e| e.to_string())?
                        .into_inner()
                        .authorized;
                    if authorized {
                        Ok(id)
                    } else {
                        Err(api::NoticeKind::SourceNotAuthorized)
                    }
                }
                Resolution::PeerNotActive(_) => Err(api::NoticeKind::PeerNotActive),
                Resolution::BadSyntax | Resolution::UnknownProvider | Resolution::OwnPlatform => {
                    Err(api::NoticeKind::UnknownProvider)
                }
            };
            match refusal {
                Ok(id) => (id, request.request.request_expires_at),
                Err(notice) => {
                    self.notice(client, &record.request_id, notice).await?;
                    return self.ack(client, &record.handoff_id).await;
                }
            }
        } else {
            match PlatformId::new(record.peer_platform_id.clone()) {
                Ok(id) if self.store.peer(&id).await?.is_some() => (id, now + LIFECYCLE_LIFETIME),
                _ => {
                    eprintln!("hand-off {}: unknown peer; dropped", record.handoff_id);
                    return self.ack(client, &record.handoff_id).await;
                }
            }
        };
        let source_side = api::ActorSide::try_from(record.actor_side) == Ok(api::ActorSide::Source);
        let actor = if source_side { ActorSide::Source } else { ActorSide::Destination };
        let scope = match record.relationship_id.as_str() {
            "" => format!("pair/{}/{:?}", peer.as_str(), actor),
            id => format!("rel/{id}/{actor:?}"),
        };
        let event_id = format!("ev-{}", record.handoff_id);
        let event = serde_json::json!({
            "schema": CONTROL_SCHEMA,
            "event_id": event_id,
            "kind": kind,
            "sender_platform_id": local,
            "recipient_platform_id": peer,
            "originating_platform_id": if source_side { &local } else { &peer },
            "relationship_id": (!record.relationship_id.is_empty()).then_some(&record.relationship_id),
            "request_id": (!record.request_id.is_empty()).then_some(&record.request_id),
            "actor_side": actor,
            "actor_revision": self.store.next_actor_revision(&scope).await?,
            "created_at": format_utc(now),
            "delivery_expires_at": format_utc(expires_at.max(now + 1)),
            "payload": payload,
        });
        let bytes = serde_json::to_vec(&event)?;
        let parsed = match parse_control_event(&bytes, &local, &peer) {
            Ok(parsed) => parsed,
            Err(e) => {
                eprintln!("hand-off {}: event rejected by Base ({e:?}); dropped", record.handoff_id);
                return self.ack(client, &record.handoff_id).await;
            }
        };
        self.store
            .enqueue(
                &OutboxEvent {
                    event_id,
                    handoff_id: Some(record.handoff_id.clone()),
                    peer,
                    channel: Channel::Control,
                    kind: kind.into(),
                    exact_bytes: parsed.exact_bytes,
                    body_digest: parsed.body_digest,
                    expires_at,
                    attempts: 0,
                },
                now,
            )
            .await?;
        self.ack(client, &record.handoff_id).await?;
        if kind == "RELATIONSHIP_REQUEST" {
            self.notice(client, &record.request_id, api::NoticeKind::WaitingForDelivery).await?;
        }
        if kind == "RELATIONSHIP_REVOKE" {
            self.close_relationship_streams(&record.relationship_id).await;
        }
        self.outbox_wake.notify_one();
        Ok(())
    }

    async fn close_relationship_streams(&self, relationship_id: &str) {
        let _ = self
            .bridge
            .close_streams(&CloseStreamsBody { relationship_id: Some(relationship_id.into()), peer_service_id: None })
            .await;
    }

    // --- Outbox -------------------------------------------------------------

    /// Deliver due events for every peer this copy holds the lease for, then
    /// pass stored receipts to the platform.
    pub async fn deliver_due(&self) -> Result<()> {
        let now = now_unix();
        let own_digest = self.own_manifest(now).await?.digest;
        for peer in self.store.peers_with_queued().await? {
            if !self
                .store
                .acquire_peer_lease(&peer, &self.config.worker_id, now, crate::PEER_LEASE_SECONDS)
                .await?
            {
                continue;
            }
            let Some(record) = self.store.peer(&peer).await? else { continue };
            let state = record.gate(&own_digest, None).state;
            for event in self.store.due(&peer, now, 20).await? {
                if event.expires_at <= now {
                    self.store.mark_expired(&event.event_id).await?;
                    if event.kind == "RELATIONSHIP_REQUEST" {
                        if let (Ok(mut client), Some(request_id)) = (self.client().await, request_id_of(&event.exact_bytes)) {
                            let _ = self.notice(&mut client, &request_id, api::NoticeKind::ExpiredUndelivered).await;
                        }
                    }
                    continue;
                }
                if event.channel == Channel::Control && !peer_allows(state, traffic(&event.kind)) {
                    continue;
                }
                let service = &record.bootstrap.expected_control_service_id;
                match self.bridge.send(service, event.exact_bytes.clone()).await {
                    Ok(receipt) if self.receipt_matches(&event, &peer, &receipt) => {
                        self.set_bridge_reachable(true);
                        self.store.mark_receipted(&event, &receipt).await?;
                    }
                    Ok(_) => {
                        eprintln!("event {}: receipt does not match; will retry", event.event_id);
                        self.store.reschedule(&event.event_id, event.attempts, now).await?;
                    }
                    Err(crate::bridge::BridgeError::Unavailable(_)) => {
                        self.set_bridge_reachable(false);
                        self.store.reschedule(&event.event_id, event.attempts, now).await?;
                    }
                    Err(crate::bridge::BridgeError::Refused(_)) => {
                        self.store.reschedule(&event.event_id, event.attempts, now).await?;
                    }
                }
            }
        }
        self.confirm_receipts().await
    }

    fn receipt_matches(&self, event: &OutboxEvent, peer: &PlatformId, receipt: &[u8]) -> bool {
        let local = &self.config.platform_id;
        match event.channel {
            Channel::Control => {
                let (Ok(sent), Ok(parsed)) =
                    (parse_control_event(&event.exact_bytes, local, peer), parse_receipt(receipt))
                else {
                    return false;
                };
                parsed.validate_against(&sent).is_ok() && &parsed.sender_platform_id == local
            }
            Channel::Peer => {
                // Re-parse our own message as the peer sees it (sent by our
                // control service), then check the receipt binds those bytes.
                let own = &self.config.control_service_id;
                match parse_peer_message(&event.exact_bytes, local, peer, own, own) {
                    Ok(parsed) => parse_peer_receipt(receipt, &parsed, peer).is_ok(),
                    Err(_) => false,
                }
            }
        }
    }

    async fn confirm_receipts(&self) -> Result<()> {
        let pending = self.store.unconfirmed(50).await?;
        if pending.is_empty() {
            return Ok(());
        }
        let mut client = self.client().await?;
        for (handoff_id, event_id, receipt) in pending {
            let result = match parse_receipt(&receipt).map(|r| r.result) {
                Ok(ReceiptResult::QueuedForLocalOwner) => api::ReceiptResult::QueuedForLocalOwner,
                Ok(ReceiptResult::AddressNotRecognized) => api::ReceiptResult::AddressNotRecognized,
                Ok(ReceiptResult::Applied) => api::ReceiptResult::Applied,
                _ => api::ReceiptResult::Rejected,
            };
            if let Err(e) = client
                .confirm_receipt(api::ConfirmReceiptRequest { handoff_id, result: result as i32 })
                .await
            {
                return Err(self.platform_failed(e).await);
            }
            self.store.mark_confirmed(&event_id).await?;
        }
        Ok(())
    }

    // --- Inbound control events ---------------------------------------------

    /// One authenticated inbound control event. Returns the receipt bytes. A
    /// platform failure returns an error and stores nothing, so the peer
    /// retries the same bytes.
    pub async fn receive_control(&self, service: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        let claimed: serde_json::Value = serde_json::from_slice(bytes)?;
        let claimed = PlatformId::new(claimed["sender_platform_id"].as_str().unwrap_or_default())?;
        let (peer, record) = self.peer_by_control_service(service, &claimed).await?;
        let local = &self.config.platform_id;
        let parsed = parse_control_event(bytes, &peer, local).map_err(|e| format!("control: {e:?}"))?;
        let event_id = parsed.event.event_id.as_str().to_owned();
        match self.store.inbox_receipt(&peer, &event_id, &parsed.body_digest).await? {
            Some(Ok(receipt)) => return Ok(receipt),
            Some(Err(())) => return Err("same event ID with different bytes".into()),
            None => {}
        }
        let now = now_unix();
        let own_digest = self.own_manifest(now).await?.digest;
        let gate = record.gate(&own_digest, Some(service));
        let kind = api_kind(&parsed.event.payload);
        let kind_text = kind_name(kind).unwrap_or_default();
        if !peer_allows(gate.state, traffic(kind_text)) {
            return Err("peer not active".into());
        }
        let peer_domain = record.bootstrap.provider_domain.as_str();
        let own_domain = self.config.provider_domain.as_str();
        let mut client = self.client().await?;
        let result = match &parsed.event.payload {
            ControlPayload::Request(payload) => {
                if check_inbound_request(&payload.request, &peer, peer_domain, own_domain, &gate, now).is_err() {
                    ReceiptResult::Rejected
                } else {
                    let response = client
                        .deliver_inbound(api::DeliverInboundRequest {
                            source_platform_id: peer.as_str().into(),
                            event_id: event_id.clone(),
                            request_json: serde_json::to_vec(&payload.request)?,
                        })
                        .await;
                    match response {
                        Ok(r) if r.get_ref().result == api::DeliveryResult::QueuedForLocalOwner as i32 => {
                            ReceiptResult::QueuedForLocalOwner
                        }
                        Ok(_) => ReceiptResult::AddressNotRecognized,
                        Err(e) => return Err(self.platform_failed(e).await),
                    }
                }
            }
            ControlPayload::Decision(payload) => {
                let ca_root = record
                    .current
                    .as_ref()
                    .and_then(|m| federation_base::provider_manifest::parse_manifest(&m.exact_bytes).ok())
                    .map(|s| s.manifest.agent_trust.ca_root)
                    .unwrap_or_default();
                let response = client
                    .apply_decision(api::ApplyDecisionRequest {
                        source_platform_id: peer.as_str().into(),
                        event_id: event_id.clone(),
                        request_id: parsed.event.request_id.as_ref().map(|r| r.as_str().to_owned()).unwrap_or_default(),
                        decision_json: serde_json::to_vec(payload)?,
                        peer_agent_ca_root: ca_root,
                        peer_edge_service_id: record.bootstrap.expected_edge_service_id.clone(),
                    })
                    .await;
                applied(self, response).await?
            }
            other => {
                if let ControlPayload::PairBlockStatus(block) = other {
                    if !address_in_domain(&block.requester_reference, own_domain)
                        || !address_in_domain(&block.destination_address, peer_domain)
                    {
                        let receipt = ControlReceipt::for_event(&parsed, ReceiptResult::Rejected);
                        let bytes = serde_json::to_vec(&receipt)?;
                        self.store.store_inbox(&peer, &event_id, &parsed.body_digest, &bytes, now).await?;
                        return Ok(bytes);
                    }
                }
                let payload_json = control_payload_json(other)?;
                let response = client
                    .apply_lifecycle(api::ApplyLifecycleRequest {
                        peer_platform_id: peer.as_str().into(),
                        event_id: event_id.clone(),
                        kind: kind as i32,
                        relationship_id: parsed.event.relationship_id.as_ref().map(|r| r.as_str().to_owned()).unwrap_or_default(),
                        payload_json,
                    })
                    .await;
                let result = applied(self, response).await?;
                if matches!(other, ControlPayload::Revoke(_)) && result == ReceiptResult::Applied {
                    if let Some(id) = &parsed.event.relationship_id {
                        self.close_relationship_streams(id.as_str()).await;
                    }
                }
                result
            }
        };
        let receipt = serde_json::to_vec(&ControlReceipt::for_event(&parsed, result))?;
        self.store.store_inbox(&peer, &event_id, &parsed.body_digest, &receipt, now).await?;
        Ok(receipt)
    }
}

async fn applied(
    adapter: &Adapter,
    response: std::result::Result<tonic::Response<api::ApplyResponse>, tonic::Status>,
) -> Result<ReceiptResult> {
    match response {
        Ok(r) if r.get_ref().result == api::ApplyResult::Applied as i32 => Ok(ReceiptResult::Applied),
        Ok(_) => Ok(ReceiptResult::Rejected),
        Err(e) => Err(adapter.platform_failed(e).await),
    }
}

fn control_payload_json(payload: &ControlPayload) -> Result<Vec<u8>> {
    Ok(match payload {
        ControlPayload::Request(p) => serde_json::to_vec(p)?,
        ControlPayload::Decision(p) => serde_json::to_vec(p)?,
        ControlPayload::Revoke(p) => serde_json::to_vec(p)?,
        ControlPayload::Status(p) => serde_json::to_vec(p)?,
        ControlPayload::SourceAuthorization(p) => serde_json::to_vec(p)?,
        ControlPayload::ConfigAck(p) => serde_json::to_vec(p)?,
        ControlPayload::PairBlockStatus(p) => serde_json::to_vec(p)?,
    })
}

fn request_id_of(bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    value["request_id"].as_str().map(str::to_owned)
}
