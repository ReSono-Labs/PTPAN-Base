//! The agent-traffic edge (D3, D4, D11, D12). The bridge carries the bytes;
//! the runtime decides. Inbound: verify the admission token (stateless,
//! Base) with the platform's current bound key, then let the platform decide
//! atomically (`AdmitCall`). Outbound: route the destination address to a
//! verified, active peer's edge.

use crate::peers::Resolution;
use crate::Adapter;
use federation_base::address::address_in_domain;
use federation_base::live_admission::{
    admission_response_json, parse_admission_frame, verify_admission_token, AdmissionDecision,
    AdmissionDeny,
};
use federation_base::time::now_unix;
use federation_ipc::{AdmitReply, RouteEgressReply};
use ptpan_platform_api::v1 as api;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn deny(reason: AdmissionDeny, relationship_id: &str, destination: &str) -> AdmitReply {
    AdmitReply {
        response: admission_response_json(&AdmissionDecision::Deny(reason)).into_bytes(),
        allow: false,
        deadline: 0,
        relationship_id: relationship_id.into(),
        destination_address: destination.into(),
    }
}

impl Adapter {
    /// `ADMIT`: one admission frame from a peer's relay, authenticated as the
    /// peer edge `service`.
    pub async fn admit(&self, service: &str, frame: &[u8]) -> Result<AdmitReply> {
        let Ok(frame) = parse_admission_frame(frame) else {
            return Ok(deny(AdmissionDeny::BadProof, "", ""));
        };
        let relationship = frame.relationship_id.as_str();
        let destination = frame.destination_address.as_str();
        let Some((peer, record)) = self.peer_by_edge_service(service).await? else {
            return Ok(deny(AdmissionDeny::WrongIssuer, relationship, destination));
        };
        let now = now_unix();
        let own_digest = self.own_manifest(now).await?.digest;
        let active = record.gate(&own_digest, None).permits_request_delivery();
        let mut client = self.platform.client().await?;
        let key = client
            .get_bound_key(api::GetBoundKeyRequest { relationship_id: relationship.into() })
            .await?
            .into_inner();
        if !key.found {
            return Ok(deny(AdmissionDeny::GrantDenied, relationship, destination));
        }
        let claims = match verify_admission_token(&frame.token, &key.did_key, &peer, &self.config.edge_service_id, active, now) {
            Ok(claims) => claims,
            Err(reason) => return Ok(deny(reason, relationship, destination)),
        };
        if claims.relationship_id != frame.relationship_id
            || claims.destination_address != frame.destination_address
            || !address_in_domain(&claims.destination_address, &self.config.provider_domain)
            || !address_in_domain(&claims.sub, &record.bootstrap.provider_domain)
        {
            return Ok(deny(AdmissionDeny::BadProof, relationship, destination));
        }
        let decision = client
            .admit_call(api::AdmitCallRequest {
                relationship_id: relationship.into(),
                claims_json: serde_json::to_vec(&claims)?,
                verified_key_revision: key.key_revision,
            })
            .await?
            .into_inner();
        let reply = if decision.allowed {
            AdmitReply {
                response: admission_response_json(&AdmissionDecision::Allow { deadline: decision.deadline }).into_bytes(),
                allow: true,
                deadline: decision.deadline,
                relationship_id: relationship.into(),
                destination_address: destination.into(),
            }
        } else {
            AdmitReply {
                response: serde_json::to_vec(&serde_json::json!({
                    "schema": federation_base::live_admission::ADMISSION_SCHEMA,
                    "result": "DENY",
                    "reason": decision.reason,
                }))?,
                ..deny(AdmissionDeny::GrantDenied, relationship, destination)
            }
        };
        Ok(reply)
    }

    /// `ROUTE_EGRESS`: where to carry an agent stream the platform handed out.
    pub async fn route_egress(&self, frame: &[u8]) -> Result<Option<RouteEgressReply>> {
        let Ok(frame) = parse_admission_frame(frame) else { return Ok(None) };
        match self.resolve_address(&frame.destination_address).await? {
            Resolution::Peer(_, record) => Ok(Some(RouteEgressReply {
                edge_service_id: record.bootstrap.expected_edge_service_id.clone(),
                edge_endpoint: record.bootstrap.expected_edge_endpoint.clone(),
                relationship_id: frame.relationship_id.as_str().into(),
            })),
            _ => Ok(None),
        }
    }
}
