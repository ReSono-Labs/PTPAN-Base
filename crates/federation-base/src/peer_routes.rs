//! Peer selection follows the authenticated service, never a claimed platform
//! ID. One service ID binds one platform. Another peer's failure is not an
//! input to this choice.

use crate::PlatformId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceRoute {
    pub service_id: String,
    pub platform_id: PlatformId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteError {
    UnknownService,
    AmbiguousService,
    ClaimedIdentityMismatch,
}

pub fn select_peer(
    authenticated_service: &str,
    claimed_platform: &PlatformId,
    routes: &[ServiceRoute],
) -> Result<PlatformId, RouteError> {
    if authenticated_service.is_empty() {
        return Err(RouteError::UnknownService);
    }
    let mut found: Option<&PlatformId> = None;
    for route in routes {
        if route.service_id != authenticated_service {
            continue;
        }
        if found.is_some() {
            return Err(RouteError::AmbiguousService);
        }
        found = Some(&route.platform_id);
    }
    let Some(platform) = found else {
        return Err(RouteError::UnknownService);
    };
    if platform != claimed_platform {
        return Err(RouteError::ClaimedIdentityMismatch);
    }
    Ok(platform.clone())
}

/// Failure of one recipient leaves every other recipient's queued delivery
/// in place. The failed recipient is retried on its own queue.
pub fn other_peers_remain_queued(queued: &[PlatformId], failed: &PlatformId) -> Vec<PlatformId> {
    queued
        .iter()
        .filter(|peer| *peer != failed)
        .cloned()
        .collect()
}
