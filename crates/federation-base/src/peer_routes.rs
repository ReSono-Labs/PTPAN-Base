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

#[cfg(test)]
mod tests {
    use super::*;

    fn platform(value: &str) -> PlatformId {
        PlatformId::new(value).unwrap()
    }

    fn routes() -> Vec<ServiceRoute> {
        vec![
            ServiceRoute {
                service_id: "spiffe://provider-b.test/federation/control".into(),
                platform_id: platform("provider-b"),
            },
            ServiceRoute {
                service_id: "spiffe://provider-c.test/federation/control".into(),
                platform_id: platform("provider-c"),
            },
        ]
    }

    #[test]
    fn authenticated_service_selects_its_platform_only() {
        let routes = routes();
        assert_eq!(
            select_peer(
                "spiffe://provider-c.test/federation/control",
                &platform("provider-c"),
                &routes
            )
            .unwrap(),
            platform("provider-c")
        );
        assert_eq!(
            select_peer(
                "spiffe://provider-c.test/federation/control",
                &platform("provider-b"),
                &routes
            ),
            Err(RouteError::ClaimedIdentityMismatch)
        );
        assert_eq!(
            select_peer("spiffe://link-d.test/federation/control", &platform("link-d"), &routes),
            Err(RouteError::UnknownService)
        );
    }

    #[test]
    fn duplicate_service_binding_is_rejected() {
        let mut routes = routes();
        routes.push(ServiceRoute {
            service_id: "spiffe://provider-c.test/federation/control".into(),
            platform_id: platform("provider-c"),
        });
        assert_eq!(
            select_peer(
                "spiffe://provider-c.test/federation/control",
                &platform("provider-c"),
                &routes
            ),
            Err(RouteError::AmbiguousService)
        );
    }

    #[test]
    fn failure_of_one_peer_leaves_the_other_queued() {
        let queued = [platform("provider-b"), platform("provider-c")];
        assert_eq!(
            other_peers_remain_queued(&queued, &platform("provider-b")),
            vec![platform("provider-c")]
        );
        assert_eq!(
            other_peers_remain_queued(&queued, &platform("provider-c")),
            vec![platform("provider-b")]
        );
    }
}
