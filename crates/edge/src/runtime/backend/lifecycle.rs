use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use log::{debug, info, warn};
use spooky_lb::{backend::HealthTransition, upstream_pool::UpstreamPool};
use spooky_transport::{h2_client::SharedDnsResolver, transport_pool::UpstreamTransportPool};

use super::{
    event::{
        BackendHealthObservation, BackendHealthObservationOutcome, BackendHealthObservationSource,
        BackendLifecycleMutation, BackendRefreshOutcome, BackendRequestFeedback,
        BackendRequestFeedbackOutcome,
    },
    resolution::RuntimeBackendResolution,
    store::RuntimeBackendResolutionStore,
    state::{
        BackendHealthState, BackendIdentity, BackendLifecycleSnapshot, BackendMembershipState,
        BackendResolutionState,
    },
};
use crate::Metrics;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBackendLifecycleState {
    pub identity: BackendIdentity,
    pub resolution: BackendResolutionState,
    pub health: BackendHealthState,
    pub membership: BackendMembershipState,
}

impl RuntimeBackendLifecycleState {
    pub fn new(
        identity: BackendIdentity,
        resolution: BackendResolutionState,
        health: BackendHealthState,
        membership: BackendMembershipState,
    ) -> Self {
        Self {
            identity,
            resolution,
            health,
            membership,
        }
    }

    pub fn from_resolution_seed(resolution: &RuntimeBackendResolution) -> Self {
        Self {
            identity: BackendIdentity::from(resolution),
            resolution: BackendResolutionState::from(resolution),
            health: BackendHealthState::Unknown,
            membership: BackendMembershipState::Active,
        }
    }

    pub fn snapshot(&self) -> BackendLifecycleSnapshot {
        BackendLifecycleSnapshot {
            identity: self.identity.clone(),
            resolution: self.resolution.clone(),
            health: self.health.clone(),
            membership: self.membership,
        }
    }
}

impl From<&RuntimeBackendResolution> for RuntimeBackendLifecycleState {
    fn from(value: &RuntimeBackendResolution) -> Self {
        Self::from_resolution_seed(value)
    }
}

impl From<&RuntimeBackendLifecycleState> for BackendLifecycleSnapshot {
    fn from(value: &RuntimeBackendLifecycleState) -> Self {
        value.snapshot()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveHealthCheckEvaluation {
    pub observation: BackendHealthObservation,
    pub next_consecutive_failures: u32,
    pub next_delay: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendDnsLookupResult {
    Resolved(Vec<SocketAddr>),
    EmptyAnswer,
    LookupFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendDnsRefreshApplication {
    Updated {
        backend_addr: String,
        authority_host: String,
        previous_addrs: Vec<SocketAddr>,
        current_addrs: Vec<SocketAddr>,
        generation: u64,
        refreshed_at: SystemTime,
        client_rotated: bool,
    },
    Unchanged {
        backend_addr: String,
        authority_host: String,
        current_addrs: Vec<SocketAddr>,
        generation: u64,
        refreshed_at: SystemTime,
    },
    EmptyAnswerRetained {
        backend_addr: String,
        authority_host: String,
        retained_addrs: Vec<SocketAddr>,
    },
    LookupFailed {
        backend_addr: String,
        authority_host: String,
        retained_addrs: Vec<SocketAddr>,
        error: String,
    },
}

#[derive(Debug, Clone)]
pub struct BackendLifecycleCoordinator {
    resolution_store: Arc<RuntimeBackendResolutionStore>,
}

impl BackendLifecycleCoordinator {
    pub fn new(resolution_store: Arc<RuntimeBackendResolutionStore>) -> Self {
        Self { resolution_store }
    }

    pub fn resolution_store(&self) -> &Arc<RuntimeBackendResolutionStore> {
        &self.resolution_store
    }

    pub fn backend(&self, backend_addr: &str) -> Option<RuntimeBackendLifecycleState> {
        self.resolution_store.backend(backend_addr)
    }

    pub fn hostname_backends(&self) -> Vec<RuntimeBackendLifecycleState> {
        self.resolution_store.hostname_backends()
    }

    pub fn snapshot_backend(&self, backend_addr: &str) -> Option<BackendLifecycleSnapshot> {
        self.backend(backend_addr).map(|backend| backend.snapshot())
    }

    pub fn snapshot_all(&self) -> HashMap<String, BackendLifecycleSnapshot> {
        self.resolution_store.snapshot()
    }

    pub fn apply_refresh(
        &self,
        backend: &RuntimeBackendLifecycleState,
        lookup_result: BackendDnsLookupResult,
        backend_dns_resolver: &SharedDnsResolver,
        transport_pool: &UpstreamTransportPool,
    ) -> BackendDnsRefreshApplication {
        apply_backend_dns_refresh(
            backend,
            lookup_result,
            self.resolution_store.as_ref(),
            backend_dns_resolver,
            transport_pool,
        )
    }

    pub fn apply_request_accounting(
        &self,
        upstream_pool: Option<&Arc<RwLock<UpstreamPool>>>,
        backend_index: Option<usize>,
        elapsed: Duration,
        status: Option<u16>,
    ) {
        apply_backend_request_accounting(upstream_pool, backend_index, elapsed, status);
    }

    pub fn apply_request_feedback(
        &self,
        upstream_pool: Option<&Arc<RwLock<UpstreamPool>>>,
        backend_index: Option<usize>,
        feedback: &BackendRequestFeedback,
    ) -> Option<HealthTransition> {
        apply_backend_request_feedback(upstream_pool, backend_index, feedback)
    }

    pub fn apply_health_observation(
        &self,
        upstream_pool: Option<&Arc<RwLock<UpstreamPool>>>,
        backend_index: Option<usize>,
        observation: &BackendHealthObservation,
    ) -> Option<HealthTransition> {
        apply_backend_health_observation(upstream_pool, backend_index, observation)
    }
}

pub fn apply_backend_request_accounting(
    upstream_pool: Option<&Arc<RwLock<UpstreamPool>>>,
    backend_index: Option<usize>,
    elapsed: Duration,
    status: Option<u16>,
) {
    if let (Some(pool), Some(index)) = (upstream_pool, backend_index)
        && let Ok(mut guard) = pool.write()
    {
        guard.finish_request(index, elapsed, status);
    }
}

pub fn apply_backend_request_feedback(
    upstream_pool: Option<&Arc<RwLock<UpstreamPool>>>,
    backend_index: Option<usize>,
    feedback: &BackendRequestFeedback,
) -> Option<HealthTransition> {
    let (Some(pool), Some(index)) = (upstream_pool, backend_index) else {
        return None;
    };
    let mut pool = pool.write().ok()?;
    match feedback.outcome {
        BackendRequestFeedbackOutcome::Success => pool.mark_backend_healthy(index),
        BackendRequestFeedbackOutcome::Neutral => None,
        BackendRequestFeedbackOutcome::Failure { reason } => {
            reason.and_then(|reason| pool.mark_backend_request_failure(index, reason))
        }
    }
}

pub fn evaluate_active_health_check(
    identity: BackendIdentity,
    outcome: BackendHealthObservationOutcome,
    reason: Option<spooky_lb::health::HealthFailureReason>,
    base_interval_ms: u64,
    consecutive_failures: u32,
) -> ActiveHealthCheckEvaluation {
    let next_consecutive_failures = match outcome {
        BackendHealthObservationOutcome::Failure => consecutive_failures.saturating_add(1),
        BackendHealthObservationOutcome::Success | BackendHealthObservationOutcome::Neutral => 0,
    };
    let backoff_multiplier = 1u64 << next_consecutive_failures.min(2);
    let delay_ms = base_interval_ms.saturating_mul(backoff_multiplier);

    ActiveHealthCheckEvaluation {
        observation: BackendHealthObservation::active_check(identity, outcome, reason),
        next_consecutive_failures,
        next_delay: Duration::from_millis(delay_ms),
    }
}

pub fn apply_backend_health_observation(
    upstream_pool: Option<&Arc<RwLock<UpstreamPool>>>,
    backend_index: Option<usize>,
    observation: &BackendHealthObservation,
) -> Option<HealthTransition> {
    let (Some(pool), Some(index)) = (upstream_pool, backend_index) else {
        return None;
    };
    let mut pool = pool.write().ok()?;
    match (observation.source, observation.outcome) {
        (
            BackendHealthObservationSource::ActiveCheck,
            BackendHealthObservationOutcome::Success,
        ) => pool.mark_backend_healthy(index),
        (
            BackendHealthObservationSource::ActiveCheck,
            BackendHealthObservationOutcome::Failure,
        ) => pool.mark_backend_failure_from_active_check(index),
        (
            BackendHealthObservationSource::ActiveCheck,
            BackendHealthObservationOutcome::Neutral,
        ) => None,
        (_, BackendHealthObservationOutcome::Success) => pool.mark_backend_healthy(index),
        (_, BackendHealthObservationOutcome::Neutral) => None,
        (_, BackendHealthObservationOutcome::Failure) => observation
            .reason
            .and_then(|reason| pool.mark_backend_request_failure(index, reason)),
    }
}

pub fn apply_backend_dns_refresh(
    backend: &RuntimeBackendLifecycleState,
    lookup_result: BackendDnsLookupResult,
    resolution_store: &RuntimeBackendResolutionStore,
    backend_dns_resolver: &SharedDnsResolver,
    transport_pool: &UpstreamTransportPool,
) -> BackendDnsRefreshApplication {
    match lookup_result {
        BackendDnsLookupResult::LookupFailed(error) => BackendDnsRefreshApplication::LookupFailed {
            backend_addr: backend.identity.backend_addr.clone(),
            authority_host: backend.resolution.authority_host.clone(),
            retained_addrs: backend.resolution.resolved_addrs.clone(),
            error,
        },
        BackendDnsLookupResult::EmptyAnswer => BackendDnsRefreshApplication::EmptyAnswerRetained {
            backend_addr: backend.identity.backend_addr.clone(),
            authority_host: backend.resolution.authority_host.clone(),
            retained_addrs: backend.resolution.resolved_addrs.clone(),
        },
        BackendDnsLookupResult::Resolved(resolved) => {
            let refreshed_at = SystemTime::now();
            let Some(mutation) = resolution_store.apply_resolution_refresh(
                &backend.identity.backend_addr,
                resolved.clone(),
                refreshed_at,
            ) else {
                return BackendDnsRefreshApplication::LookupFailed {
                    backend_addr: backend.identity.backend_addr.clone(),
                    authority_host: backend.resolution.authority_host.clone(),
                    retained_addrs: backend.resolution.resolved_addrs.clone(),
                    error: "hostname backend disappeared from resolution store".to_string(),
                };
            };

            let _ = backend_dns_resolver.replace_host_addrs(
                &backend.resolution.authority_host,
                resolved
                    .into_iter()
                    .map(|addr| SocketAddr::new(addr.ip(), 0)),
            );

            let BackendLifecycleMutation::ResolutionUpdated { result, .. } = mutation else {
                return BackendDnsRefreshApplication::LookupFailed {
                    backend_addr: backend.identity.backend_addr.clone(),
                    authority_host: backend.resolution.authority_host.clone(),
                    retained_addrs: backend.resolution.resolved_addrs.clone(),
                    error: "unexpected backend lifecycle mutation during dns refresh".to_string(),
                };
            };

            let client_rotated = if matches!(result.outcome, BackendRefreshOutcome::Updated { .. })
            {
                matches!(
                    transport_pool.rotate_backend_client(&result.identity.backend_addr),
                    Ok(true)
                )
            } else {
                false
            };

            match result.outcome {
                BackendRefreshOutcome::Updated {
                    previous_addrs,
                    current_addrs,
                    refreshed_at,
                    refresh_generation,
                } => BackendDnsRefreshApplication::Updated {
                    backend_addr: result.identity.backend_addr,
                    authority_host: backend.resolution.authority_host.clone(),
                    previous_addrs,
                    current_addrs,
                    generation: refresh_generation,
                    refreshed_at: refreshed_at.unwrap_or_else(SystemTime::now),
                    client_rotated,
                },
                BackendRefreshOutcome::Unchanged {
                    current_addrs,
                    refreshed_at,
                    refresh_generation,
                } => BackendDnsRefreshApplication::Unchanged {
                    backend_addr: result.identity.backend_addr,
                    authority_host: backend.resolution.authority_host.clone(),
                    current_addrs,
                    generation: refresh_generation,
                    refreshed_at: refreshed_at.unwrap_or_else(SystemTime::now),
                },
                BackendRefreshOutcome::EmptyAnswerRetained { retained_addrs } => {
                    BackendDnsRefreshApplication::EmptyAnswerRetained {
                        backend_addr: result.identity.backend_addr,
                        authority_host: backend.resolution.authority_host.clone(),
                        retained_addrs,
                    }
                }
                BackendRefreshOutcome::LookupFailed {
                    retained_addrs,
                    error,
                } => BackendDnsRefreshApplication::LookupFailed {
                    backend_addr: result.identity.backend_addr,
                    authority_host: backend.resolution.authority_host.clone(),
                    retained_addrs,
                    error,
                },
            }
        }
    }
}

pub fn observe_backend_dns_refresh(metrics: &Metrics, outcome: &BackendDnsRefreshApplication) {
    match outcome {
        BackendDnsRefreshApplication::Updated {
            backend_addr,
            current_addrs,
            refreshed_at,
            client_rotated,
            ..
        } => {
            metrics.record_backend_dns_refresh_success(
                backend_addr,
                *refreshed_at,
                current_addrs.len(),
                true,
            );
            if *client_rotated {
                metrics.inc_backend_client_rotation(backend_addr);
            }
        }
        BackendDnsRefreshApplication::Unchanged {
            backend_addr,
            current_addrs,
            refreshed_at,
            ..
        } => {
            metrics.record_backend_dns_refresh_success(
                backend_addr,
                *refreshed_at,
                current_addrs.len(),
                false,
            );
        }
        BackendDnsRefreshApplication::EmptyAnswerRetained { .. }
        | BackendDnsRefreshApplication::LookupFailed { .. } => {
            metrics.inc_backend_dns_refresh_failure();
        }
    }
}

pub fn log_backend_dns_refresh(outcome: &BackendDnsRefreshApplication) {
    match outcome {
        BackendDnsRefreshApplication::Updated {
            backend_addr,
            authority_host,
            previous_addrs,
            current_addrs,
            generation,
            ..
        } => {
            if previous_addrs.is_empty() {
                info!(
                    "backend DNS refresh populated '{}' (backend '{}') with {:?} generation={}",
                    authority_host, backend_addr, current_addrs, generation
                );
            } else {
                info!(
                    "backend DNS refresh updated '{}' (backend '{}'): {:?} -> {:?} generation={} stale_pooled_connections=possible_until_idle_timeout",
                    authority_host,
                    backend_addr,
                    previous_addrs,
                    current_addrs,
                    generation
                );
            }
        }
        BackendDnsRefreshApplication::Unchanged {
            backend_addr,
            authority_host,
            current_addrs,
            generation,
            ..
        } => {
            debug!(
                "backend DNS refresh unchanged for '{}' (backend '{}') addrs={:?} generation={}",
                authority_host, backend_addr, current_addrs, generation
            );
        }
        BackendDnsRefreshApplication::EmptyAnswerRetained {
            backend_addr,
            authority_host,
            retained_addrs,
        } => {
            warn!(
                "backend DNS refresh returned no addresses for '{}' (backend '{}'); retaining {:?}",
                authority_host, backend_addr, retained_addrs
            );
        }
        BackendDnsRefreshApplication::LookupFailed {
            backend_addr,
            authority_host,
            retained_addrs,
            error,
        } => {
            warn!(
                "backend DNS refresh failed for '{}' (backend '{}'): {}; retaining {:?}",
                authority_host, backend_addr, error, retained_addrs
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use spooky_config::{
        config::{Backend, Config, HealthCheck, Listen, LoadBalancing, RouteMatch, Tls, Upstream},
        runtime::RuntimeConfig,
    };

    use crate::runtime::backend::event::{
        BackendHealthObservationOutcome, BackendRequestFeedback,
    };

    use super::*;

    fn test_upstream_pool() -> Arc<RwLock<UpstreamPool>> {
        let mut upstreams = std::collections::HashMap::new();
        upstreams.insert(
            "api".to_string(),
            Upstream {
                tls: None,
                load_balancing: LoadBalancing {
                    lb_type: "round-robin".to_string(),
                    key: None,
                },
                auth: Default::default(),
                host_policy: Default::default(),
                forwarded_headers: Default::default(),
                route: RouteMatch::default(),
                backends: vec![Backend {
                    id: "backend-a".to_string(),
                    address: "127.0.0.1:8080".to_string(),
                    weight: 1,
                    health_check: Some(HealthCheck {
                        path: "/health".to_string(),
                        interval: 0,
                        timeout_ms: 1000,
                        failure_threshold: 1,
                        success_threshold: 1,
                        cooldown_ms: 0,
                    }),
                }],
            },
        );

        let runtime = RuntimeConfig::from_config(&Config {
            version: 1,
            listen: Listen {
                protocol: "http1".to_string(),
                tls: Tls {
                    cert: "/tmp/test-cert.pem".to_string(),
                    key: "/tmp/test-key.pem".to_string(),
                    ..Tls::default()
                },
                ..Listen::default()
            },
            listeners: Vec::new(),
            upstream: upstreams,
            load_balancing: None,
            upstream_tls: Default::default(),
            log: Default::default(),
            performance: Default::default(),
            observability: Default::default(),
            resilience: Default::default(),
            security: Default::default(),
        })
        .expect("runtime config");

        Arc::new(RwLock::new(
            UpstreamPool::from_runtime_upstream(runtime.upstreams.get("api").expect("upstream"))
                .expect("pool"),
        ))
    }

    #[test]
    fn lifecycle_state_seeds_from_resolution_with_unknown_health() {
        let resolution = RuntimeBackendResolution::hostname(
            "https://backend.internal:8443".to_string(),
            "backend.internal".to_string(),
            8443,
        );

        let state = RuntimeBackendLifecycleState::from(&resolution);

        assert_eq!(state.identity.backend_addr, "https://backend.internal:8443");
        assert_eq!(state.membership, BackendMembershipState::Active);
        assert_eq!(state.health, BackendHealthState::Unknown);
        assert!(state.resolution.is_hostname());
    }

    #[test]
    fn lifecycle_coordinator_exposes_backend_snapshots() {
        let store = Arc::new(RuntimeBackendResolutionStore::new([
            RuntimeBackendResolution::hostname(
                "https://backend.internal:8443".to_string(),
                "backend.internal".to_string(),
                8443,
            ),
        ]));
        let coordinator = BackendLifecycleCoordinator::new(Arc::clone(&store));

        let snapshot = coordinator
            .snapshot_backend("https://backend.internal:8443")
            .expect("backend snapshot");
        assert_eq!(snapshot.identity.backend_addr, "https://backend.internal:8443");

        let all = coordinator.snapshot_all();
        assert_eq!(all.len(), 1);
        assert!(all.contains_key("https://backend.internal:8443"));
    }

    #[test]
    fn request_feedback_applier_marks_backend_unhealthy_and_healthy() {
        let pool = test_upstream_pool();
        let unhealthy = apply_backend_request_feedback(
            Some(&pool),
            Some(0),
            &BackendRequestFeedback::failure(
                BackendIdentity::new("127.0.0.1:8080"),
                Duration::from_millis(10),
                Some(503),
                Some(spooky_lb::health::HealthFailureReason::HttpStatus5xx),
            ),
        );
        assert!(matches!(unhealthy, Some(HealthTransition::BecameUnhealthy)));

        let healthy = apply_backend_request_feedback(
            Some(&pool),
            Some(0),
            &BackendRequestFeedback::from_status(
                BackendIdentity::new("127.0.0.1:8080"),
                Duration::from_millis(10),
                http::StatusCode::OK,
            ),
        );
        assert!(matches!(healthy, Some(HealthTransition::BecameHealthy)));
    }

    #[test]
    fn request_accounting_applier_finishes_inflight_request() {
        let pool = test_upstream_pool();
        {
            let guard = pool.read().expect("read");
            assert!(guard.begin_request_if_healthy(0));
        }

        apply_backend_request_accounting(
            Some(&pool),
            Some(0),
            Duration::from_millis(15),
            Some(200),
        );

        let guard = pool.read().expect("read");
        assert_eq!(guard.pool.backends[0].active_requests(), 0);
        assert!(guard.pool.backends[0].ewma_latency_ms().is_some());
    }

    #[test]
    fn active_health_check_evaluation_tracks_backoff_and_transition() {
        let pool = test_upstream_pool();

        let failure = evaluate_active_health_check(
            BackendIdentity::new("127.0.0.1:8080"),
            BackendHealthObservationOutcome::Failure,
            Some(spooky_lb::health::HealthFailureReason::Transport),
            100,
            0,
        );
        assert_eq!(failure.next_consecutive_failures, 1);
        assert_eq!(failure.next_delay, Duration::from_millis(200));
        let transition =
            apply_backend_health_observation(Some(&pool), Some(0), &failure.observation);
        assert!(matches!(transition, Some(HealthTransition::BecameUnhealthy)));

        let success = evaluate_active_health_check(
            BackendIdentity::new("127.0.0.1:8080"),
            BackendHealthObservationOutcome::Success,
            None,
            100,
            failure.next_consecutive_failures,
        );
        assert_eq!(success.next_consecutive_failures, 0);
        assert_eq!(success.next_delay, Duration::from_millis(100));
        let transition =
            apply_backend_health_observation(Some(&pool), Some(0), &success.observation);
        assert!(matches!(transition, Some(HealthTransition::BecameHealthy)));
    }
}
