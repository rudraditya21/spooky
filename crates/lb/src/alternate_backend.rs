use crate::upstream_pool::UpstreamPool;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlternateBackendSelectionMode {
    LoadBalancerReadonly,
    HealthyFallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlternateBackendChoice {
    pub index: usize,
    pub mode: AlternateBackendSelectionMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlternateBackendFailureReason {
    NoHealthyBackends,
    OnlyExcludedBackendsHealthy,
    PoolUnavailable,
    BackendAddressMissing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlternateBackendDecision {
    Select(AlternateBackendChoice),
    DoNotSelect {
        denial: AlternateBackendFailureReason,
    },
}

fn is_excluded(index: usize, excluded_indices: &[usize]) -> bool {
    excluded_indices.contains(&index)
}

pub fn choose_alternate_backend(
    pool: &UpstreamPool,
    excluded_indices: &[usize],
    lb_key: Option<&str>,
) -> AlternateBackendDecision {
    let policy = pool.alternate_backend_policy();

    if policy.readonly_lb_pick {
        let readonly_candidate = pool
            .pick_readonly(lb_key.unwrap_or_default())
            .filter(|index| !is_excluded(*index, excluded_indices));
        if let Some(index) = readonly_candidate {
            return AlternateBackendDecision::Select(AlternateBackendChoice {
                index,
                mode: AlternateBackendSelectionMode::LoadBalancerReadonly,
            });
        }
    }

    if policy.healthy_fallback {
        let fallback_candidate = pool
            .pool
            .healthy_indices_iter()
            .find(|index| !is_excluded(*index, excluded_indices));
        if let Some(index) = fallback_candidate {
            return AlternateBackendDecision::Select(AlternateBackendChoice {
                index,
                mode: AlternateBackendSelectionMode::HealthyFallback,
            });
        }
    }

    if pool.pool.healthy_len() == 0 {
        AlternateBackendDecision::DoNotSelect {
            denial: AlternateBackendFailureReason::NoHealthyBackends,
        }
    } else {
        AlternateBackendDecision::DoNotSelect {
            denial: AlternateBackendFailureReason::OnlyExcludedBackendsHealthy,
        }
    }
}

#[cfg(test)]
mod tests {
    use spooky_config::config::{Backend, HealthCheck, LoadBalancing, RouteMatch, Upstream};
    use spooky_config::runtime::RuntimeAlternateBackendPolicy;

    use super::*;
    use crate::health::HealthFailureReason;

    fn upstream(lb_type: &str, backends: &[&str]) -> Upstream {
        Upstream {
            tls: None,
            load_balancing: LoadBalancing {
                lb_type: lb_type.to_string(),
                key: None,
            },
            auth: Default::default(),
            host_policy: Default::default(),
            forwarded_headers: Default::default(),
            route: RouteMatch::default(),
            backends: backends
                .iter()
                .enumerate()
                .map(|(index, address)| Backend {
                    id: format!("backend-{index}"),
                    address: (*address).to_string(),
                    weight: 1,
                    health_check: Some(HealthCheck {
                        path: "/health".to_string(),
                        interval: 0,
                        timeout_ms: 1000,
                        failure_threshold: 1,
                        success_threshold: 1,
                        cooldown_ms: 1000,
                    }),
                })
                .collect(),
        }
    }

    #[test]
    fn chooses_non_excluded_backend_from_readonly_lb_pick() {
        let pool = UpstreamPool::from_upstream(&upstream(
            "round-robin",
            &["http://a", "http://b", "http://c"],
        ))
        .expect("pool");

        let decision = choose_alternate_backend(&pool, &[2], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::Select(AlternateBackendChoice {
                index: 0,
                mode: AlternateBackendSelectionMode::LoadBalancerReadonly,
            })
        );
    }

    #[test]
    fn falls_back_when_readonly_pick_hits_excluded_backend() {
        let pool = UpstreamPool::from_upstream(&upstream(
            "round-robin",
            &["http://a", "http://b", "http://c"],
        ))
        .expect("pool");

        let decision = choose_alternate_backend(&pool, &[0], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::Select(AlternateBackendChoice {
                index: 1,
                mode: AlternateBackendSelectionMode::HealthyFallback,
            })
        );
    }

    #[test]
    fn falls_back_to_healthy_scan_when_readonly_strategy_is_unavailable() {
        let pool =
            UpstreamPool::from_upstream(&upstream("consistent-hash", &["http://a", "http://b"]))
                .expect("pool");

        let decision = choose_alternate_backend(&pool, &[0], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::Select(AlternateBackendChoice {
                index: 1,
                mode: AlternateBackendSelectionMode::HealthyFallback,
            })
        );
    }

    #[test]
    fn reports_when_only_excluded_backends_are_healthy() {
        let pool =
            UpstreamPool::from_upstream(&upstream("round-robin", &["http://a"])).expect("pool");

        let decision = choose_alternate_backend(&pool, &[0], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::DoNotSelect {
                denial: AlternateBackendFailureReason::OnlyExcludedBackendsHealthy,
            }
        );
    }

    #[test]
    fn reports_when_no_backends_are_healthy() {
        let mut pool =
            UpstreamPool::from_upstream(&upstream("round-robin", &["http://a", "http://b"]))
                .expect("pool");

        let _ = pool
            .pool
            .mark_failure_with_reason(0, HealthFailureReason::Transport);
        let _ = pool
            .pool
            .mark_failure_with_reason(1, HealthFailureReason::Transport);

        let decision = choose_alternate_backend(&pool, &[], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::DoNotSelect {
                denial: AlternateBackendFailureReason::NoHealthyBackends,
            }
        );
    }

    #[test]
    fn suppresses_readonly_pick_when_policy_disables_it() {
        let mut pool = UpstreamPool::from_upstream(&upstream(
            "round-robin",
            &["http://a", "http://b", "http://c"],
        ))
        .expect("pool");
        pool.set_alternate_backend_policy(RuntimeAlternateBackendPolicy {
            readonly_lb_pick: false,
            healthy_fallback: true,
        });

        let decision = choose_alternate_backend(&pool, &[0], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::Select(AlternateBackendChoice {
                index: 1,
                mode: AlternateBackendSelectionMode::HealthyFallback,
            })
        );
    }

    #[test]
    fn reports_excluded_backends_when_all_failover_modes_are_disabled() {
        let mut pool =
            UpstreamPool::from_upstream(&upstream("round-robin", &["http://a", "http://b"]))
                .expect("pool");
        pool.set_alternate_backend_policy(RuntimeAlternateBackendPolicy {
            readonly_lb_pick: false,
            healthy_fallback: false,
        });

        let decision = choose_alternate_backend(&pool, &[0], None);
        assert_eq!(
            decision,
            AlternateBackendDecision::DoNotSelect {
                denial: AlternateBackendFailureReason::OnlyExcludedBackendsHealthy,
            }
        );
    }
}
