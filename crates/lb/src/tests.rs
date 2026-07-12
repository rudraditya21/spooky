use spooky_config::config::RouteMatch;

use super::*;

#[test]
fn unhealthy_backends_are_skipped() {
    let mut pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 1),
        create_backend_state("10.0.0.2:1", 1),
    ]);

    pool.mark_failure(0);
    pool.mark_failure(0);
    pool.mark_failure(0);

    let mut rr = RoundRobin::new();
    let pick = rr.pick(&pool).unwrap();
    assert_eq!(pick, 1);
}

#[test]
fn load_balancing_from_config() {
    assert!(LoadBalancing::from_config("round-robin").is_ok());
    assert!(LoadBalancing::from_config("consistent-hash").is_ok());
    assert!(LoadBalancing::from_config("random").is_ok());
    assert!(LoadBalancing::from_config("least-connections").is_ok());
    assert!(LoadBalancing::from_config("latency-aware").is_ok());
    assert!(LoadBalancing::from_config("sticky-cid").is_ok());
    assert!(LoadBalancing::from_config("unknown").is_err());
}

#[test]
fn least_connections_picks_lowest_active() {
    let pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 1),
        create_backend_state("10.0.0.2:1", 1),
        create_backend_state("10.0.0.3:1", 1),
    ]);
    pool.begin_request(0);
    pool.begin_request(0);
    pool.begin_request(1);

    let mut lb = LeastConnections::new();
    assert_eq!(lb.pick(&pool), Some(2));
}

#[test]
fn latency_aware_prefers_lower_ewma() {
    let mut pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 1),
        create_backend_state("10.0.0.2:1", 1),
    ]);

    pool.finish_request(0, Duration::from_millis(150), Some(200));
    pool.finish_request(1, Duration::from_millis(20), Some(200));

    let mut lb = LatencyAware::new();
    assert_eq!(lb.pick(&pool), Some(1));
}

#[test]
fn sticky_cid_is_deterministic_for_same_key() {
    let pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 1),
        create_backend_state("10.0.0.2:1", 1),
        create_backend_state("10.0.0.3:1", 1),
    ]);

    let mut lb = StickyCid::new(16);
    let first = lb.pick("cid:abc123", &pool);
    let second = lb.pick("cid:abc123", &pool);
    assert_eq!(first, second);
}

#[test]
fn no_healthy_backends_returns_none() {
    let mut pool = BackendPool::new_from_states(vec![create_backend_state("10.0.0.1:1", 1)]);
    pool.mark_failure(0);
    pool.mark_failure(0);
    pool.mark_failure(0);

    let mut rr = RoundRobin::new();
    assert!(rr.pick(&pool).is_none());
}
#[test]
fn upstream_pool_from_config() {
    let upstream = spooky_config::config::Upstream {
        load_balancing: spooky_config::config::LoadBalancing {
            lb_type: "round-robin".to_string(),
            key: None,
        },
        auth: Default::default(),
        host_policy: Default::default(),
        forwarded_headers: Default::default(),
        tls: None,
        route: RouteMatch {
            path_prefix: Some("/".to_string()),
            ..Default::default()
        },
        backends: vec![
            Backend {
                id: "backend1".to_string(),
                address: "127.0.0.1:8001".to_string(),
                weight: 100,
                health_check: Some(HealthCheck {
                    path: "/health".to_string(),
                    interval: 5000,
                    timeout_ms: 2000,
                    failure_threshold: 3,
                    success_threshold: 2,
                    cooldown_ms: 10000,
                }),
            },
            Backend {
                id: "backend2".to_string(),
                address: "127.0.0.1:8002".to_string(),
                weight: 200,
                health_check: Some(HealthCheck {
                    path: "/health".to_string(),
                    interval: 5000,
                    timeout_ms: 2000,
                    failure_threshold: 3,
                    success_threshold: 2,
                    cooldown_ms: 10000,
                }),
            },
        ],
    };

    let upstream_pool = UpstreamPool::from_upstream(&upstream).unwrap();
    assert!(matches!(
        upstream_pool.load_balancer,
        LoadBalancing::RoundRobin(_)
    ));
    assert_eq!(upstream_pool.pool.len(), 2);
    assert_eq!(upstream_pool.pool.address(0), Some("127.0.0.1:8001"));
    assert_eq!(upstream_pool.pool.address(1), Some("127.0.0.1:8002"));
}

#[test]
fn passively_ejected_backend_recovers_after_cooldown() {
    // Backend without an active health check (interval 0) so request-path
    // failures drive ejection and only time-based re-admission can recover it.
    let backend = Backend {
        id: "b1".to_string(),
        address: "10.0.0.1:1".to_string(),
        weight: 1,
        health_check: Some(HealthCheck {
            path: "/health".to_string(),
            interval: 0,
            timeout_ms: 1000,
            failure_threshold: 2,
            success_threshold: 1,
            cooldown_ms: 10_000,
        }),
    };
    let mut pool = BackendPool::new_from_states(vec![BackendState::new(&backend)]);
    assert_eq!(pool.healthy_len(), 1);

    // Trip past the failure threshold via the passive request path.
    pool.mark_request_failure(0, HealthFailureReason::Transport);
    pool.mark_request_failure(0, HealthFailureReason::Transport);
    assert_eq!(pool.healthy_len(), 0, "backend should be ejected");
    assert!(pool.readmit_due(), "a re-admission should be pending");

    // Before the cooldown elapses: no recovery.
    pool.reconcile_readmit_at(Instant::now());
    assert_eq!(pool.healthy_len(), 0);
    assert!(pool.readmit_due());

    // After the cooldown: re-admitted so live traffic can probe it again.
    pool.reconcile_readmit_at(Instant::now() + Duration::from_millis(10_001));
    assert_eq!(
        pool.healthy_len(),
        1,
        "backend should recover after cooldown"
    );
    assert!(
        !pool.readmit_due(),
        "no pending re-admission after recovery"
    );
}
