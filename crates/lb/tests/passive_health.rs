use std::time::{Duration, Instant};

use spooky_config::config::{Backend, HealthCheck};
use spooky_lb::{backend::BackendState, backend_pool::BackendPool, health::HealthFailureReason};

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
