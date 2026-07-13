use spooky_config::config::{Backend, HealthCheck, RouteMatch};
use spooky_lb::{load_balancing::LoadBalancing, upstream_pool::UpstreamPool};

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
