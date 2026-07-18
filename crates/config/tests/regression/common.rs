//! Shared fixtures for the runtime-config regression suite.

use std::collections::HashMap;

use spooky_config::config::{
    Backend, ClientAuth, Config, ForwardedHeaderPolicy, ForwardedHeaderPolicyMode, Listen,
    LoadBalancing, Log, Observability, Performance, Resilience, RouteMatch, Security, Tls,
    Upstream, UpstreamHostPolicy, UpstreamHostPolicyMode, UpstreamTls,
};

/// A minimal, valid single-upstream config used as the base for regression cases.
pub fn sample_config() -> Config {
    let mut config = Config {
        version: 1,
        listen: Listen {
            protocol: "http3".to_string(),
            port: 443,
            address: "0.0.0.0".to_string(),
            tls: Tls {
                cert: "/tmp/tls/default.pem".to_string(),
                key: "/tmp/tls/default.key".to_string(),
                certificates: Vec::new(),
                client_auth: ClientAuth::default(),
            },
        },
        listeners: Vec::new(),
        upstream: HashMap::new(),
        load_balancing: None,
        upstream_tls: UpstreamTls::default(),
        log: Log::default(),
        performance: Performance::default(),
        observability: Observability::default(),
        resilience: Resilience::default(),
        security: Security::default(),
    };

    config.upstream.insert(
        "api".to_string(),
        Upstream {
            load_balancing: LoadBalancing {
                lb_type: "round-robin".to_string(),
                key: None,
            },
            auth: Default::default(),
            host_policy: UpstreamHostPolicy {
                mode: UpstreamHostPolicyMode::Rewrite,
                host: Some("api.internal".to_string()),
            },
            forwarded_headers: ForwardedHeaderPolicy {
                mode: ForwardedHeaderPolicyMode::Append,
            },
            tls: None,
            route: RouteMatch {
                host: Some("api.example.com".to_string()),
                path_prefix: Some("/".to_string()),
                method: None,
            },
            backends: vec![Backend {
                id: "api-1".to_string(),
                address: "https://api.internal:8443".to_string(),
                weight: 100,
                health_check: None,
            }],
        },
    );

    config
}
