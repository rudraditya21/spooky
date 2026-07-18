//! Policy-combination and route-matcher rejection cases.

use spooky_config::config::UpstreamHostPolicyMode;
use spooky_config::runtime::RuntimeConfig;

use crate::common::sample_config;

#[test]
fn runtime_config_rejects_ignored_host_rewrite_value() {
    let mut config = sample_config();
    config
        .upstream
        .get_mut("api")
        .expect("upstream")
        .host_policy
        .mode = UpstreamHostPolicyMode::Upstream;
    config
        .upstream
        .get_mut("api")
        .expect("upstream")
        .host_policy
        .host = Some("ignored.example.com".to_string());

    let err = RuntimeConfig::from_config(&config).expect_err("conflicting host policy");
    assert_eq!(err.category(), "unsupported_policy_combination");
    assert!(err.to_string().contains("mode is not rewrite"));
}

#[test]
fn runtime_config_rejects_duplicate_route_matchers() {
    let mut config = sample_config();
    config.upstream.insert(
        "api-copy".to_string(),
        config.upstream.get("api").expect("api").clone(),
    );

    let err = RuntimeConfig::from_config(&config).expect_err("duplicate routes");
    assert_eq!(err.category(), "duplicate_route_ambiguity");
    assert!(err.to_string().contains("conflicts with upstream"));
}

#[test]
fn runtime_config_rejects_invalid_lb_key_spec() {
    let mut config = sample_config();
    config
        .upstream
        .get_mut("api")
        .expect("api")
        .load_balancing
        .key = Some("header:   ".to_string());

    let err = RuntimeConfig::from_config(&config).expect_err("invalid key spec must fail");
    assert_eq!(err.category(), "config_invalid");
    assert!(err.to_string().contains("unsupported request key spec"));
}

#[test]
fn runtime_config_rejects_connect_route_when_protocol_disallows_connect() {
    let mut config = sample_config();
    config
        .upstream
        .get_mut("api")
        .expect("upstream")
        .route
        .method = Some("CONNECT".to_string());
    config.resilience.protocol.allow_connect = false;

    let err = RuntimeConfig::from_config(&config).expect_err("connect route must fail");
    assert_eq!(err.category(), "unsupported_policy_combination");
    assert!(err.to_string().contains("allow_connect=false"));
}
