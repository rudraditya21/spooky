//! Upstream TLS lowering: effective-TLS resolution and validation.

use spooky_config::{
    config::{ForwardedHeaderPolicyMode, UpstreamHostPolicyMode, UpstreamTls},
    runtime::{RuntimeBackendTransportKind, RuntimeConfig},
};

use crate::common::sample_config;

#[test]
fn runtime_upstream_applies_effective_tls_and_policy_wrappers() {
    let mut config = sample_config();
    config.upstream_tls = UpstreamTls {
        verify_certificates: true,
        strict_sni: true,
        ca_file: Some("/tmp/roots/global.pem".to_string()),
        ca_dir: None,
    };
    config.upstream.get_mut("api").expect("upstream").tls = Some(UpstreamTls {
        verify_certificates: false,
        strict_sni: false,
        ca_file: Some("/tmp/roots/upstream.pem".to_string()),
        ca_dir: Some("/tmp/roots/upstream".to_string()),
    });

    let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
    let upstream = runtime.upstreams.get("api").expect("runtime upstream");

    assert_eq!(upstream.name, "api");
    assert!(!upstream.effective_tls.verify_certificates);
    assert!(!upstream.effective_tls.strict_sni);
    assert_eq!(
        upstream.effective_tls.ca_file.as_deref(),
        Some("/tmp/roots/upstream.pem")
    );
    assert_eq!(upstream.backends.len(), 1);
    assert_eq!(
        upstream.backends[0].backend.address,
        "https://api.internal:8443"
    );
    assert_eq!(upstream.backends[0].endpoint.authority_host, "api.internal");
    assert_eq!(upstream.backends[0].endpoint.authority_port, 8443);
    assert_eq!(
        upstream.backends[0].endpoint.transport_kind,
        RuntimeBackendTransportKind::H2
    );
    assert_eq!(
        upstream.backend_tls_policy().ca_file.as_deref(),
        Some("/tmp/roots/upstream.pem")
    );
    assert_eq!(upstream.policy.host.0.mode, UpstreamHostPolicyMode::Rewrite);
    assert_eq!(
        upstream.policy.forwarded_headers.0.mode,
        ForwardedHeaderPolicyMode::Append
    );
}

#[test]
fn runtime_http_only_upstream_skips_unused_global_tls_validation() {
    let mut config = sample_config();
    config.upstream.get_mut("api").expect("upstream").backends[0].address =
        "http://127.0.0.1:8080".to_string();
    config.upstream_tls.ca_file = Some("   ".to_string());
    config.upstream_tls.ca_dir = Some("   ".to_string());

    let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
    let upstream = runtime.upstreams.get("api").expect("runtime upstream");

    assert_eq!(
        upstream.backends[0].backend.address,
        "http://127.0.0.1:8080"
    );
}

#[test]
fn runtime_http_only_upstream_skips_unused_per_upstream_tls_validation() {
    let mut config = sample_config();
    config.upstream.get_mut("api").expect("upstream").backends[0].address =
        "http://127.0.0.1:8080".to_string();
    config.upstream.get_mut("api").expect("upstream").tls = Some(UpstreamTls {
        verify_certificates: true,
        strict_sni: true,
        ca_file: Some("   ".to_string()),
        ca_dir: Some("   ".to_string()),
    });

    let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
    let upstream = runtime.upstreams.get("api").expect("runtime upstream");

    assert_eq!(
        upstream.backends[0].backend.address,
        "http://127.0.0.1:8080"
    );
}

#[test]
fn runtime_https_upstream_still_requires_non_empty_effective_tls_fields() {
    let mut config = sample_config();
    config.upstream_tls.ca_file = Some("   ".to_string());

    let err = RuntimeConfig::from_config(&config).expect_err("https upstream must validate");
    assert_eq!(err.category(), "tls_material_invalid");
    assert!(
        err.to_string()
            .contains("upstream 'api' has an empty effective upstream_tls.ca_file")
    );
}
