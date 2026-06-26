use super::state::ControlApiState;
use super::*;
use spooky_config::{
    config::{
        Backend, ClientAuth, Config as SpookyConfigConfig, Listen, LoadBalancing, Log,
        Observability, Performance, Resilience, RouteMatch, Security, Tls, Upstream, UpstreamTls,
    },
    runtime::RuntimeConfig,
};
use std::{collections::HashMap, path::Path, sync::Arc};
use tempfile::tempdir;

fn write_test_cert_for_name(dir: &Path, cert_name: &str, dns_name: &str) -> (String, String) {
    use rcgen::{Certificate, CertificateParams, SanType};

    let mut params = CertificateParams::new(vec![dns_name.to_string()]);
    params
        .subject_alt_names
        .push(SanType::DnsName(dns_name.to_string()));
    let cert = Certificate::from_params(params).expect("failed to build cert");

    let cert_path = dir.join(format!("{cert_name}.pem"));
    let key_path = dir.join(format!("{cert_name}.key.pem"));
    std::fs::write(&cert_path, cert.serialize_pem().expect("serialize cert")).expect("write cert");
    std::fs::write(&key_path, cert.serialize_private_key_pem()).expect("write key");
    (
        cert_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
    )
}

fn test_config(cert: String, key: String) -> SpookyConfigConfig {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        Upstream {
            load_balancing: LoadBalancing {
                lb_type: "round-robin".to_string(),
                key: None,
            },
            host_policy: Default::default(),
            forwarded_headers: Default::default(),
            tls: None,
            route: RouteMatch {
                path_prefix: Some("/".to_string()),
                ..Default::default()
            },
            backends: vec![Backend {
                id: "b1".to_string(),
                address: "http://127.0.0.1:7001".to_string(),
                weight: 1,
                health_check: None,
            }],
        },
    );

    SpookyConfigConfig {
        version: 1,
        listen: Listen {
            protocol: "http3".to_string(),
            port: 9889,
            address: "127.0.0.1".to_string(),
            tls: Tls {
                cert,
                key,
                certificates: vec![],
                client_auth: ClientAuth::default(),
            },
        },
        listeners: vec![],
        upstream: upstreams,
        load_balancing: Some(LoadBalancing {
            lb_type: "round-robin".to_string(),
            key: None,
        }),
        upstream_tls: UpstreamTls::default(),
        log: Log::default(),
        performance: Performance::default(),
        observability: Observability::default(),
        resilience: Resilience::default(),
        security: Security::default(),
    }
}

fn runtime_bundle_from_config(config_path: &str, config: &SpookyConfigConfig) -> RuntimeBundle {
    let runtime_config = RuntimeConfig::from_config(config).expect("runtime config");
    QUICListener::build_runtime_bundle(config_path.to_string(), config.log.clone(), &runtime_config)
        .expect("runtime bundle")
}

fn control_api_state_with_runtime_bundle(
    startup: &SpookyConfigConfig,
    reloaded: &SpookyConfigConfig,
) -> ControlApiState {
    let startup_bundle = runtime_bundle_from_config("startup.yaml", startup);
    let reloaded_bundle = runtime_bundle_from_config("reloaded.yaml", reloaded);
    let listener_config = startup_bundle
        .runtime_config
        .primary_listener_runtime_config()
        .expect("listener runtime config");

    ControlApiState {
        control_api: startup_bundle
            .runtime_config
            .observability
            .control_api
            .clone(),
        metrics: Arc::clone(&startup_bundle.shared_state.metrics),
        resilience: Arc::clone(&startup_bundle.shared_state.resilience),
        watchdog: Arc::clone(&startup_bundle.shared_state.watchdog),
        upstream_pools: startup_bundle.shared_state.upstream_pools.clone(),
        listener_runtime_configs: Arc::clone(&startup_bundle.shared_state.listener_runtime_configs),
        listener_tls_store: Arc::clone(&startup_bundle.shared_state.listener_tls_store),
        primary_listener_label: QUICListener::listener_label(&listener_config),
        expected_workers: 1,
        started_at: Instant::now(),
        runtime_bundle: Some(Arc::new(RuntimeBundleHandle::new(reloaded_bundle))),
    }
}

#[test]
fn watchdog_restart_env_keeps_path_when_present() {
    let env =
        QUICListener::watchdog_restart_env(Some(OsString::from("/usr/bin:/bin")), "timeout_spike");
    let map: HashMap<OsString, OsString> = env.into_iter().collect();

    assert_eq!(
        map.get(&OsString::from("PATH")),
        Some(&OsString::from("/usr/bin:/bin"))
    );
    assert_eq!(
        map.get(&OsString::from("SPOOKY_WATCHDOG_REASON")),
        Some(&OsString::from("timeout_spike"))
    );
}

#[test]
fn watchdog_restart_env_omits_path_when_missing() {
    let env = QUICListener::watchdog_restart_env(None, "poll_stall");
    let map: HashMap<OsString, OsString> = env.into_iter().collect();

    assert!(!map.contains_key(&OsString::from("PATH")));
    assert_eq!(
        map.get(&OsString::from("SPOOKY_WATCHDOG_REASON")),
        Some(&OsString::from("poll_stall"))
    );
}

#[test]
fn bearer_authorization_scheme_is_case_insensitive() {
    assert_eq!(
        QUICListener::bearer_token_from_authorization_header("Bearer token-1"),
        Some("token-1")
    );
    assert_eq!(
        QUICListener::bearer_token_from_authorization_header("bearer token-2"),
        Some("token-2")
    );
    assert_eq!(
        QUICListener::bearer_token_from_authorization_header("BEARER token-3"),
        Some("token-3")
    );
}

#[test]
fn bearer_authorization_rejects_malformed_headers() {
    assert_eq!(
        QUICListener::bearer_token_from_authorization_header("Basic abc"),
        None
    );
    assert_eq!(
        QUICListener::bearer_token_from_authorization_header("Bearer"),
        None
    );
    assert_eq!(
        QUICListener::bearer_token_from_authorization_header("Bearer   "),
        None
    );
}

#[test]
fn control_api_state_prefers_reloaded_paths_and_auth_token() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut startup = test_config(cert.clone(), key.clone());
    startup.observability.control_api.enabled = true;
    startup.observability.control_api.health_path = "/health-old".to_string();
    startup.observability.control_api.runtime_path = "/runtime-old".to_string();
    startup.observability.control_api.auth_token = Some("old-token".to_string());

    let mut reloaded = startup.clone();
    reloaded.observability.control_api.health_path = "/health-new".to_string();
    reloaded.observability.control_api.runtime_path = "/runtime-new".to_string();
    reloaded.observability.control_api.auth_token = Some("new-token".to_string());

    let state = control_api_state_with_runtime_bundle(&startup, &reloaded);
    let paths = state.current_paths();

    assert_eq!(paths.health_path, "/health-new");
    assert_eq!(paths.runtime_path, "/runtime-new");
    assert_eq!(
        state.current_control_api().auth_token.as_deref(),
        Some("new-token")
    );
}

#[test]
fn validate_control_api_reload_compatibility_allows_bind_change_when_socket_is_free() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut current = test_config(cert.clone(), key.clone());
    current.observability.control_api.enabled = true;
    current.observability.control_api.address = "127.0.0.1".to_string();
    current.observability.control_api.port = 9443;

    let mut next = current.clone();
    next.observability.control_api.port = 9555;

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);
    assert!(
        QUICListener::validate_control_api_reload_compatibility(&current_bundle, &next_bundle)
            .is_none()
    );
}

#[test]
fn validate_metrics_reload_compatibility_allows_bind_change_when_socket_is_free() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let mut current = test_config(cert.clone(), key.clone());
    current.observability.metrics.enabled = true;
    current.observability.metrics.address = "127.0.0.1".to_string();
    current.observability.metrics.port = 9100;

    let mut next = current.clone();
    next.observability.metrics.port = 9200;

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);
    assert!(
        QUICListener::validate_metrics_reload_compatibility(&current_bundle, &next_bundle)
            .is_none()
    );
}

#[test]
fn validate_startup_owned_reload_compatibility_rejects_log_change() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let mut next = current.clone();
    next.log.level = "debug".to_string();

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);
    let issues =
        QUICListener::validate_startup_owned_reload_compatibility(&current_bundle, &next_bundle);

    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("log.level") && issue.contains("restart required"))
    );
}

#[test]
fn validate_startup_owned_reload_compatibility_allows_worker_topology_change() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let mut next = current.clone();
    next.performance.worker_threads = 4;
    next.performance.packet_shards_per_worker = 2;

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);
    let issues =
        QUICListener::validate_startup_owned_reload_compatibility(&current_bundle, &next_bundle);

    assert!(issues.is_empty());
}

#[test]
fn validate_runtime_reload_compatibility_allows_listener_addition_when_binds_are_free() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let mut next = current.clone();
    let mut extra_listener = next.listen.clone();
    extra_listener.port = 9891;
    next.listeners = vec![next.listen.clone(), extra_listener];

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);

    assert!(
        QUICListener::validate_runtime_reload_compatibility(&current_bundle, &next_bundle)
            .is_none()
    );
}

#[test]
fn validate_runtime_reload_compatibility_rejects_listener_removal() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let mut next = current.clone();
    next.listeners = vec![{
        let mut l = next.listen.clone();
        l.port = 9892;
        l
    }];

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);

    let err = QUICListener::validate_runtime_reload_compatibility(&current_bundle, &next_bundle);
    assert!(
        err.as_deref()
            .is_some_and(|e| e.contains("restart required")),
        "expected rejection, got: {:?}",
        err
    );
}

#[test]
fn validate_runtime_reload_compatibility_rejects_listener_bind_change() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let mut next = current.clone();
    next.listen.port = 9893;

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);

    let err = QUICListener::validate_runtime_reload_compatibility(&current_bundle, &next_bundle);
    assert!(
        err.as_deref()
            .is_some_and(|e| e.contains("restart required")),
        "expected rejection, got: {:?}",
        err
    );
}

#[test]
fn validate_startup_owned_reload_compatibility_rejects_control_plane_thread_change() {
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
    let current = test_config(cert.clone(), key.clone());

    let mut next = current.clone();
    next.performance.control_plane_threads = 7;

    let current_bundle = runtime_bundle_from_config("current.yaml", &current);
    let next_bundle = runtime_bundle_from_config("next.yaml", &next);
    let issues =
        QUICListener::validate_startup_owned_reload_compatibility(&current_bundle, &next_bundle);

    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("performance.control_plane_threads"))
    );
}
