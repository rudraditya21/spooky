use std::{collections::HashMap, fmt, net::IpAddr};

use crate::{
    backend_endpoint::BackendEndpoint,
    config::{
        Backend, ClientAuth, Config, ForwardedHeaderPolicy, Listen, LoadBalancing, Observability,
        Performance, ProtocolPolicy, Resilience, Security, TlsCertificate, Upstream,
        UpstreamHostPolicy, UpstreamHostPolicyMode, UpstreamTls,
    },
};

#[path = "runtime/listeners.rs"]
mod listeners;
#[path = "runtime/policies.rs"]
mod policies;
#[path = "runtime/upstreams.rs"]
mod upstreams;

pub use policies::{
    RuntimeAdmissionPolicy, RuntimeApiKeyAuth, RuntimeAuthPolicy, RuntimeBrownoutPolicy,
    RuntimeBackendAddressKind, RuntimeBackendConnectionPolicy, RuntimeBackendDnsPolicy,
    RuntimeBackendEndpoint, RuntimeBackendHealthCheck, RuntimeBackendTlsPolicy,
    RuntimeBackendTransportKind, RuntimeCircuitBreakerPolicy, RuntimeConnectionLimits,
    RuntimeExternalAuth, RuntimeExternalAuthFailureMode, RuntimeExternalAuthRequestHeader,
    RuntimeHedgingPolicy, RuntimeJwtAuth, RuntimeAlternateBackendPolicy, RuntimeRequestKeySpec,
    RuntimeListenerPolicySet, RuntimeLoadBalancingPolicy, RuntimeLoadBalancingStrategy,
    RuntimePolicySet, RuntimeRateLimitPolicy, RuntimeRetryBudgetPolicy,
    RuntimeRouteHostPattern, RuntimeRouteMatchPolicy, RuntimeRouteQueuePolicy,
    RuntimeScopedRateLimitPolicy, RuntimeTimeoutPolicy,
    RuntimeTransportPolicy, RuntimeUpstreamPolicySet, RuntimeUpstreamTransportPolicy,
    RuntimeWatchdogPolicy,
};

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub version: u32,
    pub listeners: Vec<RuntimeListener>,
    pub upstreams: HashMap<String, RuntimeUpstream>,
    pub policies: RuntimePolicySet,
    pub performance: Performance,
    pub observability: Observability,
    pub resilience: Resilience,
    pub security: Security,
}

impl RuntimeConfig {
    pub fn from_config(config: &Config) -> Result<Self, RuntimeConfigError> {
        let policies = RuntimePolicySet::from_config(config)?;
        Ok(Self {
            version: config.version,
            listeners: listeners::runtime_listeners(config)?,
            upstreams: upstreams::normalize_upstreams(config, &policies)?,
            policies,
            performance: config.performance.clone(),
            observability: config.observability.clone(),
            resilience: config.resilience.clone(),
            security: config.security.clone(),
        })
    }

    pub fn listener_runtime_configs(&self) -> Vec<ListenerRuntimeConfig> {
        self.listeners
            .iter()
            .cloned()
            .map(|listen| ListenerRuntimeConfig {
                policies: RuntimeListenerPolicySet {
                    timeouts: self.policies.timeouts.clone(),
                    transport: self.policies.transport.clone(),
                    tls: listen.tls.clone(),
                },
                listen,
                performance: self.performance.clone(),
                observability: self.observability.clone(),
            })
            .collect()
    }

    pub fn primary_listener_runtime_config(&self) -> Option<ListenerRuntimeConfig> {
        self.listener_runtime_configs().into_iter().next()
    }

    #[cfg(test)]
    pub(crate) fn upstreams_as_config(&self) -> HashMap<String, Upstream> {
        self.upstreams
            .iter()
            .map(|(name, upstream)| (name.clone(), upstream.as_config_upstream()))
            .collect()
    }

    pub fn policies(&self) -> RuntimePolicySet {
        self.policies.clone()
    }

    #[cfg(test)]
    pub(crate) fn upstream_policy_sets(&self) -> HashMap<String, RuntimeUpstreamPolicySet> {
        self.upstreams
            .iter()
            .map(|(name, upstream)| (name.clone(), upstream.policy_set.clone()))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeConfigError {
    ConfigInvalid(String),
    TlsMaterialInvalid(String),
    BackendAddressInvalid {
        upstream: String,
        backend: String,
        address: String,
        reason: String,
    },
    DuplicateRouteAmbiguity {
        upstream: String,
        existing_upstream: String,
        host: Option<String>,
        path_prefix: Option<String>,
        method: Option<String>,
    },
    ListenerBindConflict {
        current: String,
        existing: String,
        address: String,
        port: u16,
    },
    UnsupportedPolicyCombination(String),
}

impl RuntimeConfigError {
    pub fn category(&self) -> &'static str {
        match self {
            Self::ConfigInvalid(_) => "config_invalid",
            Self::TlsMaterialInvalid(_) => "tls_material_invalid",
            Self::BackendAddressInvalid { .. } => "backend_address_invalid",
            Self::DuplicateRouteAmbiguity { .. } => "duplicate_route_ambiguity",
            Self::ListenerBindConflict { .. } => "listener_bind_conflict",
            Self::UnsupportedPolicyCombination(_) => "unsupported_policy_combination",
        }
    }
}

impl fmt::Display for RuntimeConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigInvalid(message)
            | Self::TlsMaterialInvalid(message)
            | Self::UnsupportedPolicyCombination(message) => {
                write!(f, "{}: {}", self.category(), message)
            }
            Self::BackendAddressInvalid {
                upstream,
                backend,
                address,
                reason,
            } => write!(
                f,
                "{}: upstream '{}' backend '{}' address '{}' is invalid: {}",
                self.category(),
                upstream,
                backend,
                address,
                reason
            ),
            Self::DuplicateRouteAmbiguity {
                upstream,
                existing_upstream,
                host,
                path_prefix,
                method,
            } => write!(
                f,
                "{}: upstream '{}' conflicts with upstream '{}' for host={:?} path_prefix={:?} method={:?}",
                self.category(),
                upstream,
                existing_upstream,
                host,
                path_prefix,
                method
            ),
            Self::ListenerBindConflict {
                current,
                existing,
                address,
                port,
            } => write!(
                f,
                "{}: {} duplicates {} on {}:{}",
                self.category(),
                current,
                existing,
                address,
                port
            ),
        }
    }
}

impl std::error::Error for RuntimeConfigError {}

#[derive(Debug, Clone)]
pub struct RuntimeListener {
    pub index: usize,
    pub source: RuntimeListenerSource,
    pub listen: Listen,
    pub tls: RuntimeListenerTls,
}

#[derive(Debug, Clone)]
pub struct ListenerRuntimeConfig {
    pub listen: RuntimeListener,
    pub policies: RuntimeListenerPolicySet,
    pub performance: Performance,
    pub observability: Observability,
}

impl ListenerRuntimeConfig {
    pub fn policies(&self) -> RuntimeListenerPolicySet {
        RuntimeListenerPolicySet::from_listener_runtime_config(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeListenerSource {
    LegacyListen,
    ExplicitListeners,
}

#[derive(Debug, Clone)]
pub struct RuntimeListenerTls {
    pub default_identity: RuntimeTlsIdentity,
    pub sni_identities: HashMap<String, RuntimeTlsIdentity>,
    pub client_auth: ClientAuth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTlsIdentity {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone)]
pub struct RuntimeUpstream {
    pub name: String,
    pub load_balancing: RuntimeLoadBalancingPolicy,
    pub route: RuntimeRouteMatchPolicy,
    pub policy: RuntimeUpstreamPolicy,
    pub policy_set: RuntimeUpstreamPolicySet,
    pub effective_tls: UpstreamTls,
    pub backends: Vec<RuntimeBackend>,
}

#[derive(Debug, Clone)]
pub struct RuntimeBackend {
    pub backend: Backend,
    pub endpoint: RuntimeBackendEndpoint,
    pub health_check: Option<RuntimeBackendHealthCheck>,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeHostPolicy(pub UpstreamHostPolicy);

#[derive(Debug, Clone, Default)]
pub struct RuntimeForwardedHeaderPolicy(pub ForwardedHeaderPolicy);

#[derive(Debug, Clone, Default)]
pub struct RuntimeProtocolPolicy(pub ProtocolPolicy);

#[derive(Debug, Clone, Default)]
pub struct RuntimeUpstreamPolicy {
    /// Upstream-owned auth policy selected after route lookup resolves an upstream.
    pub upstream_auth: RuntimeAuthPolicy,
    pub host: RuntimeHostPolicy,
    pub forwarded_headers: RuntimeForwardedHeaderPolicy,
    pub protocol: RuntimeProtocolPolicy,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{listeners::runtime_listeners, *};
    use crate::config::{
        Config, ForwardedHeaderPolicyMode, Listen, RouteMatch, Tls, TlsCertificate, Upstream,
        UpstreamHostPolicyMode,
    };

    fn sample_config() -> Config {
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
            log: crate::config::Log::default(),
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

    #[test]
    fn runtime_config_preserves_external_auth_contract() {
        let mut config = sample_config();
        config
            .upstream
            .get_mut("api")
            .expect("api")
            .auth
            .external_auth = Some(crate::config::ExternalAuth::Http {
            endpoint: "https://auth.internal/check".to_string(),
            request_headers: Vec::new(),
            response_header_allowlist: Vec::new(),
            timeout_ms: 1_000,
            failure_mode: crate::config::ExternalAuthFailureMode::FailClosed,
        });

        let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
        let auth = &runtime
            .upstreams
            .get("api")
            .expect("api")
            .policy
            .upstream_auth;
        match auth.external_auth.as_ref() {
            Some(RuntimeExternalAuth::Http {
                endpoint,
                request_headers,
                response_header_allowlist,
                timeout,
                ..
            }) => {
                assert_eq!(endpoint, "https://auth.internal/check");
                assert!(request_headers.is_empty());
                assert!(response_header_allowlist.is_empty());
                assert_eq!(*timeout, Duration::from_millis(1_000));
            }
            other => panic!("unexpected external_auth contract: {:?}", other),
        }
    }

    #[test]
    fn runtime_config_preserves_oidc_external_auth_metadata() {
        let mut config = sample_config();
        config
            .upstream
            .get_mut("api")
            .expect("api")
            .auth
            .external_auth = Some(crate::config::ExternalAuth::Oidc {
            discovery_url: Some(
                "https://issuer.example.com/.well-known/openid-configuration".to_string(),
            ),
            issuer_url: Some("https://issuer.example.com".to_string()),
            client_id: "edge-gateway".to_string(),
            client_secret: Some("secret-1".to_string()),
            audience: Some("spooky-api".to_string()),
            scopes: vec!["openid".to_string(), "profile".to_string()],
            request_headers: Vec::new(),
            response_header_allowlist: Vec::new(),
            timeout_ms: 1_500,
            failure_mode: crate::config::ExternalAuthFailureMode::FailClosed,
        });

        let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
        match runtime
            .upstreams
            .get("api")
            .expect("api")
            .policy
            .upstream_auth
            .external_auth
            .as_ref()
        {
            Some(RuntimeExternalAuth::Oidc {
                discovery_url,
                issuer_url,
                client_id,
                client_secret,
                audience,
                scopes,
                request_headers,
                response_header_allowlist,
                timeout,
                ..
            }) => {
                assert_eq!(
                    discovery_url.as_deref(),
                    Some("https://issuer.example.com/.well-known/openid-configuration")
                );
                assert_eq!(issuer_url.as_deref(), Some("https://issuer.example.com"));
                assert_eq!(client_id, "edge-gateway");
                assert_eq!(client_secret.as_deref(), Some("secret-1"));
                assert_eq!(audience.as_deref(), Some("spooky-api"));
                assert_eq!(scopes, &vec!["openid".to_string(), "profile".to_string()]);
                assert!(request_headers.is_empty());
                assert!(response_header_allowlist.is_empty());
                assert_eq!(*timeout, Duration::from_millis(1_500));
            }
            other => panic!("unexpected external_auth contract: {:?}", other),
        }
    }

    #[test]
    fn runtime_policy_set_normalizes_timeout_and_transport_knobs() {
        let mut config = sample_config();
        config.performance.backend_timeout_ms = 2_500;
        config.performance.backend_connect_timeout_ms = 400;
        config.performance.backend_body_idle_timeout_ms = 3_500;
        config.performance.backend_body_total_timeout_ms = 4_500;
        config.performance.backend_total_request_timeout_ms = 5_500;
        config.performance.h2_pool_idle_timeout_ms = 91_000;
        config.performance.max_active_connections = 1234;
        config.performance.max_request_body_bytes = 8_000;
        config.performance.request_buffer_global_cap_bytes = 9_999;
        config.resilience.route_queue.shed_retry_after_seconds = 17;

        let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
        let policies = runtime.policies();

        assert_eq!(policies.timeouts.backend_request, Duration::from_millis(2_500));
        assert_eq!(policies.timeouts.backend_connect, Duration::from_millis(400));
        assert_eq!(policies.timeouts.h2_pool_idle, Duration::from_millis(91_000));
        assert_eq!(policies.transport.max_active_connections, 1234);
        assert_eq!(policies.transport.request_buffer_global_cap_bytes, 9_999);
        assert_eq!(policies.admission.route_queue.shed_retry_after_seconds, 17);
    }

    #[test]
    fn runtime_defaults_produce_listener_and_runtime_policy_parity() {
        let config = sample_config();
        let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
        let listener = runtime
            .primary_listener_runtime_config()
            .expect("primary listener");

        assert_eq!(
            runtime.policies.timeouts.backend_request,
            Duration::from_millis(config.performance.backend_timeout_ms)
        );
        assert_eq!(
            runtime.policies.timeouts.quic_max_idle,
            Duration::from_millis(config.performance.quic_max_idle_timeout_ms)
        );
        assert_eq!(
            runtime.policies.transport.connection_limits.global_inflight,
            config.performance.global_inflight_limit
        );
        assert_eq!(
            runtime.policies.transport.quic_initial_max_data,
            config.performance.quic_initial_max_data
        );
        assert_eq!(
            runtime.policies.admission.watchdog.check_interval,
            Duration::from_millis(config.resilience.watchdog.check_interval_ms)
        );
        assert_eq!(listener.policies.timeouts, runtime.policies.timeouts);
        assert_eq!(listener.policies.transport, runtime.policies.transport);
    }

    #[test]
    fn runtime_upstream_policy_set_carries_canonical_lb_auth_and_tls_shapes() {
        let mut config = sample_config();
        let upstream = config.upstream.get_mut("api").expect("api upstream");
        upstream.load_balancing = LoadBalancing {
            lb_type: "sticky-cid".to_string(),
            key: Some("header:x-user-id".to_string()),
        };
        upstream.auth.api_key = Some(crate::config::ApiKeyAuth {
            header_name: "x-api-key".to_string(),
            keys: vec!["secret-1".to_string()],
        });
        upstream.tls = Some(UpstreamTls {
            verify_certificates: false,
            strict_sni: false,
            ca_file: Some("/tmp/upstream-ca.pem".to_string()),
            ca_dir: None,
        });
        config.resilience.scoped_rate_limits = vec![crate::config::ScopedRateLimit {
            name: "client-default".to_string(),
            scope: crate::config::ScopedRateLimitScope::Client,
            requests_per_sec: 10,
            burst: 20,
            key: Some("peer_ip".to_string()),
            route_allowlist: vec!["api".to_string()],
            idle_ttl_secs: 30,
        }];

        let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
        let upstream_policies = runtime.upstream_policy_sets();
        let api = upstream_policies.get("api").expect("api runtime policy set");

        assert_eq!(
            api.load_balancing.strategy,
            RuntimeLoadBalancingStrategy::StickyCid
        );
        assert_eq!(
            api.load_balancing.key.as_deref(),
            Some("header:x-user-id")
        );
        assert_eq!(
            api.auth.api_key.as_ref().map(|auth| auth.header_name.as_str()),
            Some("x-api-key")
        );
        assert_eq!(
            api.transport.tls.ca_file.as_deref(),
            Some("/tmp/upstream-ca.pem")
        );
        assert_eq!(
            api.transport.connection.max_inflight,
            runtime.policies.transport.connection_limits.backend_pool_max_inflight
        );
        assert_eq!(api.rate_limits.scoped_limits.len(), 1);
        assert_eq!(
            api.rate_limits.scoped_limits[0].idle_ttl,
            Duration::from_secs(30)
        );
    }

    #[test]
    fn runtime_config_normalizes_jwt_and_scoped_rate_limit_shapes() {
        let mut config = sample_config();
        let upstream = config.upstream.get_mut("api").expect("api upstream");
        upstream.auth.jwt = Some(crate::config::JwtAuth {
            secret: "jwt-secret".to_string(),
            issuer: Some(" issuer-1 ".to_string()),
            audience: Some(" spooky-api ".to_string()),
            clock_skew_secs: 45,
        });
        upstream.auth.required_scopes = vec![" read:api ".to_string()];
        upstream.auth.required_roles = vec![" admin ".to_string()];
        config.resilience.scoped_rate_limits = vec![crate::config::ScopedRateLimit {
            name: " tenant-default ".to_string(),
            scope: crate::config::ScopedRateLimitScope::Tenant,
            requests_per_sec: 12,
            burst: 34,
            key: Some("header:x-tenant-id".to_string()),
            route_allowlist: vec![" api ".to_string()],
            idle_ttl_secs: 9,
        }];

        let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
        let api = runtime.upstreams.get("api").expect("api runtime upstream");
        let jwt = api
            .policy
            .upstream_auth
            .jwt
            .as_ref()
            .expect("jwt policy");
        let scoped_limit = runtime
            .policies
            .rate_limits
            .scoped_limits
            .first()
            .expect("scoped rate limit");

        assert_eq!(jwt.issuer.as_deref(), Some("issuer-1"));
        assert_eq!(jwt.audience.as_deref(), Some("spooky-api"));
        assert_eq!(jwt.clock_skew, Duration::from_secs(45));
        assert_eq!(
            api.policy.upstream_auth.required_scopes,
            vec!["read:api".to_string()]
        );
        assert_eq!(
            api.policy.upstream_auth.required_roles,
            vec!["admin".to_string()]
        );
        assert_eq!(scoped_limit.name, " tenant-default ");
        assert_eq!(
            scoped_limit.route_allowlist,
            vec!["api".to_string()]
        );
        assert_eq!(scoped_limit.key.as_deref(), Some("header:x-tenant-id"));
        assert_eq!(scoped_limit.idle_ttl, Duration::from_secs(9));
    }

    #[test]
    fn runtime_upstreams_as_config_canonicalizes_route_and_lb_shapes() {
        let mut config = sample_config();
        let upstream = config.upstream.get_mut("api").expect("api upstream");
        upstream.load_balancing = LoadBalancing {
            lb_type: "cid_sticky".to_string(),
            key: Some("header:x-user-id".to_string()),
        };
        upstream.route = RouteMatch {
            host: Some("API.EXAMPLE.COM:443.".to_string()),
            path_prefix: Some("/v1".to_string()),
            method: Some("get".to_string()),
        };

        let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
        let runtime_upstream = runtime.upstreams.get("api").expect("api runtime upstream");
        let exported = runtime
            .upstreams_as_config()
            .remove("api")
            .expect("api exported upstream");

        assert_eq!(
            runtime_upstream.load_balancing.strategy,
            RuntimeLoadBalancingStrategy::StickyCid
        );
        assert_eq!(
            runtime_upstream.load_balancing.key_spec,
            Some(RuntimeRequestKeySpec::Header("x-user-id".to_string()))
        );
        assert!(!runtime_upstream.load_balancing.alternate_backend.readonly_lb_pick);
        assert!(runtime_upstream.load_balancing.alternate_backend.healthy_fallback);
        assert_eq!(runtime_upstream.route.host.as_deref(), Some("api.example.com:443"));
        assert_eq!(runtime_upstream.route.method.as_deref(), Some("GET"));
        assert_eq!(runtime_upstream.route.path_prefix.as_deref(), Some("/v1"));
        assert_eq!(exported.load_balancing.lb_type, "sticky-cid");
        assert_eq!(exported.route.host.as_deref(), Some("api.example.com:443"));
        assert_eq!(exported.route.method.as_deref(), Some("GET"));
        assert_eq!(exported.route.path_prefix.as_deref(), Some("/v1"));
    }

    #[test]
    fn runtime_listeners_uses_legacy_listen_when_explicit_list_is_empty() {
        let config = sample_config();
        let listeners = runtime_listeners(&config).expect("legacy listeners");

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].source, RuntimeListenerSource::LegacyListen);
        assert_eq!(listeners[0].listen.port, 443);
    }

    #[test]
    fn runtime_listeners_prefer_explicit_listeners() {
        let mut config = sample_config();
        config.listeners = vec![
            Listen {
                protocol: "http3".to_string(),
                port: 8443,
                address: "127.0.0.1".to_string(),
                tls: Tls {
                    cert: "/tmp/tls/explicit-1.pem".to_string(),
                    key: "/tmp/tls/explicit-1.key".to_string(),
                    certificates: Vec::new(),
                    client_auth: ClientAuth::default(),
                },
            },
            Listen {
                protocol: "http3".to_string(),
                port: 9443,
                address: "127.0.0.2".to_string(),
                tls: Tls {
                    cert: "/tmp/tls/explicit-2.pem".to_string(),
                    key: "/tmp/tls/explicit-2.key".to_string(),
                    certificates: Vec::new(),
                    client_auth: ClientAuth::default(),
                },
            },
        ];

        let listeners = runtime_listeners(&config).expect("explicit listeners");

        assert_eq!(listeners.len(), 2);
        assert_eq!(
            listeners[0].source,
            RuntimeListenerSource::ExplicitListeners
        );
        assert_eq!(listeners[0].listen.port, 8443);
        assert_eq!(listeners[1].listen.port, 9443);
    }

    #[test]
    fn runtime_listener_tls_uses_legacy_pair_as_default_identity() {
        let mut config = sample_config();
        config.listen.tls.cert = "/tmp/tls/cert.pem".to_string();
        config.listen.tls.key = "/tmp/tls/key.pem".to_string();
        config.listen.tls.certificates = vec![TlsCertificate {
            server_name: "api.example.com".to_string(),
            cert: "/tmp/tls/api.pem".to_string(),
            key: "/tmp/tls/api.key".to_string(),
        }];

        let listeners = runtime_listeners(&config).expect("runtime listeners");
        let tls = &listeners[0].tls;

        assert_eq!(
            tls.default_identity,
            RuntimeTlsIdentity {
                cert_path: "/tmp/tls/cert.pem".to_string(),
                key_path: "/tmp/tls/key.pem".to_string(),
            }
        );
        assert!(tls.sni_identities.contains_key("api.example.com"));
    }

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
            upstream.policy_set.transport.tls.ca_file.as_deref(),
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

    #[test]
    fn runtime_backend_health_check_and_endpoint_are_canonicalized() {
        let mut config = sample_config();
        config.upstream.get_mut("api").expect("api").backends[0].health_check =
            Some(crate::config::HealthCheck {
                path: String::new(),
                interval: 2_000,
                timeout_ms: 250,
                failure_threshold: 4,
                success_threshold: 3,
                cooldown_ms: 5_000,
            });

        let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
        let backend = &runtime.upstreams.get("api").expect("api").backends[0];
        let health = backend.health_check.as_ref().expect("health check");

        assert_eq!(backend.endpoint.origin, "https://api.internal:8443");
        assert_eq!(health.path, "/");
        assert_eq!(health.interval, Duration::from_millis(2_000));
        assert_eq!(health.timeout, Duration::from_millis(250));
        assert_eq!(health.failure_threshold, 4);
        assert_eq!(health.success_threshold, 3);
    }

    #[test]
    fn runtime_listeners_reject_duplicate_effective_bindings() {
        let mut config = sample_config();
        config.listeners = vec![
            Listen {
                protocol: "http3".to_string(),
                port: 8443,
                address: "127.0.0.1".to_string(),
                tls: Tls {
                    cert: "/tmp/tls/dup-1.pem".to_string(),
                    key: "/tmp/tls/dup-1.key".to_string(),
                    certificates: Vec::new(),
                    client_auth: ClientAuth::default(),
                },
            },
            Listen {
                protocol: "http3".to_string(),
                port: 8443,
                address: "127.0.0.1".to_string(),
                tls: Tls {
                    cert: "/tmp/tls/dup-2.pem".to_string(),
                    key: "/tmp/tls/dup-2.key".to_string(),
                    certificates: Vec::new(),
                    client_auth: ClientAuth::default(),
                },
            },
        ];

        let err = runtime_listeners(&config).expect_err("duplicate listeners must fail");
        assert_eq!(err.category(), "listener_bind_conflict");
        assert!(err.to_string().contains("duplicates"));
    }

    #[test]
    fn runtime_listener_tls_rejects_partial_legacy_pair() {
        let mut config = sample_config();
        config.listen.tls.cert = "/tmp/tls/cert.pem".to_string();
        config.listen.tls.key.clear();

        let err = runtime_listeners(&config).expect_err("partial legacy pair must fail");
        assert_eq!(err.category(), "tls_material_invalid");
        assert!(
            err.to_string()
                .contains("listen.tls.cert and listen.tls.key must both be set")
        );
    }

    #[test]
    fn runtime_listener_tls_rejects_duplicate_sni_names() {
        let mut config = sample_config();
        config.listen.tls.certificates = vec![
            TlsCertificate {
                server_name: "api.example.com".to_string(),
                cert: "/tmp/tls/api.pem".to_string(),
                key: "/tmp/tls/api.key".to_string(),
            },
            TlsCertificate {
                server_name: "API.EXAMPLE.COM".to_string(),
                cert: "/tmp/tls/api-2.pem".to_string(),
                key: "/tmp/tls/api-2.key".to_string(),
            },
        ];

        let err = runtime_listeners(&config).expect_err("duplicate sni names must fail");
        assert_eq!(err.category(), "tls_material_invalid");
        assert!(err.to_string().contains("duplicate server_name"));
    }

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
    fn runtime_config_rejects_invalid_timeout_ordering() {
        let mut config = sample_config();
        config.performance.backend_connect_timeout_ms = 2_000;
        config.performance.backend_timeout_ms = 1_000;

        let err =
            RuntimeConfig::from_config(&config).expect_err("timeout ordering must be validated");
        assert_eq!(err.category(), "config_invalid");
        assert!(
            err.to_string()
                .contains("backend_connect_timeout_ms must be <= backend_timeout_ms")
        );
    }

    #[test]
    fn runtime_config_rejects_invalid_lb_key_spec() {
        let mut config = sample_config();
        config.upstream.get_mut("api").expect("api").load_balancing.key =
            Some("header:   ".to_string());

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
}
