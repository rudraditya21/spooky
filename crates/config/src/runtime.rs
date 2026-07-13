use std::{collections::HashMap, fmt, net::IpAddr};

use crate::{
    backend_endpoint::BackendEndpoint,
    config::{
        Backend, ClientAuth, Config, ForwardedHeaderPolicy, Listen, LoadBalancing, Observability,
        Performance, ProtocolPolicy, Resilience, RouteMatch, Security, TlsCertificate, Upstream,
        UpstreamHostPolicy, UpstreamHostPolicyMode, UpstreamTls,
    },
};

#[path = "runtime/listeners.rs"]
mod listeners;
#[path = "runtime/upstreams.rs"]
mod upstreams;

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub version: u32,
    pub listeners: Vec<RuntimeListener>,
    pub upstreams: HashMap<String, RuntimeUpstream>,
    pub performance: Performance,
    pub observability: Observability,
    pub resilience: Resilience,
    pub security: Security,
}

impl RuntimeConfig {
    pub fn from_config(config: &Config) -> Result<Self, RuntimeConfigError> {
        Ok(Self {
            version: config.version,
            listeners: listeners::runtime_listeners(config)?,
            upstreams: upstreams::normalize_upstreams(config)?,
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
                listen,
                performance: self.performance.clone(),
                observability: self.observability.clone(),
            })
            .collect()
    }

    pub fn primary_listener_runtime_config(&self) -> Option<ListenerRuntimeConfig> {
        self.listener_runtime_configs().into_iter().next()
    }

    pub fn upstreams_as_config(&self) -> HashMap<String, Upstream> {
        self.upstreams
            .iter()
            .map(|(name, upstream)| (name.clone(), upstream.as_config_upstream()))
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
    pub performance: Performance,
    pub observability: Observability,
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
    pub load_balancing: LoadBalancing,
    pub route: RouteMatch,
    pub policy: RuntimeUpstreamPolicy,
    pub effective_tls: UpstreamTls,
    pub backends: Vec<RuntimeBackend>,
}

#[derive(Debug, Clone)]
pub struct RuntimeBackend {
    pub backend: Backend,
    pub effective_tls: UpstreamTls,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeHostPolicy(pub UpstreamHostPolicy);

#[derive(Debug, Clone, Default)]
pub struct RuntimeForwardedHeaderPolicy(pub ForwardedHeaderPolicy);

#[derive(Debug, Clone, Default)]
pub struct RuntimeProtocolPolicy(pub ProtocolPolicy);

#[derive(Debug, Clone, Default)]
pub struct RuntimeApiKeyAuth {
    pub header_name: String,
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeJwtAuth {
    pub secret: String,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub clock_skew_secs: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RuntimeExternalAuthFailureMode {
    FailOpen,
    #[default]
    FailClosed,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeExternalAuthRequestHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub enum RuntimeExternalAuth {
    Http {
        endpoint: String,
        request_headers: Vec<RuntimeExternalAuthRequestHeader>,
        response_header_allowlist: Vec<String>,
        timeout_ms: u64,
        failure_mode: RuntimeExternalAuthFailureMode,
    },
    Oidc {
        discovery_url: Option<String>,
        issuer_url: Option<String>,
        client_id: String,
        client_secret: Option<String>,
        audience: Option<String>,
        scopes: Vec<String>,
        request_headers: Vec<RuntimeExternalAuthRequestHeader>,
        response_header_allowlist: Vec<String>,
        timeout_ms: u64,
        failure_mode: RuntimeExternalAuthFailureMode,
    },
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeAuthPolicy {
    pub api_key: Option<RuntimeApiKeyAuth>,
    pub jwt: Option<RuntimeJwtAuth>,
    pub external_auth: Option<RuntimeExternalAuth>,
    pub required_scopes: Vec<String>,
    pub required_roles: Vec<String>,
}

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
                load_balancing: LoadBalancing::default(),
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
                timeout_ms,
                ..
            }) => {
                assert_eq!(endpoint, "https://auth.internal/check");
                assert!(request_headers.is_empty());
                assert!(response_header_allowlist.is_empty());
                assert_eq!(*timeout_ms, 1_000);
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
                timeout_ms,
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
                assert_eq!(*timeout_ms, 1_500);
            }
            other => panic!("unexpected external_auth contract: {:?}", other),
        }
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
