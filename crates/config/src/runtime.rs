use std::collections::HashMap;

use crate::config::{
    Backend, ClientAuth, Config, ForwardedHeaderPolicy, Listen, LoadBalancing, Observability,
    Performance, ProtocolPolicy, Resilience, RouteMatch, Security, TlsCertificate, Upstream,
    UpstreamHostPolicy, UpstreamTls,
};

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
    pub fn from_config(config: &Config) -> Result<Self, String> {
        Ok(Self {
            version: config.version,
            listeners: runtime_listeners(config)?,
            upstreams: config
                .upstream
                .iter()
                .map(|(name, upstream)| {
                    (
                        name.clone(),
                        RuntimeUpstream::from_config(config, name.as_str(), upstream),
                    )
                })
                .collect(),
            performance: config.performance.clone(),
            observability: config.observability.clone(),
            resilience: config.resilience.clone(),
            security: config.security.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeListener {
    pub index: usize,
    pub source: RuntimeListenerSource,
    pub listen: Listen,
    pub tls: RuntimeListenerTls,
}

impl RuntimeListener {
    fn new(
        index: usize,
        source: RuntimeListenerSource,
        listen: Listen,
        label: &str,
    ) -> Result<Self, String> {
        let tls = RuntimeListenerTls::normalize(&listen, label)?;
        Ok(Self {
            index,
            source,
            listen,
            tls,
        })
    }

    pub fn bind_key(&self) -> (String, u16) {
        (self.listen.address.trim().to_ascii_lowercase(), self.listen.port)
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

impl RuntimeListenerTls {
    pub fn normalize(listen: &Listen, label: &str) -> Result<Self, String> {
        let mut sni_identities = HashMap::new();
        let legacy_identity = RuntimeTlsIdentity::from_legacy_pair(listen, label)?;

        for entry in &listen.tls.certificates {
            let identity = RuntimeTlsIdentity::from_certificate(entry, label)?;
            let server_name = entry.server_name.trim().to_ascii_lowercase();
            if let Some(existing) = sni_identities.insert(server_name.clone(), identity) {
                return Err(format!(
                    "{label}.tls.certificates contains duplicate server_name '{server_name}' for '{}' and '{}'",
                    existing.cert_path, entry.cert
                ));
            }
        }

        let default_identity = match legacy_identity {
            Some(identity) => identity,
            None => listen
                .tls
                .certificates
                .first()
                .map(|entry| RuntimeTlsIdentity::from_certificate(entry, label))
                .transpose()?
                .ok_or_else(|| {
                    format!("{label}.tls requires either cert/key or certificates entries")
                })?,
        };

        Ok(Self {
            default_identity,
            sni_identities,
            client_auth: listen.tls.client_auth.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTlsIdentity {
    pub cert_path: String,
    pub key_path: String,
}

impl RuntimeTlsIdentity {
    fn from_certificate(certificate: &TlsCertificate, label: &str) -> Result<Self, String> {
        let server_name = certificate.server_name.trim();
        if server_name.is_empty() {
            return Err(format!(
                "{label}.tls.certificates entries must include a non-empty server_name"
            ));
        }

        let cert_path = certificate.cert.trim();
        let key_path = certificate.key.trim();
        if cert_path.is_empty() || key_path.is_empty() {
            return Err(format!(
                "{label}.tls.certificates entries must include non-empty cert and key"
            ));
        }

        Ok(Self {
            cert_path: cert_path.to_string(),
            key_path: key_path.to_string(),
        })
    }

    fn from_legacy_pair(listen: &Listen, label: &str) -> Result<Option<Self>, String> {
        let cert = listen.tls.cert.trim();
        let key = listen.tls.key.trim();
        if cert.is_empty() || key.is_empty() {
            if cert.is_empty() && key.is_empty() {
                return Ok(None);
            }
            return Err(format!(
                "{label}.tls.cert and {label}.tls.key must both be set when either is provided"
            ));
        }

        Ok(Some(Self {
            cert_path: cert.to_string(),
            key_path: key.to_string(),
        }))
    }
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

impl RuntimeUpstream {
    fn from_config(config: &Config, name: &str, upstream: &Upstream) -> Self {
        let effective_tls = upstream
            .tls
            .clone()
            .unwrap_or_else(|| config.upstream_tls.clone());

        Self {
            name: name.to_string(),
            load_balancing: upstream.load_balancing.clone(),
            route: upstream.route.clone(),
            policy: RuntimeUpstreamPolicy {
                host: RuntimeHostPolicy(upstream.host_policy.clone()),
                forwarded_headers: RuntimeForwardedHeaderPolicy(
                    upstream.forwarded_headers.clone(),
                ),
                protocol: RuntimeProtocolPolicy(config.resilience.protocol.clone()),
            },
            effective_tls: effective_tls.clone(),
            backends: upstream
                .backends
                .iter()
                .cloned()
                .map(|backend| RuntimeBackend {
                    backend,
                    effective_tls: effective_tls.clone(),
                })
                .collect(),
        }
    }
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
pub struct RuntimeUpstreamPolicy {
    pub host: RuntimeHostPolicy,
    pub forwarded_headers: RuntimeForwardedHeaderPolicy,
    pub protocol: RuntimeProtocolPolicy,
}

pub fn runtime_listeners(config: &Config) -> Result<Vec<RuntimeListener>, String> {
    let listeners = if config.listeners.is_empty() {
        vec![RuntimeListener::new(
            0,
            RuntimeListenerSource::LegacyListen,
            config.listen.clone(),
            "listen",
        )?]
    } else {
        config
            .listeners
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, listen)| {
                RuntimeListener::new(
                    index,
                    RuntimeListenerSource::ExplicitListeners,
                    listen,
                    &format!("listeners[{index}]"),
                )
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    validate_listener_bindings(&listeners)?;
    Ok(listeners)
}

fn validate_listener_bindings(listeners: &[RuntimeListener]) -> Result<(), String> {
    let mut seen = HashMap::new();
    for listener in listeners {
        let bind_key = listener.bind_key();
        let current = format!(
            "{}:{} (listener #{})",
            listener.listen.address, listener.listen.port, listener.index
        );
        if let Some(existing) = seen.insert(bind_key, current.clone()) {
            return Err(format!(
                "listener binding conflict: {current} duplicates {existing}"
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
                host_policy: UpstreamHostPolicy {
                    mode: UpstreamHostPolicyMode::Upstream,
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
                tls: Tls::default(),
            },
            Listen {
                protocol: "http3".to_string(),
                port: 9443,
                address: "127.0.0.2".to_string(),
                tls: Tls::default(),
            },
        ];

        let listeners = runtime_listeners(&config).expect("explicit listeners");

        assert_eq!(listeners.len(), 2);
        assert_eq!(listeners[0].source, RuntimeListenerSource::ExplicitListeners);
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
        config
            .upstream
            .get_mut("api")
            .expect("upstream")
            .tls = Some(UpstreamTls {
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
        assert_eq!(upstream.backends[0].backend.address, "https://api.internal:8443");
        assert_eq!(upstream.policy.host.0.mode, UpstreamHostPolicyMode::Upstream);
        assert_eq!(
            upstream.policy.forwarded_headers.0.mode,
            ForwardedHeaderPolicyMode::Append
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
                tls: Tls::default(),
            },
            Listen {
                protocol: "http3".to_string(),
                port: 8443,
                address: "127.0.0.1".to_string(),
                tls: Tls::default(),
            },
        ];

        let err = runtime_listeners(&config).expect_err("duplicate listeners must fail");
        assert!(err.contains("listener binding conflict"));
    }

    #[test]
    fn runtime_listener_tls_rejects_partial_legacy_pair() {
        let mut config = sample_config();
        config.listen.tls.cert = "/tmp/tls/cert.pem".to_string();
        config.listen.tls.key.clear();

        let err = runtime_listeners(&config).expect_err("partial legacy pair must fail");
        assert!(err.contains("listen.tls.cert and listen.tls.key must both be set"));
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
        assert!(err.contains("duplicate server_name"));
    }
}
