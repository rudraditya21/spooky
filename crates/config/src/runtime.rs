use std::{collections::HashMap, fmt, net::IpAddr};

use crate::{
    backend_endpoint::BackendEndpoint,
    config::{
        Backend, ClientAuth, Config, ForwardedHeaderPolicy, Listen, LoadBalancing, Observability,
        Performance, ProtocolPolicy, Resilience, RouteMatch, Security, TlsCertificate, Upstream,
        UpstreamHostPolicy, UpstreamHostPolicyMode, UpstreamTls,
    },
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
    pub fn from_config(config: &Config) -> Result<Self, RuntimeConfigError> {
        Ok(Self {
            version: config.version,
            listeners: runtime_listeners(config)?,
            upstreams: normalize_upstreams(config)?,
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

impl RuntimeListener {
    fn new(
        index: usize,
        source: RuntimeListenerSource,
        listen: Listen,
        label: &str,
    ) -> Result<Self, RuntimeConfigError> {
        let tls = RuntimeListenerTls::normalize(&listen, label)?;
        Ok(Self {
            index,
            source,
            listen,
            tls,
        })
    }

    pub fn bind_key(&self) -> (String, u16) {
        (
            self.listen.address.trim().to_ascii_lowercase(),
            self.listen.port,
        )
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
    pub fn normalize(listen: &Listen, label: &str) -> Result<Self, RuntimeConfigError> {
        let mut sni_identities = HashMap::new();
        let legacy_identity = RuntimeTlsIdentity::from_legacy_pair(listen, label)?;

        if !listen.tls.client_auth.enabled && listen.tls.client_auth.require_client_cert {
            return Err(RuntimeConfigError::UnsupportedPolicyCombination(format!(
                "{label}.tls.client_auth.require_client_cert requires client_auth.enabled=true"
            )));
        }
        if listen.tls.client_auth.enabled {
            let Some(ca_file) = listen.tls.client_auth.ca_file.as_deref().map(str::trim) else {
                return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
                    "{label}.tls.client_auth.ca_file is required when client_auth.enabled=true"
                )));
            };
            if ca_file.is_empty() {
                return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
                    "{label}.tls.client_auth.ca_file must be non-empty when client_auth.enabled=true"
                )));
            }
        }

        for entry in &listen.tls.certificates {
            let identity = RuntimeTlsIdentity::from_certificate(entry, label)?;
            let server_name = normalize_sni_server_name(&entry.server_name).ok_or_else(|| {
                RuntimeConfigError::TlsMaterialInvalid(format!(
                    "{label}.tls.certificates entries must include a valid DNS server_name"
                ))
            })?;
            if let Some(existing) = sni_identities.insert(server_name.clone(), identity) {
                return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
                    "{label}.tls.certificates contains duplicate server_name '{server_name}' for '{}' and '{}'",
                    existing.cert_path, entry.cert
                )));
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
                    RuntimeConfigError::TlsMaterialInvalid(format!(
                        "{label}.tls requires either cert/key or certificates entries"
                    ))
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
    fn from_certificate(
        certificate: &TlsCertificate,
        label: &str,
    ) -> Result<Self, RuntimeConfigError> {
        let server_name = certificate.server_name.trim();
        if server_name.is_empty() {
            return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
                "{label}.tls.certificates entries must include a non-empty server_name"
            )));
        }

        let cert_path = certificate.cert.trim();
        let key_path = certificate.key.trim();
        if cert_path.is_empty() || key_path.is_empty() {
            return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
                "{label}.tls.certificates entries must include non-empty cert and key"
            )));
        }

        Ok(Self {
            cert_path: cert_path.to_string(),
            key_path: key_path.to_string(),
        })
    }

    fn from_legacy_pair(listen: &Listen, label: &str) -> Result<Option<Self>, RuntimeConfigError> {
        let cert = listen.tls.cert.trim();
        let key = listen.tls.key.trim();
        if cert.is_empty() || key.is_empty() {
            if cert.is_empty() && key.is_empty() {
                return Ok(None);
            }
            return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
                "{label}.tls.cert and {label}.tls.key must both be set when either is provided"
            )));
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
                forwarded_headers: RuntimeForwardedHeaderPolicy(upstream.forwarded_headers.clone()),
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

    pub fn as_config_upstream(&self) -> Upstream {
        Upstream {
            load_balancing: self.load_balancing.clone(),
            host_policy: self.policy.host.0.clone(),
            forwarded_headers: self.policy.forwarded_headers.0.clone(),
            tls: Some(self.effective_tls.clone()),
            route: self.route.clone(),
            backends: self
                .backends
                .iter()
                .map(|backend| backend.backend.clone())
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

pub fn runtime_listeners(config: &Config) -> Result<Vec<RuntimeListener>, RuntimeConfigError> {
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

fn validate_listener_bindings(listeners: &[RuntimeListener]) -> Result<(), RuntimeConfigError> {
    let mut seen = HashMap::new();
    for listener in listeners {
        let bind_key = listener.bind_key();
        let current = format!(
            "{}:{} (listener #{})",
            listener.listen.address, listener.listen.port, listener.index
        );
        if let Some(existing) = seen.insert(bind_key, current.clone()) {
            return Err(RuntimeConfigError::ListenerBindConflict {
                current,
                existing,
                address: listener.listen.address.clone(),
                port: listener.listen.port,
            });
        }
    }

    Ok(())
}

fn normalize_upstreams(
    config: &Config,
) -> Result<HashMap<String, RuntimeUpstream>, RuntimeConfigError> {
    if config.upstream.is_empty() {
        return Err(RuntimeConfigError::ConfigInvalid(
            "no upstreams configured".to_string(),
        ));
    }

    validate_protocol_policy(&config.resilience.protocol)?;

    let mut seen_route_matchers: HashMap<RouteMatcherKey, String> = HashMap::new();
    let mut seen_backend_origins: HashMap<String, (String, String)> = HashMap::new();
    let mut normalized = HashMap::new();

    for (upstream_name, upstream) in &config.upstream {
        validate_upstream_policy(config, upstream_name, upstream)?;

        let route_key = (
            upstream.route.host.as_deref().map(normalize_route_host),
            upstream.route.path_prefix.clone(),
            normalized_route_method(upstream.route.method.as_deref()),
        );
        if let Some(existing) = seen_route_matchers.insert(route_key.clone(), upstream_name.clone())
        {
            return Err(RuntimeConfigError::DuplicateRouteAmbiguity {
                upstream: upstream_name.clone(),
                existing_upstream: existing,
                host: route_key.0.clone(),
                path_prefix: route_key.1.clone(),
                method: route_key.2.clone(),
            });
        }

        let runtime_upstream =
            RuntimeUpstream::from_config(config, upstream_name.as_str(), upstream);
        validate_runtime_upstream_tls(upstream_name, &runtime_upstream.effective_tls)?;

        for backend in &runtime_upstream.backends {
            if backend.backend.id.trim().is_empty() {
                return Err(RuntimeConfigError::ConfigInvalid(format!(
                    "upstream '{upstream_name}' contains an empty backend id"
                )));
            }
            if backend.backend.address.trim().is_empty() {
                return Err(RuntimeConfigError::ConfigInvalid(format!(
                    "backend '{}' in upstream '{}' has an empty address",
                    backend.backend.id, upstream_name
                )));
            }

            let endpoint = BackendEndpoint::parse(&backend.backend.address).map_err(|err| {
                RuntimeConfigError::BackendAddressInvalid {
                    upstream: upstream_name.clone(),
                    backend: backend.backend.id.clone(),
                    address: backend.backend.address.clone(),
                    reason: err,
                }
            })?;

            let origin = endpoint.origin();
            if let Some((existing_upstream, existing_backend)) = seen_backend_origins.insert(
                origin.clone(),
                (upstream_name.clone(), backend.backend.id.clone()),
            ) {
                return Err(RuntimeConfigError::BackendAddressInvalid {
                    upstream: upstream_name.clone(),
                    backend: backend.backend.id.clone(),
                    address: origin,
                    reason: format!(
                        "conflicts with upstream '{}' backend '{}'",
                        existing_upstream, existing_backend
                    ),
                });
            }
        }

        normalized.insert(upstream_name.clone(), runtime_upstream);
    }

    Ok(normalized)
}

fn validate_protocol_policy(policy: &ProtocolPolicy) -> Result<(), RuntimeConfigError> {
    if policy.max_headers_count == 0 {
        return Err(RuntimeConfigError::ConfigInvalid(
            "resilience.protocol.max_headers_count must be greater than 0".to_string(),
        ));
    }
    if policy.max_headers_bytes == 0 {
        return Err(RuntimeConfigError::ConfigInvalid(
            "resilience.protocol.max_headers_bytes must be greater than 0".to_string(),
        ));
    }
    if policy
        .allowed_methods
        .iter()
        .any(|method| method.trim().is_empty())
    {
        return Err(RuntimeConfigError::ConfigInvalid(
            "resilience.protocol.allowed_methods must not contain empty values".to_string(),
        ));
    }
    if policy
        .denied_path_prefixes
        .iter()
        .any(|prefix| prefix.is_empty() || !prefix.starts_with('/'))
    {
        return Err(RuntimeConfigError::ConfigInvalid(
            "resilience.protocol.denied_path_prefixes must contain '/'-prefixed paths".to_string(),
        ));
    }
    if !policy.allow_connect
        && (!policy.connect_allowed_ports.is_empty()
            || !policy.connect_allowed_authorities.is_empty())
    {
        return Err(RuntimeConfigError::UnsupportedPolicyCombination(
            "resilience.protocol.connect_allowed_ports/connect_allowed_authorities require allow_connect=true"
                .to_string(),
        ));
    }
    if policy.connect_allowed_ports.contains(&0) {
        return Err(RuntimeConfigError::ConfigInvalid(
            "resilience.protocol.connect_allowed_ports must contain ports in range 1-65535"
                .to_string(),
        ));
    }
    if policy
        .connect_allowed_authorities
        .iter()
        .any(|authority| !is_valid_connect_authority(authority))
    {
        return Err(RuntimeConfigError::ConfigInvalid(
            "resilience.protocol.connect_allowed_authorities must contain authority-form host:port targets"
                .to_string(),
        ));
    }
    if policy.allow_0rtt && policy.early_data_safe_methods.is_empty() {
        return Err(RuntimeConfigError::UnsupportedPolicyCombination(
            "resilience.protocol.early_data_safe_methods must be non-empty when allow_0rtt=true"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_upstream_policy(
    config: &Config,
    upstream_name: &str,
    upstream: &Upstream,
) -> Result<(), RuntimeConfigError> {
    match upstream.host_policy.mode {
        UpstreamHostPolicyMode::PassThrough | UpstreamHostPolicyMode::Upstream => {
            if upstream.host_policy.host.is_some() {
                return Err(RuntimeConfigError::UnsupportedPolicyCombination(format!(
                    "upstream '{upstream_name}' sets host_policy.host but mode is not rewrite"
                )));
            }
        }
        UpstreamHostPolicyMode::Rewrite => match upstream.host_policy.host.as_deref() {
            Some(host) if valid_static_host_header(host) => {}
            _ => {
                return Err(RuntimeConfigError::UnsupportedPolicyCombination(format!(
                    "upstream '{upstream_name}' requires a valid non-empty host_policy.host when mode=rewrite"
                )));
            }
        },
    }

    if let Some(path) = upstream.route.path_prefix.as_deref()
        && (path.is_empty() || !path.starts_with('/'))
    {
        return Err(RuntimeConfigError::ConfigInvalid(format!(
            "upstream '{upstream_name}' has an invalid route.path_prefix '{}'",
            path
        )));
    }

    if normalized_route_method(upstream.route.method.as_deref()).as_deref() == Some("CONNECT")
        && !config.resilience.protocol.allow_connect
    {
        return Err(RuntimeConfigError::UnsupportedPolicyCombination(format!(
            "upstream '{upstream_name}' routes CONNECT but resilience.protocol.allow_connect=false"
        )));
    }

    Ok(())
}

fn validate_runtime_upstream_tls(
    upstream_name: &str,
    tls: &UpstreamTls,
) -> Result<(), RuntimeConfigError> {
    if tls
        .ca_file
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
            "upstream '{upstream_name}' has an empty effective upstream_tls.ca_file"
        )));
    }
    if tls
        .ca_dir
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
            "upstream '{upstream_name}' has an empty effective upstream_tls.ca_dir"
        )));
    }
    Ok(())
}

type RouteMatcherKey = (Option<String>, Option<String>, Option<String>);

fn normalize_route_host(raw: &str) -> String {
    let trimmed = raw.trim();
    let host = if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            &rest[..end]
        } else {
            trimmed
        }
    } else if let Some((candidate_host, candidate_port)) = trimmed.rsplit_once(':') {
        if !candidate_host.contains(':') && candidate_port.chars().all(|c| c.is_ascii_digit()) {
            candidate_host
        } else {
            trimmed
        }
    } else {
        trimmed
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn normalized_route_method(method: Option<&str>) -> Option<String> {
    method
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_uppercase())
}

fn valid_static_host_header(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed == value
        && !trimmed.chars().any(|ch| ch.is_ascii_whitespace())
        && !trimmed.contains('/')
        && !trimmed.contains('?')
        && !trimmed.contains('#')
        && http::HeaderValue::from_str(trimmed).is_ok()
}

fn normalize_sni_server_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains(':')
        || trimmed.contains('*')
        || trimmed.chars().any(char::is_whitespace)
    {
        return None;
    }
    let without_trailing_dot = trimmed.trim_end_matches('.');
    if without_trailing_dot.is_empty() {
        return None;
    }
    let ascii = idna::domain_to_ascii(without_trailing_dot).ok()?;
    if ascii.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(ascii.to_ascii_lowercase())
}

fn is_valid_connect_authority(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return false;
    }

    if let Some(rest) = trimmed.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        let suffix = &rest[end + 1..];
        if !suffix.starts_with(':') || suffix.len() <= 1 {
            return false;
        }
        return suffix[1..].parse::<u16>().ok().is_some_and(|port| port > 0);
    }

    let Some((host, port)) = trimmed.rsplit_once(':') else {
        return false;
    };
    if host.is_empty() || host.contains(':') {
        return false;
    }
    port.parse::<u16>().ok().is_some_and(|value| value > 0)
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
