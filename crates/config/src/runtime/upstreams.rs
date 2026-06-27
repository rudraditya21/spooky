use super::*;

type RouteMatcherKey = (Option<String>, Option<String>, Option<String>);

impl RuntimeUpstream {
    pub(super) fn from_config(config: &Config, name: &str, upstream: &Upstream) -> Self {
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

pub(super) fn normalize_upstreams(
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
        let mut upstream_uses_https_backends = false;

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
            if endpoint.scheme() == crate::backend_endpoint::BackendScheme::Https {
                upstream_uses_https_backends = true;
            }

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

        if upstream_uses_https_backends {
            validate_runtime_upstream_tls(upstream_name, &runtime_upstream.effective_tls)?;
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

pub(super) fn normalize_sni_server_name(raw: &str) -> Option<String> {
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
