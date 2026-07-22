mod admission;
mod auth;
mod backend;
mod lb;
mod resilience;
mod timeouts;
mod transport;
mod watchdog;

use super::*;
pub use self::admission::{
    RuntimeAdmissionPolicy, RuntimeBrownoutPolicy, RuntimeRateLimitPolicy,
    RuntimeRouteQueuePolicy, RuntimeScopedRateLimitPolicy,
};
pub use self::auth::{
    RuntimeApiKeyAuth, RuntimeAuthPolicy, RuntimeExternalAuth, RuntimeExternalAuthFailureMode,
    RuntimeExternalAuthRequestHeader, RuntimeJwtAuth,
};
pub use self::backend::{
    RuntimeBackendAddressKind, RuntimeBackendDnsPolicy, RuntimeBackendEndpoint,
    RuntimeBackendHealthCheck, RuntimeBackendTlsPolicy,
};
pub use self::lb::{
    RuntimeAlternateBackendPolicy, RuntimeLoadBalancingPolicy, RuntimeLoadBalancingStrategy,
    RuntimeRequestKeySpec,
};
pub use self::resilience::{
    RuntimeCircuitBreakerPolicy, RuntimeHedgingPolicy, RuntimeRetryBudgetPolicy,
};
pub use self::timeouts::RuntimeTimeoutPolicy;
pub use self::transport::{
    RuntimeBackendConnectionPolicy, RuntimeConnectionLimits, RuntimeTransportPolicy,
};
pub use self::watchdog::RuntimeWatchdogPolicy;

fn config_invalid(message: impl Into<String>) -> RuntimeConfigError {
    RuntimeConfigError::ConfigInvalid(message.into())
}

fn unsupported_policy(message: impl Into<String>) -> RuntimeConfigError {
    RuntimeConfigError::UnsupportedPolicyCombination(message.into())
}

fn require_nonzero_u64(name: &str, value: u64) -> Result<(), RuntimeConfigError> {
    if value == 0 {
        return Err(config_invalid(format!("{name} must be greater than 0")));
    }
    Ok(())
}

fn require_nonzero_usize(name: &str, value: usize) -> Result<(), RuntimeConfigError> {
    if value == 0 {
        return Err(config_invalid(format!("{name} must be greater than 0")));
    }
    Ok(())
}

fn require_nonzero_u32(name: &str, value: u32) -> Result<(), RuntimeConfigError> {
    if value == 0 {
        return Err(config_invalid(format!("{name} must be greater than 0")));
    }
    Ok(())
}

fn normalize_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn normalize_string_vec(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn normalize_nonempty_string_vec(
    field_name: &str,
    values: &[String],
) -> Result<Vec<String>, RuntimeConfigError> {
    let normalized = normalize_string_vec(values);
    if normalized.len() != values.len() {
        return Err(config_invalid(format!(
            "{field_name} must not contain empty values"
        )));
    }
    Ok(normalized)
}

fn is_valid_http_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| matches!(byte, b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'0'..=b'9' | b'A'..=b'Z' | b'^' | b'_' | b'`' | b'a'..=b'z' | b'|' | b'~'))
}

fn is_valid_connect_authority(authority: &str) -> bool {
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    !host.trim().is_empty() && port.parse::<u16>().ok().is_some_and(|parsed| parsed > 0)
}

fn is_valid_request_key_spec(key_spec: &str) -> bool {
    let key_spec = key_spec.trim().to_ascii_lowercase();
    matches!(
        key_spec.as_str(),
        "path"
            | "authority"
            | "method"
            | "cid"
            | "sticky-cid"
            | "peer_ip"
            | "client_ip"
            | "bearer_token"
    ) || key_spec.split_once(':').is_some_and(|(source, key_name)| {
        !key_name.trim().is_empty() && matches!(source.trim(), "header" | "cookie" | "query")
    })
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

fn parse_runtime_route_host_pattern(raw: &str) -> RuntimeRouteHostPattern {
    let normalized = normalize_route_host(raw);
    let Some(wildcard_suffix) = normalized.strip_prefix("*.") else {
        return RuntimeRouteHostPattern::Exact(normalized);
    };
    if wildcard_suffix.is_empty() || wildcard_suffix.contains('*') {
        return RuntimeRouteHostPattern::Exact(normalized);
    }
    RuntimeRouteHostPattern::WildcardSuffix(wildcard_suffix.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RuntimeRouteHostPattern {
    Exact(String),
    WildcardSuffix(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuntimeRouteMatchPolicy {
    pub host: Option<String>,
    pub host_pattern: Option<RuntimeRouteHostPattern>,
    pub path_prefix: Option<String>,
    pub method: Option<String>,
    pub path_len: usize,
    pub host_specific: bool,
    pub method_specific: bool,
}

impl RuntimeRouteMatchPolicy {
    pub(crate) fn normalize(
        upstream_name: &str,
        route: &crate::config::RouteMatch,
    ) -> Result<Self, RuntimeConfigError> {
        let path_prefix = normalize_optional_string(route.path_prefix.as_deref());
        if let Some(path_prefix) = path_prefix.as_deref()
            && !path_prefix.starts_with('/')
        {
            return Err(config_invalid(format!(
                "upstream '{upstream_name}' has an invalid route.path_prefix '{}'",
                path_prefix
            )));
        }

        let host = normalize_optional_string(route.host.as_deref())
            .map(|host| normalize_route_host(&host));
        let host_pattern = host.as_deref().map(parse_runtime_route_host_pattern);
        let method = normalized_route_method(route.method.as_deref());

        Ok(Self {
            path_len: path_prefix.as_ref().map(|value| value.len()).unwrap_or(0),
            host_specific: host.is_some(),
            method_specific: method.is_some(),
            host,
            host_pattern,
            path_prefix,
            method,
        })
    }

    #[cfg(test)]
    pub(crate) fn as_config(&self) -> crate::config::RouteMatch {
        crate::config::RouteMatch {
            host: self.host.clone(),
            path_prefix: self.path_prefix.clone(),
            method: self.method.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeBackendTransportKind {
    Http1,
    H2,
}

#[derive(Debug, Clone)]
pub struct RuntimeUpstreamTransportPolicy {
    pub tls: RuntimeBackendTlsPolicy,
    pub connection: RuntimeBackendConnectionPolicy,
    pub dns: RuntimeBackendDnsPolicy,
}

impl RuntimeUpstreamTransportPolicy {
    pub fn from_effective_tls(
        effective_tls: &UpstreamTls,
        transport: &RuntimeTransportPolicy,
    ) -> Self {
        Self {
            tls: RuntimeBackendTlsPolicy::from_effective_tls(effective_tls),
            connection: transport.backend_connections.clone(),
            dns: transport.backend_dns.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimePolicySet {
    pub timeouts: RuntimeTimeoutPolicy,
    pub admission: RuntimeAdmissionPolicy,
    pub rate_limits: RuntimeRateLimitPolicy,
    pub transport: RuntimeTransportPolicy,
}

impl RuntimePolicySet {
    pub(crate) fn from_config(config: &Config) -> Result<Self, RuntimeConfigError> {
        let timeouts = RuntimeTimeoutPolicy::normalize(&config.performance)?;
        let transport = RuntimeTransportPolicy::normalize(&config.performance)?;
        let rate_limits = RuntimeRateLimitPolicy::normalize(&config.resilience)?;
        let admission =
            RuntimeAdmissionPolicy::normalize(&config.resilience, transport.global_inflight_limit)?;

        Ok(Self {
            timeouts,
            admission,
            rate_limits,
            transport,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeListenerPolicySet {
    pub timeouts: RuntimeTimeoutPolicy,
    pub transport: RuntimeTransportPolicy,
    pub tls: RuntimeListenerTls,
}

impl RuntimeListenerPolicySet {
    pub fn from_listener_runtime_config(config: &ListenerRuntimeConfig) -> Self {
        Self {
            timeouts: config.policies.timeouts.clone(),
            transport: config.policies.transport.clone(),
            tls: config.listen.tls.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeUpstreamPolicySet {
    pub timeouts: RuntimeTimeoutPolicy,
    pub auth: RuntimeAuthPolicy,
    pub rate_limits: RuntimeRateLimitPolicy,
    pub load_balancing: RuntimeLoadBalancingPolicy,
    pub admission: RuntimeAdmissionPolicy,
    pub transport: RuntimeUpstreamTransportPolicy,
    pub host: RuntimeHostPolicy,
    pub forwarded_headers: RuntimeForwardedHeaderPolicy,
    pub protocol: RuntimeProtocolPolicy,
}
