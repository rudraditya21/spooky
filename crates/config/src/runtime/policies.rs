use std::time::Duration;

use super::*;

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
    !host.trim().is_empty()
        && port
            .parse::<u16>()
            .ok()
            .is_some_and(|parsed| parsed > 0)
}

fn is_valid_request_key_spec(key_spec: &str) -> bool {
    let key_spec = key_spec.trim().to_ascii_lowercase();
    matches!(
        key_spec.as_str(),
        "path" | "authority" | "method" | "cid" | "sticky-cid" | "peer_ip" | "client_ip" | "bearer_token"
    ) || key_spec.split_once(':').is_some_and(|(source, key_name)| {
        !key_name.trim().is_empty()
            && matches!(source.trim(), "header" | "cookie" | "query")
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeLoadBalancingStrategy {
    RoundRobin,
    ConsistentHash,
    Random,
    LeastConnections,
    LatencyAware,
    StickyCid,
    Other,
}

impl RuntimeLoadBalancingStrategy {
    pub fn from_lb_type(lb_type: &str) -> Self {
        match lb_type.trim().to_ascii_lowercase().as_str() {
            "round-robin" => Self::RoundRobin,
            "consistent-hash" => Self::ConsistentHash,
            "random" => Self::Random,
            "least-connections" => Self::LeastConnections,
            "latency-aware" => Self::LatencyAware,
            "sticky-cid" => Self::StickyCid,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimeApiKeyAuth {
    pub header_name: String,
    pub keys: Vec<String>,
}

impl RuntimeApiKeyAuth {
    pub fn normalize(
        api_key: &crate::config::ApiKeyAuth,
        upstream_name: &str,
    ) -> Result<Self, RuntimeConfigError> {
        let header_name = api_key.header_name.trim();
        if header_name.is_empty() {
            return Err(config_invalid(format!(
                "upstream '{upstream_name}' auth.api_key.header_name must be non-empty"
            )));
        }
        let keys = normalize_nonempty_string_vec(
            &format!("upstream '{upstream_name}' auth.api_key.keys"),
            &api_key.keys,
        )?;
        Ok(Self {
            header_name: header_name.to_string(),
            keys,
        })
    }

    pub fn as_config(&self) -> crate::config::ApiKeyAuth {
        crate::config::ApiKeyAuth {
            header_name: self.header_name.clone(),
            keys: self.keys.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimeJwtAuth {
    pub secret: String,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub clock_skew: Duration,
}

impl RuntimeJwtAuth {
    pub fn normalize(
        jwt: &crate::config::JwtAuth,
        upstream_name: &str,
    ) -> Result<Self, RuntimeConfigError> {
        let secret = jwt.secret.trim();
        if secret.is_empty() {
            return Err(config_invalid(format!(
                "upstream '{upstream_name}' auth.jwt.secret must be non-empty"
            )));
        }

        Ok(Self {
            secret: secret.to_string(),
            issuer: normalize_optional_string(jwt.issuer.as_deref()),
            audience: normalize_optional_string(jwt.audience.as_deref()),
            clock_skew: Duration::from_secs(jwt.clock_skew_secs),
        })
    }

    pub fn as_config(&self) -> crate::config::JwtAuth {
        crate::config::JwtAuth {
            secret: self.secret.clone(),
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
            clock_skew_secs: self.clock_skew.as_secs(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RuntimeExternalAuthFailureMode {
    FailOpen,
    #[default]
    FailClosed,
}

impl RuntimeExternalAuthFailureMode {
    pub fn from_config(mode: crate::config::ExternalAuthFailureMode) -> Self {
        match mode {
            crate::config::ExternalAuthFailureMode::FailOpen => Self::FailOpen,
            crate::config::ExternalAuthFailureMode::FailClosed => Self::FailClosed,
        }
    }

    pub fn as_config(self) -> crate::config::ExternalAuthFailureMode {
        match self {
            Self::FailOpen => crate::config::ExternalAuthFailureMode::FailOpen,
            Self::FailClosed => crate::config::ExternalAuthFailureMode::FailClosed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimeExternalAuthRequestHeader {
    pub name: String,
    pub value: String,
}

impl RuntimeExternalAuthRequestHeader {
    fn normalize(
        header: &crate::config::ExternalAuthRequestHeader,
        field_name: &str,
    ) -> Result<Self, RuntimeConfigError> {
        let name = header.name.trim();
        if name.is_empty() {
            return Err(config_invalid(format!("{field_name}.name must be non-empty")));
        }
        http::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            config_invalid(format!("{field_name}.name must be a valid HTTP header name"))
        })?;

        Ok(Self {
            name: name.to_string(),
            value: header.value.clone(),
        })
    }

    fn normalize_many(
        headers: &[crate::config::ExternalAuthRequestHeader],
        field_name: &str,
    ) -> Result<Vec<Self>, RuntimeConfigError> {
        headers
            .iter()
            .enumerate()
            .map(|(index, header)| Self::normalize(header, &format!("{field_name}[{index}]")))
            .collect()
    }

    fn as_config(&self) -> crate::config::ExternalAuthRequestHeader {
        crate::config::ExternalAuthRequestHeader {
            name: self.name.clone(),
            value: self.value.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeExternalAuth {
    Http {
        endpoint: String,
        request_headers: Vec<RuntimeExternalAuthRequestHeader>,
        response_header_allowlist: Vec<String>,
        timeout: Duration,
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
        timeout: Duration,
        failure_mode: RuntimeExternalAuthFailureMode,
    },
}

impl RuntimeExternalAuth {
    fn normalize(
        external_auth: &crate::config::ExternalAuth,
        upstream_name: &str,
    ) -> Result<Self, RuntimeConfigError> {
        match external_auth {
            crate::config::ExternalAuth::Http {
                endpoint,
                request_headers,
                response_header_allowlist,
                timeout_ms,
                failure_mode,
            } => {
                if *timeout_ms == 0 {
                    return Err(config_invalid(format!(
                        "upstream '{upstream_name}' auth.external_auth.http.timeout_ms must be greater than 0"
                    )));
                }
                Ok(Self::Http {
                    endpoint: endpoint.clone(),
                    request_headers: RuntimeExternalAuthRequestHeader::normalize_many(
                        request_headers,
                        &format!("upstream '{upstream_name}' auth.external_auth.http.request_headers"),
                    )?,
                    response_header_allowlist: normalize_nonempty_string_vec(
                        &format!(
                            "upstream '{upstream_name}' auth.external_auth.http.response_header_allowlist"
                        ),
                        response_header_allowlist,
                    )?,
                    timeout: Duration::from_millis(*timeout_ms),
                    failure_mode: RuntimeExternalAuthFailureMode::from_config(*failure_mode),
                })
            }
            crate::config::ExternalAuth::Oidc {
                discovery_url,
                issuer_url,
                client_id,
                client_secret,
                audience,
                scopes,
                request_headers,
                response_header_allowlist,
                timeout_ms,
                failure_mode,
            } => {
                if *timeout_ms == 0 {
                    return Err(config_invalid(format!(
                        "upstream '{upstream_name}' auth.external_auth.oidc.timeout_ms must be greater than 0"
                    )));
                }
                let client_id = client_id.trim();
                if client_id.is_empty() {
                    return Err(config_invalid(format!(
                        "upstream '{upstream_name}' auth.external_auth.oidc.client_id must be non-empty"
                    )));
                }
                Ok(Self::Oidc {
                    discovery_url: normalize_optional_string(discovery_url.as_deref()),
                    issuer_url: normalize_optional_string(issuer_url.as_deref()),
                    client_id: client_id.to_string(),
                    client_secret: normalize_optional_string(client_secret.as_deref()),
                    audience: normalize_optional_string(audience.as_deref()),
                    scopes: normalize_nonempty_string_vec(
                        &format!("upstream '{upstream_name}' auth.external_auth.oidc.scopes"),
                        scopes,
                    )?,
                    request_headers: RuntimeExternalAuthRequestHeader::normalize_many(
                        request_headers,
                        &format!("upstream '{upstream_name}' auth.external_auth.oidc.request_headers"),
                    )?,
                    response_header_allowlist: normalize_nonempty_string_vec(
                        &format!(
                            "upstream '{upstream_name}' auth.external_auth.oidc.response_header_allowlist"
                        ),
                        response_header_allowlist,
                    )?,
                    timeout: Duration::from_millis(*timeout_ms),
                    failure_mode: RuntimeExternalAuthFailureMode::from_config(*failure_mode),
                })
            }
        }
    }

    fn as_config(&self) -> crate::config::ExternalAuth {
        match self {
            Self::Http {
                endpoint,
                request_headers,
                response_header_allowlist,
                timeout,
                failure_mode,
            } => crate::config::ExternalAuth::Http {
                endpoint: endpoint.clone(),
                request_headers: request_headers.iter().map(Self::header_as_config).collect(),
                response_header_allowlist: response_header_allowlist.clone(),
                timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX),
                failure_mode: failure_mode.as_config(),
            },
            Self::Oidc {
                discovery_url,
                issuer_url,
                client_id,
                client_secret,
                audience,
                scopes,
                request_headers,
                response_header_allowlist,
                timeout,
                failure_mode,
            } => crate::config::ExternalAuth::Oidc {
                discovery_url: discovery_url.clone(),
                issuer_url: issuer_url.clone(),
                client_id: client_id.clone(),
                client_secret: client_secret.clone(),
                audience: audience.clone(),
                scopes: scopes.clone(),
                request_headers: request_headers.iter().map(Self::header_as_config).collect(),
                response_header_allowlist: response_header_allowlist.clone(),
                timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX),
                failure_mode: failure_mode.as_config(),
            },
        }
    }

    fn header_as_config(
        header: &RuntimeExternalAuthRequestHeader,
    ) -> crate::config::ExternalAuthRequestHeader {
        header.as_config()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimeAuthPolicy {
    pub api_key: Option<RuntimeApiKeyAuth>,
    pub jwt: Option<RuntimeJwtAuth>,
    pub external_auth: Option<RuntimeExternalAuth>,
    pub required_scopes: Vec<String>,
    pub required_roles: Vec<String>,
}

impl RuntimeAuthPolicy {
    pub fn normalize(
        auth: &crate::config::RouteAuth,
        upstream_name: &str,
    ) -> Result<Self, RuntimeConfigError> {
        Ok(Self {
            api_key: auth
                .api_key
                .as_ref()
                .map(|api_key| RuntimeApiKeyAuth::normalize(api_key, upstream_name))
                .transpose()?,
            jwt: auth
                .jwt
                .as_ref()
                .map(|jwt| RuntimeJwtAuth::normalize(jwt, upstream_name))
                .transpose()?,
            external_auth: auth
                .external_auth
                .as_ref()
                .map(|external_auth| RuntimeExternalAuth::normalize(external_auth, upstream_name))
                .transpose()?,
            required_scopes: normalize_nonempty_string_vec(
                &format!("upstream '{upstream_name}' auth.required_scopes"),
                &auth.required_scopes,
            )?,
            required_roles: normalize_nonempty_string_vec(
                &format!("upstream '{upstream_name}' auth.required_roles"),
                &auth.required_roles,
            )?,
        })
    }

    pub fn as_config(&self) -> crate::config::RouteAuth {
        crate::config::RouteAuth {
            api_key: self.api_key.as_ref().map(RuntimeApiKeyAuth::as_config),
            jwt: self.jwt.as_ref().map(RuntimeJwtAuth::as_config),
            external_auth: self.external_auth.as_ref().map(RuntimeExternalAuth::as_config),
            required_scopes: self.required_scopes.clone(),
            required_roles: self.required_roles.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTimeoutPolicy {
    pub inflight_acquire_wait: Duration,
    pub backend_request: Duration,
    pub backend_connect: Duration,
    pub backend_body_idle: Duration,
    pub backend_body_total: Duration,
    pub backend_total_request: Duration,
    pub shutdown_drain: Duration,
    pub client_body_idle: Duration,
    pub h2_pool_idle: Duration,
    pub backend_dns_refresh_interval: Duration,
    pub quic_max_idle: Duration,
}

impl RuntimeTimeoutPolicy {
    pub fn normalize(performance: &Performance) -> Result<Self, RuntimeConfigError> {
        require_nonzero_u64("performance.backend_timeout_ms", performance.backend_timeout_ms)?;
        require_nonzero_u64(
            "performance.backend_connect_timeout_ms",
            performance.backend_connect_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.backend_body_idle_timeout_ms",
            performance.backend_body_idle_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.backend_body_total_timeout_ms",
            performance.backend_body_total_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.backend_total_request_timeout_ms",
            performance.backend_total_request_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.shutdown_drain_timeout_ms",
            performance.shutdown_drain_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.client_body_idle_timeout_ms",
            performance.client_body_idle_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.h2_pool_idle_timeout_ms",
            performance.h2_pool_idle_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.backend_dns_refresh_interval_ms",
            performance.backend_dns_refresh_interval_ms,
        )?;
        require_nonzero_u64(
            "performance.quic_max_idle_timeout_ms",
            performance.quic_max_idle_timeout_ms,
        )?;

        if performance.backend_connect_timeout_ms > performance.backend_timeout_ms {
            return Err(config_invalid(
                "performance.backend_connect_timeout_ms must be <= backend_timeout_ms",
            ));
        }
        if performance.backend_timeout_ms > performance.backend_body_idle_timeout_ms {
            return Err(config_invalid(
                "performance.backend_timeout_ms must be <= backend_body_idle_timeout_ms",
            ));
        }
        if performance.backend_body_idle_timeout_ms > performance.backend_body_total_timeout_ms {
            return Err(config_invalid(
                "performance.backend_body_idle_timeout_ms must be <= backend_body_total_timeout_ms",
            ));
        }
        if performance.backend_body_total_timeout_ms
            > performance.backend_total_request_timeout_ms
        {
            return Err(config_invalid(
                "performance.backend_body_total_timeout_ms must be <= backend_total_request_timeout_ms",
            ));
        }

        Ok(Self {
            inflight_acquire_wait: Duration::from_millis(performance.inflight_acquire_wait_ms),
            backend_request: Duration::from_millis(performance.backend_timeout_ms),
            backend_connect: Duration::from_millis(performance.backend_connect_timeout_ms),
            backend_body_idle: Duration::from_millis(performance.backend_body_idle_timeout_ms),
            backend_body_total: Duration::from_millis(performance.backend_body_total_timeout_ms),
            backend_total_request: Duration::from_millis(
                performance.backend_total_request_timeout_ms,
            ),
            shutdown_drain: Duration::from_millis(performance.shutdown_drain_timeout_ms),
            client_body_idle: Duration::from_millis(performance.client_body_idle_timeout_ms),
            h2_pool_idle: Duration::from_millis(performance.h2_pool_idle_timeout_ms),
            backend_dns_refresh_interval: Duration::from_millis(
                performance.backend_dns_refresh_interval_ms,
            ),
            quic_max_idle: Duration::from_millis(performance.quic_max_idle_timeout_ms),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTransportPolicy {
    pub worker_threads: usize,
    pub control_plane_threads: usize,
    pub packet_shards_per_worker: usize,
    pub packet_shard_queue_capacity: usize,
    pub packet_shard_queue_max_bytes: usize,
    pub reuseport: bool,
    pub pin_workers: bool,
    pub global_inflight_limit: usize,
    pub per_upstream_inflight_limit: usize,
    pub per_backend_inflight_limit: usize,
    pub udp_recv_buffer_bytes: usize,
    pub udp_send_buffer_bytes: usize,
    pub h2_pool_max_idle_per_backend: usize,
    pub backend_dns_refresh_enabled: bool,
    pub new_connections_per_sec: u32,
    pub new_connections_burst: u32,
    pub max_active_connections: usize,
    pub quic_initial_max_data: u64,
    pub quic_initial_max_stream_data: u64,
    pub quic_initial_max_streams_bidi: u64,
    pub quic_initial_max_streams_uni: u64,
    pub max_response_body_bytes: usize,
    pub max_request_body_bytes: usize,
    pub request_buffer_global_cap_bytes: usize,
    pub unknown_length_response_prebuffer_bytes: usize,
}

impl RuntimeTransportPolicy {
    pub fn normalize(performance: &Performance) -> Result<Self, RuntimeConfigError> {
        require_nonzero_usize("performance.worker_threads", performance.worker_threads)?;
        if performance.worker_threads > 1024 {
            return Err(config_invalid(format!(
                "performance.worker_threads={} exceeds the maximum of 1024",
                performance.worker_threads
            )));
        }
        require_nonzero_usize(
            "performance.control_plane_threads",
            performance.control_plane_threads,
        )?;
        if performance.control_plane_threads > 1024 {
            return Err(config_invalid(format!(
                "performance.control_plane_threads={} exceeds the maximum of 1024",
                performance.control_plane_threads
            )));
        }
        require_nonzero_usize(
            "performance.packet_shards_per_worker",
            performance.packet_shards_per_worker,
        )?;
        if performance.packet_shards_per_worker > 256 {
            return Err(config_invalid(format!(
                "performance.packet_shards_per_worker={} exceeds the maximum of 256",
                performance.packet_shards_per_worker
            )));
        }
        require_nonzero_usize(
            "performance.packet_shard_queue_capacity",
            performance.packet_shard_queue_capacity,
        )?;
        require_nonzero_usize(
            "performance.packet_shard_queue_max_bytes",
            performance.packet_shard_queue_max_bytes,
        )?;
        if performance.worker_threads > 1 && !performance.reuseport {
            return Err(config_invalid(
                "performance.reuseport must be true when performance.worker_threads > 1",
            ));
        }
        require_nonzero_usize(
            "performance.global_inflight_limit",
            performance.global_inflight_limit,
        )?;
        require_nonzero_usize(
            "performance.per_upstream_inflight_limit",
            performance.per_upstream_inflight_limit,
        )?;
        require_nonzero_usize(
            "performance.per_backend_inflight_limit",
            performance.per_backend_inflight_limit,
        )?;
        require_nonzero_usize(
            "performance.udp_recv_buffer_bytes",
            performance.udp_recv_buffer_bytes,
        )?;
        require_nonzero_usize(
            "performance.udp_send_buffer_bytes",
            performance.udp_send_buffer_bytes,
        )?;
        require_nonzero_usize(
            "performance.h2_pool_max_idle_per_backend",
            performance.h2_pool_max_idle_per_backend,
        )?;
        require_nonzero_u32(
            "performance.new_connections_per_sec",
            performance.new_connections_per_sec,
        )?;
        require_nonzero_u32(
            "performance.new_connections_burst",
            performance.new_connections_burst,
        )?;
        require_nonzero_usize(
            "performance.max_active_connections",
            performance.max_active_connections,
        )?;
        require_nonzero_u64(
            "performance.quic_initial_max_data",
            performance.quic_initial_max_data,
        )?;
        require_nonzero_u64(
            "performance.quic_initial_max_stream_data",
            performance.quic_initial_max_stream_data,
        )?;
        if performance.quic_initial_max_stream_data > performance.quic_initial_max_data {
            return Err(config_invalid(format!(
                "performance.quic_initial_max_stream_data ({}) must be <= quic_initial_max_data ({})",
                performance.quic_initial_max_stream_data,
                performance.quic_initial_max_data
            )));
        }
        require_nonzero_u64(
            "performance.quic_initial_max_streams_bidi",
            performance.quic_initial_max_streams_bidi,
        )?;
        require_nonzero_u64(
            "performance.quic_initial_max_streams_uni",
            performance.quic_initial_max_streams_uni,
        )?;
        require_nonzero_usize(
            "performance.max_response_body_bytes",
            performance.max_response_body_bytes,
        )?;
        require_nonzero_usize(
            "performance.max_request_body_bytes",
            performance.max_request_body_bytes,
        )?;
        require_nonzero_usize(
            "performance.request_buffer_global_cap_bytes",
            performance.request_buffer_global_cap_bytes,
        )?;
        require_nonzero_usize(
            "performance.unknown_length_response_prebuffer_bytes",
            performance.unknown_length_response_prebuffer_bytes,
        )?;
        if performance.max_request_body_bytes > performance.quic_initial_max_stream_data as usize {
            return Err(config_invalid(format!(
                "performance.max_request_body_bytes ({}) must be <= quic_initial_max_stream_data ({})",
                performance.max_request_body_bytes,
                performance.quic_initial_max_stream_data
            )));
        }
        if performance.request_buffer_global_cap_bytes < performance.max_request_body_bytes {
            return Err(config_invalid(format!(
                "performance.request_buffer_global_cap_bytes ({}) must be >= max_request_body_bytes ({})",
                performance.request_buffer_global_cap_bytes,
                performance.max_request_body_bytes
            )));
        }
        if performance.unknown_length_response_prebuffer_bytes
            > performance.max_response_body_bytes
        {
            return Err(config_invalid(format!(
                "performance.unknown_length_response_prebuffer_bytes ({}) must be <= max_response_body_bytes ({})",
                performance.unknown_length_response_prebuffer_bytes,
                performance.max_response_body_bytes
            )));
        }

        Ok(Self {
            worker_threads: performance.worker_threads,
            control_plane_threads: performance.control_plane_threads,
            packet_shards_per_worker: performance.packet_shards_per_worker,
            packet_shard_queue_capacity: performance.packet_shard_queue_capacity,
            packet_shard_queue_max_bytes: performance.packet_shard_queue_max_bytes,
            reuseport: performance.reuseport,
            pin_workers: performance.pin_workers,
            global_inflight_limit: performance.global_inflight_limit,
            per_upstream_inflight_limit: performance.per_upstream_inflight_limit,
            per_backend_inflight_limit: performance.per_backend_inflight_limit,
            udp_recv_buffer_bytes: performance.udp_recv_buffer_bytes,
            udp_send_buffer_bytes: performance.udp_send_buffer_bytes,
            h2_pool_max_idle_per_backend: performance.h2_pool_max_idle_per_backend,
            backend_dns_refresh_enabled: performance.backend_dns_refresh_enabled,
            new_connections_per_sec: performance.new_connections_per_sec,
            new_connections_burst: performance.new_connections_burst,
            max_active_connections: performance.max_active_connections,
            quic_initial_max_data: performance.quic_initial_max_data,
            quic_initial_max_stream_data: performance.quic_initial_max_stream_data,
            quic_initial_max_streams_bidi: performance.quic_initial_max_streams_bidi,
            quic_initial_max_streams_uni: performance.quic_initial_max_streams_uni,
            max_response_body_bytes: performance.max_response_body_bytes,
            max_request_body_bytes: performance.max_request_body_bytes,
            request_buffer_global_cap_bytes: performance.request_buffer_global_cap_bytes,
            unknown_length_response_prebuffer_bytes:
                performance.unknown_length_response_prebuffer_bytes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLoadBalancingPolicy {
    pub strategy: RuntimeLoadBalancingStrategy,
    pub key: Option<String>,
}

impl RuntimeLoadBalancingPolicy {
    pub fn normalize(load_balancing: &LoadBalancing) -> Result<Self, RuntimeConfigError> {
        let strategy = RuntimeLoadBalancingStrategy::from_lb_type(&load_balancing.lb_type);
        if matches!(strategy, RuntimeLoadBalancingStrategy::Other) {
            return Err(config_invalid(format!(
                "unsupported load balancing type '{}'",
                load_balancing.lb_type
            )));
        }

        Ok(Self {
            strategy,
            key: normalize_optional_string(load_balancing.key.as_deref()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeScopedRateLimitPolicy {
    pub name: String,
    pub scope: crate::config::ScopedRateLimitScope,
    pub requests_per_sec: u32,
    pub burst: u32,
    pub key: Option<String>,
    pub route_allowlist: Vec<String>,
    pub idle_ttl: Duration,
}

impl RuntimeScopedRateLimitPolicy {
    pub fn normalize(rule: &crate::config::ScopedRateLimit) -> Result<Self, RuntimeConfigError> {
        let rule_name = rule.name.trim();
        if rule_name.is_empty() {
            return Err(config_invalid(
                "resilience.scoped_rate_limits[].name must be non-empty",
            ));
        }
        if rule.requests_per_sec == 0 {
            return Err(config_invalid(format!(
                "resilience.scoped_rate_limits['{}'].requests_per_sec must be greater than 0",
                rule_name
            )));
        }
        if rule.burst == 0 {
            return Err(config_invalid(format!(
                "resilience.scoped_rate_limits['{}'].burst must be greater than 0",
                rule_name
            )));
        }
        if rule.idle_ttl_secs == 0 {
            return Err(config_invalid(format!(
                "resilience.scoped_rate_limits['{}'].idle_ttl_secs must be greater than 0",
                rule_name
            )));
        }
        let route_allowlist = normalize_string_vec(&rule.route_allowlist);
        if route_allowlist.len() != rule.route_allowlist.len() {
            return Err(config_invalid(format!(
                "resilience.scoped_rate_limits['{}'].route_allowlist must not contain empty values",
                rule_name
            )));
        }

        let key = normalize_optional_string(rule.key.as_deref());
        match rule.scope {
            crate::config::ScopedRateLimitScope::Route => {
                if key.is_some() {
                    return Err(config_invalid(format!(
                        "resilience.scoped_rate_limits['{}'].key is invalid for scope=route",
                        rule_name
                    )));
                }
            }
            crate::config::ScopedRateLimitScope::Tenant => {
                let Some(key_spec) = key.as_deref() else {
                    return Err(config_invalid(format!(
                        "resilience.scoped_rate_limits['{}'].key is required for scope=tenant",
                        rule_name
                    )));
                };
                if !is_valid_request_key_spec(key_spec) {
                    return Err(config_invalid(format!(
                        "resilience.scoped_rate_limits['{}'].key must be a supported request key spec",
                        rule_name
                    )));
                }
            }
            crate::config::ScopedRateLimitScope::Client
            | crate::config::ScopedRateLimitScope::Token => {
                if let Some(key_spec) = key.as_deref() && !is_valid_request_key_spec(key_spec) {
                    return Err(config_invalid(format!(
                        "resilience.scoped_rate_limits['{}'].key must be a supported request key spec",
                        rule_name
                    )));
                }
            }
        }

        Ok(Self {
            name: rule.name.clone(),
            scope: rule.scope,
            requests_per_sec: rule.requests_per_sec,
            burst: rule.burst,
            key,
            route_allowlist,
            idle_ttl: Duration::from_secs(rule.idle_ttl_secs),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAdaptiveAdmissionPolicy {
    pub enabled: bool,
    pub min_limit: usize,
    pub max_limit: usize,
    pub decrease_step: usize,
    pub increase_step: usize,
    pub high_latency: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRouteQueuePolicy {
    pub default_cap: usize,
    pub global_cap: usize,
    pub shed_retry_after_seconds: u32,
    pub caps: HashMap<String, usize>,
}

impl RuntimeRouteQueuePolicy {
    pub fn clamped(&self, default_cap_limit: usize, global_cap_limit: usize) -> Self {
        let mut clamped = self.clone();
        clamped.default_cap = clamped.default_cap.min(default_cap_limit).max(1);
        clamped.global_cap = clamped.global_cap.min(global_cap_limit).max(1);
        for cap in clamped.caps.values_mut() {
            *cap = (*cap).min(default_cap_limit).max(1);
        }
        clamped
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCircuitBreakerPolicy {
    pub enabled: bool,
    pub failure_threshold: u32,
    pub open: Duration,
    pub half_open_max_probes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeHedgingPolicy {
    pub enabled: bool,
    pub delay: Duration,
    pub safe_methods: Vec<String>,
    pub route_allowlist: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRetryBudgetPolicy {
    pub enabled: bool,
    pub ratio_percent: u8,
    pub per_route_ratio_percent: HashMap<String, u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBrownoutPolicy {
    pub enabled: bool,
    pub trigger_inflight_percent: u8,
    pub recover_inflight_percent: u8,
    pub core_routes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeWatchdogPolicy {
    pub enabled: bool,
    pub check_interval: Duration,
    pub poll_stall_timeout: Duration,
    pub timeout_error_rate_percent: u8,
    pub min_requests_per_window: u64,
    pub overload_inflight_percent: u8,
    pub unhealthy_consecutive_windows: u32,
    pub drain_grace: Duration,
    pub restart_cooldown: Duration,
    pub restart_command: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeRateLimitPolicy {
    pub scoped_limits: Vec<RuntimeScopedRateLimitPolicy>,
}

impl RuntimeRateLimitPolicy {
    pub fn normalize(resilience: &Resilience) -> Result<Self, RuntimeConfigError> {
        let mut seen_names = std::collections::HashSet::new();
        let mut scoped_limits = Vec::with_capacity(resilience.scoped_rate_limits.len());
        for rule in &resilience.scoped_rate_limits {
            let normalized = RuntimeScopedRateLimitPolicy::normalize(rule)?;
            if !seen_names.insert(normalized.name.clone()) {
                return Err(config_invalid(format!(
                    "resilience.scoped_rate_limits contains duplicate rule name '{}'",
                    normalized.name
                )));
            }
            scoped_limits.push(normalized);
        }

        Ok(Self { scoped_limits })
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeAdmissionPolicy {
    pub adaptive_admission: RuntimeAdaptiveAdmissionPolicy,
    pub route_queue: RuntimeRouteQueuePolicy,
    pub circuit_breaker: RuntimeCircuitBreakerPolicy,
    pub hedging: RuntimeHedgingPolicy,
    pub retry_budget: RuntimeRetryBudgetPolicy,
    pub brownout: RuntimeBrownoutPolicy,
    pub watchdog: RuntimeWatchdogPolicy,
    pub protocol: RuntimeProtocolPolicy,
}

impl RuntimeAdmissionPolicy {
    pub fn normalize(
        resilience: &Resilience,
        global_inflight_limit: usize,
    ) -> Result<Self, RuntimeConfigError> {
        if resilience.adaptive_admission.min_limit == 0 {
            return Err(config_invalid(
                "resilience.adaptive_admission.min_limit must be greater than 0",
            ));
        }
        if let Some(max_limit) = resilience.adaptive_admission.max_limit {
            if max_limit == 0 {
                return Err(config_invalid(
                    "resilience.adaptive_admission.max_limit must be greater than 0",
                ));
            }
            if max_limit < resilience.adaptive_admission.min_limit {
                return Err(config_invalid(format!(
                    "resilience.adaptive_admission.max_limit ({}) must be >= min_limit ({})",
                    max_limit, resilience.adaptive_admission.min_limit
                )));
            }
            if max_limit > global_inflight_limit {
                return Err(config_invalid(format!(
                    "resilience.adaptive_admission.max_limit ({}) must be <= performance.global_inflight_limit ({})",
                    max_limit, global_inflight_limit
                )));
            }
        }
        require_nonzero_usize(
            "resilience.adaptive_admission.decrease_step",
            resilience.adaptive_admission.decrease_step,
        )?;
        require_nonzero_usize(
            "resilience.adaptive_admission.increase_step",
            resilience.adaptive_admission.increase_step,
        )?;

        require_nonzero_usize(
            "resilience.route_queue.default_cap",
            resilience.route_queue.default_cap,
        )?;
        require_nonzero_usize(
            "resilience.route_queue.global_cap",
            resilience.route_queue.global_cap,
        )?;
        if resilience.route_queue.shed_retry_after_seconds == 0 {
            return Err(config_invalid(
                "resilience.route_queue.shed_retry_after_seconds must be greater than 0",
            ));
        }
        if resilience.route_queue.caps.values().any(|cap| *cap == 0) {
            return Err(config_invalid(
                "resilience.route_queue.caps values must be greater than 0",
            ));
        }

        let early_data_safe_methods = normalize_nonempty_string_vec(
            "resilience.protocol.early_data_safe_methods",
            &resilience.protocol.early_data_safe_methods,
        )?;
        let allowed_methods = normalize_nonempty_string_vec(
            "resilience.protocol.allowed_methods",
            &resilience.protocol.allowed_methods,
        )?;
        if allowed_methods.iter().any(|method| !is_valid_http_token(method)) {
            return Err(config_invalid(
                "resilience.protocol.allowed_methods must contain valid HTTP method tokens",
            ));
        }
        let denied_path_prefixes = normalize_nonempty_string_vec(
            "resilience.protocol.denied_path_prefixes",
            &resilience.protocol.denied_path_prefixes,
        )?;
        if denied_path_prefixes.iter().any(|prefix| !prefix.starts_with('/')) {
            return Err(config_invalid(
                "resilience.protocol.denied_path_prefixes must contain '/'-prefixed paths",
            ));
        }
        require_nonzero_usize(
            "resilience.protocol.max_headers_count",
            resilience.protocol.max_headers_count,
        )?;
        require_nonzero_usize(
            "resilience.protocol.max_headers_bytes",
            resilience.protocol.max_headers_bytes,
        )?;
        if !resilience.protocol.allow_connect
            && (!resilience.protocol.connect_allowed_ports.is_empty()
                || !resilience.protocol.connect_allowed_authorities.is_empty())
        {
            return Err(config_invalid(
                "resilience.protocol.connect_allowed_ports/connect_allowed_authorities require allow_connect=true",
            ));
        }
        if resilience.protocol.connect_allowed_ports.contains(&0) {
            return Err(config_invalid(
                "resilience.protocol.connect_allowed_ports must contain ports in range 1-65535",
            ));
        }
        if resilience
            .protocol
            .connect_allowed_authorities
            .iter()
            .any(|authority| !is_valid_connect_authority(authority))
        {
            return Err(config_invalid(
                "resilience.protocol.connect_allowed_authorities must contain authority-form host:port targets",
            ));
        }
        if resilience.protocol.allow_0rtt && early_data_safe_methods.is_empty() {
            return Err(config_invalid(
                "resilience.protocol.early_data_safe_methods must be non-empty when allow_0rtt=true",
            ));
        }

        if resilience.circuit_breaker.failure_threshold == 0 {
            return Err(config_invalid(
                "resilience.circuit_breaker.failure_threshold must be greater than 0",
            ));
        }
        if resilience.circuit_breaker.open_ms == 0 {
            return Err(config_invalid(
                "resilience.circuit_breaker.open_ms must be greater than 0",
            ));
        }
        if resilience.circuit_breaker.half_open_max_probes == 0 {
            return Err(config_invalid(
                "resilience.circuit_breaker.half_open_max_probes must be greater than 0",
            ));
        }

        if resilience.hedging.enabled && resilience.hedging.delay_ms == 0 {
            return Err(config_invalid(
                "resilience.hedging: delay_ms must be > 0 when hedging is enabled",
            ));
        }

        if resilience.retry_budget.ratio_percent > 100 {
            return Err(config_invalid(
                "resilience.retry_budget.ratio_percent must be <= 100",
            ));
        }
        if resilience
            .retry_budget
            .per_route_ratio_percent
            .values()
            .any(|ratio| *ratio > 100)
        {
            return Err(config_invalid(
                "resilience.retry_budget.per_route_ratio_percent values must be <= 100",
            ));
        }

        if resilience.brownout.trigger_inflight_percent > 100
            || resilience.brownout.recover_inflight_percent > 100
        {
            return Err(config_invalid(
                "resilience.brownout inflight percentages must be <= 100",
            ));
        }
        if resilience.brownout.recover_inflight_percent
            >= resilience.brownout.trigger_inflight_percent
        {
            return Err(config_invalid(
                "resilience.brownout.recover_inflight_percent must be < trigger_inflight_percent",
            ));
        }

        require_nonzero_u64(
            "resilience.watchdog.check_interval_ms",
            resilience.watchdog.check_interval_ms,
        )?;
        require_nonzero_u64(
            "resilience.watchdog.poll_stall_timeout_ms",
            resilience.watchdog.poll_stall_timeout_ms,
        )?;
        if resilience.watchdog.timeout_error_rate_percent > 100 {
            return Err(config_invalid(
                "resilience.watchdog.timeout_error_rate_percent must be <= 100",
            ));
        }
        require_nonzero_u64(
            "resilience.watchdog.min_requests_per_window",
            resilience.watchdog.min_requests_per_window,
        )?;
        if resilience.watchdog.overload_inflight_percent > 100 {
            return Err(config_invalid(
                "resilience.watchdog.overload_inflight_percent must be <= 100",
            ));
        }
        if resilience.watchdog.unhealthy_consecutive_windows == 0 {
            return Err(config_invalid(
                "resilience.watchdog.unhealthy_consecutive_windows must be greater than 0",
            ));
        }
        require_nonzero_u64(
            "resilience.watchdog.drain_grace_ms",
            resilience.watchdog.drain_grace_ms,
        )?;
        require_nonzero_u64(
            "resilience.watchdog.restart_cooldown_ms",
            resilience.watchdog.restart_cooldown_ms,
        )?;
        if !resilience.watchdog.restart_command.is_empty()
            && resilience.watchdog.restart_command[0].trim().is_empty()
        {
            return Err(config_invalid(
                "resilience.watchdog.restart_command[0] must be a non-empty executable path",
            ));
        }
        if resilience.watchdog.restart_hook.is_some() {
            return Err(unsupported_policy(
                "resilience.watchdog.restart_hook is deprecated and unsupported; use restart_command instead",
            ));
        }

        let mut protocol = resilience.protocol.clone();
        protocol.early_data_safe_methods = early_data_safe_methods;
        protocol.allowed_methods = allowed_methods;
        protocol.denied_path_prefixes = denied_path_prefixes;

        Ok(Self {
            adaptive_admission: RuntimeAdaptiveAdmissionPolicy {
                enabled: resilience.adaptive_admission.enabled,
                min_limit: resilience.adaptive_admission.min_limit,
                max_limit: resilience
                    .adaptive_admission
                    .max_limit
                    .unwrap_or(global_inflight_limit)
                    .max(resilience.adaptive_admission.min_limit),
                decrease_step: resilience.adaptive_admission.decrease_step,
                increase_step: resilience.adaptive_admission.increase_step,
                high_latency: Duration::from_millis(resilience.adaptive_admission.high_latency_ms),
            },
            route_queue: RuntimeRouteQueuePolicy {
                default_cap: resilience.route_queue.default_cap,
                global_cap: resilience.route_queue.global_cap,
                shed_retry_after_seconds: resilience.route_queue.shed_retry_after_seconds.max(1),
                caps: resilience.route_queue.caps.clone(),
            },
            circuit_breaker: RuntimeCircuitBreakerPolicy {
                enabled: resilience.circuit_breaker.enabled,
                failure_threshold: resilience.circuit_breaker.failure_threshold,
                open: Duration::from_millis(resilience.circuit_breaker.open_ms.max(1)),
                half_open_max_probes: resilience.circuit_breaker.half_open_max_probes,
            },
            hedging: RuntimeHedgingPolicy {
                enabled: resilience.hedging.enabled,
                delay: Duration::from_millis(resilience.hedging.delay_ms),
                safe_methods: normalize_string_vec(&resilience.hedging.safe_methods),
                route_allowlist: normalize_string_vec(&resilience.hedging.route_allowlist),
            },
            retry_budget: RuntimeRetryBudgetPolicy {
                enabled: resilience.retry_budget.enabled,
                ratio_percent: resilience.retry_budget.ratio_percent,
                per_route_ratio_percent: resilience.retry_budget.per_route_ratio_percent.clone(),
            },
            brownout: RuntimeBrownoutPolicy {
                enabled: resilience.brownout.enabled,
                trigger_inflight_percent: resilience.brownout.trigger_inflight_percent,
                recover_inflight_percent: resilience.brownout.recover_inflight_percent,
                core_routes: normalize_string_vec(&resilience.brownout.core_routes),
            },
            watchdog: RuntimeWatchdogPolicy {
                enabled: resilience.watchdog.enabled,
                check_interval: Duration::from_millis(resilience.watchdog.check_interval_ms),
                poll_stall_timeout: Duration::from_millis(
                    resilience.watchdog.poll_stall_timeout_ms,
                ),
                timeout_error_rate_percent: resilience.watchdog.timeout_error_rate_percent,
                min_requests_per_window: resilience.watchdog.min_requests_per_window,
                overload_inflight_percent: resilience.watchdog.overload_inflight_percent,
                unhealthy_consecutive_windows: resilience
                    .watchdog
                    .unhealthy_consecutive_windows,
                drain_grace: Duration::from_millis(resilience.watchdog.drain_grace_ms),
                restart_cooldown: Duration::from_millis(
                    resilience.watchdog.restart_cooldown_ms,
                ),
                restart_command: resilience.watchdog.restart_command.clone(),
            },
            protocol: RuntimeProtocolPolicy(protocol),
        })
    }

    pub fn with_runtime_overrides(
        &self,
        default_route_cap_limit: usize,
        global_route_cap_limit: usize,
        adaptive_high_latency_limit: Duration,
    ) -> Self {
        let mut updated = self.clone();
        updated.route_queue = updated
            .route_queue
            .clamped(default_route_cap_limit, global_route_cap_limit);
        if updated.adaptive_admission.high_latency > adaptive_high_latency_limit {
            updated.adaptive_admission.high_latency = adaptive_high_latency_limit;
        }
        updated
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeUpstreamTransportPolicy {
    pub effective_tls: UpstreamTls,
}

impl RuntimeUpstreamTransportPolicy {
    pub fn from_effective_tls(effective_tls: &UpstreamTls) -> Self {
        Self {
            effective_tls: effective_tls.clone(),
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
    pub fn from_config(config: &Config) -> Result<Self, RuntimeConfigError> {
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

impl RuntimeUpstreamPolicySet {
    pub fn normalize(
        upstream: &RuntimeUpstream,
        base: &RuntimePolicySet,
    ) -> Result<Self, RuntimeConfigError> {
        Ok(Self {
            timeouts: base.timeouts.clone(),
            auth: upstream.policy.upstream_auth.clone(),
            rate_limits: base.rate_limits.clone(),
            load_balancing: RuntimeLoadBalancingPolicy::normalize(&upstream.load_balancing)?,
            admission: base.admission.clone(),
            transport: RuntimeUpstreamTransportPolicy::from_effective_tls(&upstream.effective_tls),
            host: upstream.policy.host.clone(),
            forwarded_headers: upstream.policy.forwarded_headers.clone(),
            protocol: upstream.policy.protocol.clone(),
        })
    }
}
