use std::time::Duration;

use super::*;

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
    pub fn from_performance(performance: &Performance) -> Self {
        Self {
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
        }
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
    pub fn from_performance(performance: &Performance) -> Self {
        Self {
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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLoadBalancingPolicy {
    pub strategy: RuntimeLoadBalancingStrategy,
    pub key: Option<String>,
}

impl RuntimeLoadBalancingPolicy {
    pub fn from_config(load_balancing: &LoadBalancing) -> Self {
        Self {
            strategy: RuntimeLoadBalancingStrategy::from_lb_type(&load_balancing.lb_type),
            key: load_balancing.key.clone(),
        }
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
    pub fn from_config(rule: &crate::config::ScopedRateLimit) -> Self {
        Self {
            name: rule.name.clone(),
            scope: rule.scope,
            requests_per_sec: rule.requests_per_sec,
            burst: rule.burst,
            key: rule.key.clone(),
            route_allowlist: rule.route_allowlist.clone(),
            idle_ttl: Duration::from_secs(rule.idle_ttl_secs),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeRateLimitPolicy {
    pub scoped_limits: Vec<RuntimeScopedRateLimitPolicy>,
}

impl RuntimeRateLimitPolicy {
    pub fn from_resilience(resilience: &Resilience) -> Self {
        Self {
            scoped_limits: resilience
                .scoped_rate_limits
                .iter()
                .map(RuntimeScopedRateLimitPolicy::from_config)
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeAdmissionPolicy {
    pub adaptive_admission: crate::config::AdaptiveAdmission,
    pub route_queue: crate::config::RouteQueue,
    pub circuit_breaker: crate::config::CircuitBreaker,
    pub hedging: crate::config::Hedging,
    pub retry_budget: crate::config::RetryBudget,
    pub brownout: crate::config::Brownout,
    pub watchdog: crate::config::Watchdog,
    pub protocol: RuntimeProtocolPolicy,
}

impl RuntimeAdmissionPolicy {
    pub fn from_resilience(resilience: &Resilience) -> Self {
        Self {
            adaptive_admission: resilience.adaptive_admission.clone(),
            route_queue: resilience.route_queue.clone(),
            circuit_breaker: resilience.circuit_breaker.clone(),
            hedging: resilience.hedging.clone(),
            retry_budget: resilience.retry_budget.clone(),
            brownout: resilience.brownout.clone(),
            watchdog: resilience.watchdog.clone(),
            protocol: RuntimeProtocolPolicy(resilience.protocol.clone()),
        }
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
    pub fn from_runtime_config(config: &RuntimeConfig) -> Self {
        Self {
            timeouts: RuntimeTimeoutPolicy::from_performance(&config.performance),
            admission: RuntimeAdmissionPolicy::from_resilience(&config.resilience),
            rate_limits: RuntimeRateLimitPolicy::from_resilience(&config.resilience),
            transport: RuntimeTransportPolicy::from_performance(&config.performance),
        }
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
            timeouts: RuntimeTimeoutPolicy::from_performance(&config.performance),
            transport: RuntimeTransportPolicy::from_performance(&config.performance),
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
    pub fn from_runtime_parts(
        upstream: &RuntimeUpstream,
        performance: &Performance,
        resilience: &Resilience,
    ) -> Self {
        Self {
            timeouts: RuntimeTimeoutPolicy::from_performance(performance),
            auth: upstream.policy.upstream_auth.clone(),
            rate_limits: RuntimeRateLimitPolicy::from_resilience(resilience),
            load_balancing: RuntimeLoadBalancingPolicy::from_config(&upstream.load_balancing),
            admission: RuntimeAdmissionPolicy::from_resilience(resilience),
            transport: RuntimeUpstreamTransportPolicy::from_effective_tls(&upstream.effective_tls),
            host: upstream.policy.host.clone(),
            forwarded_headers: upstream.policy.forwarded_headers.clone(),
            protocol: upstream.policy.protocol.clone(),
        }
    }
}
