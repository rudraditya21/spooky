use std::{
    cell::Cell,
    collections::HashMap,
    env,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

pub use spooky_lb::HealthFailureReason;

pub struct Metrics {
    pub requests_total: AtomicU64,
    pub requests_success: AtomicU64,
    pub requests_failure: AtomicU64,
    pub request_validation_rejects: AtomicU64,
    pub policy_denied: AtomicU64,
    pub early_data_accepted: AtomicU64,
    pub early_data_rejected: AtomicU64,
    pub health_checks_total: AtomicU64,
    pub health_checks_success: AtomicU64,
    pub health_checks_failure: AtomicU64,
    pub backend_timeouts: AtomicU64,
    pub backend_errors: AtomicU64,
    pub overload_shed: AtomicU64,
    pub overload_shed_brownout: AtomicU64,
    pub overload_shed_adaptive: AtomicU64,
    pub overload_shed_route_cap: AtomicU64,
    pub overload_shed_route_global_cap: AtomicU64,
    pub overload_shed_global_inflight: AtomicU64,
    pub overload_shed_upstream_inflight: AtomicU64,
    pub overload_shed_backend_inflight: AtomicU64,
    pub overload_shed_request_buffer: AtomicU64,
    pub overload_shed_response_prebuffer: AtomicU64,
    pub overload_shed_connection_cap: AtomicU64,
    pub active_connections: AtomicU64,
    pub connection_cap_rejects: AtomicU64,
    pub hedge_triggered: AtomicU64,
    pub hedge_won: AtomicU64,
    pub hedge_wasted: AtomicU64,
    pub hedge_primary_won_after_trigger: AtomicU64,
    pub hedge_primary_late_ms_total: AtomicU64,
    pub hedge_primary_late_samples: AtomicU64,
    pub ingress_packets_total: AtomicU64,
    pub ingress_queue_drops: AtomicU64,
    pub ingress_queue_drop_bytes: AtomicU64,
    pub ingress_queue_bytes: AtomicU64,
    pub ingress_bad_header_total: AtomicU64,
    pub ingress_rate_limited_total: AtomicU64,
    pub ingress_unroutable_total: AtomicU64,
    pub ingress_draining_drops_total: AtomicU64,
    pub ingress_connection_create_failed_total: AtomicU64,
    pub ingress_version_neg_failed_total: AtomicU64,
    pub request_buffered_bytes: AtomicU64,
    pub request_buffered_high_watermark_bytes: AtomicU64,
    pub request_buffer_limit_rejects: AtomicU64,
    pub response_prebuffer_limit_rejects: AtomicU64,
    pub scid_rotations: AtomicU64,
    pub control_api_connection_limit_drops: AtomicU64,
    pub watchdog_restart_requests: AtomicU64,
    pub watchdog_restart_hooks: AtomicU64,
    pub watchdog_degraded_windows: AtomicU64,
    pub runtime_panics: AtomicU64,
    pub retries_total: AtomicU64,
    pub retry_denied_budget: AtomicU64,
    pub retry_denied_no_bodyless: AtomicU64,
    pub retry_denied_no_alternate: AtomicU64,
    pub retry_reason_timeout: AtomicU64,
    pub retry_reason_transport: AtomicU64,
    pub retry_reason_pool: AtomicU64,
    pub circuit_breaker_rejected_total: AtomicU64,
    pub brownout_active: AtomicU64,
    pub health_failure_5xx: AtomicU64,
    pub health_failure_timeout: AtomicU64,
    pub health_failure_transport: AtomicU64,
    pub health_failure_tls: AtomicU64,
    route_latency_sample_every: u64,
    route_latency_sample_counter: AtomicU64,
    route_labels: Vec<String>,
    route_label_to_id: HashMap<String, usize>,
    route_stats: Vec<RouteStatsAtomic>,
    unrouted_route_id: usize,
    worker_labels: Vec<String>,
    worker_stats: Vec<WorkerStatsAtomic>,
}

const LATENCY_BUCKETS_MS: [u64; 14] = [
    1, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_000, 5_000, 10_000, 30_000, 60_000,
];
const ROUTE_LATENCY_SAMPLE_EVERY_ENV: &str = "SPOOKY_ROUTE_LATENCY_SAMPLE_EVERY";

#[derive(Default, Clone)]
struct RouteStats {
    requests_total: u64,
    success: u64,
    failure: u64,
    timeout: u64,
    backend_error: u64,
    overload_shed: u64,
    latency_buckets: [u64; LATENCY_BUCKETS_MS.len() + 1],
}

#[derive(Default, Clone)]
struct WorkerStats {
    requests_total: u64,
    requests_success: u64,
    requests_failure: u64,
    ingress_packets_total: u64,
    ingress_queue_drops: u64,
    ingress_queue_drop_bytes: u64,
}

struct RouteStatsAtomic {
    requests_total: AtomicU64,
    success: AtomicU64,
    failure: AtomicU64,
    timeout: AtomicU64,
    backend_error: AtomicU64,
    overload_shed: AtomicU64,
    latency_buckets: [AtomicU64; LATENCY_BUCKETS_MS.len() + 1],
}

impl RouteStatsAtomic {
    fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            success: AtomicU64::new(0),
            failure: AtomicU64::new(0),
            timeout: AtomicU64::new(0),
            backend_error: AtomicU64::new(0),
            overload_shed: AtomicU64::new(0),
            latency_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn snapshot(&self) -> RouteStats {
        let mut latency_buckets = [0u64; LATENCY_BUCKETS_MS.len() + 1];
        for (idx, bucket) in self.latency_buckets.iter().enumerate() {
            latency_buckets[idx] = bucket.load(Ordering::Relaxed);
        }

        RouteStats {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            success: self.success.load(Ordering::Relaxed),
            failure: self.failure.load(Ordering::Relaxed),
            timeout: self.timeout.load(Ordering::Relaxed),
            backend_error: self.backend_error.load(Ordering::Relaxed),
            overload_shed: self.overload_shed.load(Ordering::Relaxed),
            latency_buckets,
        }
    }
}

struct WorkerStatsAtomic {
    requests_total: AtomicU64,
    requests_success: AtomicU64,
    requests_failure: AtomicU64,
    ingress_packets_total: AtomicU64,
    ingress_queue_drops: AtomicU64,
    ingress_queue_drop_bytes: AtomicU64,
}

impl WorkerStatsAtomic {
    fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            requests_success: AtomicU64::new(0),
            requests_failure: AtomicU64::new(0),
            ingress_packets_total: AtomicU64::new(0),
            ingress_queue_drops: AtomicU64::new(0),
            ingress_queue_drop_bytes: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> WorkerStats {
        WorkerStats {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_success: self.requests_success.load(Ordering::Relaxed),
            requests_failure: self.requests_failure.load(Ordering::Relaxed),
            ingress_packets_total: self.ingress_packets_total.load(Ordering::Relaxed),
            ingress_queue_drops: self.ingress_queue_drops.load(Ordering::Relaxed),
            ingress_queue_drop_bytes: self.ingress_queue_drop_bytes.load(Ordering::Relaxed),
        }
    }
}

pub enum RouteOutcome {
    Success,
    Failure,
    Timeout,
    BackendError,
    OverloadShed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverloadShedReason {
    Brownout,
    AdaptiveAdmission,
    RouteCap,
    RouteGlobalCap,
    GlobalInflight,
    UpstreamInflight,
    BackendInflight,
    RequestBufferCap,
    ResponsePrebufferCap,
    ConnectionCap,
}

#[derive(Clone, Copy, Debug)]
pub enum RetryReason {
    BackendTimeout,
    BackendTransport,
    BackendPool,
    BudgetDenied,
    NotBodylessMode,
    NoAlternateBackend,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new(1, [String::from("unrouted")])
    }
}

thread_local! {
    static WORKER_METRICS_SLOT: Cell<usize> = const { Cell::new(0) };
}

impl Metrics {
    pub fn new<I>(worker_slots: usize, route_labels: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let route_latency_sample_every = env::var(ROUTE_LATENCY_SAMPLE_EVERY_ENV)
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(1);

        let mut route_labels_dedup = Vec::new();
        let mut route_label_to_id = HashMap::new();
        for raw in route_labels {
            let label = raw.trim();
            if label.is_empty() || route_label_to_id.contains_key(label) {
                continue;
            }
            let id = route_labels_dedup.len();
            route_labels_dedup.push(label.to_string());
            route_label_to_id.insert(label.to_string(), id);
        }
        if !route_label_to_id.contains_key("unrouted") {
            let id = route_labels_dedup.len();
            route_labels_dedup.push("unrouted".to_string());
            route_label_to_id.insert("unrouted".to_string(), id);
        }
        let unrouted_route_id = route_label_to_id.get("unrouted").copied().unwrap_or(0);

        let worker_slots = worker_slots.max(1);
        let worker_labels = (0..worker_slots)
            .map(|idx| format!("worker-{idx}"))
            .collect::<Vec<_>>();
        let worker_stats = (0..worker_slots)
            .map(|_| WorkerStatsAtomic::new())
            .collect::<Vec<_>>();
        let route_stats = route_labels_dedup
            .iter()
            .map(|_| RouteStatsAtomic::new())
            .collect::<Vec<_>>();

        Self {
            requests_total: AtomicU64::new(0),
            requests_success: AtomicU64::new(0),
            requests_failure: AtomicU64::new(0),
            request_validation_rejects: AtomicU64::new(0),
            policy_denied: AtomicU64::new(0),
            early_data_accepted: AtomicU64::new(0),
            early_data_rejected: AtomicU64::new(0),
            health_checks_total: AtomicU64::new(0),
            health_checks_success: AtomicU64::new(0),
            health_checks_failure: AtomicU64::new(0),
            backend_timeouts: AtomicU64::new(0),
            backend_errors: AtomicU64::new(0),
            overload_shed: AtomicU64::new(0),
            overload_shed_brownout: AtomicU64::new(0),
            overload_shed_adaptive: AtomicU64::new(0),
            overload_shed_route_cap: AtomicU64::new(0),
            overload_shed_route_global_cap: AtomicU64::new(0),
            overload_shed_global_inflight: AtomicU64::new(0),
            overload_shed_upstream_inflight: AtomicU64::new(0),
            overload_shed_backend_inflight: AtomicU64::new(0),
            overload_shed_request_buffer: AtomicU64::new(0),
            overload_shed_response_prebuffer: AtomicU64::new(0),
            overload_shed_connection_cap: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            connection_cap_rejects: AtomicU64::new(0),
            hedge_triggered: AtomicU64::new(0),
            hedge_won: AtomicU64::new(0),
            hedge_wasted: AtomicU64::new(0),
            hedge_primary_won_after_trigger: AtomicU64::new(0),
            hedge_primary_late_ms_total: AtomicU64::new(0),
            hedge_primary_late_samples: AtomicU64::new(0),
            ingress_packets_total: AtomicU64::new(0),
            ingress_queue_drops: AtomicU64::new(0),
            ingress_queue_drop_bytes: AtomicU64::new(0),
            ingress_queue_bytes: AtomicU64::new(0),
            ingress_bad_header_total: AtomicU64::new(0),
            ingress_rate_limited_total: AtomicU64::new(0),
            ingress_unroutable_total: AtomicU64::new(0),
            ingress_draining_drops_total: AtomicU64::new(0),
            ingress_connection_create_failed_total: AtomicU64::new(0),
            ingress_version_neg_failed_total: AtomicU64::new(0),
            request_buffered_bytes: AtomicU64::new(0),
            request_buffered_high_watermark_bytes: AtomicU64::new(0),
            request_buffer_limit_rejects: AtomicU64::new(0),
            response_prebuffer_limit_rejects: AtomicU64::new(0),
            scid_rotations: AtomicU64::new(0),
            control_api_connection_limit_drops: AtomicU64::new(0),
            watchdog_restart_requests: AtomicU64::new(0),
            watchdog_restart_hooks: AtomicU64::new(0),
            watchdog_degraded_windows: AtomicU64::new(0),
            runtime_panics: AtomicU64::new(0),
            retries_total: AtomicU64::new(0),
            retry_denied_budget: AtomicU64::new(0),
            retry_denied_no_bodyless: AtomicU64::new(0),
            retry_denied_no_alternate: AtomicU64::new(0),
            retry_reason_timeout: AtomicU64::new(0),
            retry_reason_transport: AtomicU64::new(0),
            retry_reason_pool: AtomicU64::new(0),
            circuit_breaker_rejected_total: AtomicU64::new(0),
            brownout_active: AtomicU64::new(0),
            health_failure_5xx: AtomicU64::new(0),
            health_failure_timeout: AtomicU64::new(0),
            health_failure_transport: AtomicU64::new(0),
            health_failure_tls: AtomicU64::new(0),
            route_latency_sample_every,
            route_latency_sample_counter: AtomicU64::new(0),
            route_labels: route_labels_dedup,
            route_label_to_id,
            route_stats,
            unrouted_route_id,
            worker_labels,
            worker_stats,
        }
    }

    pub fn bind_worker_slot(&self, slot: usize) {
        let max_index = self.worker_stats.len().saturating_sub(1);
        WORKER_METRICS_SLOT.with(|current| current.set(slot.min(max_index)));
    }

    pub fn inc_total(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.inc_worker_requests_total();
    }

    pub fn inc_success(&self) {
        self.requests_success.fetch_add(1, Ordering::Relaxed);
        self.inc_worker_requests_success();
    }

    pub fn inc_failure(&self) {
        self.requests_failure.fetch_add(1, Ordering::Relaxed);
        self.inc_worker_requests_failure();
    }

    pub fn inc_request_validation_reject(&self) {
        self.request_validation_rejects
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_policy_denied(&self) {
        self.policy_denied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_early_data_accepted(&self) {
        self.early_data_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_early_data_rejected(&self) {
        self.early_data_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_health_check_success(&self) {
        self.health_checks_total.fetch_add(1, Ordering::Relaxed);
        self.health_checks_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_health_check_failure(&self) {
        self.health_checks_total.fetch_add(1, Ordering::Relaxed);
        self.health_checks_failure.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_timeout(&self) {
        self.backend_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_backend_error(&self) {
        self.backend_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_overload_shed(&self) {
        self.overload_shed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_overload_shed_reason(&self, reason: OverloadShedReason) {
        self.overload_shed.fetch_add(1, Ordering::Relaxed);
        match reason {
            OverloadShedReason::Brownout => {
                self.overload_shed_brownout.fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::AdaptiveAdmission => {
                self.overload_shed_adaptive.fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::RouteCap => {
                self.overload_shed_route_cap.fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::RouteGlobalCap => {
                self.overload_shed_route_global_cap
                    .fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::GlobalInflight => {
                self.overload_shed_global_inflight
                    .fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::UpstreamInflight => {
                self.overload_shed_upstream_inflight
                    .fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::BackendInflight => {
                self.overload_shed_backend_inflight
                    .fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::RequestBufferCap => {
                self.overload_shed_request_buffer
                    .fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::ResponsePrebufferCap => {
                self.overload_shed_response_prebuffer
                    .fetch_add(1, Ordering::Relaxed);
            }
            OverloadShedReason::ConnectionCap => {
                self.overload_shed_connection_cap
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn set_active_connections(&self, count: usize) {
        self.active_connections
            .store(count as u64, Ordering::Relaxed);
    }

    pub fn inc_connection_cap_reject(&self) {
        self.connection_cap_rejects.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_hedge_triggered(&self) {
        self.hedge_triggered.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_hedge_won(&self) {
        self.hedge_won.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_hedge_wasted(&self) {
        self.hedge_wasted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_hedge_primary_won_after_trigger(&self) {
        self.hedge_primary_won_after_trigger
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn observe_hedge_primary_late_ms(&self, late_ms: u64) {
        self.hedge_primary_late_ms_total
            .fetch_add(late_ms, Ordering::Relaxed);
        self.hedge_primary_late_samples
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ingress_packet(&self) {
        self.ingress_packets_total.fetch_add(1, Ordering::Relaxed);
        self.inc_worker_ingress_packets_total();
    }

    pub fn inc_ingress_queue_drop(&self) {
        self.ingress_queue_drops.fetch_add(1, Ordering::Relaxed);
        self.inc_worker_ingress_queue_drops();
    }

    pub fn inc_ingress_queue_drop_bytes(&self, bytes: usize) {
        self.ingress_queue_drop_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.inc_worker_ingress_queue_drop_bytes(bytes as u64);
    }

    pub fn set_ingress_queue_bytes(&self, bytes: usize) {
        self.ingress_queue_bytes
            .store(bytes as u64, Ordering::Relaxed);
    }

    pub fn inc_ingress_bad_header(&self) {
        self.ingress_bad_header_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ingress_rate_limited(&self) {
        self.ingress_rate_limited_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ingress_unroutable(&self) {
        self.ingress_unroutable_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ingress_draining_drop(&self) {
        self.ingress_draining_drops_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ingress_connection_create_failed(&self) {
        self.ingress_connection_create_failed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ingress_version_neg_failed(&self) {
        self.ingress_version_neg_failed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn current_worker_stats(&self) -> Option<&WorkerStatsAtomic> {
        let idx = WORKER_METRICS_SLOT.with(|current| current.get());
        self.worker_stats
            .get(idx)
            .or_else(|| self.worker_stats.first())
    }

    fn inc_worker_requests_total(&self) {
        if let Some(stats) = self.current_worker_stats() {
            stats.requests_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn inc_worker_requests_success(&self) {
        if let Some(stats) = self.current_worker_stats() {
            stats.requests_success.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn inc_worker_requests_failure(&self) {
        if let Some(stats) = self.current_worker_stats() {
            stats.requests_failure.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn inc_worker_ingress_packets_total(&self) {
        if let Some(stats) = self.current_worker_stats() {
            stats.ingress_packets_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn inc_worker_ingress_queue_drops(&self) {
        if let Some(stats) = self.current_worker_stats() {
            stats.ingress_queue_drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn inc_worker_ingress_queue_drop_bytes(&self, bytes: u64) {
        if let Some(stats) = self.current_worker_stats() {
            stats
                .ingress_queue_drop_bytes
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub fn try_reserve_request_buffer(&self, bytes: usize, cap_bytes: usize) -> bool {
        let add = bytes as u64;
        let cap = cap_bytes as u64;
        loop {
            let current = self.request_buffered_bytes.load(Ordering::Relaxed);
            let next = current.saturating_add(add);
            if next > cap {
                return false;
            }
            if self
                .request_buffered_bytes
                .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                self.observe_request_buffer_high_water(next);
                return true;
            }
        }
    }

    pub fn release_request_buffer(&self, bytes: usize) {
        let sub = bytes as u64;
        loop {
            let current = self.request_buffered_bytes.load(Ordering::Relaxed);
            let next = current.saturating_sub(sub);
            if self
                .request_buffered_bytes
                .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }

    pub fn inc_request_buffer_limit_reject(&self) {
        self.request_buffer_limit_rejects
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_response_prebuffer_limit_reject(&self) {
        self.response_prebuffer_limit_rejects
            .fetch_add(1, Ordering::Relaxed);
    }

    fn observe_request_buffer_high_water(&self, candidate: u64) {
        loop {
            let current = self
                .request_buffered_high_watermark_bytes
                .load(Ordering::Relaxed);
            if candidate <= current {
                return;
            }
            if self
                .request_buffered_high_watermark_bytes
                .compare_exchange(current, candidate, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }

    pub fn inc_scid_rotation(&self) {
        self.scid_rotations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_control_api_connection_limit_drop(&self) {
        self.control_api_connection_limit_drops
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_watchdog_restart_request(&self) {
        self.watchdog_restart_requests
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_watchdog_restart_hook(&self) {
        self.watchdog_restart_hooks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_watchdog_degraded_window(&self) {
        self.watchdog_degraded_windows
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_runtime_panic(&self) {
        self.runtime_panics.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_retry(&self, reason: RetryReason) {
        self.retries_total.fetch_add(1, Ordering::Relaxed);
        match reason {
            RetryReason::BackendTimeout => {
                self.retry_reason_timeout.fetch_add(1, Ordering::Relaxed);
            }
            RetryReason::BackendTransport => {
                self.retry_reason_transport.fetch_add(1, Ordering::Relaxed);
            }
            RetryReason::BackendPool => {
                self.retry_reason_pool.fetch_add(1, Ordering::Relaxed);
            }
            RetryReason::BudgetDenied => {
                self.retry_denied_budget.fetch_add(1, Ordering::Relaxed);
            }
            RetryReason::NotBodylessMode => {
                self.retry_denied_no_bodyless
                    .fetch_add(1, Ordering::Relaxed);
            }
            RetryReason::NoAlternateBackend => {
                self.retry_denied_no_alternate
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn inc_circuit_breaker_rejected(&self) {
        self.circuit_breaker_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_brownout_active(&self, active: bool) {
        self.brownout_active
            .store(if active { 1 } else { 0 }, Ordering::Relaxed);
    }

    pub fn inc_health_failure(&self, reason: HealthFailureReason) {
        match reason {
            HealthFailureReason::HttpStatus5xx => {
                self.health_failure_5xx.fetch_add(1, Ordering::Relaxed);
            }
            HealthFailureReason::Timeout => {
                self.health_failure_timeout.fetch_add(1, Ordering::Relaxed);
            }
            HealthFailureReason::Transport => {
                self.health_failure_transport
                    .fetch_add(1, Ordering::Relaxed);
            }
            HealthFailureReason::Tls => {
                self.health_failure_tls.fetch_add(1, Ordering::Relaxed);
            }
            HealthFailureReason::CircuitOpen => {}
        }
    }

    pub fn record_route(&self, route: &str, latency: Duration, outcome: RouteOutcome) {
        let route_id = self
            .route_label_to_id
            .get(route)
            .copied()
            .unwrap_or(self.unrouted_route_id);
        let Some(entry) = self.route_stats.get(route_id) else {
            return;
        };
        entry.requests_total.fetch_add(1, Ordering::Relaxed);

        match outcome {
            RouteOutcome::Success => {
                entry.success.fetch_add(1, Ordering::Relaxed);
            }
            RouteOutcome::Failure => {
                entry.failure.fetch_add(1, Ordering::Relaxed);
            }
            RouteOutcome::Timeout => {
                entry.timeout.fetch_add(1, Ordering::Relaxed);
            }
            RouteOutcome::BackendError => {
                entry.backend_error.fetch_add(1, Ordering::Relaxed);
            }
            RouteOutcome::OverloadShed => {
                entry.overload_shed.fetch_add(1, Ordering::Relaxed);
            }
        }

        if self.route_latency_sample_every > 1 {
            let seq = self
                .route_latency_sample_counter
                .fetch_add(1, Ordering::Relaxed);
            if !seq.is_multiple_of(self.route_latency_sample_every) {
                return;
            }
        }

        let latency_ms = latency.as_millis() as u64;
        let bucket = LATENCY_BUCKETS_MS
            .iter()
            .position(|cutoff| latency_ms <= *cutoff)
            .unwrap_or(LATENCY_BUCKETS_MS.len());
        entry.latency_buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }
}

mod prometheus;
