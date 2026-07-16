use std::{collections::HashSet, sync::Arc, time::Duration};

use spooky_config::config::Resilience as ResilienceConfig;

use crate::resilience::{
    adaptive_admission::AdaptiveAdmission,
    brownout::BrownoutController,
    circuit_breaker::CircuitBreakers,
    connect::{connect_authority_port, normalize_connect_authority},
    retry_budget::RetryBudget,
    route_queue::RouteQueueLimiter,
    scoped_rate_limit::ScopedRateLimiters,
};

pub struct RuntimeResilience {
    pub adaptive_admission: Arc<AdaptiveAdmission>,
    pub route_queue: Arc<RouteQueueLimiter>,
    pub scoped_rate_limits: Arc<ScopedRateLimiters>,
    pub circuit_breakers: Arc<CircuitBreakers>,
    pub retry_budget: Arc<RetryBudget>,
    pub brownout: Arc<BrownoutController>,
    pub shed_retry_after_seconds: u32,
    pub allow_0rtt: bool,
    pub max_headers_count: usize,
    pub max_headers_bytes: usize,
    pub enforce_authority_host_match: bool,
    pub allow_connect: bool,
    pub hedging_enabled: bool,
    pub hedging_delay: Duration,
    hedge_safe_methods: HashSet<String>,
    early_data_safe_methods: HashSet<String>,
    allowed_methods: HashSet<String>,
    denied_path_prefixes: Vec<String>,
    connect_allowed_ports: HashSet<u16>,
    connect_allowed_authorities: HashSet<String>,
    route_allowlist: HashSet<String>,
}

impl RuntimeResilience {
    pub fn from_config(config: &ResilienceConfig, global_limit: usize) -> Self {
        let adaptive = &config.adaptive_admission;
        let adaptive_max_limit = adaptive.max_limit.unwrap_or(global_limit);
        let admission = Arc::new(AdaptiveAdmission::new(
            adaptive.enabled,
            adaptive.min_limit,
            adaptive_max_limit.max(adaptive.min_limit),
            adaptive.increase_step,
            adaptive.decrease_step,
            adaptive.high_latency_ms,
        ));
        let route_queue = Arc::new(RouteQueueLimiter::new(
            config.route_queue.default_cap,
            config.route_queue.global_cap,
            config.route_queue.caps.clone(),
        ));
        let scoped_rate_limits = Arc::new(ScopedRateLimiters::new(&config.scoped_rate_limits));
        let cb = &config.circuit_breaker;
        let circuit_breakers = Arc::new(CircuitBreakers::new(
            cb.enabled,
            cb.failure_threshold,
            Duration::from_millis(cb.open_ms.max(1)),
            cb.half_open_max_probes,
        ));
        let retry_budget = Arc::new(RetryBudget::new(
            config.retry_budget.enabled,
            config.retry_budget.ratio_percent,
            config.retry_budget.per_route_ratio_percent.clone(),
        ));
        let brownout = Arc::new(BrownoutController::new(
            config.brownout.enabled,
            config.brownout.trigger_inflight_percent,
            config.brownout.recover_inflight_percent,
            config.brownout.core_routes.clone(),
        ));

        let hedge_safe_methods = config
            .hedging
            .safe_methods
            .iter()
            .map(|method| method.to_ascii_uppercase())
            .collect::<HashSet<_>>();
        let early_data_safe_methods = config
            .protocol
            .early_data_safe_methods
            .iter()
            .map(|method| method.to_ascii_uppercase())
            .collect::<HashSet<_>>();
        let allowed_methods = config
            .protocol
            .allowed_methods
            .iter()
            .map(|method| method.to_ascii_uppercase())
            .collect::<HashSet<_>>();
        let route_allowlist = config
            .hedging
            .route_allowlist
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        let connect_allowed_ports = config
            .protocol
            .connect_allowed_ports
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let connect_allowed_authorities = config
            .protocol
            .connect_allowed_authorities
            .iter()
            .filter_map(|authority| normalize_connect_authority(authority))
            .collect::<HashSet<_>>();

        Self {
            adaptive_admission: admission,
            route_queue,
            scoped_rate_limits,
            circuit_breakers,
            retry_budget,
            brownout,
            shed_retry_after_seconds: config.route_queue.shed_retry_after_seconds.max(1),
            allow_0rtt: config.protocol.allow_0rtt,
            max_headers_count: config.protocol.max_headers_count.max(1),
            max_headers_bytes: config.protocol.max_headers_bytes.max(1),
            enforce_authority_host_match: config.protocol.enforce_authority_host_match,
            allow_connect: config.protocol.allow_connect,
            hedging_enabled: config.hedging.enabled,
            hedging_delay: Duration::from_millis(config.hedging.delay_ms),
            hedge_safe_methods,
            early_data_safe_methods,
            allowed_methods,
            denied_path_prefixes: config.protocol.denied_path_prefixes.clone(),
            connect_allowed_ports,
            connect_allowed_authorities,
            route_allowlist,
        }
    }

    pub fn hedging_route_enabled_for(&self, route: &str) -> bool {
        if !self.hedging_enabled || self.brownout.is_active() {
            return false;
        }
        self.route_allowlist.is_empty() || self.route_allowlist.contains(route)
    }

    pub fn hedging_method_allowed(&self, method: &str) -> bool {
        self.hedge_safe_methods
            .contains(&method.to_ascii_uppercase())
    }

    pub fn hedging_allowed_for(&self, method: &str, route: &str, bodyless: bool) -> bool {
        self.hedging_route_enabled_for(route)
            && bodyless
            && self.hedging_method_allowed(method)
    }

    pub fn early_data_allowed_for(&self, method: &str) -> bool {
        self.allow_0rtt
            && self
                .early_data_safe_methods
                .contains(&method.to_ascii_uppercase())
    }

    pub fn method_allowed(&self, method: &str) -> bool {
        self.allowed_methods.is_empty()
            || self.allowed_methods.contains(&method.to_ascii_uppercase())
    }

    pub fn path_denied(&self, path: &str) -> bool {
        self.denied_path_prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix))
    }

    pub fn connect_allowed(&self, authority: &str) -> bool {
        if !self.allow_connect {
            return false;
        }
        let Some(normalized_authority) = normalize_connect_authority(authority) else {
            return false;
        };
        let Some(port) = connect_authority_port(&normalized_authority) else {
            return false;
        };
        if !self.connect_allowed_ports.is_empty() && !self.connect_allowed_ports.contains(&port) {
            return false;
        }
        if self.connect_allowed_authorities.is_empty() {
            return true;
        }
        self.connect_allowed_authorities
            .contains(&normalized_authority)
    }
}
