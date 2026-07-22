use std::{collections::HashMap, time::Duration};

use super::{
    config_invalid, is_valid_connect_authority, is_valid_http_token, is_valid_request_key_spec,
    normalize_nonempty_string_vec, normalize_optional_string, normalize_string_vec,
    require_nonzero_usize,
};
use crate::{
    config::Resilience,
    runtime::{RuntimeConfigError, RuntimeProtocolPolicy},
};

use super::{
    resilience::{
        normalize_circuit_breaker_policy, normalize_hedging_policy,
        normalize_retry_budget_policy,
    },
    watchdog::normalize_watchdog_policy,
};

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
    pub(crate) fn normalize(
        rule: &crate::config::ScopedRateLimit,
    ) -> Result<Self, RuntimeConfigError> {
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
                if let Some(key_spec) = key.as_deref()
                    && !is_valid_request_key_spec(key_spec)
                {
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
pub struct RuntimeBrownoutPolicy {
    pub enabled: bool,
    pub trigger_inflight_percent: u8,
    pub recover_inflight_percent: u8,
    pub core_routes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeRateLimitPolicy {
    pub scoped_limits: Vec<RuntimeScopedRateLimitPolicy>,
}

impl RuntimeRateLimitPolicy {
    pub(crate) fn normalize(resilience: &Resilience) -> Result<Self, RuntimeConfigError> {
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
    pub circuit_breaker: super::RuntimeCircuitBreakerPolicy,
    pub hedging: super::RuntimeHedgingPolicy,
    pub retry_budget: super::RuntimeRetryBudgetPolicy,
    pub brownout: RuntimeBrownoutPolicy,
    pub watchdog: super::RuntimeWatchdogPolicy,
    pub protocol: RuntimeProtocolPolicy,
}

impl RuntimeAdmissionPolicy {
    pub(crate) fn normalize(
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
        if allowed_methods
            .iter()
            .any(|method| !is_valid_http_token(method))
        {
            return Err(config_invalid(
                "resilience.protocol.allowed_methods must contain valid HTTP method tokens",
            ));
        }
        let denied_path_prefixes = normalize_nonempty_string_vec(
            "resilience.protocol.denied_path_prefixes",
            &resilience.protocol.denied_path_prefixes,
        )?;
        if denied_path_prefixes
            .iter()
            .any(|prefix| !prefix.starts_with('/'))
        {
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

        let mut protocol = resilience.protocol.clone();
        protocol.early_data_safe_methods = early_data_safe_methods;
        protocol.allowed_methods = allowed_methods;
        protocol.denied_path_prefixes = denied_path_prefixes;
        let hedging_safe_methods = normalize_string_vec(&resilience.hedging.safe_methods);
        let hedging_route_allowlist = normalize_string_vec(&resilience.hedging.route_allowlist);

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
            circuit_breaker: normalize_circuit_breaker_policy(resilience)?,
            hedging: normalize_hedging_policy(
                resilience,
                hedging_safe_methods,
                hedging_route_allowlist,
            )?,
            retry_budget: normalize_retry_budget_policy(resilience)?,
            brownout: RuntimeBrownoutPolicy {
                enabled: resilience.brownout.enabled,
                trigger_inflight_percent: resilience.brownout.trigger_inflight_percent,
                recover_inflight_percent: resilience.brownout.recover_inflight_percent,
                core_routes: normalize_string_vec(&resilience.brownout.core_routes),
            },
            watchdog: normalize_watchdog_policy(resilience)?,
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
