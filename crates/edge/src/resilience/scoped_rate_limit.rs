use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use spooky_config::config::{ScopedRateLimit as ScopedRateLimitConfig, ScopedRateLimitScope};

struct ScopedRateLimitBucket {
    burst: f64,
    rate_per_sec: f64,
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

impl ScopedRateLimitBucket {
    fn new(rate_per_sec: u32, burst: u32) -> Self {
        let now = Instant::now();
        let burst = burst.max(1) as f64;
        Self {
            burst,
            rate_per_sec: rate_per_sec.max(1) as f64,
            tokens: burst,
            last_refill: now,
            last_seen: now,
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let refill = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64()
            * self.rate_per_sec;
        self.last_refill = now;
        self.last_seen = now;

        if refill.is_finite() && refill > 0.0 {
            self.tokens = (self.tokens + refill).min(self.burst);
        } else if !refill.is_finite() {
            self.tokens = self.burst;
        }

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct ScopedRateLimitRule {
    name: String,
    scope: ScopedRateLimitScope,
    key_spec: Option<String>,
    route_allowlist: HashSet<String>,
    idle_ttl: Duration,
    retry_after_seconds: u32,
    rate_per_sec: u32,
    burst: u32,
    buckets: Mutex<HashMap<String, ScopedRateLimitBucket>>,
}

impl ScopedRateLimitRule {
    pub(crate) fn from_config(config: &ScopedRateLimitConfig) -> Self {
        Self {
            name: config.name.clone(),
            scope: config.scope,
            key_spec: config.key.clone(),
            route_allowlist: config.route_allowlist.iter().cloned().collect(),
            idle_ttl: Duration::from_secs(config.idle_ttl_secs.max(1)),
            retry_after_seconds: ((1.0 / config.requests_per_sec.max(1) as f64).ceil() as u32)
                .max(1),
            rate_per_sec: config.requests_per_sec.max(1),
            burst: config.burst.max(1),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn scope(&self) -> ScopedRateLimitScope {
        self.scope
    }

    pub fn key_spec(&self) -> Option<&str> {
        self.key_spec.as_deref()
    }

    fn applies_to_route(&self, route: &str) -> bool {
        self.route_allowlist.is_empty() || self.route_allowlist.contains(route)
    }

    fn allow(&self, key: &str) -> bool {
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(_) => return true,
        };
        if buckets.len() >= 64 {
            let idle_ttl = self.idle_ttl;
            buckets.retain(|_, bucket| bucket.last_seen.elapsed() < idle_ttl);
        }
        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| ScopedRateLimitBucket::new(self.rate_per_sec, self.burst));
        bucket.try_consume()
    }
}

#[derive(Debug, Clone)]
pub struct ScopedRateLimitRejection {
    pub rule_name: String,
    pub route: String,
    pub retry_after_seconds: u32,
}

pub struct ScopedRateLimiters {
    rules: Vec<Arc<ScopedRateLimitRule>>,
}

impl ScopedRateLimiters {
    pub fn new(rules: &[ScopedRateLimitConfig]) -> Self {
        Self {
            rules: rules
                .iter()
                .map(|rule| Arc::new(ScopedRateLimitRule::from_config(rule)))
                .collect(),
        }
    }

    pub fn check<F>(&self, route: &str, mut key_for_rule: F) -> Option<ScopedRateLimitRejection>
    where
        F: FnMut(&ScopedRateLimitRule) -> Option<String>,
    {
        for rule in &self.rules {
            if !rule.applies_to_route(route) {
                continue;
            }
            let Some(key) = key_for_rule(rule) else {
                continue;
            };
            if key.is_empty() || rule.allow(&key) {
                continue;
            }
            return Some(ScopedRateLimitRejection {
                rule_name: rule.name.clone(),
                route: route.to_string(),
                retry_after_seconds: rule.retry_after_seconds,
            });
        }
        None
    }
}
