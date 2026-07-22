//! Canonical load-balancing strategy façade.
//!
//! Strategy-specific implementations stay internal; callers should choose and
//! query strategies through [`LoadBalancing`] instead of depending on
//! algorithm-specific state.

use crate::{
    algorithms::{
        consistent_hash::ConsistentHash, latency_aware::LatencyAware,
        least_connections::LeastConnections, random::Random, round_robin::RoundRobin,
        sticky_cid::StickyCid,
    },
    backend_pool::BackendPool,
    hash::DEFAULT_REPLICAS,
};

pub enum LoadBalancing {
    RoundRobin(RoundRobin),
    ConsistentHash(ConsistentHash),
    Random(Random),
    LeastConnections(LeastConnections),
    LatencyAware(LatencyAware),
    StickyCid(StickyCid),
}

impl LoadBalancing {
    pub fn from_config(value: &str) -> Result<Self, String> {
        let mode = value.trim().to_lowercase();
        match mode.as_str() {
            "round-robin" | "round_robin" | "rr" => Ok(Self::RoundRobin(RoundRobin::new())),
            "consistent-hash" | "consistent_hash" | "ch" => {
                Ok(Self::ConsistentHash(ConsistentHash::new(DEFAULT_REPLICAS)))
            }
            "random" => Ok(Self::Random(Random::new())),
            "least-connections" | "least_connections" | "lc" => {
                Ok(Self::LeastConnections(LeastConnections::new()))
            }
            "latency-aware" | "latency_aware" | "la" => Ok(Self::LatencyAware(LatencyAware::new())),
            "sticky-cid" | "sticky_cid" | "cid-sticky" | "cid_sticky" => {
                Ok(Self::StickyCid(StickyCid::new(DEFAULT_REPLICAS)))
            }
            _ => Err(format!("unsupported load balancing type: {value}")),
        }
    }

    pub fn pick(&mut self, key: &str, pool: &BackendPool) -> Option<usize> {
        match self {
            LoadBalancing::RoundRobin(rr) => rr.pick(pool),
            LoadBalancing::ConsistentHash(ch) => ch.pick(key, pool),
            LoadBalancing::Random(rand) => rand.pick(pool),
            LoadBalancing::LeastConnections(lc) => lc.pick(pool),
            LoadBalancing::LatencyAware(la) => la.pick(pool),
            LoadBalancing::StickyCid(sticky) => sticky.pick(key, pool),
        }
    }

    pub fn pick_readonly(&self, _key: &str, pool: &BackendPool) -> Option<usize> {
        match self {
            LoadBalancing::RoundRobin(rr) => rr.pick_readonly(pool),
            LoadBalancing::Random(rand) => rand.pick_readonly(pool),
            LoadBalancing::LeastConnections(lc) => lc.pick_readonly(pool),
            LoadBalancing::LatencyAware(la) => la.pick_readonly(pool),
            // ConsistentHash and StickyCid keep mutable ring caches.
            LoadBalancing::ConsistentHash(_) | LoadBalancing::StickyCid(_) => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            LoadBalancing::RoundRobin(_) => "round-robin",
            LoadBalancing::ConsistentHash(_) => "consistent-hash",
            LoadBalancing::Random(_) => "random",
            LoadBalancing::LeastConnections(_) => "least-connections",
            LoadBalancing::LatencyAware(_) => "latency-aware",
            LoadBalancing::StickyCid(_) => "sticky-cid",
        }
    }

    pub fn from_runtime_strategy(
        strategy: spooky_config::runtime::RuntimeLoadBalancingStrategy,
    ) -> Result<Self, String> {
        Self::from_config(strategy.canonical_name())
    }
}
