use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use rand::Rng;
use spooky_config::config::Backend;

const FAILURE_THRESHOLD: u32 = 3;
const COOLDOWN: Duration = Duration::from_secs(10);
const DEFAULT_REPLICAS: u32 = 64;

#[derive(Clone)]
pub struct BackendState {
    backend: Backend,
    consecutive_failures: u32,
    unhealthy_until: Option<Instant>,
}

impl BackendState {
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
            consecutive_failures: 0,
            unhealthy_until: None,
        }
    }

    pub fn is_healthy(&self) -> bool {
        match self.unhealthy_until {
            Some(until) => Instant::now() >= until,
            None => true,
        }
    }

    pub fn address(&self) -> &str {
        &self.backend.address
    }

    pub fn weight(&self) -> u32 {
        self.backend.weight.max(1)
    }

    pub fn mark_success(&mut self) {
        self.consecutive_failures = 0;
        self.unhealthy_until = None;
    }

    pub fn mark_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= FAILURE_THRESHOLD {
            self.consecutive_failures = 0;
            self.unhealthy_until = Some(Instant::now() + COOLDOWN);
        }
    }
}

pub struct BackendPool {
    backends: Vec<BackendState>,
}

impl BackendPool {
    pub fn new(backends: Vec<Backend>) -> Self {
        let backends = backends.into_iter().map(BackendState::new).collect();
        Self { backends }
    }

    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    pub fn address(&self, index: usize) -> Option<&str> {
        self.backends.get(index).map(|b| b.address())
    }

    pub fn mark_success(&mut self, index: usize) {
        if let Some(backend) = self.backends.get_mut(index) {
            backend.mark_success();
        }
    }

    pub fn mark_failure(&mut self, index: usize) {
        if let Some(backend) = self.backends.get_mut(index) {
            backend.mark_failure();
        }
    }

    pub fn healthy_indices(&self) -> Vec<usize> {
        self.backends
            .iter()
            .enumerate()
            .filter_map(|(idx, backend)| backend.is_healthy().then_some(idx))
            .collect()
    }

    pub fn all_indices(&self) -> Vec<usize> {
        (0..self.backends.len()).collect()
    }

    pub fn backend(&self, index: usize) -> Option<&BackendState> {
        self.backends.get(index)
    }
}

pub enum LoadBalancing {
    RoundRobin(RoundRobin),
    ConsistentHash(ConsistentHash),
    Random(Random),
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
            _ => Err(format!("unsupported load balancing type: {value}")),
        }
    }

    pub fn pick(&mut self, key: &str, pool: &BackendPool) -> Option<usize> {
        match self {
            LoadBalancing::RoundRobin(rr) => rr.pick(pool),
            LoadBalancing::ConsistentHash(ch) => ch.pick(key, pool),
            LoadBalancing::Random(rand) => rand.pick(pool),
        }
    }
}

pub struct RoundRobin {
    next: usize,
}

impl RoundRobin {
    pub fn new() -> Self {
        Self { next: 0 }
    }

    pub fn pick(&mut self, pool: &BackendPool) -> Option<usize> {
        let candidates = pool.healthy_indices();
        if candidates.is_empty() {
            return None;
        }

        let idx = candidates[self.next % candidates.len()];
        self.next = self.next.wrapping_add(1);
        Some(idx)
    }
}

pub struct ConsistentHash {
    replicas: u32,
}

impl ConsistentHash {
    pub fn new(replicas: u32) -> Self {
        Self { replicas: replicas.max(1) }
    }

    pub fn pick(&self, key: &str, pool: &BackendPool) -> Option<usize> {
        if pool.is_empty() {
            return None;
        }

        let candidates = pool.healthy_indices();
        if candidates.is_empty() {
            return None;
        }

        let ring = build_ring(pool, &candidates, self.replicas);
        let key_hash = hash64(key.as_bytes());

        let (_, idx) = ring
            .range(key_hash..)
            .next()
            .or_else(|| ring.iter().next())?;

        Some(*idx)
    }
}

pub struct Random;

impl Random {
    pub fn new() -> Self {
        Self
    }

    pub fn pick(&mut self, pool: &BackendPool) -> Option<usize> {
        let candidates = pool.healthy_indices();
        if candidates.is_empty() {
            return None;
        }

        let mut rng = rand::thread_rng();
        let idx = rng.gen_range(0..candidates.len());
        Some(candidates[idx])
    }
}

fn build_ring(pool: &BackendPool, indices: &[usize], replicas: u32) -> BTreeMap<u64, usize> {
    let mut ring = BTreeMap::new();
    for &idx in indices {
        let backend = match pool.backend(idx) {
            Some(backend) => backend,
            None => continue,
        };

        let weight = backend.weight();
        let replicas = replicas.saturating_mul(weight);
        for replica in 0..replicas {
            let mut key = Vec::new();
            key.extend_from_slice(backend.address().as_bytes());
            key.extend_from_slice(b"-");
            key.extend_from_slice(replica.to_string().as_bytes());
            ring.insert(hash64(&key), idx);
        }
    }
    ring
}

fn hash64(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001b3;
    let mut hash = FNV_OFFSET;
    for byte in data {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(id: &str, address: &str, weight: u32) -> Backend {
        Backend {
            id: id.to_string(),
            address: address.to_string(),
            weight,
            health_check: spooky_config::config::HealthCheck {
                path: "/health".to_string(),
                interval: 1000,
            },
        }
    }

    #[test]
    fn round_robin_cycles() {
        let pool = BackendPool::new(vec![
            backend("a", "127.0.0.1:1", 1),
            backend("b", "127.0.0.1:2", 1),
            backend("c", "127.0.0.1:3", 1),
        ]);
        let mut rr = RoundRobin::new();

        let picks: Vec<usize> = (0..6).filter_map(|_| rr.pick(&pool)).collect();
        assert_eq!(picks, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn consistent_hash_is_stable() {
        let pool = BackendPool::new(vec![
            backend("a", "10.0.0.1:1", 1),
            backend("b", "10.0.0.2:1", 1),
            backend("c", "10.0.0.3:1", 1),
        ]);

        let ch = ConsistentHash::new(16);
        let first = ch.pick("user:123", &pool);
        let second = ch.pick("user:123", &pool);
        assert_eq!(first, second);
    }

    #[test]
    fn unhealthy_backends_are_skipped() {
        let mut pool = BackendPool::new(vec![
            backend("a", "10.0.0.1:1", 1),
            backend("b", "10.0.0.2:1", 1),
        ]);

        pool.mark_failure(0);
        pool.mark_failure(0);
        pool.mark_failure(0);

        let mut rr = RoundRobin::new();
        let pick = rr.pick(&pool).unwrap();
        assert_eq!(pick, 1);
    }

    #[test]
    fn load_balancing_from_config() {
        assert!(LoadBalancing::from_config("round-robin").is_ok());
        assert!(LoadBalancing::from_config("consistent-hash").is_ok());
        assert!(LoadBalancing::from_config("random").is_ok());
        assert!(LoadBalancing::from_config("unknown").is_err());
    }

    #[test]
    fn no_healthy_backends_returns_none() {
        let mut pool = BackendPool::new(vec![backend("a", "10.0.0.1:1", 1)]);
        pool.mark_failure(0);
        pool.mark_failure(0);
        pool.mark_failure(0);

        let mut rr = RoundRobin::new();
        assert!(rr.pick(&pool).is_none());
    }
}
