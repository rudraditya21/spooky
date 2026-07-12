use crate::backend_pool::BackendPool;
use crate::hash::{expected_ring_entries, hash_backend_replica, hash64};

pub struct ConsistentHash {
    replicas: u32,
    ring: Vec<(u64, usize)>,
    ring_epoch: Option<u64>,
    ring_rebuilds: u64,
}

impl ConsistentHash {
    pub fn new(replicas: u32) -> Self {
        Self {
            replicas: replicas.max(1),
            ring: Vec::new(),
            ring_epoch: None,
            ring_rebuilds: 0,
        }
    }

    pub fn pick(&mut self, key: &str, pool: &BackendPool) -> Option<usize> {
        if pool.is_empty() {
            return None;
        }

        let epoch = pool.membership_epoch();
        if self.ring_epoch != Some(epoch) {
            self.rebuild_ring(pool);
            self.ring_epoch = Some(epoch);
            self.ring_rebuilds = self.ring_rebuilds.wrapping_add(1);
        }

        if self.ring.is_empty() {
            return None;
        }

        let key_hash = hash64(key.as_bytes());
        let lookup_idx = match self.ring.binary_search_by(|(hash, _)| hash.cmp(&key_hash)) {
            Ok(idx) => idx,
            Err(idx) if idx < self.ring.len() => idx,
            Err(_) => 0,
        };

        Some(self.ring[lookup_idx].1)
    }

    fn rebuild_ring(&mut self, pool: &BackendPool) {
        self.ring.clear();

        let expected = expected_ring_entries(pool, self.replicas);
        if self.ring.capacity() < expected {
            self.ring.reserve(expected - self.ring.capacity());
        }

        for &idx in &pool.healthy {
            let backend = &pool.backends[idx];
            let replicas = self.replicas.saturating_mul(backend.weight());
            for replica in 0..replicas {
                self.ring
                    .push((hash_backend_replica(backend.address(), replica), idx));
            }
        }

        self.ring.sort_unstable();
    }
}
