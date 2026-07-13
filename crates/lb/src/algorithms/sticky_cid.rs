use crate::{algorithms::consistent_hash::ConsistentHash, backend_pool::BackendPool};

pub struct StickyCid {
    inner: ConsistentHash,
}

impl StickyCid {
    pub fn new(replicas: u32) -> Self {
        Self {
            inner: ConsistentHash::new(replicas),
        }
    }

    pub fn pick(&mut self, key: &str, pool: &BackendPool) -> Option<usize> {
        if key.is_empty() {
            return pool.healthy.first().copied();
        }
        self.inner.pick(key, pool)
    }
}
