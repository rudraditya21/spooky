use std::sync::atomic::{AtomicUsize, Ordering};

use crate::backend_pool::BackendPool;

pub struct RoundRobin {
    next: usize,
    next_read: AtomicUsize,
}

impl RoundRobin {
    pub fn new() -> Self {
        Self {
            next: 0,
            next_read: AtomicUsize::new(0),
        }
    }

    pub fn pick(&mut self, pool: &BackendPool) -> Option<usize> {
        if pool.healthy.is_empty() {
            return None;
        }

        let idx = pool.healthy[self.next % pool.healthy.len()];
        self.next = self.next.wrapping_add(1);
        Some(idx)
    }

    pub fn pick_readonly(&self, pool: &BackendPool) -> Option<usize> {
        if pool.healthy.is_empty() {
            return None;
        }

        let next = self.next_read.fetch_add(1, Ordering::Relaxed);
        let idx = pool.healthy[next % pool.healthy.len()];
        Some(idx)
    }
}

impl Default for RoundRobin {
    fn default() -> Self {
        Self::new()
    }
}
