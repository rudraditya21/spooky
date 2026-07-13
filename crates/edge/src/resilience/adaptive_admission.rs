use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
pub struct AdaptiveAdmission {
    enabled: bool,
    min_limit: usize,
    max_limit: usize,
    increase_step: usize,
    decrease_step: usize,
    high_latency_ms: u64,
    current_limit: AtomicUsize,
    inflight: AtomicUsize,
}

impl AdaptiveAdmission {
    pub fn new(
        enabled: bool,
        min_limit: usize,
        max_limit: usize,
        increase_step: usize,
        decrease_step: usize,
        high_latency_ms: u64,
    ) -> Self {
        let max_limit = max_limit.max(1);
        let min_limit = min_limit.max(1).min(max_limit);
        Self {
            enabled,
            min_limit,
            max_limit,
            increase_step: increase_step.max(1),
            decrease_step: decrease_step.max(1),
            high_latency_ms: high_latency_ms.max(1),
            current_limit: AtomicUsize::new(max_limit),
            inflight: AtomicUsize::new(0),
        }
    }

    pub fn try_acquire(self: &Arc<Self>) -> Option<AdaptivePermit> {
        loop {
            let current = self.inflight.load(Ordering::Relaxed);
            let limit = self.current_limit.load(Ordering::Relaxed).max(1);
            if current >= limit {
                return None;
            }
            if self
                .inflight
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(AdaptivePermit {
                    admission: Arc::clone(self),
                });
            }
        }
    }

    pub fn observe(&self, latency: Duration, overloaded: bool) {
        if !self.enabled {
            return;
        }
        let latency_ms = latency.as_millis() as u64;
        let decrease = overloaded || latency_ms >= self.high_latency_ms;
        loop {
            let cur = self.current_limit.load(Ordering::Relaxed);
            let next = if decrease {
                cur.saturating_sub(self.decrease_step).max(self.min_limit)
            } else {
                cur.saturating_add(self.increase_step).min(self.max_limit)
            };

            if next == cur {
                return;
            }

            if self
                .current_limit
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }

    pub fn current_limit(&self) -> usize {
        self.current_limit.load(Ordering::Relaxed)
    }

    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Relaxed)
    }

    pub fn inflight_percent(&self) -> u8 {
        let limit = self.current_limit().max(1);
        ((self.inflight() * 100) / limit).min(100) as u8
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

pub struct AdaptivePermit {
    admission: Arc<AdaptiveAdmission>,
}

impl Drop for AdaptivePermit {
    fn drop(&mut self) {
        self.admission.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}
