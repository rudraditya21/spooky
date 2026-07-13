use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub struct RouteQueueLimiter {
    default_cap: usize,
    global_cap: usize,
    caps: HashMap<String, usize>,
    inflight: Mutex<RouteQueueState>,
}

#[derive(Default)]
struct RouteQueueState {
    total: usize,
    by_route: HashMap<String, usize>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RouteQueueRejection {
    GlobalCap,
    RouteCap,
}

impl RouteQueueLimiter {
    pub fn new(default_cap: usize, global_cap: usize, caps: HashMap<String, usize>) -> Self {
        Self {
            default_cap: default_cap.max(1),
            global_cap: global_cap.max(1),
            caps,
            inflight: Mutex::new(RouteQueueState::default()),
        }
    }

    pub fn try_acquire(
        self: &Arc<Self>,
        route: &str,
    ) -> Result<RouteQueuePermit, RouteQueueRejection> {
        let cap = self
            .caps
            .get(route)
            .copied()
            .unwrap_or(self.default_cap)
            .max(1);
        let mut guard = self
            .inflight
            .lock()
            .map_err(|_| RouteQueueRejection::GlobalCap)?;
        if guard.total >= self.global_cap {
            return Err(RouteQueueRejection::GlobalCap);
        }
        let current = guard.by_route.get(route).copied().unwrap_or(0);
        if current >= cap {
            return Err(RouteQueueRejection::RouteCap);
        }
        guard.total = guard.total.saturating_add(1);
        guard.by_route.insert(route.to_string(), current + 1);
        Ok(RouteQueuePermit {
            limiter: Arc::clone(self),
            route: route.to_string(),
        })
    }
}

pub struct RouteQueuePermit {
    limiter: Arc<RouteQueueLimiter>,
    route: String,
}

impl Drop for RouteQueuePermit {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.limiter.inflight.lock()
            && let Some(current) = guard.by_route.get_mut(&self.route)
        {
            *current = current.saturating_sub(1);
            if *current == 0 {
                guard.by_route.remove(&self.route);
            }
            guard.total = guard.total.saturating_sub(1);
        }
    }
}
