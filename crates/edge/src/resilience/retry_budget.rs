use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::RetryReason;

pub struct RetryBudget {
    enabled: bool,
    global_ratio_percent: u8,
    per_route_ratio_percent: HashMap<String, u8>,
    global_primary: AtomicU64,
    global_retries: AtomicU64,
    route_stats: Mutex<HashMap<String, (u64, u64)>>,
}

impl RetryBudget {
    pub fn new(
        enabled: bool,
        global_ratio_percent: u8,
        per_route_ratio_percent: HashMap<String, u8>,
    ) -> Self {
        Self {
            enabled,
            global_ratio_percent,
            per_route_ratio_percent,
            global_primary: AtomicU64::new(0),
            global_retries: AtomicU64::new(0),
            route_stats: Mutex::new(HashMap::new()),
        }
    }

    pub fn mark_primary(&self, route: &str) {
        self.global_primary.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut stats) = self.route_stats.lock() {
            let entry = stats.entry(route.to_string()).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(1);
        }
    }

    pub fn allow_retry(&self, route: &str) -> Result<(), RetryReason> {
        if !self.enabled {
            return Ok(());
        }

        let ratio = self
            .per_route_ratio_percent
            .get(route)
            .copied()
            .unwrap_or(self.global_ratio_percent);

        let primary = self.global_primary.load(Ordering::Relaxed);
        let retries = self.global_retries.load(Ordering::Relaxed);
        let global_limit = ((primary * ratio as u64) / 100).saturating_add(1);
        if retries >= global_limit {
            return Err(RetryReason::BudgetDenied);
        }

        let mut route_allowed = true;
        if let Ok(mut stats) = self.route_stats.lock() {
            let entry = stats.entry(route.to_string()).or_insert((0, 0));
            let route_limit = ((entry.0 * ratio as u64) / 100).saturating_add(1);
            if entry.1 >= route_limit {
                route_allowed = false;
            } else {
                entry.1 = entry.1.saturating_add(1);
            }
        }
        if !route_allowed {
            return Err(RetryReason::BudgetDenied);
        }

        self.global_retries.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
