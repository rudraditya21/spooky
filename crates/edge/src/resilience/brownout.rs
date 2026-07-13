use std::{
    collections::HashSet,
    sync::atomic::{AtomicBool, Ordering},
};

pub struct BrownoutController {
    enabled: bool,
    trigger_inflight_percent: u8,
    recover_inflight_percent: u8,
    core_routes: HashSet<String>,
    active: AtomicBool,
}

impl BrownoutController {
    pub fn new(
        enabled: bool,
        trigger_inflight_percent: u8,
        recover_inflight_percent: u8,
        core_routes: Vec<String>,
    ) -> Self {
        Self {
            enabled,
            trigger_inflight_percent: trigger_inflight_percent.min(100),
            recover_inflight_percent: recover_inflight_percent.min(100),
            core_routes: core_routes.into_iter().collect(),
            active: AtomicBool::new(false),
        }
    }

    pub fn observe_admission_pressure(&self, inflight_percent: u8) {
        if !self.enabled {
            self.active.store(false, Ordering::Relaxed);
            return;
        }

        let active = self.active.load(Ordering::Relaxed);
        if !active && inflight_percent >= self.trigger_inflight_percent {
            self.active.store(true, Ordering::Relaxed);
            return;
        }
        if active && inflight_percent <= self.recover_inflight_percent {
            self.active.store(false, Ordering::Relaxed);
        }
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    pub fn route_allowed(&self, route: &str) -> bool {
        if !self.enabled || !self.is_active() {
            return true;
        }
        self.core_routes.contains(route)
    }
}
