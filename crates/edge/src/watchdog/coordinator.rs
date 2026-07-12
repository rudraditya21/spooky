use crate::watchdog::time::now_millis;
use log::warn;
use spooky_config::config::Watchdog as WatchdogConfig;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

pub struct WatchdogCoordinator {
    enabled: bool,
    restart_cooldown_ms: u64,
    last_poll_progress_ms: AtomicU64,
    degraded: AtomicBool,
    restart_requested: AtomicBool,
    restart_requested_at_ms: AtomicU64,
    restart_requested_at_instant: Mutex<Option<Instant>>,
    last_restart_at_instant: Mutex<Option<Instant>>,
    expected_workers: AtomicUsize,
    drained_workers: AtomicUsize,
    pub restart_reason: Mutex<String>,
}

impl WatchdogCoordinator {
    pub fn new(config: &WatchdogConfig) -> Self {
        let now_ms = now_millis();
        Self {
            enabled: config.enabled,
            restart_cooldown_ms: config.restart_cooldown_ms.max(1),
            last_poll_progress_ms: AtomicU64::new(now_ms),
            degraded: AtomicBool::new(false),
            restart_requested: AtomicBool::new(false),
            restart_requested_at_ms: AtomicU64::new(0),
            restart_requested_at_instant: Mutex::new(None),
            last_restart_at_instant: Mutex::new(None),
            expected_workers: AtomicUsize::new(1),
            drained_workers: AtomicUsize::new(0),
            restart_reason: Mutex::new(String::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_expected_workers(&self, workers: usize) {
        self.expected_workers
            .store(workers.max(1), Ordering::Relaxed);
    }

    pub fn mark_poll_progress(&self) {
        self.last_poll_progress_ms
            .store(now_millis(), Ordering::Relaxed);
    }

    pub fn last_poll_progress_ms(&self) -> u64 {
        self.last_poll_progress_ms.load(Ordering::Relaxed)
    }

    pub fn set_degraded(&self, degraded: bool) {
        self.degraded.store(degraded, Ordering::Relaxed);
    }

    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    pub fn request_restart(&self, reason: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let now_instant = Instant::now();
        if let Some(last_restart_instant) =
            *lock_or_recover(&self.last_restart_at_instant, "last_restart_at_instant")
            && now_instant.duration_since(last_restart_instant).as_millis()
                < self.restart_cooldown_ms as u128
        {
            return false;
        }
        if self
            .restart_requested
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }

        self.restart_requested_at_ms
            .store(now_millis(), Ordering::Relaxed);
        *lock_or_recover(
            &self.restart_requested_at_instant,
            "restart_requested_at_instant",
        ) = Some(now_instant);
        self.drained_workers.store(0, Ordering::Relaxed);
        *lock_or_recover(&self.restart_reason, "restart_reason") = reason.to_string();
        true
    }

    pub fn restart_requested(&self) -> bool {
        self.restart_requested.load(Ordering::Relaxed)
    }

    pub fn restart_reason(&self) -> String {
        lock_or_recover(&self.restart_reason, "restart_reason").clone()
    }

    pub fn restart_requested_at_ms(&self) -> u64 {
        self.restart_requested_at_ms.load(Ordering::Relaxed)
    }

    pub fn restart_requested_elapsed_ms(&self) -> Option<u64> {
        if !self.restart_requested() {
            return None;
        }
        let guard = lock_or_recover(
            &self.restart_requested_at_instant,
            "restart_requested_at_instant",
        );
        let started_at = (*guard)?;
        Some(Instant::now().duration_since(started_at).as_millis() as u64)
    }

    pub fn mark_worker_drained(&self) {
        if !self.restart_requested() {
            return;
        }
        self.drained_workers.fetch_add(1, Ordering::Relaxed);
    }

    pub fn workers_drained(&self) -> bool {
        let expected = self.expected_workers.load(Ordering::Relaxed).max(1);
        self.drained_workers.load(Ordering::Relaxed) >= expected
    }

    pub fn complete_restart_cycle(&self) {
        *lock_or_recover(&self.last_restart_at_instant, "last_restart_at_instant") =
            Some(Instant::now());
        *lock_or_recover(
            &self.restart_requested_at_instant,
            "restart_requested_at_instant",
        ) = None;
        self.restart_requested.store(false, Ordering::Relaxed);
        self.restart_requested_at_ms.store(0, Ordering::Relaxed);
        self.drained_workers.store(0, Ordering::Relaxed);
        self.degraded.store(false, Ordering::Relaxed);
    }
}

fn lock_or_recover<'a, T>(mutex: &'a Mutex<T>, field: &str) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!(
                "WatchdogCoordinator {} mutex poisoned; continuing with recovered inner state",
                field
            );
            poisoned.into_inner()
        }
    }
}
