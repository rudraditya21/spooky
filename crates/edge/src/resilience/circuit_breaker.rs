use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Default)]
struct BreakerState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
    half_open_inflight: u32,
    half_open: bool,
}

pub struct CircuitBreakers {
    enabled: bool,
    failure_threshold: u32,
    open_for: Duration,
    half_open_max_probes: u32,
    states: Mutex<HashMap<String, BreakerState>>,
}

impl CircuitBreakers {
    pub fn new(
        enabled: bool,
        failure_threshold: u32,
        open_for: Duration,
        half_open_max_probes: u32,
    ) -> Self {
        Self {
            enabled,
            failure_threshold: failure_threshold.max(1),
            open_for,
            half_open_max_probes: half_open_max_probes.max(1),
            states: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow_request(&self, backend: &str) -> bool {
        if !self.enabled {
            return true;
        }
        let now = Instant::now();
        let mut states = match self.states.lock() {
            Ok(guard) => guard,
            Err(_) => return true,
        };
        let state = states.entry(backend.to_string()).or_default();

        if let Some(until) = state.open_until {
            if now < until {
                return false;
            }
            state.open_until = None;
            state.half_open = true;
            state.half_open_inflight = 0;
            state.consecutive_failures = 0;
        }

        if state.half_open {
            if state.half_open_inflight >= self.half_open_max_probes {
                return false;
            }
            state.half_open_inflight += 1;
        }

        true
    }

    pub fn record_success(&self, backend: &str) {
        if !self.enabled {
            return;
        }
        let mut states = match self.states.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        let state = states.entry(backend.to_string()).or_default();
        if state.half_open && state.half_open_inflight > 0 {
            state.half_open_inflight -= 1;
        }
        state.consecutive_failures = 0;
        state.open_until = None;
        state.half_open = false;
    }

    pub fn record_failure(&self, backend: &str) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let mut states = match self.states.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        let state = states.entry(backend.to_string()).or_default();

        if state.half_open {
            if state.half_open_inflight > 0 {
                state.half_open_inflight -= 1;
            }
            state.open_until = Some(now + self.open_for);
            state.half_open = false;
            state.consecutive_failures = 0;
            return;
        }

        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= self.failure_threshold {
            state.open_until = Some(now + self.open_for);
            state.half_open = false;
            state.consecutive_failures = 0;
        }
    }
}
