use spooky_config::config::{Backend, HealthCheck};
use spooky_lb::BackendState;

pub fn create_backend_state(address: &str, weight: u32) -> BackendState {
    let backend = Backend {
        id: format!("backend-{}", address),
        address: address.to_string(),
        weight,
        health_check: Some(HealthCheck {
            path: "/health".to_string(),
            interval: 1000,
            timeout_ms: 1000,
            failure_threshold: 3,
            success_threshold: 1,
            cooldown_ms: 0,
        }),
    };
    BackendState::new(&backend)
}
