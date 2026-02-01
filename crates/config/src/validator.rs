use crate::config::Config;
use log::{error, info};

pub const VALID_LOG_LEVELS: &[&str] = &[
    "whisper", "haunt", "spooky", "scream", "poltergeist", "silence",
    "trace", "debug", "info", "warn", "error", "off",
];

pub const VALID_LB_TYPES: &[&str] = &[
    "random",
    "round-robin",
    "round_robin",
    "rr",
    "consistent-hash",
    "consistent_hash",
    "ch",
];


pub fn validate(config: &Config) -> bool {
    info!("Starting configuration validation...");

    // --- Validate protocol ---
    if config.listen.protocol != "http3" {
        error!(
            "Invalid protocol: expected 'http3', found '{}'",
            config.listen.protocol
        );
        return false;
    }

    // --- Validate Log level ---
    if !VALID_LOG_LEVELS.iter().any(|lvl| lvl.eq_ignore_ascii_case(&config.log.level)) {
        error!(
            "Invalid Log Leve: {}",
            config.log.level
        );
        return false;
    }

    // --- Validate load balancing type ---
    if !VALID_LB_TYPES
        .iter()
        .any(|lb| lb.eq_ignore_ascii_case(&config.load_balancing.lb_type))
    {
        error!(
            "Invalid load balancing type: {}",
            config.load_balancing.lb_type
        );
        return false;
    }

    // --- Validate listen address ---
    if config.listen.address.is_empty() {
        error!("Listen address is empty");
        return false;
    }

    // --- Validate listen port ---
    if config.listen.port == 0 || config.listen.port > 65535 {
        error!(
            "Invalid listen port: {} (must be between 1 and 65535)",
            config.listen.port
        );
        return false;
    }

    // --- Validate TLS certs ---
    if !std::path::Path::new(&config.listen.tls.cert).exists() {
        error!("TLS certificate file does not exist: {}", config.listen.tls.cert);
        return false;
    }
    
    if !std::path::Path::new(&config.listen.tls.key).exists() {
        error!("TLS private key file does not exist: {}", config.listen.tls.key);
        return false;
    }
    
    // Optional: Try to read the files to ensure they're accessible
    if let Err(e) = std::fs::read(&config.listen.tls.cert) {
        error!("Cannot read TLS certificate file '{}': {}", config.listen.tls.cert, e);
        return false;
    }
    
    if let Err(e) = std::fs::read(&config.listen.tls.key) {
        error!("Cannot read TLS private key file '{}': {}", config.listen.tls.key, e);
        return false;
    }

    // --- Validate backends ---
    if config.backends.is_empty() {
        error!("No backends configured");
        return false;
    }

    for backend in &config.backends {
        if backend.id.is_empty() {
            error!("Backend id is missing");
            return false;
        }

        if backend.address.is_empty() {
            error!("Backend address is missing for backend id '{}'", backend.id);
            return false;
        }

        if backend.weight == 0 {
            error!(
                "Backend weight is invalid (0) for backend id '{}'",
                backend.id
            );
            return false;
        }

        if backend.health_check.interval == 0 {
            error!(
                "Health check interval is invalid (0) for backend id '{}'",
                backend.id
            );
            return false;
        }

        if backend.health_check.timeout_ms == 0 {
            error!(
                "Health check timeout is invalid (0) for backend id '{}'",
                backend.id
            );
            return false;
        }

        if backend.health_check.failure_threshold == 0 {
            error!(
                "Health check failure threshold is invalid (0) for backend id '{}'",
                backend.id
            );
            return false;
        }

        if backend.health_check.success_threshold == 0 {
            error!(
                "Health check success threshold is invalid (0) for backend id '{}'",
                backend.id
            );
            return false;
        }

        if backend.health_check.cooldown_ms == 0 {
            error!(
                "Health check cooldown is invalid (0) for backend id '{}'",
                backend.id
            );
            return false;
        }
    }

    info!("Configuration validation passed successfully\n");

    true
}
