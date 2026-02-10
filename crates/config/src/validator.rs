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

    // --- Validate version ---
    if config.version != 1 {
        error!("Invalid version: expected '1', found '{}'", config.version);
        return false;
    }

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

    // --- Validate routes ---
    for route in &config.routes {
        if route.path.is_empty() {
            error!("Route path is empty");
            return false;
        }

        if !config.upstreams.contains_key(&route.upstream) {
            error!("Route '{}' references unknown upstream '{}'", route.path, route.upstream);
            return false;
        }
    }

    // --- Validate upstreams ---
    if config.upstreams.is_empty() {
        error!("No upstreams configured");
        return false;
    }

    for (upstream_name, upstream) in &config.upstreams {
        if upstream_name.is_empty() {
            error!("Upstream name is empty");
            return false;
        }

        if upstream.servers.is_empty() {
            error!("Upstream '{}' has no servers configured", upstream_name);
            return false;
        }

        // Validate strategy
        if upstream.strategy.is_empty() {
            error!("Upstream '{}' has empty strategy", upstream_name);
            return false;
        }

        // Validate servers
        for server in &upstream.servers {
            match server {
                crate::config::Server::Simple(address) => {
                    if address.is_empty() {
                        error!("Server address is empty in upstream '{}'", upstream_name);
                        return false;
                    }
                }
                crate::config::Server::Full { address, weight, max_conns: _ } => {
                    if address.is_empty() {
                        error!("Server address is empty in upstream '{}'", upstream_name);
                        return false;
                    }
                    if *weight == 0 {
                        error!("Server weight is invalid (0) for address '{}' in upstream '{}'", address, upstream_name);
                        return false;
                    }
                }
            }
        }

        // Validate health check if present
        if let Some(health_check) = &upstream.health_check {
            if health_check.interval == 0 {
                error!("Health check interval is invalid (0) for upstream '{}'", upstream_name);
                return false;
            }

            if health_check.timeout_ms == 0 {
                error!("Health check timeout is invalid (0) for upstream '{}'", upstream_name);
                return false;
            }

            if health_check.failure_threshold == 0 {
                error!("Health check failure threshold is invalid (0) for upstream '{}'", upstream_name);
                return false;
            }

            if health_check.success_threshold == 0 {
                error!("Health check success threshold is invalid (0) for upstream '{}'", upstream_name);
                return false;
            }

            if health_check.cooldown_ms == 0 {
                error!("Health check cooldown is invalid (0) for upstream '{}'", upstream_name);
                return false;
            }
        }
    }

    info!("Configuration validation passed successfully\n");

    true
}
