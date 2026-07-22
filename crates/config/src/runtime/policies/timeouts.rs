use std::time::Duration;

use super::config_invalid;
use crate::{
    config::Performance,
    runtime::RuntimeConfigError,
};

fn require_nonzero_u64(name: &str, value: u64) -> Result<(), RuntimeConfigError> {
    if value == 0 {
        return Err(config_invalid(format!("{name} must be greater than 0")));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTimeoutPolicy {
    pub inflight_acquire_wait: Duration,
    pub backend_request: Duration,
    pub backend_connect: Duration,
    pub backend_body_idle: Duration,
    pub backend_body_total: Duration,
    pub backend_total_request: Duration,
    pub shutdown_drain: Duration,
    pub client_body_idle: Duration,
    pub h2_pool_idle: Duration,
    pub backend_dns_refresh_interval: Duration,
    pub quic_max_idle: Duration,
}

impl RuntimeTimeoutPolicy {
    pub(crate) fn normalize(performance: &Performance) -> Result<Self, RuntimeConfigError> {
        require_nonzero_u64(
            "performance.backend_timeout_ms",
            performance.backend_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.backend_connect_timeout_ms",
            performance.backend_connect_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.backend_body_idle_timeout_ms",
            performance.backend_body_idle_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.backend_body_total_timeout_ms",
            performance.backend_body_total_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.backend_total_request_timeout_ms",
            performance.backend_total_request_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.shutdown_drain_timeout_ms",
            performance.shutdown_drain_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.client_body_idle_timeout_ms",
            performance.client_body_idle_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.h2_pool_idle_timeout_ms",
            performance.h2_pool_idle_timeout_ms,
        )?;
        require_nonzero_u64(
            "performance.backend_dns_refresh_interval_ms",
            performance.backend_dns_refresh_interval_ms,
        )?;
        require_nonzero_u64(
            "performance.quic_max_idle_timeout_ms",
            performance.quic_max_idle_timeout_ms,
        )?;

        if performance.backend_connect_timeout_ms > performance.backend_timeout_ms {
            return Err(config_invalid(
                "performance.backend_connect_timeout_ms must be <= backend_timeout_ms",
            ));
        }
        if performance.backend_timeout_ms > performance.backend_body_idle_timeout_ms {
            return Err(config_invalid(
                "performance.backend_timeout_ms must be <= backend_body_idle_timeout_ms",
            ));
        }
        if performance.backend_body_idle_timeout_ms > performance.backend_body_total_timeout_ms {
            return Err(config_invalid(
                "performance.backend_body_idle_timeout_ms must be <= backend_body_total_timeout_ms",
            ));
        }
        if performance.backend_body_total_timeout_ms > performance.backend_total_request_timeout_ms
        {
            return Err(config_invalid(
                "performance.backend_body_total_timeout_ms must be <= backend_total_request_timeout_ms",
            ));
        }

        Ok(Self {
            inflight_acquire_wait: Duration::from_millis(performance.inflight_acquire_wait_ms),
            backend_request: Duration::from_millis(performance.backend_timeout_ms),
            backend_connect: Duration::from_millis(performance.backend_connect_timeout_ms),
            backend_body_idle: Duration::from_millis(performance.backend_body_idle_timeout_ms),
            backend_body_total: Duration::from_millis(performance.backend_body_total_timeout_ms),
            backend_total_request: Duration::from_millis(
                performance.backend_total_request_timeout_ms,
            ),
            shutdown_drain: Duration::from_millis(performance.shutdown_drain_timeout_ms),
            client_body_idle: Duration::from_millis(performance.client_body_idle_timeout_ms),
            h2_pool_idle: Duration::from_millis(performance.h2_pool_idle_timeout_ms),
            backend_dns_refresh_interval: Duration::from_millis(
                performance.backend_dns_refresh_interval_ms,
            ),
            quic_max_idle: Duration::from_millis(performance.quic_max_idle_timeout_ms),
        })
    }
}
