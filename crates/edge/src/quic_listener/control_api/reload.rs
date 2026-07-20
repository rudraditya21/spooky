use super::*;

impl QUICListener {
    pub(super) fn validate_runtime_reload_compatibility(
        current: &RuntimeBundle,
        next: &RuntimeBundle,
    ) -> Option<String> {
        for label in current.shared_state.listener_runtime_configs.keys() {
            if !next
                .shared_state
                .listener_runtime_configs
                .contains_key(label)
            {
                return Some(format!(
                    "runtime reload rejected: listener '{}' was removed or its bind address changed; restart required",
                    label
                ));
            }
        }

        let worker_count = next.runtime_config.performance.worker_threads.max(1);
        for (label, listener_config) in next.shared_state.listener_runtime_configs.iter() {
            if current
                .shared_state
                .listener_runtime_configs
                .contains_key(label)
            {
                continue;
            }
            if worker_count > 1 {
                if let Err(err) = Self::bind_reuseport_sockets(listener_config, worker_count) {
                    return Some(format!(
                        "runtime reload rejected: failed to preflight QUIC listener {}: {}",
                        label, err
                    ));
                }
            } else if let Err(err) = Self::bind_socket(listener_config, false) {
                return Some(format!(
                    "runtime reload rejected: failed to preflight QUIC listener {}: {}",
                    label, err
                ));
            }

            let bind = format!(
                "{}:{}",
                listener_config.listen.listen.address, listener_config.listen.listen.port
            );
            if let Err(err) = Self::probe_tcp_bind(&bind, "bootstrap TLS listener") {
                return Some(format!(
                    "runtime reload rejected: failed to preflight bootstrap listener {}: {}",
                    label, err
                ));
            }
        }
        None
    }

    pub(super) fn validate_control_api_reload_compatibility(
        current: &RuntimeBundle,
        next: &RuntimeBundle,
    ) -> Option<String> {
        let next_control_api = &next.runtime_config.observability.control_api;
        if !next_control_api.enabled {
            return None;
        }

        let Some(listener_config) = next.runtime_config.primary_listener_runtime_config() else {
            return Some(
                "runtime reload rejected: no effective listeners configured for control API TLS"
                    .to_string(),
            );
        };
        let primary_listener_label = Self::listener_label(&listener_config);
        if next
            .shared_state
            .listener_tls_store
            .bootstrap_server_config(&primary_listener_label)
            .is_none()
        {
            return Some(format!(
                "runtime reload rejected: control API TLS config missing for listener '{}'",
                primary_listener_label
            ));
        }

        let current_control_api = &current.runtime_config.observability.control_api;
        let bind_changed = !current_control_api.enabled
            || current_control_api.address != next_control_api.address
            || current_control_api.port != next_control_api.port;
        if bind_changed {
            let bind = format!("{}:{}", next_control_api.address, next_control_api.port);
            if let Err(err) = Self::probe_tcp_bind(&bind, "control API endpoint") {
                return Some(err);
            }
        }
        None
    }

    pub(super) fn validate_metrics_reload_compatibility(
        current: &RuntimeBundle,
        next: &RuntimeBundle,
    ) -> Option<String> {
        let next_metrics = &next.runtime_config.observability.metrics;
        if !next_metrics.enabled {
            return None;
        }

        let current_metrics = &current.runtime_config.observability.metrics;
        let bind_changed = !current_metrics.enabled
            || current_metrics.address != next_metrics.address
            || current_metrics.port != next_metrics.port;
        if bind_changed {
            let bind = format!("{}:{}", next_metrics.address, next_metrics.port);
            if let Err(err) = Self::probe_tcp_bind(&bind, "metrics endpoint") {
                return Some(err);
            }
        }
        None
    }

    pub(super) fn note_restart_required_change<T>(
        issues: &mut Vec<String>,
        field: &str,
        current: &T,
        next: &T,
    ) where
        T: PartialEq + std::fmt::Debug,
    {
        if current != next {
            issues.push(format!(
                "runtime reload rejected: {field} changed from {current:?} to {next:?}; restart required"
            ));
        }
    }

    pub(super) fn validate_startup_owned_reload_compatibility(
        current: &RuntimeBundle,
        next: &RuntimeBundle,
    ) -> Vec<String> {
        let mut issues = Vec::new();

        Self::note_restart_required_change(
            &mut issues,
            "log.file.enabled",
            &current.startup.log_config.file.enabled,
            &next.startup.log_config.file.enabled,
        );
        Self::note_restart_required_change(
            &mut issues,
            "log.file.path",
            &current.startup.log_config.file.path,
            &next.startup.log_config.file.path,
        );
        Self::note_restart_required_change(
            &mut issues,
            "log.format",
            &current.startup.log_config.format,
            &next.startup.log_config.format,
        );

        let current_tracing = &current.runtime_config.observability.tracing;
        let next_tracing = &next.runtime_config.observability.tracing;
        Self::note_restart_required_change(
            &mut issues,
            "observability.tracing.enabled",
            &current_tracing.enabled,
            &next_tracing.enabled,
        );
        Self::note_restart_required_change(
            &mut issues,
            "observability.tracing.service_name",
            &current_tracing.service_name,
            &next_tracing.service_name,
        );
        Self::note_restart_required_change(
            &mut issues,
            "observability.tracing.otlp_endpoint",
            &current_tracing.otlp_endpoint,
            &next_tracing.otlp_endpoint,
        );
        Self::note_restart_required_change(
            &mut issues,
            "observability.tracing.sample_ratio",
            &current_tracing.sample_ratio,
            &next_tracing.sample_ratio,
        );

        let current_perf = &current.runtime_config.performance;
        let next_perf = &next.runtime_config.performance;
        Self::note_restart_required_change(
            &mut issues,
            "performance.control_plane_threads",
            &current_perf.control_plane_threads,
            &next_perf.control_plane_threads,
        );

        issues
    }
}
