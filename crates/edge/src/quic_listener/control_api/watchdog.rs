use super::*;
use crate::quic_listener::runtime_state::WatchdogServiceCtx;

impl QUICListener {
    pub(super) fn watchdog_restart_env(
        path: Option<OsString>,
        restart_reason: &str,
    ) -> Vec<(OsString, OsString)> {
        let mut env_vars = Vec::with_capacity(2);
        if let Some(path_value) = path {
            env_vars.push((OsString::from("PATH"), path_value));
        }
        env_vars.push((
            OsString::from("SPOOKY_WATCHDOG_REASON"),
            OsString::from(restart_reason),
        ));
        env_vars
    }

    pub(in crate::quic_listener) fn spawn_watchdog(service_ctx: WatchdogServiceCtx) {
        let watchdog_config =
            WatchdogRuntimeConfig::from(&service_ctx.runtime.runtime_config().policies.admission.watchdog);
        let metrics = service_ctx.runtime.metrics();
        let resilience = service_ctx.runtime.resilience();
        let watchdog = service_ctx.runtime.watchdog();
        if !watchdog_config.enabled || !watchdog.enabled() {
            return;
        }

        let handle = match runtime_handle() {
            Some(handle) => handle,
            None => {
                error!("Watchdog disabled: no Tokio runtime available");
                return;
            }
        };

        let registration = spawn_supervised_async_task(
            &handle,
            "watchdog",
            Some(Arc::clone(&metrics)),
            async move {
                info!(
                    "Watchdog enabled: check_interval_ms={} poll_stall_timeout_ms={} timeout_error_rate_percent={} overload_inflight_percent={} unhealthy_windows={} drain_grace_ms={} restart_cooldown_ms={}",
                    watchdog_config.check_interval_ms,
                    watchdog_config.poll_stall_timeout_ms,
                    watchdog_config.timeout_error_rate_percent,
                    watchdog_config.overload_inflight_percent,
                    watchdog_config.unhealthy_consecutive_windows,
                    watchdog_config.drain_grace_ms,
                    watchdog_config.restart_cooldown_ms,
                );

                let mut interval =
                    tokio::time::interval(Duration::from_millis(watchdog_config.check_interval_ms));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let restart_program = watchdog_config
                    .restart_command
                    .first()
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty());
                let has_restart_command = restart_program.is_some();
                if watchdog_config
                    .restart_hook
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|value| !value.is_empty())
                {
                    warn!(
                        "Watchdog restart_hook is deprecated and ignored; configure resilience.watchdog.restart_command instead"
                    );
                }

                let mut previous_requests = metrics.requests_total.load(Ordering::Relaxed);
                let mut previous_timeouts = metrics.backend_timeouts.load(Ordering::Relaxed);
                let mut degraded_windows = 0u32;

                loop {
                    interval.tick().await;
                    let now = now_millis();
                    let stalled = now.saturating_sub(watchdog.last_poll_progress_ms())
                        > watchdog_config.poll_stall_timeout_ms;

                    let current_requests = metrics.requests_total.load(Ordering::Relaxed);
                    let current_timeouts = metrics.backend_timeouts.load(Ordering::Relaxed);
                    let request_delta = current_requests.saturating_sub(previous_requests);
                    let timeout_delta = current_timeouts.saturating_sub(previous_timeouts);
                    previous_requests = current_requests;
                    previous_timeouts = current_timeouts;

                    let timeout_rate_percent = timeout_delta
                        .saturating_mul(100)
                        .checked_div(request_delta)
                        .unwrap_or(0);

                    let timeout_pressure = request_delta >= watchdog_config.min_requests_per_window
                        && timeout_rate_percent
                            >= watchdog_config.timeout_error_rate_percent as u64;
                    let overload_pressure = resilience.adaptive_admission.inflight_percent()
                        >= watchdog_config.overload_inflight_percent;

                    if stalled || timeout_pressure || overload_pressure {
                        degraded_windows = degraded_windows.saturating_add(1);
                        watchdog.set_degraded(true);
                        metrics.inc_watchdog_degraded_window();
                    } else {
                        degraded_windows = 0;
                        watchdog.set_degraded(false);
                    }

                    if degraded_windows >= watchdog_config.unhealthy_consecutive_windows {
                        if !has_restart_command {
                            warn!(
                                "Watchdog detected unhealthy runtime state, but restart_command is not configured"
                            );
                            degraded_windows = 0;
                            continue;
                        }
                        let mut reasons = Vec::new();
                        if stalled {
                            reasons.push("poll_stall");
                        }
                        if timeout_pressure {
                            reasons.push("timeout_spike");
                        }
                        if overload_pressure {
                            reasons.push("inflight_overload");
                        }
                        let reason = reasons.join("+");
                        if watchdog.request_restart(&reason) {
                            metrics.inc_watchdog_restart_request();
                            warn!("Watchdog requested safe restart: {}", reason);
                        }
                        degraded_windows = 0;
                    }

                    if !watchdog.restart_requested() {
                        continue;
                    }

                    let grace_elapsed = watchdog
                        .restart_requested_elapsed_ms()
                        .is_some_and(|elapsed| elapsed >= watchdog_config.drain_grace_ms);
                    if !watchdog.workers_drained() && !grace_elapsed {
                        continue;
                    }

                    let restart_reason = watchdog.restart_reason();
                    if watchdog.workers_drained() {
                        info!(
                            "Watchdog safe restart condition reached (all workers drained): {}",
                            restart_reason
                        );
                    } else {
                        warn!(
                            "Watchdog restart drain grace elapsed; executing hook without full drain: {}",
                            restart_reason
                        );
                    }

                    let program = restart_program.as_deref().unwrap_or_default();
                    let args: Vec<&str> = watchdog_config
                        .restart_command
                        .iter()
                        .skip(1)
                        .map(String::as_str)
                        .collect();
                    let restart_env =
                        Self::watchdog_restart_env(std::env::var_os("PATH"), &restart_reason);
                    let mut command = tokio::process::Command::new(program);
                    command.args(args).env_clear();
                    for (key, value) in restart_env {
                        command.env(key, value);
                    }
                    let status = command.status().await;
                    match status {
                        Ok(status) => {
                            metrics.inc_watchdog_restart_hook();
                            let exit_status = status
                                .code()
                                .map(|code| code.to_string())
                                .unwrap_or_else(|| "signal".to_string());
                            if status.success() {
                                info!(
                                    "Watchdog restart hook exited successfully with status {}",
                                    exit_status
                                );
                                watchdog.complete_restart_cycle();
                            } else {
                                error!(
                                    "Watchdog restart hook exited unsuccessfully with status {}; keeping restart pending",
                                    exit_status
                                );
                            }
                        }
                        Err(err) => {
                            error!(
                                "Watchdog restart hook execution failed: {}; keeping restart pending",
                                err
                            );
                        }
                    }
                }
            },
        );
        service_ctx.task_registry.register(registration);
    }
}
