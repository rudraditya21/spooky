use super::*;
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub(super) struct ControlApiPaths {
    pub(super) health_path: String,
    pub(super) ready_path: String,
    pub(super) runtime_path: String,
    pub(super) restart_path: String,
}

#[derive(Clone)]
pub(super) struct ControlApiState {
    pub(super) metrics: Arc<Metrics>,
    pub(super) resilience: Arc<RuntimeResilience>,
    pub(super) watchdog: Arc<WatchdogCoordinator>,
    pub(super) upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(super) expected_workers: usize,
    pub(super) started_at: Instant,
    pub(super) auth_token: Option<String>,
}

impl ControlApiState {
    pub(super) fn snapshot_backend_health(&self) -> (usize, usize) {
        let mut healthy = 0usize;
        let mut total = 0usize;
        for pool in self.upstream_pools.values() {
            let guard = match pool.read() {
                Ok(guard) => guard,
                Err(_) => continue,
            };
            let pool_total = guard.pool.len();
            total = total.saturating_add(pool_total);
            healthy = healthy.saturating_add(guard.pool.healthy_len().min(pool_total));
        }
        (healthy, total)
    }
}

impl QUICListener {
    pub(super) fn spawn_control_api_endpoint(
        config: &SpookyConfig,
        shared_state: &SharedRuntimeState,
        worker_count: usize,
    ) -> Result<(), ProxyError> {
        let endpoint = &config.observability.control_api;
        if !endpoint.enabled {
            return Ok(());
        }
        let required = endpoint.required;

        let bind = format!("{}:{}", endpoint.address, endpoint.port);
        let max_connections = endpoint.max_connections.max(1);
        let connection_timeout = Duration::from_millis(endpoint.connection_timeout_ms.max(1));
        let acceptor = match Self::build_server_tls_acceptor(
            config,
            false,
            vec![b"http/1.1".to_vec()],
        ) {
            Ok(acceptor) => acceptor,
            Err(err) => {
                let msg = format!("failed to initialize control API TLS config: {err}");
                if required {
                    return Err(ProxyError::Tls(msg));
                }
                error!("{}", msg);
                return Ok(());
            }
        };
        let paths = ControlApiPaths {
            health_path: endpoint.health_path.clone(),
            ready_path: endpoint.ready_path.clone(),
            runtime_path: endpoint.runtime_path.clone(),
            restart_path: endpoint.restart_path.clone(),
        };
        let state = ControlApiState {
            metrics: Arc::clone(&shared_state.metrics),
            resilience: Arc::clone(&shared_state.resilience),
            watchdog: Arc::clone(&shared_state.watchdog),
            upstream_pools: shared_state.upstream_pools.clone(),
            expected_workers: worker_count.max(1),
            started_at: Instant::now(),
            auth_token: endpoint.auth_token.clone(),
        };

        let handle = match runtime_handle() {
            Some(handle) => handle,
            None => {
                let msg = "control API disabled (no Tokio runtime available)".to_string();
                if required {
                    return Err(ProxyError::Transport(msg));
                }
                error!("{}", msg);
                return Ok(());
            }
        };

        let std_listener = match std::net::TcpListener::bind(&bind) {
            Ok(listener) => listener,
            Err(err) => {
                let msg = format!("failed to bind control API endpoint {bind}: {err}");
                if required {
                    return Err(ProxyError::Transport(msg));
                }
                error!("{}", msg);
                return Ok(());
            }
        };
        if let Err(err) = std_listener.set_nonblocking(true) {
            let msg = format!(
                "failed to set control API endpoint listener nonblocking ({}): {}",
                bind, err
            );
            if required {
                return Err(ProxyError::Transport(msg));
            }
            error!("{}", msg);
            return Ok(());
        }
        let listener = match {
            let _guard = handle.enter();
            tokio::net::TcpListener::from_std(std_listener)
        } {
            Ok(listener) => listener,
            Err(err) => {
                let msg = format!(
                    "failed to register control API endpoint listener {}: {}",
                    bind, err
                );
                if required {
                    return Err(ProxyError::Transport(msg));
                }
                error!("{}", msg);
                return Ok(());
            }
        };

        spawn_supervised_async_task(
            &handle,
            "control-api-endpoint",
            Some(Arc::clone(&shared_state.metrics)),
            async move {
                info!(
                    "Control API endpoint listening on https://{}{} (ready={}, runtime={}, max_connections={}, connection_timeout_ms={})",
                    bind,
                    paths.health_path,
                    paths.ready_path,
                    paths.runtime_path,
                    max_connections,
                    connection_timeout.as_millis()
                );
                let connection_limiter = Arc::new(Semaphore::new(max_connections));

                loop {
                    let (stream, peer) = match listener.accept().await {
                        Ok(v) => v,
                        Err(err) => {
                            error!("Control API endpoint accept failed: {}", err);
                            continue;
                        }
                    };
                    let permit = match Arc::clone(&connection_limiter).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            continue;
                        }
                    };

                    let acceptor = acceptor.clone();
                    let paths = paths.clone();
                    let state = state.clone();
                    let timeout = connection_timeout;

                    tokio::spawn(async move {
                        let _permit = permit;
                        let tls_stream = match acceptor.accept(stream).await {
                            Ok(stream) => stream,
                            Err(err) => {
                                error!(
                                    "Control API endpoint TLS handshake failed from {}: {}",
                                    peer, err
                                );
                                return;
                            }
                        };
                        let io = TokioIo::new(tls_stream);
                        let service = service_fn(move |req: Request<Incoming>| {
                            let paths = paths.clone();
                            let state = state.clone();
                            async move {
                                Ok::<_, hyper::Error>(Self::handle_control_api_request(
                                    req, &paths, &state,
                                ))
                            }
                        });

                        let serve = http1::Builder::new().serve_connection(io, service);
                        match tokio::time::timeout(timeout, serve).await {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) => {
                                error!("Control API endpoint connection failed: {}", err);
                            }
                            Err(_) => {
                                debug!("Control API endpoint connection timed out");
                            }
                        }
                    });
                }
            },
        );
        Ok(())
    }

    pub(super) fn json_response(
        status: StatusCode,
        value: serde_json::Value,
    ) -> Response<Full<Bytes>> {
        match Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(value.to_string())))
        {
            Ok(resp) => resp,
            Err(_) => Response::new(Full::new(Bytes::from_static(b"{\"error\":\"response\"}"))),
        }
    }

    pub(super) fn handle_control_api_request(
        req: Request<Incoming>,
        paths: &ControlApiPaths,
        state: &ControlApiState,
    ) -> Response<Full<Bytes>> {
        let path = req.uri().path();

        if req.method() == http::Method::GET && path == paths.health_path {
            let response = json!({
                "status": "ok",
                "uptime_ms": state.started_at.elapsed().as_millis() as u64,
                "watchdog": {
                    "enabled": state.watchdog.enabled(),
                    "degraded": state.watchdog.is_degraded(),
                    "restart_requested": state.watchdog.restart_requested(),
                },
            });
            return Self::json_response(StatusCode::OK, response);
        }

        if req.method() == http::Method::GET && path == paths.ready_path {
            let (healthy_backends, total_backends) = state.snapshot_backend_health();
            let restart_requested = state.watchdog.restart_requested();
            let ready = !restart_requested && (total_backends == 0 || healthy_backends > 0);
            let response = json!({
                "ready": ready,
                "healthy_backends": healthy_backends,
                "total_backends": total_backends,
                "restart_requested": restart_requested,
            });
            return Self::json_response(
                if ready {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                },
                response,
            );
        }

        if req.method() == http::Method::GET && path == paths.runtime_path {
            if !Self::control_api_is_authorized(&req, state) {
                return Self::json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({
                        "error": "unauthorized",
                    }),
                );
            }
            let (healthy_backends, total_backends) = state.snapshot_backend_health();
            let response = json!({
                "uptime_ms": state.started_at.elapsed().as_millis() as u64,
                "workers": {
                    "expected": state.expected_workers,
                },
                "watchdog": {
                    "enabled": state.watchdog.enabled(),
                    "degraded": state.watchdog.is_degraded(),
                    "restart_requested": state.watchdog.restart_requested(),
                    "restart_reason": state.watchdog.restart_reason(),
                    "restart_requested_at_ms": state.watchdog.restart_requested_at_ms(),
                },
                "adaptive_admission": {
                    "enabled": state.resilience.adaptive_admission.enabled(),
                    "current_limit": state.resilience.adaptive_admission.current_limit(),
                    "inflight_percent": state.resilience.adaptive_admission.inflight_percent(),
                },
                "backends": {
                    "healthy": healthy_backends,
                    "total": total_backends,
                },
                "metrics": {
                    "requests_total": state.metrics.requests_total.load(Ordering::Relaxed),
                    "requests_success": state.metrics.requests_success.load(Ordering::Relaxed),
                    "requests_failure": state.metrics.requests_failure.load(Ordering::Relaxed),
                    "active_connections": state.metrics.active_connections.load(Ordering::Relaxed),
                    "backend_timeouts": state.metrics.backend_timeouts.load(Ordering::Relaxed),
                    "backend_errors": state.metrics.backend_errors.load(Ordering::Relaxed),
                },
                "extension_model": {
                    "status": "non_goal",
                    "details": "No plugin/middleware ABI is exposed in-process today; extension support remains a deliberate non-goal until a safe isolation model is designed.",
                },
            });
            return Self::json_response(StatusCode::OK, response);
        }

        if req.method() == http::Method::POST && path == paths.restart_path {
            if !Self::control_api_is_authorized(&req, state) {
                return Self::json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({
                        "accepted": false,
                        "error": "unauthorized",
                    }),
                );
            }
            if !state.watchdog.enabled() {
                return Self::json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({
                        "accepted": false,
                        "error": "watchdog disabled",
                    }),
                );
            }

            let accepted = state.watchdog.request_restart("admin_runtime_api");
            return Self::json_response(
                if accepted {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::CONFLICT
                },
                json!({
                    "accepted": accepted,
                    "restart_requested": state.watchdog.restart_requested(),
                    "reason": if accepted { "admin_runtime_api" } else { "restart pending or cooldown active" },
                }),
            );
        }

        match Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from_static(b"not found\n")))
        {
            Ok(resp) => resp,
            Err(_) => Response::new(Full::new(Bytes::from_static(b"not found\n"))),
        }
    }

    pub(super) fn control_api_is_authorized(
        req: &Request<Incoming>,
        state: &ControlApiState,
    ) -> bool {
        let Some(token) = state.auth_token.as_ref() else {
            return false;
        };
        let Some(header) = req.headers().get(http::header::AUTHORIZATION) else {
            return false;
        };
        let Ok(raw) = header.to_str() else {
            return false;
        };
        let Some(provided) = raw.strip_prefix("Bearer ") else {
            return false;
        };
        bool::from(provided.as_bytes().ct_eq(token.as_bytes()))
    }

    pub(super) fn spawn_watchdog(
        config: &SpookyConfig,
        metrics: Arc<Metrics>,
        resilience: Arc<RuntimeResilience>,
        watchdog: Arc<WatchdogCoordinator>,
    ) {
        let watchdog_config = WatchdogRuntimeConfig::from(&config.resilience.watchdog);
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

        spawn_supervised_async_task(
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

                    let requested_at = watchdog.restart_requested_at_ms();
                    let grace_elapsed = requested_at != 0
                        && now.saturating_sub(requested_at) >= watchdog_config.drain_grace_ms;
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
                    let status = tokio::process::Command::new(program)
                        .args(args)
                        .env("SPOOKY_WATCHDOG_REASON", &restart_reason)
                        .status()
                        .await;
                    match status {
                        Ok(status) => {
                            info!(
                                "Watchdog restart hook exited with status {}",
                                status
                                    .code()
                                    .map(|code| code.to_string())
                                    .unwrap_or_else(|| "signal".to_string())
                            );
                        }
                        Err(err) => {
                            error!("Watchdog restart hook execution failed: {}", err);
                        }
                    }
                    metrics.inc_watchdog_restart_hook();

                    watchdog.complete_restart_cycle();
                }
            },
        );
    }
}
