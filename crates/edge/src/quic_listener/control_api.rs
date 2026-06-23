use super::*;
use spooky_config::config::ControlApi as ControlApiConfig;
use spooky_config::loader::read_config;
use spooky_config::runtime::RuntimeConfig;
use std::ffi::OsString;
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub(super) struct ControlApiPaths {
    pub(super) health_path: String,
    pub(super) ready_path: String,
    pub(super) runtime_path: String,
    pub(super) restart_path: String,
    pub(super) reload_path: String,
    pub(super) reload_certs_path: String,
}

impl ControlApiPaths {
    fn from_endpoint(endpoint: &ControlApiConfig) -> Self {
        Self {
            health_path: endpoint.health_path.clone(),
            ready_path: endpoint.ready_path.clone(),
            runtime_path: endpoint.runtime_path.clone(),
            restart_path: endpoint.restart_path.clone(),
            reload_path: endpoint.reload_path.clone(),
            reload_certs_path: endpoint.reload_certs_path.clone(),
        }
    }
}

#[derive(Clone)]
pub(super) struct ControlApiState {
    pub(super) control_api: ControlApiConfig,
    pub(super) metrics: Arc<Metrics>,
    pub(super) resilience: Arc<RuntimeResilience>,
    pub(super) watchdog: Arc<WatchdogCoordinator>,
    pub(super) upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(super) listener_runtime_configs: Arc<HashMap<String, ListenerRuntimeConfig>>,
    pub(super) listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub(super) primary_listener_label: String,
    pub(super) expected_workers: usize,
    pub(super) started_at: Instant,
    pub(super) runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
}

impl ControlApiState {
    fn current_runtime(&self) -> Option<Arc<RuntimeBundle>> {
        self.runtime_bundle.as_ref().map(|handle| handle.current())
    }

    fn current_control_api(&self) -> ControlApiConfig {
        self.current_runtime()
            .map(|runtime| runtime.runtime_config.observability.control_api.clone())
            .unwrap_or_else(|| self.control_api.clone())
    }

    fn current_paths(&self) -> ControlApiPaths {
        ControlApiPaths::from_endpoint(&self.current_control_api())
    }

    fn current_listener_tls_store(&self) -> Arc<ListenerTlsReloadStore> {
        self.current_runtime()
            .map(|runtime| runtime.shared_state.listener_tls_store.clone())
            .unwrap_or_else(|| Arc::clone(&self.listener_tls_store))
    }

    fn current_metrics(&self) -> Arc<Metrics> {
        self.current_runtime()
            .map(|runtime| runtime.shared_state.metrics.clone())
            .unwrap_or_else(|| Arc::clone(&self.metrics))
    }

    pub(super) fn snapshot_backend_health(&self) -> (usize, usize) {
        if let Some(runtime) = self.current_runtime() {
            let mut healthy = 0usize;
            let mut total = 0usize;
            for pool in runtime.shared_state.upstream_pools.values() {
                let guard = match pool.read() {
                    Ok(guard) => guard,
                    Err(_) => continue,
                };
                let pool_total = guard.pool.len();
                total = total.saturating_add(pool_total);
                healthy = healthy.saturating_add(guard.pool.healthy_len().min(pool_total));
            }
            return (healthy, total);
        }

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
    fn bearer_token_from_authorization_header(raw: &str) -> Option<&str> {
        let raw = raw.trim();
        let split = raw.find(char::is_whitespace)?;
        let (scheme, rest) = raw.split_at(split);
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        let token = rest.trim_start();
        if token.is_empty() {
            return None;
        }
        Some(token)
    }

    fn watchdog_restart_env(
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

    pub(super) fn spawn_control_api_endpoint(
        config: &RuntimeConfig,
        shared_state: &SharedRuntimeState,
        runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
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
        let listener_config = config.primary_listener_runtime_config().ok_or_else(|| {
            ProxyError::Transport("no effective listeners configured".to_string())
        })?;
        let primary_listener_label = Self::listener_label(&listener_config);
        if shared_state
            .listener_tls_store
            .bootstrap_server_config(&primary_listener_label)
            .is_none()
        {
            let msg = format!(
                "failed to initialize control API TLS config: missing reload state for listener '{}'",
                primary_listener_label
            );
            if required {
                return Err(ProxyError::Tls(msg));
            }
            error!("{}", msg);
            return Ok(());
        }
        let state = ControlApiState {
            control_api: endpoint.clone(),
            metrics: Arc::clone(&shared_state.metrics),
            resilience: Arc::clone(&shared_state.resilience),
            watchdog: Arc::clone(&shared_state.watchdog),
            upstream_pools: shared_state.upstream_pools.clone(),
            listener_runtime_configs: Arc::clone(&shared_state.listener_runtime_configs),
            listener_tls_store: Arc::clone(&shared_state.listener_tls_store),
            primary_listener_label,
            expected_workers: worker_count.max(1),
            started_at: Instant::now(),
            runtime_bundle,
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
        let from_std_result = {
            let _guard = handle.enter();
            tokio::net::TcpListener::from_std(std_listener)
        };
        let listener = match from_std_result {
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
                let paths = state.current_paths();
                info!(
                    "Control API endpoint listening on https://{}{} (ready={}, runtime={}, reload_certs={}, max_connections={}, connection_timeout_ms={})",
                    bind,
                    paths.health_path,
                    paths.ready_path,
                    paths.runtime_path,
                    paths.reload_certs_path,
                    max_connections,
                    connection_timeout.as_millis()
                );
                let active_connections = Arc::new(AtomicUsize::new(0));

                loop {
                    let (stream, peer) = match listener.accept().await {
                        Ok(v) => v,
                        Err(err) => {
                            error!("Control API endpoint accept failed: {}", err);
                            continue;
                        }
                    };
                    let state = state.clone();
                    let active_connections = Arc::clone(&active_connections);
                    let endpoint = state.current_control_api();
                    let max_connections = endpoint.max_connections.max(1);
                    if !Self::try_claim_connection_slot(&active_connections, max_connections) {
                        state
                            .current_metrics()
                            .inc_control_api_connection_limit_drop();
                        warn!(
                            "Control API endpoint dropped connection from {} due to max connection limit ({})",
                            peer, max_connections
                        );
                        continue;
                    }

                    tokio::spawn(async move {
                        let _connection_guard = ConnectionSlotGuard::new(active_connections);
                        let timeout = Duration::from_millis(
                            state.current_control_api().connection_timeout_ms.max(1),
                        );
                        let listener_tls_store = state.current_listener_tls_store();
                        let Some(server_config) = listener_tls_store
                            .bootstrap_server_config(&state.primary_listener_label)
                        else {
                            error!(
                                "Control API endpoint missing live TLS config for listener {}",
                                state.primary_listener_label
                            );
                            return;
                        };
                        let acceptor = TlsAcceptor::from(server_config);
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
                            let state = state.clone();
                            async move {
                                Ok::<_, hyper::Error>(Self::handle_control_api_request(req, &state))
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

    fn try_claim_connection_slot(
        active_connections: &Arc<AtomicUsize>,
        max_connections: usize,
    ) -> bool {
        loop {
            let current = active_connections.load(Ordering::Relaxed);
            if current >= max_connections {
                return false;
            }
            if active_connections
                .compare_exchange(
                    current,
                    current.saturating_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return true;
            }
        }
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
        state: &ControlApiState,
    ) -> Response<Full<Bytes>> {
        if state.runtime_bundle.is_some() {
            return Self::handle_runtime_control_api_request(req, state);
        }
        let paths = state.current_paths();
        let path = req.uri().path();

        if req.method() == http::Method::GET && path == paths.health_path.as_str() {
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

        if req.method() == http::Method::GET && path == paths.ready_path.as_str() {
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

        if req.method() == http::Method::GET && path == paths.runtime_path.as_str() {
            if !Self::control_api_is_authorized(&req, state) {
                return Self::json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({
                        "error": "unauthorized",
                    }),
                );
            }
            let (healthy_backends, total_backends) = state.snapshot_backend_health();
            let tls_listeners = state
                .listener_tls_store
                .snapshot()
                .into_iter()
                .map(|(listener, inventory)| {
                    (
                        listener.clone(),
                        json!({
                            "default_cert": inventory.default_identity.identity.cert_path,
                            "default_key": inventory.default_identity.identity.key_path,
                            "default_cert_not_after_unix_seconds": inventory.default_identity.metadata.not_after_unix_seconds,
                            "sni_names": inventory.sni_identities.keys().cloned().collect::<Vec<_>>(),
                            "client_auth_enabled": inventory.listener_tls.client_auth.enabled,
                            "require_client_cert": inventory.listener_tls.client_auth.require_client_cert,
                            "generation": state.listener_tls_store.generation(&listener).unwrap_or(0),
                        }),
                    )
                })
                .collect::<serde_json::Map<String, serde_json::Value>>();
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
                "tls": {
                    "listeners": tls_listeners,
                },
                "extension_model": {
                    "status": "non_goal",
                    "details": "No plugin/middleware ABI is exposed in-process today; extension support remains a deliberate non-goal until a safe isolation model is designed.",
                },
            });
            return Self::json_response(StatusCode::OK, response);
        }

        if req.method() == http::Method::POST && path == paths.reload_certs_path.as_str() {
            if !Self::control_api_is_authorized(&req, state) {
                return Self::json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({
                        "reloaded": false,
                        "error": "unauthorized",
                    }),
                );
            }

            let mut reloaded = Vec::new();
            for (listener_label, listener_config) in state.listener_runtime_configs.iter() {
                let reloaded_state = match Self::build_listener_tls_reload_state(listener_config) {
                    Ok(state) => state,
                    Err(err) => {
                        return Self::json_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            json!({
                                "reloaded": false,
                                "listener": listener_label,
                                "error": err.to_string(),
                            }),
                        );
                    }
                };
                let generation = match state.listener_tls_store.replace_listener(
                    listener_label,
                    reloaded_state.inventory.clone(),
                    reloaded_state.bootstrap_server_config,
                ) {
                    Ok(generation) => generation,
                    Err(err) => {
                        return Self::json_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            json!({
                                "reloaded": false,
                                "listener": listener_label,
                                "error": err.to_string(),
                            }),
                        );
                    }
                };
                Self::update_listener_tls_expiry_metrics(
                    &state.metrics,
                    listener_label,
                    &reloaded_state.inventory,
                );
                reloaded.push(json!({
                    "listener": listener_label,
                    "generation": generation,
                }));
            }

            return Self::json_response(
                StatusCode::ACCEPTED,
                json!({
                    "reloaded": true,
                    "listeners": reloaded,
                }),
            );
        }

        if req.method() == http::Method::POST && path == paths.restart_path.as_str() {
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

    fn handle_runtime_control_api_request(
        req: Request<Incoming>,
        state: &ControlApiState,
    ) -> Response<Full<Bytes>> {
        let paths = state.current_paths();
        let path = req.uri().path();
        let Some(runtime_bundle_handle) = state.runtime_bundle.as_ref() else {
            return Self::json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "error": "runtime bundle missing",
                }),
            );
        };
        let runtime = runtime_bundle_handle.current();
        let shared_state = &runtime.shared_state;

        if req.method() == http::Method::GET && path == paths.health_path.as_str() {
            let response = json!({
                "status": "ok",
                "uptime_ms": state.started_at.elapsed().as_millis() as u64,
                "watchdog": {
                    "enabled": shared_state.watchdog.enabled(),
                    "degraded": shared_state.watchdog.is_degraded(),
                    "restart_requested": shared_state.watchdog.restart_requested(),
                },
            });
            return Self::json_response(StatusCode::OK, response);
        }

        if req.method() == http::Method::GET && path == paths.ready_path.as_str() {
            let (healthy_backends, total_backends) = state.snapshot_backend_health();
            let restart_requested = shared_state.watchdog.restart_requested();
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

        if req.method() == http::Method::GET && path == paths.runtime_path.as_str() {
            if !Self::control_api_is_authorized(&req, state) {
                return Self::json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({
                        "error": "unauthorized",
                    }),
                );
            }
            let (healthy_backends, total_backends) = state.snapshot_backend_health();
            let tls_listeners = shared_state
                .listener_tls_store
                .snapshot()
                .into_iter()
                .map(|(listener, inventory)| {
                    (
                        listener.clone(),
                        json!({
                            "default_cert": inventory.default_identity.identity.cert_path,
                            "default_key": inventory.default_identity.identity.key_path,
                            "default_cert_not_after_unix_seconds": inventory.default_identity.metadata.not_after_unix_seconds,
                            "sni_names": inventory.sni_identities.keys().cloned().collect::<Vec<_>>(),
                            "client_auth_enabled": inventory.listener_tls.client_auth.enabled,
                            "require_client_cert": inventory.listener_tls.client_auth.require_client_cert,
                            "generation": shared_state.listener_tls_store.generation(&listener).unwrap_or(0),
                        }),
                    )
                })
                .collect::<serde_json::Map<String, serde_json::Value>>();
            let response = json!({
                "uptime_ms": state.started_at.elapsed().as_millis() as u64,
                "workers": {
                    "expected": state.expected_workers,
                },
                "watchdog": {
                    "enabled": shared_state.watchdog.enabled(),
                    "degraded": shared_state.watchdog.is_degraded(),
                    "restart_requested": shared_state.watchdog.restart_requested(),
                    "restart_reason": shared_state.watchdog.restart_reason(),
                    "restart_requested_at_ms": shared_state.watchdog.restart_requested_at_ms(),
                },
                "adaptive_admission": {
                    "enabled": shared_state.resilience.adaptive_admission.enabled(),
                    "current_limit": shared_state.resilience.adaptive_admission.current_limit(),
                    "inflight_percent": shared_state.resilience.adaptive_admission.inflight_percent(),
                },
                "backends": {
                    "healthy": healthy_backends,
                    "total": total_backends,
                },
                "metrics": {
                    "requests_total": shared_state.metrics.requests_total.load(Ordering::Relaxed),
                    "requests_success": shared_state.metrics.requests_success.load(Ordering::Relaxed),
                    "requests_failure": shared_state.metrics.requests_failure.load(Ordering::Relaxed),
                    "active_connections": shared_state.metrics.active_connections.load(Ordering::Relaxed),
                    "backend_timeouts": shared_state.metrics.backend_timeouts.load(Ordering::Relaxed),
                    "backend_errors": shared_state.metrics.backend_errors.load(Ordering::Relaxed),
                },
                "tls": {
                    "listeners": tls_listeners,
                },
                "runtime": {
                    "generation": runtime.generation,
                    "config_path": runtime.config_path,
                },
                "extension_model": {
                    "status": "non_goal",
                    "details": "No plugin/middleware ABI is exposed in-process today; extension support remains a deliberate non-goal until a safe isolation model is designed.",
                },
            });
            return Self::json_response(StatusCode::OK, response);
        }

        if req.method() == http::Method::POST
            && (path == paths.reload_certs_path.as_str() || path == paths.reload_path.as_str())
        {
            if !Self::control_api_is_authorized(&req, state) {
                return Self::json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({
                        "reloaded": false,
                        "error": "unauthorized",
                    }),
                );
            }

            let config_path = runtime.config_path.clone();
            let config = match read_config(&config_path) {
                Ok(config) => config,
                Err(err) => {
                    return Self::json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({
                            "reloaded": false,
                            "error": err,
                        }),
                    );
                }
            };
            if let Err(err) = spooky_config::validator::validate(&config) {
                return Self::json_response(
                    StatusCode::BAD_REQUEST,
                    json!({
                        "reloaded": false,
                        "error": format!("Configuration validation failed: {err}"),
                    }),
                );
            }
            let runtime_config = match RuntimeConfig::from_config(&config) {
                Ok(runtime_config) => runtime_config,
                Err(err) => {
                    return Self::json_response(
                        StatusCode::BAD_REQUEST,
                        json!({
                            "reloaded": false,
                            "error": format!("Runtime configuration normalization failed: {err}"),
                        }),
                    );
                }
            };
            let next_shared_state = match QUICListener::build_shared_state(&runtime_config) {
                Ok(shared_state) => Arc::new(shared_state),
                Err(err) => {
                    return Self::json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({
                            "reloaded": false,
                            "error": err.to_string(),
                        }),
                    );
                }
            };
            let next_runtime = RuntimeBundle {
                generation: runtime.generation.saturating_add(1),
                config_path,
                log_config: config.log.clone(),
                runtime_config,
                shared_state: Arc::clone(&next_shared_state),
            };
            if let Some((missing, existing)) =
                Self::validate_runtime_reload_compatibility(&runtime, &next_runtime)
            {
                return Self::json_response(
                    StatusCode::CONFLICT,
                    json!({
                        "reloaded": false,
                        "error": format!(
                            "runtime reload rejected: listener set changed (missing={missing:?}, extra={existing:?})"
                        ),
                    }),
                );
            }
            if let Some(err) =
                Self::validate_control_api_reload_compatibility(&runtime, &next_runtime)
            {
                return Self::json_response(
                    StatusCode::CONFLICT,
                    json!({
                        "reloaded": false,
                        "error": err,
                    }),
                );
            }
            if let Some(err) = Self::validate_metrics_reload_compatibility(&runtime, &next_runtime)
            {
                return Self::json_response(
                    StatusCode::CONFLICT,
                    json!({
                        "reloaded": false,
                        "error": err,
                    }),
                );
            }
            let startup_owned_issues =
                Self::validate_startup_owned_reload_compatibility(&runtime, &next_runtime);
            if !startup_owned_issues.is_empty() {
                return Self::json_response(
                    StatusCode::CONFLICT,
                    json!({
                        "reloaded": false,
                        "error": startup_owned_issues.join("; "),
                    }),
                );
            }
            QUICListener::spawn_generation_background_tasks(
                &next_runtime.runtime_config,
                next_runtime.shared_state.as_ref(),
            );
            let (generation, retired_tasks) = match runtime_bundle_handle.replace(next_runtime) {
                Ok(result) => result,
                Err(err) => {
                    return Self::json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({
                            "reloaded": false,
                            "error": err.to_string(),
                        }),
                    );
                }
            };
            tokio::spawn(async move {
                retired_tasks
                    .retire_with_timeout(Duration::from_secs(5))
                    .await;
            });
            return Self::json_response(
                StatusCode::ACCEPTED,
                json!({
                    "reloaded": true,
                    "generation": generation,
                    "path": path,
                }),
            );
        }

        if req.method() == http::Method::POST && path == paths.restart_path.as_str() {
            if !Self::control_api_is_authorized(&req, state) {
                return Self::json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({
                        "accepted": false,
                        "error": "unauthorized",
                    }),
                );
            }
            if !shared_state.watchdog.enabled() {
                return Self::json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({
                        "accepted": false,
                        "error": "watchdog disabled",
                    }),
                );
            }

            let accepted = shared_state.watchdog.request_restart("admin_runtime_api");
            return Self::json_response(
                if accepted {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::CONFLICT
                },
                json!({
                    "accepted": accepted,
                    "restart_requested": shared_state.watchdog.restart_requested(),
                    "reason": if accepted { "admin_runtime_api" } else { "restart pending or cooldown active" },
                }),
            );
        }

        match Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from_static(
                b"not found
",
            ))) {
            Ok(resp) => resp,
            Err(_) => Response::new(Full::new(Bytes::from_static(
                b"not found
",
            ))),
        }
    }

    fn validate_runtime_reload_compatibility(
        current: &RuntimeBundle,
        next: &RuntimeBundle,
    ) -> Option<(Vec<String>, Vec<String>)> {
        let current_labels = current
            .shared_state
            .listener_runtime_configs
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let next_labels = next
            .shared_state
            .listener_runtime_configs
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        if current_labels.len() != next_labels.len() {
            let missing = current_labels
                .iter()
                .filter(|label| {
                    !next
                        .shared_state
                        .listener_runtime_configs
                        .contains_key(*label)
                })
                .cloned()
                .collect::<Vec<_>>();
            let extra = next_labels
                .iter()
                .filter(|label| {
                    !current
                        .shared_state
                        .listener_runtime_configs
                        .contains_key(*label)
                })
                .cloned()
                .collect::<Vec<_>>();
            return Some((missing, extra));
        }
        if current_labels.iter().any(|label| {
            !next
                .shared_state
                .listener_runtime_configs
                .contains_key(label)
        }) {
            let missing = current_labels
                .iter()
                .filter(|label| {
                    !next
                        .shared_state
                        .listener_runtime_configs
                        .contains_key(*label)
                })
                .cloned()
                .collect::<Vec<_>>();
            let extra = next_labels
                .iter()
                .filter(|label| {
                    !current
                        .shared_state
                        .listener_runtime_configs
                        .contains_key(*label)
                })
                .cloned()
                .collect::<Vec<_>>();
            return Some((missing, extra));
        }
        None
    }

    fn validate_control_api_reload_compatibility(
        current: &RuntimeBundle,
        next: &RuntimeBundle,
    ) -> Option<String> {
        let current_control_api = &current.runtime_config.observability.control_api;
        let next_control_api = &next.runtime_config.observability.control_api;
        if current_control_api.enabled != next_control_api.enabled {
            return Some(format!(
                "runtime reload rejected: observability.control_api.enabled changed from {} to {}; restart required",
                current_control_api.enabled, next_control_api.enabled
            ));
        }
        if current_control_api.required != next_control_api.required {
            return Some(format!(
                "runtime reload rejected: observability.control_api.required changed from {} to {}; restart required",
                current_control_api.required, next_control_api.required
            ));
        }
        if current_control_api.address != next_control_api.address
            || current_control_api.port != next_control_api.port
        {
            return Some(format!(
                "runtime reload rejected: observability.control_api bind changed from {}:{} to {}:{}; restart required",
                current_control_api.address,
                current_control_api.port,
                next_control_api.address,
                next_control_api.port
            ));
        }
        None
    }

    fn validate_metrics_reload_compatibility(
        current: &RuntimeBundle,
        next: &RuntimeBundle,
    ) -> Option<String> {
        let current_metrics = &current.runtime_config.observability.metrics;
        let next_metrics = &next.runtime_config.observability.metrics;
        if current_metrics.enabled != next_metrics.enabled {
            return Some(format!(
                "runtime reload rejected: observability.metrics.enabled changed from {} to {}; restart required",
                current_metrics.enabled, next_metrics.enabled
            ));
        }
        if current_metrics.required != next_metrics.required {
            return Some(format!(
                "runtime reload rejected: observability.metrics.required changed from {} to {}; restart required",
                current_metrics.required, next_metrics.required
            ));
        }
        if current_metrics.address != next_metrics.address
            || current_metrics.port != next_metrics.port
        {
            return Some(format!(
                "runtime reload rejected: observability.metrics bind changed from {}:{} to {}:{}; restart required",
                current_metrics.address,
                current_metrics.port,
                next_metrics.address,
                next_metrics.port
            ));
        }
        None
    }

    fn note_restart_required_change<T>(issues: &mut Vec<String>, field: &str, current: &T, next: &T)
    where
        T: PartialEq + std::fmt::Debug,
    {
        if current != next {
            issues.push(format!(
                "runtime reload rejected: {field} changed from {current:?} to {next:?}; restart required"
            ));
        }
    }

    fn validate_startup_owned_reload_compatibility(
        current: &RuntimeBundle,
        next: &RuntimeBundle,
    ) -> Vec<String> {
        let mut issues = Vec::new();

        Self::note_restart_required_change(
            &mut issues,
            "log.level",
            &current.log_config.level,
            &next.log_config.level,
        );
        Self::note_restart_required_change(
            &mut issues,
            "log.file.enabled",
            &current.log_config.file.enabled,
            &next.log_config.file.enabled,
        );
        Self::note_restart_required_change(
            &mut issues,
            "log.file.path",
            &current.log_config.file.path,
            &next.log_config.file.path,
        );
        Self::note_restart_required_change(
            &mut issues,
            "log.format",
            &current.log_config.format,
            &next.log_config.format,
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
        Self::note_restart_required_change(
            &mut issues,
            "performance.worker_threads",
            &current_perf.worker_threads,
            &next_perf.worker_threads,
        );
        Self::note_restart_required_change(
            &mut issues,
            "performance.packet_shards_per_worker",
            &current_perf.packet_shards_per_worker,
            &next_perf.packet_shards_per_worker,
        );
        Self::note_restart_required_change(
            &mut issues,
            "performance.packet_shard_queue_capacity",
            &current_perf.packet_shard_queue_capacity,
            &next_perf.packet_shard_queue_capacity,
        );
        Self::note_restart_required_change(
            &mut issues,
            "performance.packet_shard_queue_max_bytes",
            &current_perf.packet_shard_queue_max_bytes,
            &next_perf.packet_shard_queue_max_bytes,
        );
        Self::note_restart_required_change(
            &mut issues,
            "performance.reuseport",
            &current_perf.reuseport,
            &next_perf.reuseport,
        );
        Self::note_restart_required_change(
            &mut issues,
            "performance.pin_workers",
            &current_perf.pin_workers,
            &next_perf.pin_workers,
        );
        Self::note_restart_required_change(
            &mut issues,
            "performance.udp_recv_buffer_bytes",
            &current_perf.udp_recv_buffer_bytes,
            &next_perf.udp_recv_buffer_bytes,
        );
        Self::note_restart_required_change(
            &mut issues,
            "performance.udp_send_buffer_bytes",
            &current_perf.udp_send_buffer_bytes,
            &next_perf.udp_send_buffer_bytes,
        );

        issues
    }

    pub(super) fn control_api_is_authorized(
        req: &Request<Incoming>,
        state: &ControlApiState,
    ) -> bool {
        let endpoint = state.current_control_api();
        let Some(token) = endpoint.auth_token.as_ref() else {
            return false;
        };
        let Some(header) = req.headers().get(http::header::AUTHORIZATION) else {
            return false;
        };
        let Ok(raw) = header.to_str() else {
            return false;
        };
        let Some(provided) = Self::bearer_token_from_authorization_header(raw) else {
            return false;
        };
        bool::from(provided.as_bytes().ct_eq(token.as_bytes()))
    }

    pub(super) fn spawn_watchdog(
        config: &RuntimeConfig,
        metrics: Arc<Metrics>,
        resilience: Arc<RuntimeResilience>,
        watchdog: Arc<WatchdogCoordinator>,
        task_registry: Arc<RuntimeTaskRegistry>,
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
        task_registry.register(registration);
    }
}

struct ConnectionSlotGuard {
    active_connections: Arc<AtomicUsize>,
}

impl ConnectionSlotGuard {
    fn new(active_connections: Arc<AtomicUsize>) -> Self {
        Self { active_connections }
    }
}

impl Drop for ConnectionSlotGuard {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{Certificate, CertificateParams, SanType};
    use spooky_config::{
        config::{
            Backend, ClientAuth, Config as SpookyConfigConfig, Listen, LoadBalancing, Log,
            Observability, Performance, Resilience, RouteMatch, Security, Tls, Upstream,
            UpstreamTls,
        },
        runtime::RuntimeConfig,
    };
    use std::{collections::HashMap, path::Path, sync::Arc};
    use tempfile::tempdir;

    fn write_test_cert_for_name(dir: &Path, cert_name: &str, dns_name: &str) -> (String, String) {
        let mut params = CertificateParams::new(vec![dns_name.to_string()]);
        params
            .subject_alt_names
            .push(SanType::DnsName(dns_name.to_string()));
        let cert = Certificate::from_params(params).expect("failed to build cert");

        let cert_path = dir.join(format!("{cert_name}.pem"));
        let key_path = dir.join(format!("{cert_name}.key.pem"));
        std::fs::write(&cert_path, cert.serialize_pem().expect("serialize cert"))
            .expect("write cert");
        std::fs::write(&key_path, cert.serialize_private_key_pem()).expect("write key");
        (
            cert_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
        )
    }

    fn test_config(cert: String, key: String) -> SpookyConfigConfig {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "api".to_string(),
            Upstream {
                load_balancing: LoadBalancing {
                    lb_type: "round-robin".to_string(),
                    key: None,
                },
                host_policy: Default::default(),
                forwarded_headers: Default::default(),
                tls: None,
                route: RouteMatch {
                    path_prefix: Some("/".to_string()),
                    ..Default::default()
                },
                backends: vec![Backend {
                    id: "b1".to_string(),
                    address: "http://127.0.0.1:7001".to_string(),
                    weight: 1,
                    health_check: None,
                }],
            },
        );

        SpookyConfigConfig {
            version: 1,
            listen: Listen {
                protocol: "http3".to_string(),
                port: 9889,
                address: "127.0.0.1".to_string(),
                tls: Tls {
                    cert,
                    key,
                    certificates: vec![],
                    client_auth: ClientAuth::default(),
                },
            },
            listeners: vec![],
            upstream: upstreams,
            load_balancing: Some(LoadBalancing {
                lb_type: "round-robin".to_string(),
                key: None,
            }),
            upstream_tls: UpstreamTls::default(),
            log: Log::default(),
            performance: Performance::default(),
            observability: Observability::default(),
            resilience: Resilience::default(),
            security: Security::default(),
        }
    }

    fn runtime_bundle_from_config(config_path: &str, config: &SpookyConfigConfig) -> RuntimeBundle {
        let runtime_config = RuntimeConfig::from_config(config).expect("runtime config");
        QUICListener::build_runtime_bundle(
            config_path.to_string(),
            config.log.clone(),
            &runtime_config,
        )
        .expect("runtime bundle")
    }

    fn control_api_state_with_runtime_bundle(
        startup: &SpookyConfigConfig,
        reloaded: &SpookyConfigConfig,
    ) -> ControlApiState {
        let startup_bundle = runtime_bundle_from_config("startup.yaml", startup);
        let reloaded_bundle = runtime_bundle_from_config("reloaded.yaml", reloaded);
        let listener_config = startup_bundle
            .runtime_config
            .primary_listener_runtime_config()
            .expect("listener runtime config");

        ControlApiState {
            control_api: startup_bundle
                .runtime_config
                .observability
                .control_api
                .clone(),
            metrics: Arc::clone(&startup_bundle.shared_state.metrics),
            resilience: Arc::clone(&startup_bundle.shared_state.resilience),
            watchdog: Arc::clone(&startup_bundle.shared_state.watchdog),
            upstream_pools: startup_bundle.shared_state.upstream_pools.clone(),
            listener_runtime_configs: Arc::clone(
                &startup_bundle.shared_state.listener_runtime_configs,
            ),
            listener_tls_store: Arc::clone(&startup_bundle.shared_state.listener_tls_store),
            primary_listener_label: QUICListener::listener_label(&listener_config),
            expected_workers: 1,
            started_at: Instant::now(),
            runtime_bundle: Some(Arc::new(RuntimeBundleHandle::new(reloaded_bundle))),
        }
    }

    #[test]
    fn watchdog_restart_env_keeps_path_when_present() {
        let env = QUICListener::watchdog_restart_env(
            Some(OsString::from("/usr/bin:/bin")),
            "timeout_spike",
        );
        let map: HashMap<OsString, OsString> = env.into_iter().collect();

        assert_eq!(
            map.get(&OsString::from("PATH")),
            Some(&OsString::from("/usr/bin:/bin"))
        );
        assert_eq!(
            map.get(&OsString::from("SPOOKY_WATCHDOG_REASON")),
            Some(&OsString::from("timeout_spike"))
        );
    }

    #[test]
    fn watchdog_restart_env_omits_path_when_missing() {
        let env = QUICListener::watchdog_restart_env(None, "poll_stall");
        let map: HashMap<OsString, OsString> = env.into_iter().collect();

        assert!(!map.contains_key(&OsString::from("PATH")));
        assert_eq!(
            map.get(&OsString::from("SPOOKY_WATCHDOG_REASON")),
            Some(&OsString::from("poll_stall"))
        );
    }

    #[test]
    fn bearer_authorization_scheme_is_case_insensitive() {
        assert_eq!(
            QUICListener::bearer_token_from_authorization_header("Bearer token-1"),
            Some("token-1")
        );
        assert_eq!(
            QUICListener::bearer_token_from_authorization_header("bearer token-2"),
            Some("token-2")
        );
        assert_eq!(
            QUICListener::bearer_token_from_authorization_header("BEARER token-3"),
            Some("token-3")
        );
    }

    #[test]
    fn bearer_authorization_rejects_malformed_headers() {
        assert_eq!(
            QUICListener::bearer_token_from_authorization_header("Basic abc"),
            None
        );
        assert_eq!(
            QUICListener::bearer_token_from_authorization_header("Bearer"),
            None
        );
        assert_eq!(
            QUICListener::bearer_token_from_authorization_header("Bearer   "),
            None
        );
    }

    #[test]
    fn control_api_state_prefers_reloaded_paths_and_auth_token() {
        let dir = tempdir().expect("tempdir");
        let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
        let mut startup = test_config(cert.clone(), key.clone());
        startup.observability.control_api.enabled = true;
        startup.observability.control_api.health_path = "/health-old".to_string();
        startup.observability.control_api.runtime_path = "/runtime-old".to_string();
        startup.observability.control_api.auth_token = Some("old-token".to_string());

        let mut reloaded = startup.clone();
        reloaded.observability.control_api.health_path = "/health-new".to_string();
        reloaded.observability.control_api.runtime_path = "/runtime-new".to_string();
        reloaded.observability.control_api.auth_token = Some("new-token".to_string());

        let state = control_api_state_with_runtime_bundle(&startup, &reloaded);
        let paths = state.current_paths();

        assert_eq!(paths.health_path, "/health-new");
        assert_eq!(paths.runtime_path, "/runtime-new");
        assert_eq!(
            state.current_control_api().auth_token.as_deref(),
            Some("new-token")
        );
    }

    #[test]
    fn validate_control_api_reload_compatibility_rejects_bind_change() {
        let dir = tempdir().expect("tempdir");
        let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
        let mut current = test_config(cert.clone(), key.clone());
        current.observability.control_api.enabled = true;
        current.observability.control_api.address = "127.0.0.1".to_string();
        current.observability.control_api.port = 9443;

        let mut next = current.clone();
        next.observability.control_api.port = 9555;

        let current_bundle = runtime_bundle_from_config("current.yaml", &current);
        let next_bundle = runtime_bundle_from_config("next.yaml", &next);
        let err =
            QUICListener::validate_control_api_reload_compatibility(&current_bundle, &next_bundle)
                .expect("bind change should be rejected");

        assert!(err.contains("observability.control_api bind changed"));
    }

    #[test]
    fn validate_metrics_reload_compatibility_rejects_bind_change() {
        let dir = tempdir().expect("tempdir");
        let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
        let mut current = test_config(cert.clone(), key.clone());
        current.observability.metrics.enabled = true;
        current.observability.metrics.address = "127.0.0.1".to_string();
        current.observability.metrics.port = 9100;

        let mut next = current.clone();
        next.observability.metrics.port = 9200;

        let current_bundle = runtime_bundle_from_config("current.yaml", &current);
        let next_bundle = runtime_bundle_from_config("next.yaml", &next);
        let err =
            QUICListener::validate_metrics_reload_compatibility(&current_bundle, &next_bundle)
                .expect("bind change should be rejected");

        assert!(err.contains("observability.metrics bind changed"));
    }

    #[test]
    fn validate_startup_owned_reload_compatibility_rejects_log_change() {
        let dir = tempdir().expect("tempdir");
        let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
        let current = test_config(cert.clone(), key.clone());

        let mut next = current.clone();
        next.log.level = "debug".to_string();

        let current_bundle = runtime_bundle_from_config("current.yaml", &current);
        let next_bundle = runtime_bundle_from_config("next.yaml", &next);
        let issues = QUICListener::validate_startup_owned_reload_compatibility(
            &current_bundle,
            &next_bundle,
        );

        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("log.level") && issue.contains("restart required"))
        );
    }

    #[test]
    fn validate_startup_owned_reload_compatibility_rejects_worker_topology_change() {
        let dir = tempdir().expect("tempdir");
        let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
        let current = test_config(cert.clone(), key.clone());

        let mut next = current.clone();
        next.performance.worker_threads = 4;
        next.performance.packet_shards_per_worker = 2;

        let current_bundle = runtime_bundle_from_config("current.yaml", &current);
        let next_bundle = runtime_bundle_from_config("next.yaml", &next);
        let issues = QUICListener::validate_startup_owned_reload_compatibility(
            &current_bundle,
            &next_bundle,
        );

        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("performance.worker_threads"))
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("performance.packet_shards_per_worker"))
        );
    }
}
