use super::state::{
    ConnectionSlotGuard, ControlApiListenerBinding, ControlApiPaths, ControlApiState,
};
use super::*;
use ::http::{Method, header};

impl QUICListener {
    pub(super) fn bearer_token_from_authorization_header(raw: &str) -> Option<&str> {
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

    pub(crate) fn spawn_control_api_endpoint(
        config: &RuntimeConfig,
        shared_state: &SharedRuntimeState,
        runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
        worker_count: usize,
    ) -> Result<(), ProxyError> {
        let endpoint = &config.observability.control_api;
        if runtime_bundle.is_none() && !endpoint.enabled {
            return Ok(());
        }
        let required = endpoint.required;
        let startup_endpoint = endpoint.clone();
        let listener_config = config.primary_listener_runtime_config().ok_or_else(|| {
            ProxyError::Transport("no effective listeners configured".to_string())
        })?;
        let primary_listener_label = Self::listener_label(&listener_config);
        if startup_endpoint.enabled
            && shared_state
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

        let initial_binding = if startup_endpoint.enabled {
            let bind = format!("{}:{}", startup_endpoint.address, startup_endpoint.port);
            match Self::bind_tcp_listener(&bind, Some(&handle), "control API endpoint") {
                Ok(listener) => Some(ControlApiListenerBinding {
                    bind,
                    listener,
                    active_connections: Arc::new(AtomicUsize::new(0)),
                }),
                Err(msg) => {
                    if required {
                        return Err(ProxyError::Transport(msg));
                    }
                    error!("{}", msg);
                    None
                }
            }
        } else {
            None
        };

        spawn_supervised_async_task(
            &handle,
            "control-api-endpoint",
            Some(Arc::clone(&shared_state.metrics)),
            async move {
                let mut listener_binding = initial_binding;

                loop {
                    let endpoint = state.current_control_api();
                    let desired_bind = format!("{}:{}", endpoint.address, endpoint.port);

                    if !endpoint.enabled {
                        if let Some(binding) = listener_binding.take() {
                            info!(
                                "Control API endpoint disabled via runtime reload on {}",
                                binding.bind
                            );
                        }
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }

                    let needs_rebind = match listener_binding.as_ref() {
                        Some(binding) => binding.bind != desired_bind,
                        None => true,
                    };
                    if needs_rebind {
                        match Self::bind_tcp_listener(&desired_bind, None, "control API endpoint") {
                            Ok(listener) => {
                                let paths = ControlApiPaths::from_endpoint(&endpoint);
                                info!(
                                    "Control API endpoint listening on https://{}{} (ready={}, runtime={}, reload_certs={}, max_connections={}, connection_timeout_ms={})",
                                    desired_bind,
                                    paths.health_path,
                                    paths.ready_path,
                                    paths.runtime_path,
                                    paths.reload_certs_path,
                                    endpoint.max_connections.max(1),
                                    endpoint.connection_timeout_ms.max(1)
                                );
                                listener_binding = Some(ControlApiListenerBinding {
                                    bind: desired_bind.clone(),
                                    listener,
                                    active_connections: Arc::new(AtomicUsize::new(0)),
                                });
                            }
                            Err(err) => {
                                error!("{}", err);
                                tokio::time::sleep(Duration::from_millis(200)).await;
                                continue;
                            }
                        }
                    }

                    let Some(binding) = listener_binding.as_mut() else {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    };

                    let accept_result = tokio::select! {
                        accept = binding.listener.accept() => Some(accept),
                        _ = tokio::time::sleep(Duration::from_millis(200)) => None,
                    };
                    let Some(accept_result) = accept_result else {
                        continue;
                    };
                    let (stream, peer) = match accept_result {
                        Ok(v) => v,
                        Err(err) => {
                            error!("Control API endpoint accept failed: {}", err);
                            continue;
                        }
                    };
                    let state = state.clone();
                    let active_connections = Arc::clone(&binding.active_connections);
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

    pub(super) fn reload_listener_certs(
        listener_runtime_configs: &HashMap<String, ListenerRuntimeConfig>,
        listener_tls_store: &ListenerTlsReloadStore,
        metrics: &Metrics,
    ) -> Response<Full<Bytes>> {
        let mut reloaded = Vec::new();
        for (listener_label, listener_config) in listener_runtime_configs {
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
            let generation = match listener_tls_store.replace_listener(
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
                metrics,
                listener_label,
                &reloaded_state.inventory,
            );
            reloaded.push(json!({
                "listener": listener_label,
                "generation": generation,
            }));
        }

        Self::json_response(
            StatusCode::ACCEPTED,
            json!({
                "reloaded": true,
                "listeners": reloaded,
            }),
        )
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

        if req.method() == Method::GET && path == paths.health_path.as_str() {
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

        if req.method() == Method::GET && path == paths.ready_path.as_str() {
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

        if req.method() == Method::GET && path == paths.runtime_path.as_str() {
            if !Self::control_api_is_authorized(&req, state) {
                return Self::json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({
                        "error": "unauthorized",
                    }),
                );
            }
            let (healthy_backends, total_backends) = state.snapshot_backend_health();
            let live_tls_store = state.current_listener_tls_store();
            let tls_listeners = live_tls_store
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
                            "generation": live_tls_store.generation(&listener).unwrap_or(0),
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

        if req.method() == Method::POST && path == paths.reload_certs_path.as_str() {
            if !Self::control_api_is_authorized(&req, state) {
                return Self::json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({
                        "reloaded": false,
                        "error": "unauthorized",
                    }),
                );
            }

            let live_tls_store = state.current_listener_tls_store();
            let live_listener_configs = state.current_listener_runtime_configs();
            let live_metrics = state.current_metrics();
            return Self::reload_listener_certs(
                live_listener_configs.as_ref(),
                live_tls_store.as_ref(),
                live_metrics.as_ref(),
            );
        }

        if req.method() == Method::POST && path == paths.restart_path.as_str() {
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

        if req.method() == Method::GET && path == paths.health_path.as_str() {
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

        if req.method() == Method::GET && path == paths.ready_path.as_str() {
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

        if req.method() == Method::GET && path == paths.runtime_path.as_str() {
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

        if req.method() == Method::POST && path == paths.reload_certs_path.as_str() {
            if !Self::control_api_is_authorized(&req, state) {
                return Self::json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({
                        "reloaded": false,
                        "error": "unauthorized",
                    }),
                );
            }

            return Self::reload_listener_certs(
                shared_state.listener_runtime_configs.as_ref(),
                shared_state.listener_tls_store.as_ref(),
                shared_state.metrics.as_ref(),
            );
        }

        if req.method() == Method::POST && path == paths.reload_path.as_str() {
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
            if let Some(err) = Self::validate_runtime_reload_compatibility(&runtime, &next_runtime)
            {
                return Self::json_response(
                    StatusCode::CONFLICT,
                    json!({
                        "reloaded": false,
                        "error": err,
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

        if req.method() == Method::POST && path == paths.restart_path.as_str() {
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
        let endpoint = state.current_control_api();
        let Some(token) = endpoint.auth_token.as_ref() else {
            return false;
        };
        let Some(header) = req.headers().get(header::AUTHORIZATION) else {
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
}
