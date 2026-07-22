use std::sync::atomic::AtomicUsize;

use ::http::{Method, header};
use bytes::Bytes;
use http_body_util::Full;

use super::{
    state::{ConnectionSlotGuard, ControlApiListenerBinding, ControlApiPaths, ControlApiState},
    *,
};
use crate::quic_listener::runtime_state::ControlPlaneBootstrap;

impl QUICListener {
    pub(super) fn apply_live_log_level_reload(
        current_level: &str,
        next_level: &str,
    ) -> Result<bool, spooky_utils::logger::LogLevelError> {
        if current_level == next_level {
            return Ok(false);
        }

        spooky_utils::logger::set_log_level(next_level)?;
        Ok(true)
    }

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

    pub(in crate::quic_listener) fn spawn_control_api_endpoint(
        bootstrap: &ControlPlaneBootstrap<'_>,
    ) -> Result<(), ProxyError> {
        let state = bootstrap.control_api_service_ctx();
        let endpoint = state.current_control_api();
        if bootstrap.runtime_bundle.is_none() && !endpoint.enabled {
            return Ok(());
        }
        let required = endpoint.required;
        let listener_config = state.current_runtime_view().runtime_config().primary_listener_runtime_config().ok_or_else(|| {
            ProxyError::Transport("no effective listeners configured".to_string())
        })?;
        let primary_listener_label = Self::listener_label(&listener_config);
        if endpoint.enabled
            && state
                .current_listener_tls_store()
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

        let initial_binding = if endpoint.enabled {
            let bind = format!("{}:{}", endpoint.address, endpoint.port);
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
            Some(state.current_metrics()),
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
                                info!("Control API endpoint ready bind=https://{}", desired_bind,);
                                info!(
                                    "Control API endpoint paths bind={} health={} ready={} runtime={} reload_certs={}",
                                    desired_bind,
                                    paths.health_path,
                                    paths.ready_path,
                                    paths.runtime_path,
                                    paths.reload_certs_path,
                                );
                                info!(
                                    "Control API endpoint limits bind={} max_connections={} connection_timeout_ms={}",
                                    desired_bind,
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
                        let Some(primary_listener_label) = state.current_primary_listener_label()
                        else {
                            error!(
                                "Control API endpoint missing live primary listener label for TLS selection"
                            );
                            return;
                        };
                        let Some(server_config) =
                            listener_tls_store.bootstrap_server_config(&primary_listener_label)
                        else {
                            error!(
                                "Control API endpoint missing live TLS config for listener {}",
                                primary_listener_label
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
        let mut staged = Vec::with_capacity(listener_runtime_configs.len());
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
            staged.push((listener_label.clone(), reloaded_state));
        }

        let generations = match listener_tls_store.replace_listeners(&staged) {
            Ok(generations) => generations,
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

        let mut reloaded = Vec::with_capacity(staged.len());
        for (listener_label, reloaded_state) in staged {
            Self::update_listener_tls_expiry_metrics(
                metrics,
                &listener_label,
                &reloaded_state.inventory,
            );
            reloaded.push(json!({
                "listener": listener_label,
                "generation": generations.get(&listener_label).copied().unwrap_or(0),
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
        let paths = state.current_paths();
        let path = req.uri().path();
        let watchdog = state.current_watchdog();

        if req.method() == Method::GET && path == paths.health_path.as_str() {
            let response = json!({
                "status": "ok",
                "uptime_ms": state.started_at.elapsed().as_millis() as u64,
                "watchdog": {
                    "enabled": watchdog.enabled(),
                    "degraded": watchdog.is_degraded(),
                    "restart_requested": watchdog.restart_requested(),
                },
            });
            return Self::json_response(StatusCode::OK, response);
        }

        if req.method() == Method::GET && path == paths.ready_path.as_str() {
            let backend_summary = state.snapshot_backend_health();
            let healthy_backends = backend_summary.healthy_backends;
            let total_backends = backend_summary.total_backends;
            let restart_requested = watchdog.restart_requested();
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
            let backend_inventory = state.snapshot_backend_inventory();
            let backend_summary = backend_inventory.summary();
            let healthy_backends = backend_summary.healthy_backends;
            let total_backends = backend_summary.total_backends;
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
            let resilience = state.current_resilience();
            let metrics = state.current_metrics();
            let mut response = serde_json::Map::from_iter([
                (
                    "uptime_ms".to_string(),
                    json!(state.started_at.elapsed().as_millis() as u64),
                ),
                (
                    "workers".to_string(),
                    json!({
                        "expected": state.current_expected_workers(),
                    }),
                ),
                (
                    "watchdog".to_string(),
                    json!({
                        "enabled": watchdog.enabled(),
                        "degraded": watchdog.is_degraded(),
                        "restart_requested": watchdog.restart_requested(),
                        "restart_reason": watchdog.restart_reason(),
                        "restart_requested_at_ms": watchdog.restart_requested_at_ms(),
                    }),
                ),
                (
                    "adaptive_admission".to_string(),
                    json!({
                        "enabled": resilience.adaptive_admission.enabled(),
                        "current_limit": resilience.adaptive_admission.current_limit(),
                        "inflight_percent": resilience.adaptive_admission.inflight_percent(),
                    }),
                ),
                (
                    "backends".to_string(),
                    json!({
                        "healthy": healthy_backends,
                        "total": total_backends,
                        "lifecycle": backend_inventory.backends.iter().map(|backend| {
                            json!({
                                "backend": backend.identity.backend_addr,
                                "health": match &backend.health {
                                    crate::runtime::backend::state::BackendHealthState::Unknown => "unknown",
                                    crate::runtime::backend::state::BackendHealthState::Healthy => "healthy",
                                    crate::runtime::backend::state::BackendHealthState::Unhealthy { .. } => "unhealthy",
                                },
                                "membership": match &backend.membership {
                                    crate::runtime::backend::state::BackendMembershipState::Active => "active",
                                    crate::runtime::backend::state::BackendMembershipState::Suppressed => "suppressed",
                                    crate::runtime::backend::state::BackendMembershipState::Removed => "removed",
                                },
                                "authority_host": backend.resolution.authority_host,
                                "authority_port": backend.resolution.authority_port,
                                "resolved_addrs": backend.resolution.resolved_addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
                                "resolution_generation": backend.resolution.refresh_generation,
                                "last_refresh_success_at_unix_seconds": backend.resolution.last_refresh_success_at.and_then(|time| time.duration_since(std::time::SystemTime::UNIX_EPOCH).ok()).map(|duration| duration.as_secs()),
                                "placements": backend.placements.iter().map(|placement| {
                                    json!({
                                        "upstream": placement.upstream_name,
                                        "backend_index": placement.backend_index,
                                        "healthy": placement.healthy,
                                        "active_requests": placement.active_requests,
                                        "ewma_latency_ms": placement.ewma_latency_ms,
                                        "membership_epoch": placement.membership_epoch,
                                    })
                                }).collect::<Vec<_>>(),
                            })
                        }).collect::<Vec<_>>(),
                    }),
                ),
                (
                    "metrics".to_string(),
                    json!({
                        "requests_total": metrics.requests_total.load(Ordering::Relaxed),
                        "requests_success": metrics.requests_success.load(Ordering::Relaxed),
                        "requests_failure": metrics.requests_failure.load(Ordering::Relaxed),
                        "active_connections": metrics.active_connections.load(Ordering::Relaxed),
                        "backend_timeouts": metrics.backend_timeouts.load(Ordering::Relaxed),
                        "backend_errors": metrics.backend_errors.load(Ordering::Relaxed),
                    }),
                ),
                (
                    "tls".to_string(),
                    json!({
                        "listeners": tls_listeners,
                    }),
                ),
                (
                    "extension_model".to_string(),
                    json!({
                        "status": "non_goal",
                        "details": "No plugin/middleware ABI is exposed in-process today; extension support remains a deliberate non-goal until a safe isolation model is designed.",
                    }),
                ),
            ]);
            if let Some(runtime) = state.current_generation() {
                response.insert(
                    "runtime".to_string(),
                    json!({
                        "generation": runtime.generation(),
                        "config_path": runtime.startup().config_path,
                    }),
                );
            }
            return Self::json_response(StatusCode::OK, serde_json::Value::Object(response));
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

            let Some(runtime_bundle_handle) = state.runtime_bundle_handle() else {
                return match Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from_static(b"not found\n")))
                {
                    Ok(resp) => resp,
                    Err(_) => Response::new(Full::new(Bytes::from_static(b"not found\n"))),
                };
            };
            let Some(runtime) = state.current_generation() else {
                return Self::json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({
                        "reloaded": false,
                        "error": "runtime generation unavailable",
                    }),
                );
            };

            let plan = match Self::build_runtime_reload_plan(&runtime) {
                Ok(plan) => plan,
                Err(err) => {
                    let status = if err.starts_with("Configuration validation failed:")
                        || err.starts_with("Runtime configuration normalization failed:")
                    {
                        StatusCode::BAD_REQUEST
                    } else {
                        StatusCode::INTERNAL_SERVER_ERROR
                    };
                    return Self::json_response(
                        status,
                        json!({
                            "reloaded": false,
                            "error": err,
                        }),
                    );
                }
            };
            if let Err(err) = Self::validate_runtime_reload_plan(&runtime, &plan.next_runtime) {
                return Self::json_response(
                    StatusCode::CONFLICT,
                    json!({
                        "reloaded": false,
                        "error": err,
                    }),
                );
            }
            let current_log_level = plan.current_log_level.clone();
            let next_log_level = plan.next_log_level.clone();
            let generation = match Self::apply_runtime_reload_plan(runtime_bundle_handle, plan) {
                Ok(generation) => generation,
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
            if let Err(err) = Self::apply_live_log_level_reload(&current_log_level, &next_log_level)
            {
                error!(
                    "Runtime reload applied generation={} but failed to update live log.level from '{}' to '{}': {}",
                    generation, current_log_level, next_log_level, err
                );
            }
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
            if !watchdog.enabled() {
                return Self::json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({
                        "accepted": false,
                        "error": "watchdog disabled",
                    }),
                );
            }

            let accepted = watchdog.request_restart("admin_runtime_api");
            return Self::json_response(
                if accepted {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::CONFLICT
                },
                json!({
                    "accepted": accepted,
                    "restart_requested": watchdog.restart_requested(),
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
