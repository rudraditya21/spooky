use bytes::Bytes;
use http_body_util::Full;

use super::{state::ControlApiState, *};

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
        let route = match Self::gate_control_api_request(&req, state) {
            Ok(route) => route,
            Err(response) => return response,
        };
        let watchdog = state.current_watchdog();

        if route == super::auth::ControlApiRoute::Health {
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

        if route == super::auth::ControlApiRoute::Ready {
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

        if route == super::auth::ControlApiRoute::Runtime {
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

        if route == super::auth::ControlApiRoute::ReloadCerts {
            let live_tls_store = state.current_listener_tls_store();
            let live_listener_configs = state.current_listener_runtime_configs();
            let live_metrics = state.current_metrics();
            return Self::reload_listener_certs(
                live_listener_configs.as_ref(),
                live_tls_store.as_ref(),
                live_metrics.as_ref(),
            );
        }

        if route == super::auth::ControlApiRoute::ReloadRuntime {
            let Some(runtime_bundle_handle) = state.runtime_bundle_handle() else {
                return Self::control_api_not_found_response();
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
                    "path": req.uri().path(),
                }),
            );
        }

        if route == super::auth::ControlApiRoute::Restart {
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

        Self::control_api_not_found_response()
    }
}
