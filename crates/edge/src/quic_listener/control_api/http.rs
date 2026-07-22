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
            return Self::render_control_api_health(state);
        }

        if route == super::auth::ControlApiRoute::Ready {
            return Self::render_control_api_ready(state);
        }

        if route == super::auth::ControlApiRoute::Runtime {
            return Self::render_control_api_runtime_snapshot(state);
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
