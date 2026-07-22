use std::collections::HashMap;

use bytes::Bytes;
use http_body_util::Full;
use serde::Serialize;

use super::{state::ControlApiState, *};
use crate::runtime::backend::state::{
    BackendHealthState, BackendLifecycleInventorySnapshot, BackendMembershipState,
    BackendPoolPlacementSnapshot,
};

#[derive(Serialize)]
struct ControlApiHealthPayload {
    status: &'static str,
    uptime_ms: u64,
    watchdog: ControlApiHealthWatchdogPayload,
}

#[derive(Serialize)]
struct ControlApiHealthWatchdogPayload {
    enabled: bool,
    degraded: bool,
    restart_requested: bool,
}

#[derive(Serialize)]
struct ControlApiReadyPayload {
    ready: bool,
    healthy_backends: usize,
    total_backends: usize,
    restart_requested: bool,
}

#[derive(Serialize)]
struct ControlApiRuntimePayload {
    uptime_ms: u64,
    workers: ControlApiWorkerPayload,
    watchdog: ControlApiRuntimeWatchdogPayload,
    adaptive_admission: ControlApiAdaptiveAdmissionPayload,
    backends: ControlApiBackendInventoryPayload,
    metrics: ControlApiMetricsPayload,
    tls: ControlApiTlsPayload,
    extension_model: ControlApiExtensionModelPayload,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime: Option<ControlApiRuntimeGenerationPayload>,
}

#[derive(Serialize)]
struct ControlApiWorkerPayload {
    expected: usize,
}

#[derive(Serialize)]
struct ControlApiRuntimeWatchdogPayload {
    enabled: bool,
    degraded: bool,
    restart_requested: bool,
    restart_reason: String,
    restart_requested_at_ms: u64,
}

#[derive(Serialize)]
struct ControlApiAdaptiveAdmissionPayload {
    enabled: bool,
    current_limit: usize,
    inflight_percent: u8,
}

#[derive(Serialize)]
struct ControlApiBackendInventoryPayload {
    healthy: usize,
    total: usize,
    lifecycle: Vec<ControlApiBackendLifecyclePayload>,
}

#[derive(Serialize)]
struct ControlApiBackendLifecyclePayload {
    backend: String,
    health: &'static str,
    membership: &'static str,
    authority_host: String,
    authority_port: u16,
    resolved_addrs: Vec<String>,
    resolution_generation: u64,
    last_refresh_success_at_unix_seconds: Option<u64>,
    placements: Vec<ControlApiBackendPlacementPayload>,
}

#[derive(Serialize)]
struct ControlApiBackendPlacementPayload {
    upstream: String,
    backend_index: usize,
    healthy: bool,
    active_requests: usize,
    ewma_latency_ms: Option<f64>,
    membership_epoch: u64,
}

#[derive(Serialize)]
struct ControlApiMetricsPayload {
    requests_total: u64,
    requests_success: u64,
    requests_failure: u64,
    active_connections: u64,
    backend_timeouts: u64,
    backend_errors: u64,
}

#[derive(Serialize)]
struct ControlApiTlsPayload {
    listeners: HashMap<String, ControlApiTlsListenerPayload>,
}

#[derive(Serialize)]
struct ControlApiTlsListenerPayload {
    default_cert: String,
    default_key: String,
    default_cert_not_after_unix_seconds: i64,
    sni_names: Vec<String>,
    client_auth_enabled: bool,
    require_client_cert: bool,
    generation: u64,
}

#[derive(Serialize)]
struct ControlApiExtensionModelPayload {
    status: &'static str,
    details: &'static str,
}

#[derive(Serialize)]
struct ControlApiRuntimeGenerationPayload {
    generation: u64,
    config_path: String,
}

impl QUICListener {
    pub(super) fn json_response<T>(status: StatusCode, value: T) -> Response<Full<Bytes>>
    where
        T: Serialize,
    {
        let body = match serde_json::to_vec(&value) {
            Ok(body) => body,
            Err(_) => br#"{"error":"response"}"#.to_vec(),
        };
        match Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
        {
            Ok(resp) => resp,
            Err(_) => Response::new(Full::new(Bytes::from_static(b"{\"error\":\"response\"}"))),
        }
    }

    pub(super) fn render_control_api_health(state: &ControlApiState) -> Response<Full<Bytes>> {
        let watchdog = state.current_watchdog();
        let payload = ControlApiHealthPayload {
            status: "ok",
            uptime_ms: state.started_at.elapsed().as_millis() as u64,
            watchdog: ControlApiHealthWatchdogPayload {
                enabled: watchdog.enabled(),
                degraded: watchdog.is_degraded(),
                restart_requested: watchdog.restart_requested(),
            },
        };
        Self::json_response(StatusCode::OK, payload)
    }

    pub(super) fn render_control_api_ready(state: &ControlApiState) -> Response<Full<Bytes>> {
        let backend_summary = state.snapshot_backend_health();
        let restart_requested = state.current_watchdog().restart_requested();
        let payload = ControlApiReadyPayload {
            ready: !restart_requested
                && (backend_summary.total_backends == 0 || backend_summary.healthy_backends > 0),
            healthy_backends: backend_summary.healthy_backends,
            total_backends: backend_summary.total_backends,
            restart_requested,
        };
        Self::json_response(
            if payload.ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            payload,
        )
    }

    pub(super) fn render_control_api_runtime_snapshot(
        state: &ControlApiState,
    ) -> Response<Full<Bytes>> {
        let payload = ControlApiRuntimePayload::from_state(state);
        Self::json_response(StatusCode::OK, payload)
    }
}

impl ControlApiRuntimePayload {
    fn from_state(state: &ControlApiState) -> Self {
        let runtime = state.current_runtime_view();
        let watchdog = runtime.watchdog();
        let resilience = runtime.resilience();
        let metrics = runtime.metrics();
        let listener_tls_store = runtime.listener_tls_store();
        let backend_inventory = runtime
            .backend_lifecycle()
            .snapshot_inventory(runtime.upstream_pools());
        let backend_summary = backend_inventory.summary();

        Self {
            uptime_ms: state.started_at.elapsed().as_millis() as u64,
            workers: ControlApiWorkerPayload {
                expected: runtime.expected_workers(),
            },
            watchdog: ControlApiRuntimeWatchdogPayload {
                enabled: watchdog.enabled(),
                degraded: watchdog.is_degraded(),
                restart_requested: watchdog.restart_requested(),
                restart_reason: watchdog.restart_reason(),
                restart_requested_at_ms: watchdog.restart_requested_at_ms(),
            },
            adaptive_admission: ControlApiAdaptiveAdmissionPayload {
                enabled: resilience.adaptive_admission.enabled(),
                current_limit: resilience.adaptive_admission.current_limit(),
                inflight_percent: resilience.adaptive_admission.inflight_percent(),
            },
            backends: ControlApiBackendInventoryPayload::from_inventory(
                backend_inventory,
                backend_summary.healthy_backends,
                backend_summary.total_backends,
            ),
            metrics: ControlApiMetricsPayload {
                requests_total: metrics.requests_total.load(Ordering::Relaxed),
                requests_success: metrics.requests_success.load(Ordering::Relaxed),
                requests_failure: metrics.requests_failure.load(Ordering::Relaxed),
                active_connections: metrics.active_connections.load(Ordering::Relaxed),
                backend_timeouts: metrics.backend_timeouts.load(Ordering::Relaxed),
                backend_errors: metrics.backend_errors.load(Ordering::Relaxed),
            },
            tls: ControlApiTlsPayload {
                listeners: listener_tls_store
                    .snapshot()
                    .into_iter()
                    .map(|(listener, inventory)| {
                        (
                            listener.clone(),
                            ControlApiTlsListenerPayload {
                                default_cert: inventory.default_identity.identity.cert_path,
                                default_key: inventory.default_identity.identity.key_path,
                                default_cert_not_after_unix_seconds: inventory
                                    .default_identity
                                    .metadata
                                    .not_after_unix_seconds,
                                sni_names: inventory.sni_identities.keys().cloned().collect(),
                                client_auth_enabled: inventory.listener_tls.client_auth.enabled,
                                require_client_cert: inventory
                                    .listener_tls
                                    .client_auth
                                    .require_client_cert,
                                generation: listener_tls_store.generation(&listener).unwrap_or(0),
                            },
                        )
                    })
                    .collect(),
            },
            extension_model: ControlApiExtensionModelPayload {
                status: "non_goal",
                details: "No plugin/middleware ABI is exposed in-process today; extension support remains a deliberate non-goal until a safe isolation model is designed.",
            },
            runtime: state
                .current_generation()
                .map(|active| ControlApiRuntimeGenerationPayload {
                    generation: active.generation(),
                    config_path: active.startup().config_path.clone(),
                }),
        }
    }
}

impl ControlApiBackendInventoryPayload {
    fn from_inventory(
        inventory: BackendLifecycleInventorySnapshot,
        healthy: usize,
        total: usize,
    ) -> Self {
        Self {
            healthy,
            total,
            lifecycle: inventory
                .backends
                .into_iter()
                .map(|backend| ControlApiBackendLifecyclePayload {
                    backend: backend.identity.backend_addr,
                    health: match backend.health {
                        BackendHealthState::Unknown => "unknown",
                        BackendHealthState::Healthy => "healthy",
                        BackendHealthState::Unhealthy { .. } => "unhealthy",
                    },
                    membership: match backend.membership {
                        BackendMembershipState::Active => "active",
                        BackendMembershipState::Suppressed => "suppressed",
                        BackendMembershipState::Removed => "removed",
                    },
                    authority_host: backend.resolution.authority_host,
                    authority_port: backend.resolution.authority_port,
                    resolved_addrs: backend
                        .resolution
                        .resolved_addrs
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                    resolution_generation: backend.resolution.refresh_generation,
                    last_refresh_success_at_unix_seconds: backend
                        .resolution
                        .last_refresh_success_at
                        .and_then(|time| time.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
                        .map(|duration| duration.as_secs()),
                    placements: backend
                        .placements
                        .into_iter()
                        .map(ControlApiBackendPlacementPayload::from_snapshot)
                        .collect(),
                })
                .collect(),
        }
    }
}

impl ControlApiBackendPlacementPayload {
    fn from_snapshot(snapshot: BackendPoolPlacementSnapshot) -> Self {
        Self {
            upstream: snapshot.upstream_name,
            backend_index: snapshot.backend_index,
            healthy: snapshot.healthy,
            active_requests: snapshot.active_requests,
            ewma_latency_ms: snapshot.ewma_latency_ms,
            membership_epoch: snapshot.membership_epoch,
        }
    }
}
