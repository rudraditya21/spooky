use super::*;
use crate::{
    quic_listener::runtime_state::WatchdogServiceCtx,
    watchdog::{
        service::run_watchdog_service,
        state::{WatchdogServiceState, WatchdogSpawnState},
    },
};

impl QUICListener {
    pub(in crate::quic_listener) fn spawn_watchdog(service_ctx: WatchdogServiceCtx) {
        let spawn_state = WatchdogSpawnState {
            service: WatchdogServiceState {
                config: WatchdogRuntimeConfig::from(
                    &service_ctx.runtime.runtime_config().policies.admission.watchdog,
                ),
                metrics: service_ctx.runtime.metrics(),
                resilience: service_ctx.runtime.resilience(),
                watchdog: service_ctx.runtime.watchdog(),
            },
            task_registry: Arc::clone(&service_ctx.task_registry),
        };
        if !spawn_state.service.is_enabled() {
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
            Some(Arc::clone(&spawn_state.service.metrics)),
            run_watchdog_service(spawn_state.service),
        );
        spawn_state.task_registry.register(registration);
    }
}
