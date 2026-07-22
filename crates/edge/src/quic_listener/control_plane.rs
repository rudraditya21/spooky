use std::sync::Arc;

use spooky_config::runtime::RuntimeConfig;
use spooky_errors::ProxyError;

use super::{
    QUICListener,
    runtime_state::{ControlPlaneBootstrap, WatchdogServiceCtx},
};
use crate::runtime::{bundle::RuntimeBundleHandle, shared_state::SharedRuntimeState};

impl QUICListener {
    pub fn spawn_control_plane_tasks(
        config: &RuntimeConfig,
        shared_state: &SharedRuntimeState,
        worker_count: usize,
    ) -> Result<(), ProxyError> {
        Self::spawn_control_plane_bootstrap(ControlPlaneBootstrap {
            runtime_config: config,
            shared_state,
            runtime_bundle: None,
            worker_count,
        })
    }

    pub fn spawn_control_plane_tasks_with_runtime_bundle(
        config: &RuntimeConfig,
        shared_state: &SharedRuntimeState,
        runtime_bundle: Arc<RuntimeBundleHandle>,
        worker_count: usize,
    ) -> Result<(), ProxyError> {
        Self::spawn_control_plane_bootstrap(ControlPlaneBootstrap {
            runtime_config: config,
            shared_state,
            runtime_bundle: Some(runtime_bundle),
            worker_count,
        })
    }

    fn spawn_control_plane_bootstrap(
        bootstrap: ControlPlaneBootstrap<'_>,
    ) -> Result<(), ProxyError> {
        Self::configure_expected_workers(
            bootstrap.shared_state.shared_services().watchdog.as_ref(),
            bootstrap.worker_count,
        );
        Self::spawn_generation_background_tasks(&bootstrap);
        Self::spawn_metrics_endpoint(&bootstrap)?;
        Self::spawn_control_api_endpoint(&bootstrap)?;
        Ok(())
    }

    pub(super) fn spawn_generation_background_tasks(bootstrap: &ControlPlaneBootstrap<'_>) {
        bootstrap.with_runtime_view(|runtime| {
            Self::configure_expected_workers(runtime.watchdog().as_ref(), runtime.expected_workers());
            let task_registry = runtime.generation_tasks();
            Self::spawn_backend_dns_refresh(
                runtime.runtime_config(),
                runtime.transport_pool(),
                runtime.backend_lifecycle(),
                runtime.backend_dns_resolver(),
                runtime.metrics(),
                Arc::clone(&task_registry),
            );
            Self::spawn_health_checks(
                runtime.upstream_pools().clone(),
                runtime.transport_pool(),
                runtime.backend_endpoints(),
                runtime.backend_health_checks(),
                runtime.backend_lifecycle(),
                runtime.metrics(),
                Arc::clone(&task_registry),
            );
            Self::spawn_watchdog(WatchdogServiceCtx::new(runtime, task_registry));
        });
    }

    pub(super) fn spawn_generation_background_tasks_for_runtime(
        config: &RuntimeConfig,
        shared_state: &SharedRuntimeState,
    ) {
        Self::spawn_generation_background_tasks(&ControlPlaneBootstrap {
            runtime_config: config,
            shared_state,
            runtime_bundle: None,
            worker_count: config
                .policies
                .transport
                .worker_threads
                .max(1)
                .saturating_mul(config.policies.transport.packet_shards_per_worker.max(1))
                .max(1),
        });
    }

    fn configure_expected_workers(
        watchdog: &crate::watchdog::coordinator::WatchdogCoordinator,
        worker_count: usize,
    ) {
        watchdog.set_expected_workers(worker_count.max(1));
    }
}
