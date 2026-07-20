use std::sync::Arc;

use spooky_config::runtime::RuntimeConfig;
use spooky_errors::ProxyError;

use crate::runtime::{bundle::RuntimeBundleHandle, shared_state::SharedRuntimeState};

use super::{QUICListener, runtime_state::ControlPlaneBootstrap};

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
        Self::configure_expected_workers(bootstrap.shared_state, bootstrap.worker_count);
        Self::spawn_generation_background_tasks(&bootstrap);
        Self::spawn_metrics_endpoint(
            bootstrap.runtime_config,
            Arc::clone(&bootstrap.shared_state.metrics),
            bootstrap.runtime_bundle.clone(),
        )?;
        Self::spawn_control_api_endpoint(
            bootstrap.runtime_config,
            bootstrap.shared_state,
            bootstrap.runtime_bundle,
            bootstrap.worker_count,
        )?;
        Ok(())
    }

    pub(super) fn spawn_generation_background_tasks(bootstrap: &ControlPlaneBootstrap<'_>) {
        Self::configure_expected_workers_from_runtime(
            bootstrap.runtime_config,
            bootstrap.shared_state,
        );
        let shared_state = bootstrap.shared_state;
        let task_registry = Arc::clone(&shared_state.generation_tasks);
        Self::spawn_backend_dns_refresh(
            bootstrap.runtime_config,
            Arc::clone(&shared_state.transport_pool),
            Arc::clone(&shared_state.backend_resolution_store),
            shared_state.backend_dns_resolver.clone(),
            Arc::clone(&shared_state.metrics),
            Arc::clone(&task_registry),
        );
        Self::spawn_health_checks(
            shared_state.upstream_pools.clone(),
            Arc::clone(&shared_state.transport_pool),
            Arc::clone(&shared_state.backend_endpoints),
            Arc::clone(&shared_state.backend_health_checks),
            Arc::clone(&shared_state.backend_resolution_store),
            Arc::clone(&shared_state.metrics),
            Arc::clone(&task_registry),
        );
        Self::spawn_watchdog(
            bootstrap.runtime_config,
            Arc::clone(&shared_state.metrics),
            Arc::clone(&shared_state.resilience),
            Arc::clone(&shared_state.watchdog),
            task_registry,
        );
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

    fn configure_expected_workers(shared_state: &SharedRuntimeState, worker_count: usize) {
        shared_state
            .watchdog
            .set_expected_workers(worker_count.max(1));
    }

    fn configure_expected_workers_from_runtime(
        config: &RuntimeConfig,
        shared_state: &SharedRuntimeState,
    ) {
        Self::configure_expected_workers(
            shared_state,
            config
                .policies
                .transport
                .worker_threads
                .max(1)
                .saturating_mul(config.policies.transport.packet_shards_per_worker.max(1))
                .max(1),
        );
    }
}
