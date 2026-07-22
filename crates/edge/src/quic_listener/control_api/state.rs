use std::sync::atomic::AtomicUsize;

use super::*;
use crate::runtime::{
    backend::{
        state::{BackendLifecycleInventorySnapshot, BackendLifecycleInventorySummary},
    },
};
use crate::quic_listener::runtime_state::ControlApiServiceCtx;

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
    pub(super) fn from_endpoint(endpoint: &ControlApiConfig) -> Self {
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

pub(super) type ControlApiState = ControlApiServiceCtx;

pub(super) struct ControlApiListenerBinding {
    pub(super) bind: String,
    pub(super) listener: tokio::net::TcpListener,
    pub(super) active_connections: Arc<AtomicUsize>,
}

pub(super) struct ConnectionSlotGuard {
    active_connections: Arc<AtomicUsize>,
}

impl ConnectionSlotGuard {
    pub(super) fn new(active_connections: Arc<AtomicUsize>) -> Self {
        Self { active_connections }
    }
}

impl Drop for ConnectionSlotGuard {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ControlApiServiceCtx {
    pub(super) fn current_runtime_view(&self) -> crate::quic_listener::runtime_state::ControlPlaneRuntimeView {
        self.runtime.current_view()
    }

    pub(super) fn current_generation(&self) -> Option<crate::runtime::bundle::ActiveRuntimeGeneration> {
        self.runtime.current_generation()
    }

    pub(super) fn runtime_bundle_handle(&self) -> Option<&Arc<RuntimeBundleHandle>> {
        self.runtime.runtime_bundle_handle()
    }

    pub(super) fn current_control_api(&self) -> ControlApiConfig {
        self.current_runtime_view()
            .runtime_config()
            .observability
            .control_api
            .clone()
    }

    pub(super) fn current_paths(&self) -> ControlApiPaths {
        ControlApiPaths::from_endpoint(&self.current_control_api())
    }

    pub(super) fn current_listener_tls_store(&self) -> Arc<ListenerTlsReloadStore> {
        self.current_runtime_view().listener_tls_store()
    }

    pub(super) fn current_listener_runtime_configs(
        &self,
    ) -> Arc<HashMap<String, ListenerRuntimeConfig>> {
        self.current_runtime_view().listener_runtime_configs()
    }

    pub(super) fn current_metrics(&self) -> Arc<Metrics> {
        self.current_runtime_view().metrics()
    }

    pub(super) fn current_watchdog(&self) -> Arc<WatchdogCoordinator> {
        self.current_runtime_view().watchdog()
    }

    pub(super) fn current_resilience(&self) -> Arc<RuntimeResilience> {
        self.current_runtime_view().resilience()
    }

    pub(super) fn current_primary_listener_label(&self) -> Option<String> {
        self.current_runtime_view()
            .primary_listener_label()
            .map(ToOwned::to_owned)
    }

    pub(super) fn current_expected_workers(&self) -> usize {
        self.current_runtime_view().expected_workers()
    }

    pub(super) fn snapshot_backend_inventory(&self) -> BackendLifecycleInventorySnapshot {
        let runtime = self.current_runtime_view();
        runtime
            .backend_lifecycle()
            .snapshot_inventory(runtime.upstream_pools())
    }

    pub(super) fn snapshot_backend_health(&self) -> BackendLifecycleInventorySummary {
        self.snapshot_backend_inventory().summary()
    }
}
