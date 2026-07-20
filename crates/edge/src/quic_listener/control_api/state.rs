use std::sync::atomic::AtomicUsize;

use super::*;
use crate::runtime::{
    backend::{
        lifecycle::BackendLifecycleCoordinator,
        state::{BackendLifecycleInventorySnapshot, BackendLifecycleInventorySummary},
    },
    bundle::ActiveRuntimeGeneration,
    generation::RuntimeGenerationView,
};

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

#[derive(Clone)]
pub(super) struct ControlApiState {
    pub(super) control_api: ControlApiConfig,
    pub(super) metrics: Arc<Metrics>,
    pub(super) resilience: Arc<RuntimeResilience>,
    pub(super) watchdog: Arc<WatchdogCoordinator>,
    pub(super) backend_lifecycle: Arc<BackendLifecycleCoordinator>,
    pub(super) upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(super) listener_runtime_configs: Arc<HashMap<String, ListenerRuntimeConfig>>,
    pub(super) listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub(super) primary_listener_label: String,
    pub(super) expected_workers: usize,
    pub(super) started_at: Instant,
    pub(super) runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
}

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

impl ControlApiState {
    pub(super) fn current_generation(&self) -> Option<ActiveRuntimeGeneration> {
        self.runtime_bundle
            .as_ref()
            .map(|handle| handle.current_view())
    }

    pub(super) fn with_current_generation<R>(
        &self,
        f: impl FnOnce(Option<RuntimeGenerationView<'_>>) -> R,
    ) -> R {
        match self.runtime_bundle.as_ref() {
            Some(handle) => handle.with_current_view(|view| f(Some(view))),
            None => f(None),
        }
    }

    pub(super) fn current_control_api(&self) -> ControlApiConfig {
        self.with_current_generation(|runtime| {
            runtime.map(|view| view.runtime_config.observability.control_api.clone())
        })
        .unwrap_or_else(|| self.control_api.clone())
    }

    pub(super) fn current_paths(&self) -> ControlApiPaths {
        ControlApiPaths::from_endpoint(&self.current_control_api())
    }

    pub(super) fn current_listener_tls_store(&self) -> Arc<ListenerTlsReloadStore> {
        self.with_current_generation(|runtime| {
            runtime.map(|view| view.shared.listener_tls_store.clone())
        })
        .unwrap_or_else(|| Arc::clone(&self.listener_tls_store))
    }

    pub(super) fn current_listener_runtime_configs(
        &self,
    ) -> Arc<HashMap<String, ListenerRuntimeConfig>> {
        self.with_current_generation(|runtime| {
            runtime.map(|view| view.state.listener_runtime_configs.clone())
        })
        .unwrap_or_else(|| Arc::clone(&self.listener_runtime_configs))
    }

    pub(super) fn current_metrics(&self) -> Arc<Metrics> {
        self.with_current_generation(|runtime| runtime.map(|view| view.shared.metrics.clone()))
            .unwrap_or_else(|| Arc::clone(&self.metrics))
    }

    pub(super) fn current_watchdog(&self) -> Arc<WatchdogCoordinator> {
        self.with_current_generation(|runtime| runtime.map(|view| view.shared.watchdog.clone()))
            .unwrap_or_else(|| Arc::clone(&self.watchdog))
    }

    pub(super) fn current_resilience(&self) -> Arc<RuntimeResilience> {
        self.with_current_generation(|runtime| runtime.map(|view| view.state.resilience.clone()))
            .unwrap_or_else(|| Arc::clone(&self.resilience))
    }

    pub(super) fn current_primary_listener_label(&self) -> Option<String> {
        self.with_current_generation(|runtime| {
            runtime.and_then(|view| {
                view.runtime_config
                    .primary_listener_runtime_config()
                    .map(|listener| QUICListener::listener_label(&listener))
            })
        })
        .or_else(|| Some(self.primary_listener_label.clone()))
    }

    pub(super) fn snapshot_backend_inventory(&self) -> BackendLifecycleInventorySnapshot {
        if let Some(runtime) = self.current_generation() {
            return runtime
                .shared_services()
                .backend_lifecycle
                .snapshot_inventory(&runtime.state().upstream_pools);
        }

        self.backend_lifecycle.snapshot_inventory(&self.upstream_pools)
    }

    pub(super) fn snapshot_backend_health(&self) -> BackendLifecycleInventorySummary {
        self.snapshot_backend_inventory().summary()
    }
}
