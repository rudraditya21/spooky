use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use spooky_config::{
    backend_endpoint::BackendEndpoint,
    config::Log,
    runtime::{
        ListenerRuntimeConfig, RuntimeBackendHealthCheck, RuntimeConfig, RuntimeUpstreamPolicy,
    },
};
use spooky_lb::upstream_pool::UpstreamPool;
use spooky_transport::{h2_client::SharedDnsResolver, transport_pool::UpstreamTransportPool};
use tokio::sync::Semaphore;

use crate::{
    Metrics,
    resilience::runtime::RuntimeResilience,
    routing::index::RouteIndex,
    runtime::{
        backend::store::RuntimeBackendResolutionStore, tasks::RuntimeTaskRegistry,
        tls::store::ListenerTlsReloadStore,
    },
    watchdog::coordinator::WatchdogCoordinator,
};

#[derive(Clone)]
pub struct StartupOwnedRuntimeState {
    pub config_path: String,
    pub log_config: Log,
}

#[derive(Clone)]
pub struct RuntimeSharedServices {
    pub listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub transport_pool: Arc<UpstreamTransportPool>,
    pub backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
    pub backend_dns_resolver: SharedDnsResolver,
    pub metrics: Arc<Metrics>,
    pub watchdog: Arc<WatchdogCoordinator>,
}

#[derive(Clone)]
pub struct RuntimeGenerationState {
    pub listener_runtime_configs: Arc<HashMap<String, ListenerRuntimeConfig>>,
    pub backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub backend_health_checks: Arc<HashMap<String, RuntimeBackendHealthCheck>>,
    pub upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    pub upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub upstream_inflight: HashMap<String, Arc<Semaphore>>,
    pub global_inflight: Arc<Semaphore>,
    pub routing_index: Arc<RouteIndex>,
    pub resilience: Arc<RuntimeResilience>,
    pub generation_tasks: Arc<RuntimeTaskRegistry>,
}

#[derive(Clone, Copy)]
pub struct RuntimeGenerationView<'a> {
    pub generation: u64,
    pub startup: &'a StartupOwnedRuntimeState,
    pub runtime_config: &'a RuntimeConfig,
    pub shared: &'a RuntimeSharedServices,
    pub state: &'a RuntimeGenerationState,
}

impl<'a> RuntimeGenerationView<'a> {
    pub fn listener_runtime_config(&self, label: &str) -> Option<ListenerRuntimeConfig> {
        self.state.listener_runtime_configs.get(label).cloned()
    }
}
