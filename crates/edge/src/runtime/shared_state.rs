use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use spooky_config::{
    backend_endpoint::BackendEndpoint,
    runtime::{ListenerRuntimeConfig, RuntimeBackendHealthCheck, RuntimeUpstreamPolicy},
};
use spooky_lb::upstream_pool::UpstreamPool;
use spooky_transport::{h2_client::SharedDnsResolver, transport_pool::UpstreamTransportPool};
use tokio::sync::Semaphore;

use crate::{
    Metrics,
    resilience::runtime::RuntimeResilience,
    routing::index::RouteIndex,
    runtime::{
        backend::store::RuntimeBackendResolutionStore,
        generation::{RuntimeGenerationState, RuntimeSharedServices},
        tasks::RuntimeTaskRegistry,
        tls::store::ListenerTlsReloadStore,
    },
    watchdog::coordinator::WatchdogCoordinator,
};

pub struct SharedRuntimeState {
    pub(crate) shared_services: Arc<RuntimeSharedServices>,
    pub(crate) generation_state: Arc<RuntimeGenerationState>,
    pub(crate) listener_runtime_configs: Arc<HashMap<String, ListenerRuntimeConfig>>,
    pub(crate) listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub(crate) transport_pool: Arc<UpstreamTransportPool>,
    pub(crate) backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub(crate) backend_health_checks: Arc<HashMap<String, RuntimeBackendHealthCheck>>,
    pub(crate) backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
    pub(crate) backend_dns_resolver: SharedDnsResolver,
    pub(crate) upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    pub(crate) upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(crate) upstream_inflight: HashMap<String, Arc<Semaphore>>,
    pub(crate) global_inflight: Arc<Semaphore>,
    pub(crate) routing_index: Arc<RouteIndex>,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) resilience: Arc<RuntimeResilience>,
    pub(crate) watchdog: Arc<WatchdogCoordinator>,
    pub(crate) generation_tasks: Arc<RuntimeTaskRegistry>,
}

impl SharedRuntimeState {
    pub(crate) fn from_parts(
        shared_services: RuntimeSharedServices,
        generation_state: RuntimeGenerationState,
    ) -> Self {
        let shared_services = Arc::new(shared_services);
        let generation_state = Arc::new(generation_state);

        Self {
            listener_runtime_configs: Arc::clone(&generation_state.listener_runtime_configs),
            listener_tls_store: Arc::clone(&shared_services.listener_tls_store),
            transport_pool: Arc::clone(&shared_services.transport_pool),
            backend_endpoints: Arc::clone(&generation_state.backend_endpoints),
            backend_health_checks: Arc::clone(&generation_state.backend_health_checks),
            backend_resolution_store: Arc::clone(&shared_services.backend_resolution_store),
            backend_dns_resolver: shared_services.backend_dns_resolver.clone(),
            upstream_policies: Arc::clone(&generation_state.upstream_policies),
            upstream_pools: generation_state.upstream_pools.clone(),
            upstream_inflight: generation_state.upstream_inflight.clone(),
            global_inflight: Arc::clone(&generation_state.global_inflight),
            routing_index: Arc::clone(&generation_state.routing_index),
            metrics: Arc::clone(&shared_services.metrics),
            resilience: Arc::clone(&generation_state.resilience),
            watchdog: Arc::clone(&shared_services.watchdog),
            generation_tasks: Arc::clone(&generation_state.generation_tasks),
            shared_services,
            generation_state,
        }
    }

    pub fn shared_services(&self) -> &RuntimeSharedServices {
        self.shared_services.as_ref()
    }

    pub fn generation_state(&self) -> &RuntimeGenerationState {
        self.generation_state.as_ref()
    }

    pub fn bind_metrics_worker_slot(&self, slot: usize) {
        self.metrics.bind_worker_slot(slot);
    }

    pub fn inc_ingress_queue_drop(&self) {
        self.metrics.inc_ingress_queue_drop();
    }

    pub fn inc_ingress_queue_drop_bytes(&self, bytes: usize) {
        self.metrics.inc_ingress_queue_drop_bytes(bytes);
    }

    pub fn set_ingress_queue_bytes(&self, bytes: usize) {
        self.metrics.set_ingress_queue_bytes(bytes);
    }

    pub fn snapshot_backend_health(&self) -> (usize, usize) {
        let mut healthy = 0usize;
        let mut total = 0usize;

        for pool in self.generation_state.upstream_pools.values() {
            let guard = match pool.read() {
                Ok(guard) => guard,
                Err(_) => continue,
            };
            let pool_total = guard.pool.len();
            total = total.saturating_add(pool_total);
            healthy = healthy.saturating_add(guard.pool.healthy_len().min(pool_total));
        }

        (healthy, total)
    }
}
