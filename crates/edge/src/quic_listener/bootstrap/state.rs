use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use spooky_config::{
    backend_endpoint::BackendEndpoint,
    runtime::{ListenerRuntimeConfig, RuntimeUpstreamPolicy},
};
use spooky_lb::upstream_pool::UpstreamPool;
use spooky_transport::transport_pool::UpstreamTransportPool;

use crate::{
    Metrics,
    resilience::runtime::RuntimeResilience,
    routing::index::RouteIndex,
    runtime::{
        bundle::RuntimeBundleHandle, shared_state::SharedRuntimeState,
        tls::store::ListenerTlsReloadStore,
    },
};

pub(in crate::quic_listener) struct BootstrapConnectionState {
    pub(in crate::quic_listener) alt_svc_value: String,
    pub(in crate::quic_listener) backend_timeout: Duration,
    pub(in crate::quic_listener) max_request_body_bytes: usize,
    pub(in crate::quic_listener) max_response_body_bytes: usize,
    pub(in crate::quic_listener) max_connections: usize,
    pub(in crate::quic_listener) connection_timeout: Duration,
    pub(in crate::quic_listener) listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub(in crate::quic_listener) transport_pool: Arc<UpstreamTransportPool>,
    pub(in crate::quic_listener) backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub(in crate::quic_listener) upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    pub(in crate::quic_listener) metrics: Arc<Metrics>,
    pub(in crate::quic_listener) resilience: Arc<RuntimeResilience>,
    pub(in crate::quic_listener) upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(in crate::quic_listener) routing_index: Arc<RouteIndex>,
}

pub(in crate::quic_listener) struct BootstrapStartupState {
    pub(in crate::quic_listener) listener_config: ListenerRuntimeConfig,
    pub(in crate::quic_listener) listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub(in crate::quic_listener) transport_pool: Arc<UpstreamTransportPool>,
    pub(in crate::quic_listener) backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub(in crate::quic_listener) upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    pub(in crate::quic_listener) metrics: Arc<Metrics>,
    pub(in crate::quic_listener) resilience: Arc<RuntimeResilience>,
    pub(in crate::quic_listener) upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(in crate::quic_listener) routing_index: Arc<RouteIndex>,
}

pub(in crate::quic_listener) fn build_bootstrap_startup_state(
    config: &ListenerRuntimeConfig,
    shared_state: &SharedRuntimeState,
) -> BootstrapStartupState {
    BootstrapStartupState {
        listener_config: config.clone(),
        listener_tls_store: Arc::clone(&shared_state.listener_tls_store),
        transport_pool: Arc::clone(&shared_state.transport_pool),
        backend_endpoints: Arc::clone(&shared_state.backend_endpoints),
        upstream_policies: Arc::clone(&shared_state.upstream_policies),
        metrics: Arc::clone(&shared_state.metrics),
        resilience: Arc::clone(&shared_state.resilience),
        upstream_pools: shared_state.upstream_pools.clone(),
        routing_index: Arc::clone(&shared_state.routing_index),
    }
}

pub(in crate::quic_listener) fn bootstrap_connection_state(
    listener_label: &str,
    runtime_bundle: Option<&Arc<RuntimeBundleHandle>>,
    startup: &BootstrapStartupState,
) -> Option<BootstrapConnectionState> {
    let (
        listener_config,
        listener_tls_store,
        transport_pool,
        backend_endpoints,
        upstream_policies,
        metrics,
        resilience,
        upstream_pools,
        routing_index,
    ) = if let Some(handle) = runtime_bundle {
        let runtime = handle.current();
        (
            runtime.listener_runtime_config(listener_label)?,
            runtime.shared_state.listener_tls_store.clone(),
            runtime.shared_state.transport_pool.clone(),
            runtime.shared_state.backend_endpoints.clone(),
            runtime.shared_state.upstream_policies.clone(),
            runtime.shared_state.metrics.clone(),
            runtime.shared_state.resilience.clone(),
            runtime.shared_state.upstream_pools.clone(),
            runtime.shared_state.routing_index.clone(),
        )
    } else {
        (
            startup.listener_config.clone(),
            Arc::clone(&startup.listener_tls_store),
            Arc::clone(&startup.transport_pool),
            Arc::clone(&startup.backend_endpoints),
            Arc::clone(&startup.upstream_policies),
            Arc::clone(&startup.metrics),
            Arc::clone(&startup.resilience),
            startup.upstream_pools.clone(),
            Arc::clone(&startup.routing_index),
        )
    };

    Some(BootstrapConnectionState {
        alt_svc_value: format!("h3=\":{}\"; ma=86400", listener_config.listen.listen.port),
        backend_timeout: listener_config.policies.timeouts.backend_request,
        max_request_body_bytes: listener_config.policies.transport.max_request_body_bytes,
        max_response_body_bytes: listener_config.policies.transport.max_response_body_bytes,
        max_connections: listener_config
            .policies
            .transport
            .connection_limits
            .max_active_connections
            .max(1),
        connection_timeout: listener_config.policies.timeouts.client_body_idle,
        listener_tls_store,
        transport_pool,
        backend_endpoints,
        upstream_policies,
        metrics,
        resilience,
        upstream_pools,
        routing_index,
    })
}
