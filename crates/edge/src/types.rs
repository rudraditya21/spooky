use bytes::Bytes;
use core::net::SocketAddr;
use rustls::ServerConfig as RustlsServerConfig;
use spooky_config::{
    backend_endpoint::BackendEndpoint,
    runtime::{
        ListenerRuntimeConfig, RuntimeListenerTls, RuntimeTlsIdentity, RuntimeUpstreamPolicy,
    },
};
use spooky_errors::ProxyError;
use spooky_lb::UpstreamPool;
use spooky_transport::{h2_client::SharedDnsResolver, transport_pool::UpstreamTransportPool};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::UdpSocket,
    sync::{Arc, RwLock},
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tracing::Span;

use crate::Metrics;
use crate::RetryReason;
use crate::cid_radix::CidRadix;
use crate::constants::MAX_DATAGRAM_SIZE_BYTES;
use crate::resilience::{AdaptivePermit, RouteQueuePermit, RuntimeResilience};
use crate::route_index;
use crate::watchdog::WatchdogCoordinator;

pub struct SharedRuntimeState {
    pub(crate) listener_runtime_configs: Arc<HashMap<String, ListenerRuntimeConfig>>,
    pub(crate) listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub(crate) transport_pool: Arc<UpstreamTransportPool>,
    pub(crate) backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub(crate) backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
    pub(crate) backend_dns_resolver: SharedDnsResolver,
    pub(crate) upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    pub(crate) upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(crate) upstream_inflight: HashMap<String, Arc<Semaphore>>,
    pub(crate) global_inflight: Arc<Semaphore>,
    pub(crate) routing_index: Arc<route_index::RouteIndex>,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) resilience: Arc<RuntimeResilience>,
    pub(crate) watchdog: Arc<WatchdogCoordinator>,
}

impl SharedRuntimeState {
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

        for pool in self.upstream_pools.values() {
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

pub struct QUICListener {
    pub socket: UdpSocket,
    pub local_addr: SocketAddr,
    pub config: ListenerRuntimeConfig,
    pub listener_label: String,
    pub listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub tls_reload_generation: u64,
    pub quic_config: quiche::Config,
    pub h3_config: Arc<quiche::h3::Config>,
    pub transport_pool: Arc<UpstreamTransportPool>,
    pub backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
    pub backend_dns_resolver: SharedDnsResolver,
    pub upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    pub upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub upstream_inflight: HashMap<String, Arc<Semaphore>>,
    pub global_inflight: Arc<Semaphore>,
    pub(crate) routing_index: Arc<route_index::RouteIndex>,
    pub metrics: Arc<Metrics>,
    pub resilience: Arc<RuntimeResilience>,
    pub watchdog: Arc<WatchdogCoordinator>,
    pub draining: bool,
    pub drain_start: Option<Instant>,
    pub watchdog_worker_drained: bool,
    pub drain_timeout: Duration,
    pub backend_timeout: Duration,
    pub backend_body_idle_timeout: Duration,
    pub backend_body_total_timeout: Duration,
    pub client_body_idle_timeout: Duration,
    pub backend_total_request_timeout: Duration,
    pub inflight_acquire_wait: Duration,
    pub max_active_connections: usize,
    pub max_streams_per_connection: usize,
    pub max_request_body_bytes: usize,
    pub max_response_body_bytes: usize,
    pub request_buffer_global_cap_bytes: usize,
    pub unknown_length_response_prebuffer_bytes: usize,
    pub require_client_cert: bool,

    pub(crate) recv_buf: Box<[u8; MAX_DATAGRAM_SIZE_BYTES]>,
    pub(crate) send_buf: Box<[u8; MAX_DATAGRAM_SIZE_BYTES]>,

    pub(crate) connections: HashMap<Arc<[u8]>, QuicConnection>, // KEY: SCID(server connection id)
    pub(crate) cid_routes: HashMap<Arc<[u8]>, Arc<[u8]>>, // KEY: alias SCID, VALUE: primary SCID
    pub(crate) peer_routes: HashMap<SocketAddr, Arc<[u8]>>, // KEY: peer address, VALUE: primary SCID
    pub(crate) cid_radix: CidRadix,
    pub(crate) conn_rate_limiter: crate::quic_listener::TokenBucket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTlsCertificateMetadata {
    pub serial_hex: String,
    pub dns_names: Vec<String>,
    pub not_before_unix_seconds: i64,
    pub not_after_unix_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLoadedTlsIdentity {
    pub identity: RuntimeTlsIdentity,
    pub metadata: RuntimeTlsCertificateMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLoadedClientAuthCa {
    pub ca_file: String,
    pub certificate_count: usize,
}

#[derive(Debug, Clone)]
pub struct ListenerTlsInventory {
    pub listener_tls: RuntimeListenerTls,
    pub default_identity: RuntimeLoadedTlsIdentity,
    pub sni_identities: HashMap<String, RuntimeLoadedTlsIdentity>,
    pub client_auth_ca: Option<RuntimeLoadedClientAuthCa>,
}

pub struct ListenerTlsReloadState {
    pub generation: u64,
    pub inventory: ListenerTlsInventory,
    pub bootstrap_server_config: Arc<RustlsServerConfig>,
}

pub struct ListenerTlsReloadStore {
    listeners: RwLock<HashMap<String, ListenerTlsReloadState>>,
}

impl ListenerTlsReloadStore {
    pub fn new(listeners: HashMap<String, ListenerTlsReloadState>) -> Self {
        Self {
            listeners: RwLock::new(listeners),
        }
    }

    pub fn generation(&self, listener: &str) -> Option<u64> {
        self.listeners
            .read()
            .ok()
            .and_then(|listeners| listeners.get(listener).map(|state| state.generation))
    }

    pub fn bootstrap_server_config(&self, listener: &str) -> Option<Arc<RustlsServerConfig>> {
        self.listeners.read().ok().and_then(|listeners| {
            listeners
                .get(listener)
                .map(|state| Arc::clone(&state.bootstrap_server_config))
        })
    }

    pub fn inventory(&self, listener: &str) -> Option<ListenerTlsInventory> {
        self.listeners
            .read()
            .ok()
            .and_then(|listeners| listeners.get(listener).map(|state| state.inventory.clone()))
    }

    pub fn replace_listener(
        &self,
        listener: &str,
        inventory: ListenerTlsInventory,
        bootstrap_server_config: Arc<RustlsServerConfig>,
    ) -> Result<u64, ProxyError> {
        let mut listeners = self.listeners.write().map_err(|_| {
            ProxyError::Transport("listener TLS reload store lock poisoned".to_string())
        })?;
        let state = listeners.get_mut(listener).ok_or_else(|| {
            ProxyError::Transport(format!(
                "listener TLS reload requested for unknown listener '{}'",
                listener
            ))
        })?;
        state.generation = state.generation.saturating_add(1);
        state.inventory = inventory;
        state.bootstrap_server_config = bootstrap_server_config;
        Ok(state.generation)
    }

    pub fn snapshot(&self) -> HashMap<String, ListenerTlsInventory> {
        self.listeners
            .read()
            .map(|listeners| {
                listeners
                    .iter()
                    .map(|(listener, state)| (listener.clone(), state.inventory.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn generations(&self) -> HashMap<String, u64> {
        self.listeners
            .read()
            .map(|listeners| {
                listeners
                    .iter()
                    .map(|(listener, state)| (listener.clone(), state.generation))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeBackendAddressKind {
    Hostname,
    IpLiteral,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBackendResolution {
    pub backend_addr: String,
    pub authority_host: String,
    pub authority_port: u16,
    pub address_kind: RuntimeBackendAddressKind,
    pub resolved_addrs: Vec<SocketAddr>,
    pub last_refresh_success_at: Option<SystemTime>,
    pub refresh_generation: u64,
}

impl RuntimeBackendResolution {
    pub fn hostname(backend_addr: String, authority_host: String, authority_port: u16) -> Self {
        Self {
            backend_addr,
            authority_host,
            authority_port,
            address_kind: RuntimeBackendAddressKind::Hostname,
            resolved_addrs: Vec::new(),
            last_refresh_success_at: None,
            refresh_generation: 0,
        }
    }

    pub fn ip_literal(
        backend_addr: String,
        authority_host: String,
        authority_port: u16,
        resolved_addrs: Vec<SocketAddr>,
    ) -> Self {
        Self {
            backend_addr,
            authority_host,
            authority_port,
            address_kind: RuntimeBackendAddressKind::IpLiteral,
            resolved_addrs,
            last_refresh_success_at: None,
            refresh_generation: 0,
        }
    }

    pub fn is_hostname(&self) -> bool {
        self.address_kind == RuntimeBackendAddressKind::Hostname
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBackendResolutionUpdate {
    pub backend_addr: String,
    pub authority_host: String,
    pub authority_port: u16,
    pub address_kind: RuntimeBackendAddressKind,
    pub previous_addrs: Vec<SocketAddr>,
    pub current_addrs: Vec<SocketAddr>,
    pub last_refresh_success_at: Option<SystemTime>,
    pub refresh_generation: u64,
}

impl RuntimeBackendResolutionUpdate {
    pub fn changed(&self) -> bool {
        self.previous_addrs != self.current_addrs
    }

    pub fn cleared(&self) -> bool {
        self.current_addrs.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeBackendResolutionStore {
    entries: Arc<RwLock<HashMap<String, RuntimeBackendResolution>>>,
}

impl RuntimeBackendResolutionStore {
    pub fn new<I>(entries: I) -> Self
    where
        I: IntoIterator<Item = RuntimeBackendResolution>,
    {
        let entries = entries
            .into_iter()
            .map(|entry| (entry.backend_addr.clone(), entry))
            .collect();
        Self {
            entries: Arc::new(RwLock::new(entries)),
        }
    }

    pub fn get(&self, backend_addr: &str) -> Option<RuntimeBackendResolution> {
        self.entries
            .read()
            .ok()
            .and_then(|guard| guard.get(backend_addr).cloned())
    }

    pub fn snapshot(&self) -> HashMap<String, RuntimeBackendResolution> {
        self.entries
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    pub fn hostname_entries(&self) -> Vec<RuntimeBackendResolution> {
        self.entries
            .read()
            .map(|guard| {
                guard
                    .values()
                    .filter(|entry| entry.is_hostname())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn update_hostname_resolution(
        &self,
        backend_addr: &str,
        resolved_addrs: Vec<SocketAddr>,
        refreshed_at: SystemTime,
    ) -> Option<RuntimeBackendResolutionUpdate> {
        let resolved_addrs = canonicalize_socket_addrs(resolved_addrs);
        let mut guard = self.entries.write().ok()?;
        let entry = guard.get_mut(backend_addr)?;
        if !entry.is_hostname() {
            return None;
        }

        let previous_addrs = std::mem::replace(&mut entry.resolved_addrs, resolved_addrs.clone());
        entry.last_refresh_success_at = Some(refreshed_at);
        entry.refresh_generation = entry.refresh_generation.saturating_add(1);

        Some(RuntimeBackendResolutionUpdate {
            backend_addr: entry.backend_addr.clone(),
            authority_host: entry.authority_host.clone(),
            authority_port: entry.authority_port,
            address_kind: entry.address_kind,
            previous_addrs,
            current_addrs: resolved_addrs,
            last_refresh_success_at: entry.last_refresh_success_at,
            refresh_generation: entry.refresh_generation,
        })
    }
}

fn canonicalize_socket_addrs(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    addrs.sort_unstable();
    addrs.dedup();
    addrs
}

#[cfg(test)]
mod backend_resolution_tests {
    use super::{
        RuntimeBackendAddressKind, RuntimeBackendResolution, RuntimeBackendResolutionStore,
    };
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::SystemTime;

    #[test]
    fn hostname_entries_exclude_ip_literal_backends() {
        let store = RuntimeBackendResolutionStore::new([
            RuntimeBackendResolution::hostname(
                "api.internal:443".to_string(),
                "api.internal".to_string(),
                443,
            ),
            RuntimeBackendResolution::ip_literal(
                "10.0.0.10:8443".to_string(),
                "10.0.0.10".to_string(),
                8443,
                vec![SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
                    8443,
                )],
            ),
        ]);

        let entries = store.hostname_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].backend_addr, "api.internal:443");
        assert_eq!(entries[0].address_kind, RuntimeBackendAddressKind::Hostname);
    }

    #[test]
    fn store_snapshot_preserves_seeded_resolution_state() {
        let store = RuntimeBackendResolutionStore::new([RuntimeBackendResolution::ip_literal(
            "127.0.0.1:8080".to_string(),
            "127.0.0.1".to_string(),
            8080,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)],
        )]);

        let snapshot = store.snapshot();
        let entry = snapshot.get("127.0.0.1:8080").expect("entry");
        assert_eq!(entry.authority_host, "127.0.0.1");
        assert_eq!(entry.authority_port, 8080);
        assert_eq!(entry.resolved_addrs.len(), 1);
    }

    #[test]
    fn hostname_resolution_update_canonicalizes_and_tracks_generation() {
        let store = RuntimeBackendResolutionStore::new([RuntimeBackendResolution::hostname(
            "api.internal:443".to_string(),
            "api.internal".to_string(),
            443,
        )]);

        let update = store
            .update_hostname_resolution(
                "api.internal:443",
                vec![
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
                ],
                SystemTime::UNIX_EPOCH,
            )
            .expect("update");

        assert!(update.changed());
        assert_eq!(update.refresh_generation, 1);
        assert_eq!(
            update.current_addrs,
            vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443)
            ]
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuicConnectionErrorSnapshot {
    pub(crate) is_app: bool,
    pub(crate) error_code: u64,
    pub(crate) reason: Vec<u8>,
}

pub struct QuicConnection {
    pub quic: quiche::Connection,
    pub h3: Option<quiche::h3::Connection>,
    pub h3_config: Arc<quiche::h3::Config>,
    pub streams: HashMap<u64, RequestEnvelope>,

    pub peer_address: SocketAddr,
    pub last_activity: Instant,
    pub primary_scid: Arc<[u8]>,
    pub routing_scids: HashSet<Arc<[u8]>>,
    pub packets_since_rotation: u64,
    pub last_scid_rotation: Instant,
    pub tls_observed: bool,
    pub tls_handshake_failure_recorded: bool,
    pub tls_client_auth_failure_recorded: bool,
    pub(crate) last_peer_error_snapshot: Option<QuicConnectionErrorSnapshot>,
    pub(crate) last_local_error_snapshot: Option<QuicConnectionErrorSnapshot>,
}

/// Result type returned by the in-flight H2 forwarding task.
pub type ForwardResult =
    Result<(http::StatusCode, http::HeaderMap, hyper::body::Incoming), ProxyError>;

#[derive(Debug, Clone, Copy, Default)]
pub struct HedgeTelemetry {
    pub launched: bool,
    pub hedge_won: bool,
    pub hedge_wasted: bool,
    pub primary_won_after_trigger: bool,
    pub primary_late_ms: u64,
}

pub struct UpstreamResult {
    pub forward: ForwardResult,
    pub hedge: HedgeTelemetry,
    pub retry_count: u8,
    /// Set when a retry was attempted; the error reason that triggered it.
    pub retry_attempt_reason: Option<RetryReason>,
    /// Set when a retry was denied; the first denial reason encountered.
    pub retry_denial_reason: Option<RetryReason>,
}

/// Lifecycle phase of a single HTTP/3 request stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamPhase {
    /// Still receiving request headers/body from the QUIC client.
    ReceivingRequest,
    /// Request fully received; waiting for the upstream H2 response.
    AwaitingUpstream,
    /// Upstream responded; streaming response back to the QUIC client.
    SendingResponse,
    /// Stream finished cleanly.
    Completed,
    /// Stream terminated with an error.
    Failed,
}

/// A chunk of the upstream response being streamed back to the client.
#[derive(Debug)]
pub enum ResponseChunk {
    /// Emit downstream response headers (used when headers are deferred until
    /// body-size validation completes).
    Start {
        status: http::StatusCode,
        headers: Vec<(Vec<u8>, Vec<u8>)>,
    },
    Data(Bytes),
    Trailers {
        headers: Vec<(Vec<u8>, Vec<u8>)>,
    },
    End,
    Error(ProxyError),
}

pub struct RequestEnvelope {
    pub request_id: u64,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub traceparent: Option<String>,
    pub trace_span: Option<Span>,

    pub method: String,
    pub path: String,
    pub authority: Option<String>,
    /// Sender half of the body channel.  Dropping it signals end-of-body to hyper.
    pub body_tx: Option<mpsc::Sender<Bytes>>,
    /// Body chunks that arrived before the channel had capacity.
    pub body_buf: VecDeque<Bytes>,
    /// Current bytes held in `body_buf`.
    pub body_buf_bytes: usize,
    /// Total body bytes received on this stream (buffered + already forwarded).
    pub body_bytes_received: usize,
    /// Last observed request-body byte arrival time.
    pub last_body_activity: Instant,
    /// Resolved backend address and index (for health marking on response).
    pub backend_addr: Option<String>,
    pub backend_index: Option<usize>,
    pub upstream_name: Option<String>,
    pub route_reason: Option<String>,
    pub route_path_len: Option<usize>,
    pub route_host_specific: Option<bool>,
    pub backend_lb: Option<String>,
    pub upstream_pool: Option<Arc<RwLock<UpstreamPool>>>,
    pub routing_transparency_enabled: bool,
    pub routing_transparency_include_reason: bool,
    pub response_status: Option<u16>,
    pub backend_request_finished: bool,
    pub global_inflight_permit: Option<OwnedSemaphorePermit>,
    pub upstream_inflight_permit: Option<OwnedSemaphorePermit>,
    pub adaptive_admission_permit: Option<AdaptivePermit>,
    pub route_queue_permit: Option<RouteQueuePermit>,
    pub start: Instant,
    pub total_request_deadline: Instant,
    pub bodyless_mode: bool,

    pub retry_count: u8,
    pub error_kind: Option<&'static str>,

    /// Current lifecycle phase of this stream.
    pub phase: StreamPhase,
    /// True once the client has sent FIN on the request stream.
    pub request_fin_received: bool,
    /// Receives the upstream H2 response (status, headers, body stream).
    pub upstream_result_rx: Option<oneshot::Receiver<UpstreamResult>>,
    /// Receives response body chunks to write back over QUIC.
    pub response_chunk_rx: Option<mpsc::Receiver<ResponseChunk>>,
    /// True once downstream response headers are emitted on this stream.
    pub response_headers_sent: bool,
    /// A chunk that could not be written due to QUIC send backpressure; retried next poll.
    pub pending_chunk: Option<ResponseChunk>,
}

impl RequestEnvelope {
    pub fn request_id(&self) -> u64 {
        self.request_id
    }
}

impl QUICListener {
    pub fn connections(&self) -> &HashMap<Arc<[u8]>, QuicConnection> {
        &self.connections
    }

    pub fn cid_routes(&self) -> &HashMap<Arc<[u8]>, Arc<[u8]>> {
        &self.cid_routes
    }

    pub fn peer_routes(&self) -> &HashMap<SocketAddr, Arc<[u8]>> {
        &self.peer_routes
    }

    pub fn cid_radix(&self) -> &CidRadix {
        &self.cid_radix
    }
}

#[derive(Debug)]
pub enum HealthClassification {
    Success, // 2xx, 3xx responses
    Failure, // 5xx responses, Transport/Pool/Timeout errors
    Neutral, // 4xx responses, Bridge/TLS errors
}

pub fn outcome_from_status(status: http::StatusCode) -> HealthClassification {
    if status.is_server_error() {
        // 5xx
        HealthClassification::Failure
    } else if status.is_client_error() {
        // 4xx
        HealthClassification::Neutral
    } else {
        // 2xx, 3xx
        HealthClassification::Success
    }
}
