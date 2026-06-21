use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    future::Future,
    net::{IpAddr, SocketAddr as StdSocketAddr, ToSocketAddrs, UdpSocket},
    pin::Pin,
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use core::net::SocketAddr;

use boring::pkey::{PKey, Private};
use boring::ssl::{
    NameType, SelectCertError, SslContextBuilder, SslFiletype, SslMethod, SslVerifyMode,
};
use boring::x509::X509;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::{Body, Frame, Incoming};
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::upgrade;
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use quiche::Config;
use quiche::h3::NameValue;
use rand::RngCore;
use rustls::{RootCertStore, ServerConfig as RustlsServerConfig, server::WebPkiClientVerifier};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni},
    sign::CertifiedKey,
};
use rustls_pki_types::pem::PemObject;
use serde_json::json;
use socket2::{Domain, Protocol, Socket, Type};
use spooky_bridge::h3_to_h2::{
    ForwardedContext, ForwardedHeaderChains, build_forwarded_header_values,
    build_h2_request_for_endpoint_with_host_policy, resolve_upstream_host_value,
};
use spooky_errors::{PoolError, ProxyError, is_retryable};
use spooky_lb::{HealthFailureReason, HealthTransition, UpstreamPool};
use spooky_transport::h2_client::{SharedDnsResolver, TlsClientConfig};
use spooky_transport::transport_pool::{BackendTransportKind, UpstreamTransportPool};
use tokio::runtime::Handle;
use tokio::sync::{
    Semaphore, mpsc,
    mpsc::error::{TryRecvError, TrySendError},
    oneshot,
};
use tokio_rustls::TlsAcceptor;
use tracing::{Instrument, info_span};

use spooky_config::{
    backend_endpoint::{BackendEndpoint, BackendScheme},
    config::{ClientAuth, UpstreamTls},
    runtime::{
        ListenerRuntimeConfig, RuntimeConfig, RuntimeListenerTls, RuntimeTlsIdentity,
        RuntimeUpstreamPolicy,
    },
};

use crate::{
    ChannelBody, ForwardResult, HealthClassification, Metrics, OverloadShedReason, QUICListener,
    QuicConnection, REQUEST_ID_COUNTER, RequestEnvelope, ResponseChunk, RetryReason, RouteOutcome,
    SharedRuntimeState, StreamPhase, UpstreamResult,
    cid_radix::CidRadix,
    constants::{
        DEFAULT_SCID_LEN_BYTES, MAX_DATAGRAM_SIZE_BYTES, MAX_UDP_PAYLOAD_BYTES, MIN_SCID_LEN_BYTES,
        REQUEST_CHUNK_BYTES_LIMIT, REQUEST_CHUNK_CHANNEL_CAPACITY, RESET_TOKEN_LEN_BYTES,
        RESPONSE_CHUNK_BYTES_LIMIT, RESPONSE_CHUNK_CHANNEL_CAPACITY,
        SCID_ROTATION_PACKET_THRESHOLD, UDP_READ_TIMEOUT_MS, scid_rotation_interval,
    },
    outcome_from_status,
    resilience::{RouteQueueRejection, RuntimeResilience},
    route_index::{RouteDecisionReason, RouteIndex},
    types::{
        ListenerTlsInventory, ListenerTlsReloadState, ListenerTlsReloadStore,
        QuicConnectionErrorSnapshot, RuntimeBackendResolution, RuntimeBackendResolutionStore,
        RuntimeBundle, RuntimeBundleHandle, RuntimeLoadedClientAuthCa, RuntimeLoadedTlsIdentity,
        RuntimeTaskRegistration, RuntimeTaskRegistry, RuntimeTlsCertificateMetadata,
    },
    watchdog::{WatchdogCoordinator, WatchdogRuntimeConfig, now_millis},
};

mod backend_resolution;
mod connection;
mod control_api;
mod forwarding;
mod health_check;
mod token_bucket;
mod validation;

use connection::resolve_primary_from_radix_prefix;
pub(crate) use connection::{ConnectionRoutes, purge_connection_routes, sweep_closed_connections};
use forwarding::{ForwardRequestMeta, abort_stream};
#[cfg(test)]
use health_check::classify_active_health_check_response;
pub(crate) use token_bucket::TokenBucket;
use validation::{
    RequestBufferError, extract_header_value, generated_span_id, generated_trace_id,
    parse_traceparent, validate_http_request, validate_request_headers,
};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

#[derive(Debug)]
struct FallbackServerCertResolver {
    sni_resolver: ResolvesServerCertUsingSni,
    fallback: Arc<CertifiedKey>,
}

#[derive(Clone)]
struct LoadedListenerIdentity {
    identity: RuntimeTlsIdentity,
    certified_key: Arc<CertifiedKey>,
    metadata: RuntimeTlsCertificateMetadata,
}

#[derive(Clone)]
struct LoadedClientAuthCa {
    ca_file: String,
    certificate_count: usize,
    roots: Arc<RootCertStore>,
}

#[derive(Clone)]
struct LoadedListenerTlsMaterial {
    default_identity: LoadedListenerIdentity,
    sni_identities: HashMap<String, LoadedListenerIdentity>,
    client_auth: ClientAuth,
    client_auth_ca: Option<LoadedClientAuthCa>,
}

struct QuicSniCertMaterial {
    leaf: X509,
    chain: Vec<X509>,
    key: PKey<Private>,
}

impl ResolvesServerCert for FallbackServerCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.sni_resolver
            .resolve(client_hello)
            .or_else(|| Some(Arc::clone(&self.fallback)))
    }
}

fn is_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "transfer-encoding"
            | "upgrade"
            | "te"
            | "trailer"
    )
}

fn connection_header_tokens(headers: &http::HeaderMap) -> HashSet<String> {
    let mut tokens = HashSet::new();
    for value in headers.get_all(http::header::CONNECTION) {
        let Ok(raw) = value.to_str() else {
            continue;
        };
        for part in raw.split(',') {
            let token = part.trim().to_ascii_lowercase();
            if token.is_empty() {
                continue;
            }
            tokens.insert(token);
        }
    }
    tokens
}

#[cfg(test)]
fn should_strip_bootstrap_request_header(
    name: &http::header::HeaderName,
    connection_tokens: &HashSet<String>,
) -> bool {
    if connection_tokens.contains(name.as_str()) {
        return true;
    }

    if name == http::header::CONTENT_LENGTH {
        return true;
    }

    if name == http::header::CONNECTION
        || name == http::header::PROXY_AUTHENTICATE
        || name == http::header::PROXY_AUTHORIZATION
        || name == http::header::TE
        || name == http::header::TRAILER
        || name == http::header::TRANSFER_ENCODING
        || name == http::header::UPGRADE
        || name.as_str().eq_ignore_ascii_case("keep-alive")
        || name.as_str().eq_ignore_ascii_case("proxy-connection")
        || name.as_str().eq_ignore_ascii_case("forwarded")
        || name.as_str().eq_ignore_ascii_case("x-forwarded-for")
        || name.as_str().eq_ignore_ascii_case("x-forwarded-proto")
        || name.as_str().eq_ignore_ascii_case("x-forwarded-host")
    {
        return true;
    }

    false
}

fn should_strip_h3_response_header(
    name: &http::header::HeaderName,
    connection_tokens: &HashSet<String>,
) -> bool {
    connection_tokens.contains(name.as_str())
        || is_hop_header(name.as_str())
        || name == http::header::CONTENT_LENGTH
}

fn collect_h3_trailers(trailers: &http::HeaderMap) -> Vec<(Vec<u8>, Vec<u8>)> {
    let connection_tokens = connection_header_tokens(trailers);
    let mut out = Vec::with_capacity(trailers.len());
    for (name, value) in trailers.iter() {
        if should_strip_h3_response_header(name, &connection_tokens) {
            continue;
        }
        out.push((name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec()));
    }
    out
}

fn should_strip_bootstrap_response_header(
    name: &http::header::HeaderName,
    connection_tokens: &HashSet<String>,
) -> bool {
    connection_tokens.contains(name.as_str())
        || is_hop_header(name.as_str())
        || name.as_str().eq_ignore_ascii_case("alt-svc")
}

fn response_size_exceeded_after_chunk(
    response_bytes_received: &mut usize,
    chunk_len: usize,
    max_response_body_bytes: usize,
) -> bool {
    *response_bytes_received = response_bytes_received.saturating_add(chunk_len);
    *response_bytes_received > max_response_body_bytes
}

fn is_connect_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("CONNECT")
}

fn is_head_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("HEAD")
}

fn is_bodyless_request_mode(method: &str, content_length: Option<usize>) -> bool {
    content_length.unwrap_or(0) == 0
        && (method.eq_ignore_ascii_case("GET") || is_head_method(method))
}

fn is_connect_tunnel_response(method: &str, status: StatusCode) -> bool {
    is_connect_method(method) && status.is_success()
}

fn can_poll_upstream_result(req: &RequestEnvelope) -> bool {
    if is_connect_method(&req.method)
        && (req.phase == StreamPhase::ReceivingRequest
            || req.phase == StreamPhase::AwaitingUpstream)
    {
        return true;
    }

    req.phase == StreamPhase::AwaitingUpstream
        && req.request_fin_received
        && req.body_tx.is_none()
        && req.body_buf.is_empty()
}

fn header_has_token(value: &http::HeaderValue, token: &str) -> bool {
    value
        .to_str()
        .ok()
        .map(|raw| {
            raw.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
        .unwrap_or(false)
}

fn is_websocket_upgrade_request(req: &Request<Incoming>, use_h2: bool) -> bool {
    if use_h2 || req.method() != http::Method::GET {
        return false;
    }
    let Some(upgrade_header) = req.headers().get(http::header::UPGRADE) else {
        return false;
    };
    if !upgrade_header
        .to_str()
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
    {
        return false;
    }
    req.headers()
        .get(http::header::CONNECTION)
        .map(|v| header_has_token(v, "upgrade"))
        .unwrap_or(false)
}

fn extract_cookie_value(cookie_header: &str, cookie_name: &str) -> Option<String> {
    for pair in cookie_header.split(';') {
        let part = pair.trim();
        if part.is_empty() {
            continue;
        }
        let (name, value) = part.split_once('=')?;
        if name.trim().eq_ignore_ascii_case(cookie_name) {
            let value = value.trim();
            if value.is_empty() {
                return None;
            }
            return Some(value.to_string());
        }
    }
    None
}

fn extract_query_param(path: &str, param: &str) -> Option<String> {
    let (_, query) = path.split_once('?')?;
    for pair in query.split('&') {
        let entry = pair.trim();
        if entry.is_empty() {
            continue;
        }
        let (name, value) = entry.split_once('=')?;
        if name.eq_ignore_ascii_case(param) && !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

fn bootstrap_resolution_error_response(reason: &str) -> (StatusCode, &'static [u8]) {
    if reason.starts_with("no route for ") {
        return (StatusCode::BAD_GATEWAY, b"no route\n");
    }
    if reason.starts_with("pool not found:") {
        return (StatusCode::BAD_GATEWAY, b"no pool\n");
    }
    if reason == "upstream pool lock poisoned" {
        return (StatusCode::BAD_GATEWAY, b"pool error\n");
    }
    if reason == "no servers in upstream" || reason == "invalid server address" {
        return (StatusCode::SERVICE_UNAVAILABLE, b"no backends\n");
    }
    if reason == "no healthy servers" {
        return (StatusCode::SERVICE_UNAVAILABLE, b"no healthy backends\n");
    }

    (
        StatusCode::BAD_GATEWAY,
        b"route/backend resolution failed\n",
    )
}

type BootstrapServiceFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<
                    hyper::Response<
                        http_body_util::combinators::BoxBody<hyper::body::Bytes, Infallible>,
                    >,
                    hyper::Error,
                >,
            > + Send,
    >,
>;

type LbHeaderLookup<'a> = dyn Fn(&str) -> Option<String> + 'a;

struct BootstrapConnectionState {
    alt_svc_value: String,
    backend_timeout: Duration,
    max_request_body_bytes: usize,
    max_response_body_bytes: usize,
    max_connections: usize,
    connection_timeout: Duration,
    listener_tls_store: Arc<ListenerTlsReloadStore>,
    transport_pool: Arc<UpstreamTransportPool>,
    backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
    upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    metrics: Arc<Metrics>,
    resilience: Arc<RuntimeResilience>,
    upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    routing_index: Arc<RouteIndex>,
}

struct BootstrapStartupState {
    listener_config: ListenerRuntimeConfig,
    listener_tls_store: Arc<ListenerTlsReloadStore>,
    transport_pool: Arc<UpstreamTransportPool>,
    backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
    upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    metrics: Arc<Metrics>,
    resilience: Arc<RuntimeResilience>,
    upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    routing_index: Arc<RouteIndex>,
}

struct MetricsEndpointState {
    metrics_path: String,
    max_connections: usize,
    connection_timeout: Duration,
    metrics: Arc<Metrics>,
}

struct RuntimeConnectionSlotGuard {
    active_connections: Arc<AtomicUsize>,
}

impl RuntimeConnectionSlotGuard {
    fn new(active_connections: Arc<AtomicUsize>) -> Self {
        Self { active_connections }
    }
}

impl Drop for RuntimeConnectionSlotGuard {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

struct BootstrapStreamingBody {
    inner: Incoming,
    max_bytes: Option<usize>,
    bytes_seen: usize,
    capped: bool,
}

impl BootstrapStreamingBody {
    fn new(inner: Incoming) -> Self {
        Self {
            inner,
            max_bytes: None,
            bytes_seen: 0,
            capped: false,
        }
    }

    fn with_max_bytes(inner: Incoming, max_bytes: usize) -> Self {
        Self {
            inner,
            max_bytes: Some(max_bytes),
            bytes_seen: 0,
            capped: false,
        }
    }
}

impl Body for BootstrapStreamingBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.capped {
            return Poll::Ready(None);
        }

        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(limit) = self.max_bytes
                    && let Some(data) = frame.data_ref()
                {
                    self.bytes_seen = self.bytes_seen.saturating_add(data.len());
                    if self.bytes_seen > limit {
                        self.capped = true;
                        return Poll::Ready(None);
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(_))) => Poll::Ready(None),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn boxed_full(body: Bytes) -> http_body_util::combinators::BoxBody<Bytes, Infallible> {
    Full::new(body).map_err(|never| match never {}).boxed()
}

struct ResolvedBackend {
    upstream_name: String,
    backend_addr: String,
    backend_index: usize,
    upstream_pool: Arc<RwLock<UpstreamPool>>,
    backend_lb: String,
    route_path_len: usize,
    route_host_specific: bool,
    route_reason: RouteDecisionReason,
}

impl QUICListener {
    pub fn new(config: spooky_config::config::Config) -> Result<Self, ProxyError> {
        let runtime_config = RuntimeConfig::from_config(&config)
            .map_err(|err| ProxyError::Transport(err.to_string()))?;
        let listener_config = runtime_config
            .listener_runtime_configs()
            .into_iter()
            .next()
            .ok_or_else(|| {
                ProxyError::Transport("no effective listeners configured".to_string())
            })?;
        let shared_state = Arc::new(Self::build_shared_state(&runtime_config)?);
        Self::spawn_control_plane_tasks(&runtime_config, &shared_state, 1)?;
        let socket = Self::bind_socket(&listener_config, false)?;
        Self::new_with_socket_and_shared_state(listener_config, socket, shared_state)
    }

    fn upstream_tls_client_config(tls: &UpstreamTls) -> TlsClientConfig {
        TlsClientConfig {
            verify_certificates: tls.verify_certificates,
            strict_sni: tls.strict_sni,
            ca_file: tls.ca_file.clone(),
            ca_dir: tls.ca_dir.clone(),
        }
    }

    fn record_backend_connect_attempt(
        metrics: &Metrics,
        backend_resolution_store: &RuntimeBackendResolutionStore,
        backend: &str,
    ) {
        if let Some(resolution) = backend_resolution_store.get(backend) {
            metrics.record_backend_connect_attempt(
                backend,
                &resolution.authority_host,
                &resolution.resolved_addrs,
            );
        } else {
            metrics.record_backend_connect_attempt(backend, backend, &[]);
        }
    }

    pub fn build_shared_state(config: &RuntimeConfig) -> Result<SharedRuntimeState, ProxyError> {
        let worker_threads = config.performance.worker_threads.max(1);
        let shard_count = config.performance.packet_shards_per_worker.max(1);
        let active_worker_threads = if worker_threads > 1 && !config.performance.reuseport {
            1
        } else {
            worker_threads
        };
        let worker_slots = active_worker_threads.saturating_mul(shard_count).max(1);
        let per_upstream_limit = config.performance.per_upstream_inflight_limit.max(1);
        let global_inflight_limit = config.performance.global_inflight_limit.max(1);
        let max_inflight_per_backend = config
            .performance
            .per_backend_inflight_limit
            .saturating_mul(worker_threads);

        info!(
            "Performance profile: worker_threads={} control_plane_threads={} reuseport={} pin_workers={} global_inflight_limit={} per_upstream_inflight_limit={} per_backend_inflight_limit={} max_active_connections={} backend_connect_timeout_ms={} backend_timeout_ms={} backend_body_idle_timeout_ms={} backend_body_total_timeout_ms={} backend_total_request_timeout_ms={} client_body_idle_timeout_ms={} max_request_body_bytes={} max_response_body_bytes={} request_buffer_global_cap_bytes={} unknown_length_response_prebuffer_bytes={} udp_recv_buffer_bytes={} udp_send_buffer_bytes={} h2_pool_max_idle_per_backend={} h2_pool_idle_timeout_ms={}",
            worker_threads,
            config.performance.control_plane_threads.max(1),
            config.performance.reuseport,
            config.performance.pin_workers,
            global_inflight_limit,
            per_upstream_limit,
            config.performance.per_backend_inflight_limit,
            config.performance.max_active_connections,
            config.performance.backend_connect_timeout_ms,
            config.performance.backend_timeout_ms,
            config.performance.backend_body_idle_timeout_ms,
            config.performance.backend_body_total_timeout_ms,
            config.performance.backend_total_request_timeout_ms,
            config.performance.client_body_idle_timeout_ms,
            config.performance.max_request_body_bytes,
            config.performance.max_response_body_bytes,
            config.performance.request_buffer_global_cap_bytes,
            config.performance.unknown_length_response_prebuffer_bytes,
            config.performance.udp_recv_buffer_bytes,
            config.performance.udp_send_buffer_bytes,
            config.performance.h2_pool_max_idle_per_backend,
            config.performance.h2_pool_idle_timeout_ms
        );

        let listener_runtime_configs = config
            .listener_runtime_configs()
            .into_iter()
            .map(|listener_config| (Self::listener_label(&listener_config), listener_config))
            .collect::<HashMap<_, _>>();
        let listener_tls_store = Arc::new(Self::build_listener_tls_reload_store(config)?);

        let mut backend_transports = Vec::new();
        let mut backend_resolutions = Vec::new();
        let mut seen_backend_origins: HashMap<String, (String, String)> = HashMap::new();
        let mut backend_tls_configs: HashMap<String, TlsClientConfig> = HashMap::new();
        for (upstream_name, upstream) in &config.upstreams {
            let upstream_tls_client = Self::upstream_tls_client_config(&upstream.effective_tls);

            for backend in &upstream.backends {
                let endpoint = match BackendEndpoint::parse(&backend.backend.address) {
                    Ok(endpoint) => endpoint,
                    Err(err) => {
                        return Err(ProxyError::Transport(format!(
                            "invalid backend address '{}' in upstream '{}' (backend '{}'): {}",
                            backend.backend.address, upstream_name, backend.backend.id, err
                        )));
                    }
                };

                let origin = endpoint.origin();
                if let Some((existing_upstream, existing_backend)) = seen_backend_origins.insert(
                    origin.clone(),
                    (upstream_name.clone(), backend.backend.id.clone()),
                ) {
                    return Err(ProxyError::Transport(format!(
                        "duplicate backend address '{}' detected while building upstream transport pool: upstream '{}' backend '{}' conflicts with upstream '{}' backend '{}'",
                        origin,
                        upstream_name,
                        backend.backend.id,
                        existing_upstream,
                        existing_backend
                    )));
                }
                backend_transports.push((
                    backend.backend.address.clone(),
                    match endpoint.scheme() {
                        BackendScheme::Http => BackendTransportKind::Http1,
                        BackendScheme::Https => BackendTransportKind::H2,
                    },
                ));
                let authority_host = endpoint.authority_host().to_string();
                let authority_port = endpoint.authority_port();
                let resolution = if endpoint.authority_is_ip_literal() {
                    let ip_addr = authority_host.parse::<IpAddr>().map_err(|err| {
                        ProxyError::Transport(format!(
                            "failed to parse IP literal backend '{}' in upstream '{}' (backend '{}'): {}",
                            backend.backend.address, upstream_name, backend.backend.id, err
                        ))
                    })?;
                    RuntimeBackendResolution::ip_literal(
                        backend.backend.address.clone(),
                        authority_host,
                        authority_port,
                        vec![StdSocketAddr::new(ip_addr, authority_port)],
                    )
                } else {
                    RuntimeBackendResolution::hostname(
                        backend.backend.address.clone(),
                        authority_host,
                        authority_port,
                    )
                };
                backend_resolutions.push(resolution);
                let authority_kind = if endpoint.authority_is_ip_literal() {
                    "ip_literal"
                } else {
                    "hostname"
                };
                debug!(
                    "Configured upstream TLS policy backend={} upstream={} verify_certificates={} strict_sni={} ca_file={:?} ca_dir={:?} authority_kind={}",
                    backend.backend.address,
                    upstream_name,
                    upstream_tls_client.verify_certificates,
                    upstream_tls_client.strict_sni,
                    upstream_tls_client.ca_file,
                    upstream_tls_client.ca_dir,
                    authority_kind
                );
                if endpoint.scheme() == BackendScheme::Https {
                    backend_tls_configs
                        .insert(backend.backend.address.clone(), upstream_tls_client.clone());
                }
            }
        }

        let backend_dns_resolver = SharedDnsResolver::new();
        let backend_resolution_store =
            Arc::new(RuntimeBackendResolutionStore::new(backend_resolutions));
        let transport_pool = Arc::new(
            UpstreamTransportPool::new(
                backend_transports,
                backend_tls_configs,
                max_inflight_per_backend,
                config.performance.h2_pool_max_idle_per_backend,
                Duration::from_millis(config.performance.h2_pool_idle_timeout_ms),
                Duration::from_millis(config.performance.backend_connect_timeout_ms),
                backend_dns_resolver.clone(),
            )
            .map_err(ProxyError::Tls)?,
        );
        let mut upstream_pools = HashMap::new();
        let mut upstream_inflight = HashMap::new();
        for (name, runtime_upstream) in &config.upstreams {
            let upstream_pool = UpstreamPool::from_upstream(&runtime_upstream.as_config_upstream())
                .map_err(|err| {
                    ProxyError::Transport(format!(
                        "failed to create upstream pool '{}': {}",
                        name, err
                    ))
                })?;
            upstream_pools.insert(name.clone(), Arc::new(RwLock::new(upstream_pool)));
            upstream_inflight.insert(name.clone(), Arc::new(Semaphore::new(per_upstream_limit)));
        }

        config
            .resilience
            .validate()
            .map_err(|e| ProxyError::Transport(format!("invalid resilience config: {e}")))?;
        let mut effective_resilience = config.resilience.clone();
        let default_route_cap_limit = per_upstream_limit.saturating_mul(2).max(1);
        if effective_resilience.route_queue.default_cap > default_route_cap_limit {
            warn!(
                "resilience.route_queue.default_cap={} is above tuned limit {}; clamping for steadier timeout/admission behavior",
                effective_resilience.route_queue.default_cap, default_route_cap_limit
            );
            effective_resilience.route_queue.default_cap = default_route_cap_limit;
        }
        let global_route_cap_limit = global_inflight_limit.saturating_mul(2).max(1);
        if effective_resilience.route_queue.global_cap > global_route_cap_limit {
            warn!(
                "resilience.route_queue.global_cap={} is above tuned limit {}; clamping for steadier timeout/admission behavior",
                effective_resilience.route_queue.global_cap, global_route_cap_limit
            );
            effective_resilience.route_queue.global_cap = global_route_cap_limit;
        }
        for cap in effective_resilience.route_queue.caps.values_mut() {
            *cap = (*cap).min(default_route_cap_limit).max(1);
        }
        let tuned_high_latency = ((config.performance.backend_timeout_ms * 7) / 10).max(50);
        if effective_resilience.adaptive_admission.high_latency_ms > tuned_high_latency {
            warn!(
                "resilience.adaptive_admission.high_latency_ms={} is above tuned limit {}; clamping for faster overload reaction",
                effective_resilience.adaptive_admission.high_latency_ms, tuned_high_latency
            );
            effective_resilience.adaptive_admission.high_latency_ms = tuned_high_latency;
        }
        let resilience = Arc::new(RuntimeResilience::from_config(
            &effective_resilience,
            global_inflight_limit,
        ));
        let watchdog = Arc::new(WatchdogCoordinator::new(&config.resilience.watchdog));
        let mut route_labels = config.upstreams.keys().cloned().collect::<Vec<_>>();
        route_labels.push("unrouted".to_string());
        let routing_index = Arc::new(RouteIndex::from_upstreams(&config.upstreams_as_config()));
        let metrics = Arc::new(Metrics::new(worker_slots, route_labels));
        for (listener_label, inventory) in listener_tls_store.snapshot() {
            Self::update_listener_tls_expiry_metrics(&metrics, &listener_label, &inventory);
        }

        Ok(SharedRuntimeState {
            listener_runtime_configs: Arc::new(listener_runtime_configs),
            listener_tls_store,
            transport_pool,
            backend_endpoints: Arc::new(
                config
                    .upstreams
                    .values()
                    .flat_map(|upstream| upstream.backends.iter())
                    .filter_map(|backend| {
                        BackendEndpoint::parse(&backend.backend.address)
                            .ok()
                            .map(|endpoint| (backend.backend.address.clone(), endpoint))
                    })
                    .collect(),
            ),
            backend_resolution_store,
            backend_dns_resolver,
            upstream_policies: Arc::new(
                config
                    .upstreams
                    .iter()
                    .map(|(name, upstream)| (name.clone(), upstream.policy.clone()))
                    .collect(),
            ),
            upstream_pools,
            upstream_inflight,
            global_inflight: Arc::new(Semaphore::new(global_inflight_limit)),
            routing_index,
            metrics,
            resilience,
            watchdog,
            generation_tasks: Arc::new(RuntimeTaskRegistry::new()),
        })
    }

    pub fn build_runtime_bundle(
        config_path: String,
        runtime_config: &RuntimeConfig,
    ) -> Result<RuntimeBundle, ProxyError> {
        let shared_state = Arc::new(Self::build_shared_state(runtime_config)?);
        Ok(RuntimeBundle {
            generation: 0,
            config_path,
            runtime_config: runtime_config.clone(),
            shared_state,
        })
    }

    pub fn spawn_control_plane_tasks(
        config: &RuntimeConfig,
        shared_state: &SharedRuntimeState,
        worker_count: usize,
    ) -> Result<(), ProxyError> {
        shared_state
            .watchdog
            .set_expected_workers(worker_count.max(1));
        Self::spawn_generation_background_tasks(config, shared_state);
        Self::spawn_metrics_endpoint(config, Arc::clone(&shared_state.metrics), None)?;
        Self::spawn_control_api_endpoint(config, shared_state, None, worker_count)?;
        Ok(())
    }

    pub fn spawn_control_plane_tasks_with_runtime_bundle(
        config: &RuntimeConfig,
        shared_state: &SharedRuntimeState,
        runtime_bundle: Arc<RuntimeBundleHandle>,
        worker_count: usize,
    ) -> Result<(), ProxyError> {
        shared_state
            .watchdog
            .set_expected_workers(worker_count.max(1));
        Self::spawn_generation_background_tasks(config, shared_state);
        Self::spawn_metrics_endpoint(
            config,
            Arc::clone(&shared_state.metrics),
            Some(Arc::clone(&runtime_bundle)),
        )?;
        Self::spawn_control_api_endpoint(config, shared_state, Some(runtime_bundle), worker_count)?;
        Ok(())
    }

    pub(super) fn spawn_generation_background_tasks(
        config: &RuntimeConfig,
        shared_state: &SharedRuntimeState,
    ) {
        shared_state.watchdog.set_expected_workers(
            config
                .performance
                .worker_threads
                .max(1)
                .saturating_mul(config.performance.packet_shards_per_worker.max(1))
                .max(1),
        );
        let task_registry = Arc::clone(&shared_state.generation_tasks);
        Self::spawn_backend_dns_refresh(
            config,
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
            Arc::clone(&shared_state.backend_resolution_store),
            Arc::clone(&shared_state.metrics),
            Arc::clone(&task_registry),
        );
        Self::spawn_watchdog(
            config,
            Arc::clone(&shared_state.metrics),
            Arc::clone(&shared_state.resilience),
            Arc::clone(&shared_state.watchdog),
            task_registry,
        );
    }

    pub fn bind_reuseport_sockets(
        config: &ListenerRuntimeConfig,
        workers: usize,
    ) -> Result<Vec<UdpSocket>, ProxyError> {
        let workers = workers.max(1);
        let mut sockets = Vec::with_capacity(workers);
        for _ in 0..workers {
            sockets.push(Self::bind_socket(config, true)?);
        }
        Ok(sockets)
    }

    pub fn bind_socket(
        config: &ListenerRuntimeConfig,
        reuse_port: bool,
    ) -> Result<UdpSocket, ProxyError> {
        let bind_addr = Self::resolve_bind_addr(config)?;
        let socket = Self::create_udp_socket(
            bind_addr,
            reuse_port,
            config.performance.udp_recv_buffer_bytes,
            config.performance.udp_send_buffer_bytes,
        )?;
        socket
            .set_read_timeout(Some(Duration::from_millis(UDP_READ_TIMEOUT_MS)))
            .map_err(|err| {
                ProxyError::Transport(format!("failed to set UDP read timeout: {}", err))
            })?;

        Ok(socket)
    }

    pub fn new_with_socket_and_shared_state(
        config: ListenerRuntimeConfig,
        socket: UdpSocket,
        shared_state: Arc<SharedRuntimeState>,
    ) -> Result<Self, ProxyError> {
        let local_addr = socket.local_addr().map_err(|err| {
            ProxyError::Transport(format!("failed to read UDP socket local address: {}", err))
        })?;
        debug!("Listening on {}", local_addr);

        let listener_label = Self::listener_label(&config);
        let listener_tls_store = Arc::clone(&shared_state.listener_tls_store);
        let tls_reload_generation =
            listener_tls_store
                .generation(&listener_label)
                .ok_or_else(|| {
                    ProxyError::Transport(format!(
                        "missing TLS reload state for listener '{}'",
                        listener_label
                    ))
                })?;
        let quic_config = Self::build_quic_config(&config)?;
        let h3_config =
            Arc::new(quiche::h3::Config::new().map_err(|err| {
                ProxyError::Transport(format!("failed to create h3 config: {err}"))
            })?);
        let backend_timeout = Duration::from_millis(config.performance.backend_timeout_ms);
        let backend_body_idle_timeout =
            Duration::from_millis(config.performance.backend_body_idle_timeout_ms);
        let backend_body_total_timeout =
            Duration::from_millis(config.performance.backend_body_total_timeout_ms);
        let client_body_idle_timeout =
            Duration::from_millis(config.performance.client_body_idle_timeout_ms);
        let backend_total_request_timeout =
            Duration::from_millis(config.performance.backend_total_request_timeout_ms);
        let inflight_acquire_wait =
            Duration::from_millis(config.performance.inflight_acquire_wait_ms);
        let drain_timeout = Duration::from_millis(config.performance.shutdown_drain_timeout_ms);
        let max_active_connections = config.performance.max_active_connections.max(1);
        let max_streams_per_connection =
            usize::try_from(config.performance.quic_initial_max_streams_bidi)
                .unwrap_or(usize::MAX)
                .max(1);
        let max_request_body_bytes = config.performance.max_request_body_bytes;
        let max_response_body_bytes = config.performance.max_response_body_bytes;
        let request_buffer_global_cap_bytes = config.performance.request_buffer_global_cap_bytes;
        let unknown_length_response_prebuffer_bytes =
            config.performance.unknown_length_response_prebuffer_bytes;
        let require_client_cert = Self::runtime_listener_tls(&config)?
            .client_auth
            .require_client_cert;
        let conn_rate_limiter = TokenBucket::new(
            config.performance.new_connections_per_sec,
            config.performance.new_connections_burst,
        );

        Ok(Self {
            socket,
            local_addr,
            config,
            listener_label,
            listener_tls_store,
            tls_reload_generation,
            quic_config,
            h3_config,
            transport_pool: Arc::clone(&shared_state.transport_pool),
            backend_endpoints: Arc::clone(&shared_state.backend_endpoints),
            backend_resolution_store: Arc::clone(&shared_state.backend_resolution_store),
            backend_dns_resolver: shared_state.backend_dns_resolver.clone(),
            upstream_policies: Arc::clone(&shared_state.upstream_policies),
            upstream_pools: shared_state.upstream_pools.clone(),
            upstream_inflight: shared_state.upstream_inflight.clone(),
            global_inflight: Arc::clone(&shared_state.global_inflight),
            routing_index: Arc::clone(&shared_state.routing_index),
            metrics: Arc::clone(&shared_state.metrics),
            resilience: Arc::clone(&shared_state.resilience),
            watchdog: Arc::clone(&shared_state.watchdog),
            draining: false,
            drain_start: None,
            watchdog_worker_drained: false,
            drain_timeout,
            backend_timeout,
            backend_body_idle_timeout,
            backend_body_total_timeout,
            client_body_idle_timeout,
            backend_total_request_timeout,
            inflight_acquire_wait,
            max_active_connections,
            max_streams_per_connection,
            max_request_body_bytes,
            max_response_body_bytes,
            request_buffer_global_cap_bytes,
            unknown_length_response_prebuffer_bytes,
            require_client_cert,
            runtime_bundle: None,
            runtime_generation: 0,
            recv_buf: Box::new([0; MAX_DATAGRAM_SIZE_BYTES]),
            send_buf: Box::new([0; MAX_DATAGRAM_SIZE_BYTES]),
            connections: HashMap::new(),
            cid_routes: HashMap::new(),
            peer_routes: HashMap::new(),
            cid_radix: CidRadix::new(),
            conn_rate_limiter,
        })
    }

    pub fn with_runtime_bundle(mut self, runtime_bundle: Arc<RuntimeBundleHandle>) -> Self {
        self.runtime_generation = runtime_bundle.generation();
        self.runtime_bundle = Some(runtime_bundle);
        self
    }

    fn resolve_bind_addr(config: &ListenerRuntimeConfig) -> Result<SocketAddr, ProxyError> {
        let socket_address = format!(
            "{}:{}",
            config.listen.listen.address, config.listen.listen.port
        );
        socket_address
            .to_socket_addrs()
            .map_err(|err| {
                ProxyError::Transport(format!(
                    "failed to resolve listen address '{}': {}",
                    socket_address, err
                ))
            })?
            .next()
            .ok_or_else(|| {
                ProxyError::Transport(format!("no socket addresses found for '{socket_address}'"))
            })
    }

    fn create_udp_socket(
        bind_addr: SocketAddr,
        reuse_port: bool,
        udp_recv_buffer_bytes: usize,
        udp_send_buffer_bytes: usize,
    ) -> Result<UdpSocket, ProxyError> {
        let domain = if bind_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(|err| {
            ProxyError::Transport(format!("failed to create UDP socket: {}", err))
        })?;
        socket
            .set_reuse_address(true)
            .map_err(|err| ProxyError::Transport(format!("failed to set SO_REUSEADDR: {}", err)))?;
        socket
            .set_recv_buffer_size(udp_recv_buffer_bytes)
            .map_err(|err| {
                ProxyError::Transport(format!(
                    "failed to set UDP recv buffer size ({}): {}",
                    udp_recv_buffer_bytes, err
                ))
            })?;
        socket
            .set_send_buffer_size(udp_send_buffer_bytes)
            .map_err(|err| {
                ProxyError::Transport(format!(
                    "failed to set UDP send buffer size ({}): {}",
                    udp_send_buffer_bytes, err
                ))
            })?;

        #[cfg(all(
            unix,
            not(target_os = "solaris"),
            not(target_os = "illumos"),
            not(target_os = "cygwin")
        ))]
        {
            socket.set_reuse_port(reuse_port).map_err(|err| {
                ProxyError::Transport(format!("failed to set SO_REUSEPORT: {}", err))
            })?;
        }

        socket.bind(&bind_addr.into()).map_err(|err| {
            ProxyError::Transport(format!(
                "failed to bind UDP socket on '{}': {}",
                bind_addr, err
            ))
        })?;

        match (socket.recv_buffer_size(), socket.send_buffer_size()) {
            (Ok(actual_recv), Ok(actual_send)) => {
                debug!(
                    "UDP socket buffers on {}: recv={} (requested={}) send={} (requested={}) reuseport={}",
                    bind_addr,
                    actual_recv,
                    udp_recv_buffer_bytes,
                    actual_send,
                    udp_send_buffer_bytes,
                    reuse_port
                );
            }
            _ => {
                debug!(
                    "UDP socket bound on {} with requested buffers recv={} send={} reuseport={}",
                    bind_addr, udp_recv_buffer_bytes, udp_send_buffer_bytes, reuse_port
                );
            }
        }

        Ok(socket.into())
    }

    fn runtime_listener_tls(
        config: &ListenerRuntimeConfig,
    ) -> Result<RuntimeListenerTls, ProxyError> {
        Ok(config.listen.tls.clone())
    }

    fn build_quic_config(config: &ListenerRuntimeConfig) -> Result<Config, ProxyError> {
        let loaded_tls = Self::load_listener_tls_material(config)?;
        debug!(
            "Loaded downstream default TLS identity cert='{}' serial={} san_dns={:?} sni_identities={}",
            loaded_tls.default_identity.identity.cert_path,
            loaded_tls.default_identity.metadata.serial_hex,
            loaded_tls.default_identity.metadata.dns_names,
            loaded_tls.sni_identities.len()
        );
        if let Some(client_auth_ca) = loaded_tls.client_auth_ca.as_ref() {
            debug!(
                "Loaded downstream client-auth CA bundle '{}' with {} certificates",
                client_auth_ca.ca_file, client_auth_ca.certificate_count
            );
        }
        let mut quic_config = Self::build_quic_config_from_loaded(&loaded_tls)?;

        quic_config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .map_err(|err| {
                ProxyError::Transport(format!("failed to set ALPN protocols: {:?}", err))
            })?;
        quic_config.set_max_idle_timeout(config.performance.quic_max_idle_timeout_ms);
        quic_config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
        quic_config.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
        quic_config.set_initial_max_data(config.performance.quic_initial_max_data);
        quic_config.set_initial_max_stream_data_bidi_local(
            config.performance.quic_initial_max_stream_data,
        );
        quic_config.set_initial_max_stream_data_bidi_remote(
            config.performance.quic_initial_max_stream_data,
        );
        quic_config
            .set_initial_max_stream_data_uni(config.performance.quic_initial_max_stream_data);
        quic_config.set_initial_max_streams_bidi(config.performance.quic_initial_max_streams_bidi);
        quic_config.set_initial_max_streams_uni(config.performance.quic_initial_max_streams_uni);
        quic_config.set_disable_active_migration(true);

        if loaded_tls.client_auth.enabled {
            info!(
                "Downstream mTLS enabled (require_client_cert={})",
                loaded_tls.client_auth.require_client_cert
            );
        } else {
            quic_config.verify_peer(false);
        }

        Ok(quic_config)
    }

    fn build_quic_config_from_loaded(
        loaded_tls: &LoadedListenerTlsMaterial,
    ) -> Result<Config, ProxyError> {
        let tls_ctx_builder = Self::build_quic_ssl_context_builder(loaded_tls)?;
        Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls_ctx_builder)
            .map_err(|err| ProxyError::Transport(format!("failed to create QUIC config: {err}")))
    }

    fn build_quic_ssl_context_builder(
        loaded_tls: &LoadedListenerTlsMaterial,
    ) -> Result<SslContextBuilder, ProxyError> {
        let mut default_builder = Self::build_quic_ssl_context_builder_for_identity(
            &loaded_tls.default_identity.identity,
            &loaded_tls.client_auth,
            loaded_tls.client_auth_ca.as_ref(),
        )?;

        if loaded_tls.sni_identities.is_empty() {
            return Ok(default_builder);
        }

        let mut sni_certs: HashMap<String, QuicSniCertMaterial> =
            HashMap::with_capacity(loaded_tls.sni_identities.len());
        for (server_name, identity) in &loaded_tls.sni_identities {
            Self::validate_loaded_sni_identity(server_name, identity)?;
            let cert_pem = std::fs::read(&identity.identity.cert_path).map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to read SNI cert '{}': {}",
                    identity.identity.cert_path, err
                ))
            })?;
            let mut certs = X509::stack_from_pem(&cert_pem).map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to parse SNI cert '{}': {}",
                    identity.identity.cert_path, err
                ))
            })?;
            if certs.is_empty() {
                return Err(ProxyError::Tls(format!(
                    "SNI cert '{}' contains no certificates",
                    identity.identity.cert_path
                )));
            }
            let leaf = certs.remove(0);
            let chain = certs;
            let key_pem = std::fs::read(&identity.identity.key_path).map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to read SNI key '{}': {}",
                    identity.identity.key_path, err
                ))
            })?;
            let key = PKey::private_key_from_pem(&key_pem).map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to parse SNI key '{}': {}",
                    identity.identity.key_path, err
                ))
            })?;
            sni_certs.insert(
                server_name.clone(),
                QuicSniCertMaterial { leaf, chain, key },
            );
        }

        let sni_certs = Arc::new(sni_certs);
        default_builder.set_select_certificate_callback(move |mut hello| {
            let Some(server_name) = hello.servername(NameType::HOST_NAME) else {
                return Ok(());
            };
            let normalized_server_name = server_name.to_ascii_lowercase();
            let Some(data) = sni_certs.get(&normalized_server_name) else {
                return Ok(());
            };
            let ssl = hello.ssl_mut();
            ssl.set_certificate(&data.leaf).map_err(|err| {
                error!(
                    "failed to set QUIC SNI certificate for server_name='{}': {}",
                    normalized_server_name, err
                );
                SelectCertError::ERROR
            })?;
            for cert in &data.chain {
                ssl.add_chain_cert(cert).map_err(|err| {
                    error!(
                        "failed to add QUIC SNI chain cert for server_name='{}': {}",
                        normalized_server_name, err
                    );
                    SelectCertError::ERROR
                })?;
            }
            ssl.set_private_key(&data.key).map_err(|err| {
                error!(
                    "failed to set QUIC SNI key for server_name='{}': {}",
                    normalized_server_name, err
                );
                SelectCertError::ERROR
            })?;
            Ok(())
        });
        Ok(default_builder)
    }

    fn build_quic_ssl_context_builder_for_identity(
        identity: &RuntimeTlsIdentity,
        client_auth: &ClientAuth,
        client_auth_ca: Option<&LoadedClientAuthCa>,
    ) -> Result<SslContextBuilder, ProxyError> {
        let mut builder = SslContextBuilder::new(SslMethod::tls()).map_err(|err| {
            ProxyError::Tls(format!(
                "failed to build downstream QUIC TLS context for '{}': {}",
                identity.cert_path, err
            ))
        })?;

        builder
            .set_certificate_chain_file(&identity.cert_path)
            .map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to load certificate '{}': {}",
                    identity.cert_path, err
                ))
            })?;
        builder
            .set_private_key_file(&identity.key_path, SslFiletype::PEM)
            .map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to load key '{}': {}",
                    identity.key_path, err
                ))
            })?;

        if client_auth.enabled {
            let client_auth_ca = client_auth_ca.ok_or_else(|| {
                ProxyError::Tls(
                    "listen.tls.client_auth.ca_file is required when mTLS is enabled".to_string(),
                )
            })?;
            builder
                .set_ca_file(&client_auth_ca.ca_file)
                .map_err(|err| {
                    ProxyError::Tls(format!(
                        "failed to load listen.tls.client_auth.ca_file '{}': {}",
                        client_auth_ca.ca_file, err
                    ))
                })?;
            let verify_mode = if client_auth.require_client_cert {
                SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
            } else {
                SslVerifyMode::PEER
            };
            builder.set_verify(verify_mode);
        } else {
            builder.set_verify(SslVerifyMode::NONE);
        }

        Ok(builder)
    }

    fn tls_reload_generation_if_needed(
        listener_label: &str,
        current_generation: u64,
        listener_tls_store: &ListenerTlsReloadStore,
    ) -> Result<Option<u64>, ProxyError> {
        let next_generation = listener_tls_store
            .generation(listener_label)
            .ok_or_else(|| {
                ProxyError::Transport(format!(
                    "missing TLS reload state for listener '{}'",
                    listener_label
                ))
            })?;
        if next_generation == current_generation {
            return Ok(None);
        }
        Ok(Some(next_generation))
    }

    fn sync_tls_reload_state_if_needed(&mut self) -> Result<(), ProxyError> {
        let Some(current_generation) = Self::tls_reload_generation_if_needed(
            &self.listener_label,
            self.tls_reload_generation,
            &self.listener_tls_store,
        )?
        else {
            return Ok(());
        };

        self.quic_config = Self::build_quic_config(&self.config)?;
        self.tls_reload_generation = current_generation;
        info!(
            "Reloaded QUIC TLS configuration for listener {} at generation {}",
            self.listener_label, self.tls_reload_generation
        );
        Ok(())
    }

    fn sync_runtime_bundle_if_needed(&mut self) -> Result<(), ProxyError> {
        let Some(runtime_bundle) = self.runtime_bundle.as_ref() else {
            return self.sync_tls_reload_state_if_needed();
        };

        let runtime = runtime_bundle.current();
        let current_tls_generation = runtime
            .shared_state
            .listener_tls_store
            .generation(&self.listener_label)
            .ok_or_else(|| {
                ProxyError::Transport(format!(
                    "missing TLS reload state for listener '{}'",
                    self.listener_label
                ))
            })?;
        if runtime.generation == self.runtime_generation
            && current_tls_generation == self.tls_reload_generation
        {
            return Ok(());
        }

        let Some(listener_config) = runtime.listener_runtime_config(&self.listener_label) else {
            return Err(ProxyError::Transport(format!(
                "runtime reload dropped listener '{}'",
                self.listener_label
            )));
        };

        self.config = listener_config;
        self.listener_tls_store = Arc::clone(&runtime.shared_state.listener_tls_store);
        self.transport_pool = Arc::clone(&runtime.shared_state.transport_pool);
        self.backend_endpoints = Arc::clone(&runtime.shared_state.backend_endpoints);
        self.backend_resolution_store = Arc::clone(&runtime.shared_state.backend_resolution_store);
        self.backend_dns_resolver = runtime.shared_state.backend_dns_resolver.clone();
        self.upstream_policies = Arc::clone(&runtime.shared_state.upstream_policies);
        self.upstream_pools = runtime.shared_state.upstream_pools.clone();
        self.upstream_inflight = runtime.shared_state.upstream_inflight.clone();
        self.global_inflight = Arc::clone(&runtime.shared_state.global_inflight);
        self.routing_index = Arc::clone(&runtime.shared_state.routing_index);
        self.metrics = Arc::clone(&runtime.shared_state.metrics);
        self.resilience = Arc::clone(&runtime.shared_state.resilience);
        self.watchdog = Arc::clone(&runtime.shared_state.watchdog);
        self.backend_timeout = Duration::from_millis(self.config.performance.backend_timeout_ms);
        self.backend_body_idle_timeout =
            Duration::from_millis(self.config.performance.backend_body_idle_timeout_ms);
        self.backend_body_total_timeout =
            Duration::from_millis(self.config.performance.backend_body_total_timeout_ms);
        self.client_body_idle_timeout =
            Duration::from_millis(self.config.performance.client_body_idle_timeout_ms);
        self.backend_total_request_timeout =
            Duration::from_millis(self.config.performance.backend_total_request_timeout_ms);
        self.inflight_acquire_wait =
            Duration::from_millis(self.config.performance.inflight_acquire_wait_ms);
        self.max_active_connections = self.config.performance.max_active_connections.max(1);
        self.max_streams_per_connection =
            usize::try_from(self.config.performance.quic_initial_max_streams_bidi)
                .unwrap_or(usize::MAX)
                .max(1);
        self.max_request_body_bytes = self.config.performance.max_request_body_bytes;
        self.max_response_body_bytes = self.config.performance.max_response_body_bytes;
        self.request_buffer_global_cap_bytes =
            self.config.performance.request_buffer_global_cap_bytes;
        self.unknown_length_response_prebuffer_bytes = self
            .config
            .performance
            .unknown_length_response_prebuffer_bytes;
        self.require_client_cert = Self::runtime_listener_tls(&self.config)?
            .client_auth
            .require_client_cert;
        self.quic_config = Self::build_quic_config(&self.config)?;
        self.runtime_generation = runtime.generation;
        self.tls_reload_generation = current_tls_generation;
        info!(
            "Reloaded runtime configuration for listener {} at generation {}",
            self.listener_label, self.runtime_generation
        );
        Ok(())
    }

    pub fn start_draining(&mut self) {
        if self.draining {
            return;
        }
        self.draining = true;
        self.drain_start = Some(Instant::now());
        info!("Draining connections");
    }

    pub fn drain_complete(&mut self) -> bool {
        if !self.draining {
            return self.connections.is_empty();
        }

        if self.connections.is_empty() {
            return true;
        }

        // Once all in-flight streams are terminal, drain can complete without
        // waiting for clients to idle-close their QUIC connections.
        let has_active_streams = self
            .connections
            .values()
            .any(|conn| !conn.streams.is_empty());
        if !has_active_streams {
            self.close_all();
            return true;
        }

        if let Some(start) = self.drain_start
            && start.elapsed() >= self.drain_timeout
        {
            self.close_all();
            return true;
        }

        false
    }

    fn close_all(&mut self) {
        let mut send_buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];
        for connection in self.connections.values_mut() {
            let _ = connection.quic.close(true, 0x0, b"draining");
            Self::flush_send(&self.socket, &mut send_buf, connection);
        }

        self.connections.clear();
        self.cid_routes.clear();
        self.peer_routes.clear();
        self.cid_radix.clear();
        self.refresh_active_connection_metric();
    }

    fn take_or_create_connection(
        &mut self,
        peer: SocketAddr,
        local_addr: SocketAddr,
        packet_type: quiche::Type,
        dcid: &[u8],
        has_token: bool,
    ) -> Option<(QuicConnection, Arc<[u8]>)> {
        debug!(
            "Packet DCID (len={}): {:02x?}, type: {:?}, active connections: {}",
            dcid.len(),
            dcid,
            packet_type,
            self.connections.len()
        );

        // Try exact match first
        if let Some(mut connection) = self.connections.remove(dcid) {
            debug!("Found existing connection for DCID: {:02x?}", dcid);
            let primary = Arc::clone(&connection.primary_scid);
            self.peer_routes.remove(&connection.peer_address);
            connection.peer_address = peer;
            return Some((connection, primary));
        }

        // For Short packets, try prefix match (client may append bytes to our SCID)
        // This handles cases where client uses longer DCIDs based on server's SCID
        if packet_type == quiche::Type::Short
            && dcid.len() > MIN_SCID_LEN_BYTES
            && let Some(primary_cid) = resolve_primary_from_radix_prefix(
                dcid,
                &self.connections,
                &mut self.cid_routes,
                &mut self.cid_radix,
            )
        {
            debug!(
                "Found connection via prefix match. Resolved CID: {:02x?}, Packet DCID: {:02x?}",
                primary_cid, dcid
            );
            if let Some(mut connection) = self.connections.remove(primary_cid.as_ref()) {
                self.peer_routes.remove(&connection.peer_address);
                connection.peer_address = peer;
                return Some((connection, primary_cid));
            }
        }

        if self.draining {
            self.metrics.inc_ingress_draining_drop();
            return None;
        }

        // Only create new connections for Initial packets
        if packet_type != quiche::Type::Initial {
            debug!("Non-Initial packet for unknown connection, ignoring");
            self.metrics.inc_ingress_unroutable();
            return None;
        }

        // If this is a 0-RTT packet without a valid token, we need to reject it
        if has_token {
            debug!("Received 0-RTT attempt, will negotiate fresh connection");
            // return None;
        }

        // Rate-limit new connection creation to prevent unbounded memory growth
        // under connection floods. Existing connections are never affected.
        if !self.conn_rate_limiter.try_consume() {
            debug!(
                "New connection rate limit exceeded, dropping Initial packet from {}",
                peer
            );
            self.metrics.inc_ingress_rate_limited();
            return None;
        }

        if self.connections.len() >= self.max_active_connections {
            self.metrics.inc_connection_cap_reject();
            self.metrics
                .inc_overload_shed_reason(OverloadShedReason::ConnectionCap);
            debug!(
                "Active connection cap reached (cap={}, active={}), dropping Initial packet from {}",
                self.max_active_connections,
                self.connections.len(),
                peer
            );
            return None;
        }

        if let Err(err) = self.sync_runtime_bundle_if_needed() {
            error!(
                "Failed to reload QUIC TLS configuration for listener {}: {}",
                self.listener_label, err
            );
            self.metrics.inc_ingress_connection_create_failed();
            return None;
        }

        let mut scid_bytes = [0u8; DEFAULT_SCID_LEN_BYTES];
        rand::thread_rng().fill_bytes(&mut scid_bytes);

        let scid = quiche::ConnectionId::from_ref(&scid_bytes);

        let quic_connection =
            match quiche::accept(&scid, None, local_addr, peer, &mut self.quic_config) {
                Ok(conn) => conn,
                Err(e) => {
                    error!("quiche::accept failed: {:?}", e);
                    self.metrics.inc_ingress_connection_create_failed();
                    return None;
                }
            };

        let connection = QuicConnection {
            quic: quic_connection,
            h3: None,
            h3_config: self.h3_config.clone(),
            streams: HashMap::new(),
            peer_address: peer,
            last_activity: Instant::now(),
            primary_scid: Arc::from(&scid_bytes[..]),
            routing_scids: HashSet::from([Arc::from(&scid_bytes[..])]),
            packets_since_rotation: 0,
            last_scid_rotation: Instant::now(),
            tls_observed: false,
            tls_handshake_failure_recorded: false,
            tls_client_auth_failure_recorded: false,
            last_peer_error_snapshot: None,
            last_local_error_snapshot: None,
        };

        // Store connection using server's SCID (not client's DCID)
        // After handshake, client will use server's SCID as DCID in subsequent packets
        debug!(
            "Creating new connection with server SCID: {:02x?}",
            &scid_bytes
        );
        Some((connection, Arc::from(&scid_bytes[..])))
    }

    fn random_reset_token() -> u128 {
        let mut token = [0u8; RESET_TOKEN_LEN_BYTES];
        rand::thread_rng().fill_bytes(&mut token);
        u128::from_be_bytes(token)
    }

    fn maybe_rotate_scid(connection: &mut QuicConnection, metrics: &Metrics) {
        if !connection.quic.is_established() {
            return;
        }

        let now = Instant::now();
        let elapsed = now.saturating_duration_since(connection.last_scid_rotation);
        if connection.packets_since_rotation < SCID_ROTATION_PACKET_THRESHOLD
            && elapsed < scid_rotation_interval()
        {
            return;
        }

        if connection.quic.scids_left() == 0 {
            return;
        }

        let cid_len = connection
            .quic
            .source_id()
            .as_ref()
            .len()
            .max(MIN_SCID_LEN_BYTES);
        let mut cid_bytes = vec![0u8; cid_len];
        rand::thread_rng().fill_bytes(&mut cid_bytes);

        let new_scid = quiche::ConnectionId::from_ref(&cid_bytes);
        let reset_token = Self::random_reset_token();

        match connection.quic.new_scid(&new_scid, reset_token, true) {
            Ok(seq) => {
                connection.last_scid_rotation = now;
                connection.packets_since_rotation = 0;
                metrics.inc_scid_rotation();
                debug!(
                    "Issued new SCID seq={} cid={}",
                    seq,
                    hex::encode(&cid_bytes)
                );
            }
            Err(e) => {
                debug!("SCID rotation skipped: {:?}", e);
            }
        }
    }

    fn remove_connection_routes(&mut self, connection: &QuicConnection) {
        purge_connection_routes(
            &mut self.cid_routes,
            &mut self.cid_radix,
            &mut self.peer_routes,
            &connection.primary_scid,
            &connection.routing_scids,
            &connection.peer_address,
        );
    }

    fn sync_connection_routes(&mut self, connection: &mut QuicConnection) -> Arc<[u8]> {
        let mut active_scids: HashSet<Arc<[u8]>> = connection
            .quic
            .source_ids()
            .map(|cid| Arc::from(cid.as_ref()))
            .collect();

        if active_scids.is_empty() {
            active_scids.insert(Arc::clone(&connection.primary_scid));
        }

        let active_source_id: Arc<[u8]> = Arc::from(connection.quic.source_id().as_ref());
        let primary = if active_scids.contains(&active_source_id) {
            active_source_id
        } else if active_scids.contains(&connection.primary_scid) {
            Arc::clone(&connection.primary_scid)
        } else {
            active_scids
                .iter()
                .min_by(|left, right| left.as_ref().cmp(right.as_ref()))
                .cloned()
                .unwrap_or_else(|| Arc::clone(&connection.primary_scid))
        };

        let retired_scids: Vec<Arc<[u8]>> = connection
            .routing_scids
            .difference(&active_scids)
            .cloned()
            .collect();

        // Phase 1: make active SCIDs prefix-matchable before retirements.
        for cid in &active_scids {
            self.cid_radix.insert(Arc::clone(cid));
        }

        // Phase 2: clear previous aliases for this connection.
        for cid in &connection.routing_scids {
            self.cid_routes.remove(cid.as_ref());
        }

        // Phase 3: install aliases for active non-primary SCIDs.
        for cid in &active_scids {
            if *cid == primary {
                continue;
            }
            self.cid_routes
                .insert(Arc::clone(cid), Arc::clone(&primary));
        }

        // Phase 4: retire stale SCIDs after active set is fully installed.
        for retired in retired_scids {
            self.cid_radix.remove(retired.as_ref());
        }

        connection.routing_scids = active_scids;
        connection.primary_scid = Arc::clone(&primary);
        primary
    }

    fn poll_preamble(&mut self) -> bool {
        if let Err(err) = self.sync_runtime_bundle_if_needed() {
            error!(
                "Failed to refresh runtime configuration for listener {}: {}",
                self.listener_label, err
            );
        }
        self.watchdog.mark_poll_progress();
        if !self.watchdog.restart_requested() {
            self.watchdog_worker_drained = false;
        }
        if self.watchdog.restart_requested() && !self.draining {
            warn!("Watchdog requested restart; entering draining mode");
            self.start_draining();
        }
        if self.draining && self.drain_complete() {
            if self.watchdog.restart_requested() && !self.watchdog_worker_drained {
                self.watchdog.mark_worker_drained();
                self.watchdog_worker_drained = true;
            }
            return false;
        }
        true
    }

    pub fn poll(&mut self) {
        if !self.poll_preamble() {
            return;
        }

        // Read a UDP datagram and feed it into quiche.
        let (len, peer) = match self.socket.recv_from(self.recv_buf.as_mut_slice()) {
            Ok(v) => v,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                self.handle_timeouts();
                return;
            }
            Err(_) => return,
        };

        debug!("Received UDP datagram ({} bytes)", len);
        let local_addr = self.local_addr;
        let packet_ptr = self.recv_buf.as_mut_ptr();
        // SAFETY: `packet_ptr` points into `self.recv_buf` and remains valid for this call.
        // We do not access `self.recv_buf` again until `process_datagram_inner` returns.
        let packet = unsafe { std::slice::from_raw_parts_mut(packet_ptr, len) };
        self.process_datagram_inner(peer, local_addr, packet);
    }

    pub fn poll_idle(&mut self) {
        if !self.poll_preamble() {
            return;
        }
        self.handle_timeouts();
    }

    pub fn process_datagram(
        &mut self,
        peer: SocketAddr,
        local_addr: SocketAddr,
        packet: &mut [u8],
    ) {
        if !self.poll_preamble() {
            return;
        }
        self.process_datagram_inner(peer, local_addr, packet);
    }

    fn process_datagram_inner(
        &mut self,
        peer: SocketAddr,
        local_addr: SocketAddr,
        packet: &mut [u8],
    ) {
        self.metrics.inc_ingress_packet();

        let header = match quiche::Header::from_slice(packet, quiche::MAX_CONN_ID_LEN) {
            Ok(hdr) => hdr,
            Err(_) => {
                error!("Failed to parse QUIC packet header");
                self.metrics.inc_ingress_bad_header();
                return;
            }
        };
        let packet_type = header.ty;
        let header_has_token = header.token.is_some();
        let dcid = header.dcid.as_ref();

        if packet_type == quiche::Type::VersionNegotiation {
            let len = match quiche::negotiate_version(
                &header.scid,
                &header.dcid,
                self.send_buf.as_mut_slice(),
            ) {
                Ok(len) => len,
                Err(e) => {
                    error!("Version negotiation failed: {:?}", e);
                    self.metrics.inc_ingress_version_neg_failed();
                    return;
                }
            };

            if let Err(e) = self.socket.send_to(&self.send_buf[..len], peer) {
                error!("Failed to send version negotiation: {:?}", e);
            }
            return;
        }

        let transport_pool = self.transport_pool.clone();

        // First, try to find existing connection by DCID
        debug!("Looking up connection with DCID: {:?}", hex::encode(dcid));
        let (mut connection, current_primary) =
            if let Some(mut conn) = self.connections.remove(dcid) {
                let primary = Arc::clone(&conn.primary_scid);
                self.peer_routes.remove(&conn.peer_address);
                conn.peer_address = peer;
                debug!("Found existing connection for {}", peer);
                (conn, primary)
            } else if let Some(primary) = self.cid_routes.get(dcid).cloned() {
                if let Some(mut conn) = self.connections.remove(&primary) {
                    self.peer_routes.remove(&conn.peer_address);
                    conn.peer_address = peer;
                    debug!(
                        "Found existing connection via SCID alias {} -> {}",
                        hex::encode(dcid),
                        hex::encode(&primary)
                    );
                    (conn, primary)
                } else {
                    // Stale alias entry.
                    self.cid_routes.remove(dcid);
                    match self.take_or_create_connection(
                        peer,
                        local_addr,
                        packet_type,
                        dcid,
                        header_has_token,
                    ) {
                        Some(conn) => {
                            debug!("Created new connection for {}", peer);
                            conn
                        }
                        None => {
                            debug!(
                                "Dropping packet for unknown connection from {} (DCID: {:?})",
                                peer,
                                hex::encode(dcid)
                            );
                            return;
                        }
                    }
                }
            } else if let Some(primary) = self.peer_routes.get(&peer).cloned() {
                if let Some(mut conn) = self.connections.remove(&primary) {
                    self.peer_routes.remove(&conn.peer_address);
                    conn.peer_address = peer;
                    debug!(
                        "Found existing connection via peer map {} -> {}",
                        peer,
                        hex::encode(&primary)
                    );
                    (conn, primary)
                } else {
                    // Stale peer map entry.
                    self.peer_routes.remove(&peer);
                    match self.take_or_create_connection(
                        peer,
                        local_addr,
                        packet_type,
                        dcid,
                        header_has_token,
                    ) {
                        Some(conn_pair) => {
                            debug!("Created new connection for {}", peer);
                            conn_pair
                        }
                        None => {
                            debug!(
                                "Dropping packet for unknown connection from {} (DCID: {:?})",
                                peer,
                                hex::encode(dcid)
                            );
                            return;
                        }
                    }
                }
            } else {
                // No existing connection found, try to create new one.
                match self.take_or_create_connection(
                    peer,
                    local_addr,
                    packet_type,
                    dcid,
                    header_has_token,
                ) {
                    Some(conn_pair) => {
                        debug!("Created new connection for {}", peer);
                        conn_pair
                    }
                    None => {
                        debug!(
                            "Dropping packet for unknown connection from {} (DCID: {:?})",
                            peer,
                            hex::encode(dcid)
                        );
                        return;
                    }
                }
            };

        let recv_info = quiche::RecvInfo {
            from: peer,
            to: local_addr,
        };

        if let Err(e) = connection.quic.recv(packet, recv_info) {
            error!("QUIC recv failed: {:?}", e);
            Self::release_connection_streams(&mut connection, &self.metrics);
            self.remove_connection_routes(&connection);
            self.refresh_active_connection_metric();
            return;
        }

        if let Some(err) = connection.quic.peer_error() {
            maybe_log_quic_connection_error(
                "peer",
                connection.peer_address,
                connection.quic.trace_id(),
                err,
                &mut connection.last_peer_error_snapshot,
            );
        }

        if let Some(err) = connection.quic.local_error() {
            maybe_log_quic_connection_error(
                "local",
                connection.peer_address,
                connection.quic.trace_id(),
                err,
                &mut connection.last_local_error_snapshot,
            );
        }

        connection.last_activity = Instant::now();
        connection.packets_since_rotation = connection.packets_since_rotation.saturating_add(1);

        // Debug logs
        debug!(
            "QUIC connection state - established: {}, in_early_data: {}, closed: {}",
            connection.quic.is_established(),
            connection.quic.is_in_early_data(),
            connection.quic.is_closed()
        );

        self.maybe_record_quic_tls_observation(&mut connection);
        self.maybe_record_quic_tls_handshake_failure(&mut connection);

        if self.require_client_cert
            && connection.quic.is_established()
            && connection.quic.peer_cert().is_none()
        {
            if !connection.tls_client_auth_failure_recorded {
                self.metrics.record_downstream_tls_handshake_failure(
                    &Self::listener_label(&self.config),
                    "missing_client_cert",
                );
                connection.tls_client_auth_failure_recorded = true;
            }
            warn!(
                "closing connection {}: downstream mTLS requires a client certificate",
                connection.quic.trace_id()
            );
            let _ = connection
                .quic
                .close(true, 0x01A0, b"client certificate required");
        }

        if !connection.quic.is_closed()
            && (connection.quic.is_established() || connection.quic.is_in_early_data())
            && let Err(e) = Self::handle_h3(
                &mut connection,
                Arc::clone(&transport_pool),
                Arc::clone(&self.backend_endpoints),
                Arc::clone(&self.backend_resolution_store),
                Arc::clone(&self.upstream_policies),
                &self.upstream_pools,
                &self.upstream_inflight,
                Arc::clone(&self.global_inflight),
                self.backend_timeout,
                self.backend_body_idle_timeout,
                self.backend_body_total_timeout,
                self.backend_total_request_timeout,
                &self.routing_index,
                Arc::clone(&self.metrics),
                &self.resilience,
                self.max_request_body_bytes,
                self.max_response_body_bytes,
                self.request_buffer_global_cap_bytes,
                self.unknown_length_response_prebuffer_bytes,
                self.client_body_idle_timeout,
                self.inflight_acquire_wait,
                self.config.observability.tracing.enabled,
                self.config.observability.routing.enabled,
                self.config.observability.routing.include_reason,
                self.config.listen.listen.port,
                self.max_streams_per_connection,
            )
        {
            error!("HTTP/3 handling failed: {:?}", e);
            let _ = connection
                .quic
                .close(true, 0x1, b"http3 protocol handling error");
        }

        Self::maybe_rotate_scid(&mut connection, &self.metrics);

        let mut send_buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];

        Self::flush_send(&self.socket, &mut send_buf, &mut connection);
        Self::handle_timeout(&self.socket, &mut send_buf, &mut connection);

        if !connection.quic.is_closed() {
            let new_primary = self.sync_connection_routes(&mut connection);
            debug!(
                "Storing connection with key: {:02x?} (previous: {:02x?})",
                &new_primary, &current_primary
            );
            self.peer_routes
                .insert(connection.peer_address, Arc::clone(&new_primary));
            self.connections
                .insert(Arc::clone(&new_primary), connection);
        } else {
            Self::release_connection_streams(&mut connection, &self.metrics);
            self.remove_connection_routes(&connection);
            debug!("Connection closed, not storing");
        }

        self.refresh_active_connection_metric();
    }

    fn handle_timeouts(&mut self) {
        if self.connections.is_empty() {
            return;
        }

        let mut send_buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];
        let mut to_remove = Vec::new();

        for (scid, connection) in self.connections.iter_mut() {
            let timeout = match connection.quic.timeout() {
                Some(timeout) => timeout,
                None => {
                    if connection.quic.is_closed() {
                        Self::release_connection_streams(connection, &self.metrics);
                        to_remove.push(scid.clone());
                    }
                    continue;
                }
            };

            if connection.last_activity.elapsed() >= timeout {
                connection.quic.on_timeout();
                // Do NOT reset last_activity here: only real packet I/O
                // resets it.  Resetting on timeout would prevent quiche
                // from receiving on_timeout() again during the drain
                // period, causing draining connections to linger.
                Self::flush_send(&self.socket, &mut send_buf, connection);
            }

            if connection.quic.is_closed() {
                Self::release_connection_streams(connection, &self.metrics);
                to_remove.push(scid.clone());
                continue;
            }

            // Advance in-flight streams independent of inbound packets.
            if let Some(mut h3) = connection.h3.take() {
                if let Err(e) = Self::advance_streams_non_blocking(
                    &mut connection.streams,
                    &mut connection.quic,
                    &mut h3,
                    &self.upstream_pools,
                    &self.routing_index,
                    self.backend_body_idle_timeout,
                    self.backend_body_total_timeout,
                    &self.metrics,
                    self.backend_total_request_timeout,
                    &self.resilience,
                    self.max_response_body_bytes,
                    self.unknown_length_response_prebuffer_bytes,
                    self.client_body_idle_timeout,
                    self.config.listen.listen.port,
                ) {
                    error!("advance_streams_non_blocking in timeout path: {:?}", e);
                }
                connection.h3 = Some(h3);
                Self::flush_send(&self.socket, &mut send_buf, connection);
            }
        }

        sweep_closed_connections(
            &mut self.connections,
            &mut self.cid_routes,
            &mut self.cid_radix,
            &mut self.peer_routes,
            to_remove,
            |c| ConnectionRoutes::from(c),
        );
        self.refresh_active_connection_metric();
    }

    fn handle_timeout(socket: &UdpSocket, send_buf: &mut [u8], connection: &mut QuicConnection) {
        let timeout = match connection.quic.timeout() {
            Some(timeout) => timeout,
            None => return,
        };

        if connection.last_activity.elapsed() >= timeout {
            connection.quic.on_timeout();
            connection.last_activity = Instant::now();
            Self::flush_send(socket, send_buf, connection);
        }
    }

    fn refresh_active_connection_metric(&self) {
        self.metrics.set_active_connections(self.connections.len());
    }

    fn release_connection_streams(connection: &mut QuicConnection, metrics: &Metrics) {
        for req in connection.streams.values_mut() {
            abort_stream(req, metrics);
        }
        connection.streams.clear();
    }

    fn push_request_chunk(
        req: &mut RequestEnvelope,
        chunk: Bytes,
        metrics: &Metrics,
        max_request_body_bytes: usize,
        request_buffer_global_cap_bytes: usize,
    ) -> Result<(), RequestBufferError> {
        let chunk_len = chunk.len();
        if !metrics.try_reserve_request_buffer(chunk_len, request_buffer_global_cap_bytes) {
            return Err(RequestBufferError::GlobalCap);
        }

        let next = req.body_buf_bytes.saturating_add(chunk.len());
        if next > max_request_body_bytes {
            metrics.release_request_buffer(chunk_len);
            return Err(RequestBufferError::StreamCap);
        }
        req.body_buf_bytes = next;
        req.body_buf.push_back(chunk);
        Ok(())
    }

    fn enqueue_request_chunk(
        req: &mut RequestEnvelope,
        chunk: Bytes,
        metrics: &Metrics,
        max_request_body_bytes: usize,
        request_buffer_global_cap_bytes: usize,
    ) -> Result<(), RequestBufferError> {
        if let Some(tx) = &req.body_tx {
            match tx.try_send(chunk) {
                Ok(()) => Ok(()),
                Err(TrySendError::Full(chunk)) => Self::push_request_chunk(
                    req,
                    chunk,
                    metrics,
                    max_request_body_bytes,
                    request_buffer_global_cap_bytes,
                ),
                Err(TrySendError::Closed(_chunk)) => {
                    if req.body_buf_bytes > 0 {
                        metrics.release_request_buffer(req.body_buf_bytes);
                    }
                    req.body_tx = None;
                    req.body_buf.clear();
                    req.body_buf_bytes = 0;
                    Ok(())
                }
            }
        } else {
            Self::push_request_chunk(
                req,
                chunk,
                metrics,
                max_request_body_bytes,
                request_buffer_global_cap_bytes,
            )
        }
    }

    fn flush_request_buffer(req: &mut RequestEnvelope, metrics: &Metrics) {
        let Some(tx) = req.body_tx.as_ref() else {
            return;
        };

        loop {
            let Some(chunk) = req.body_buf.pop_front() else {
                break;
            };
            let len = chunk.len();
            match tx.try_send(chunk) {
                Ok(()) => {
                    req.body_buf_bytes = req.body_buf_bytes.saturating_sub(len);
                    metrics.release_request_buffer(len);
                }
                Err(TrySendError::Full(chunk)) => {
                    req.body_buf.push_front(chunk);
                    break;
                }
                Err(TrySendError::Closed(_chunk)) => {
                    if req.body_buf_bytes > 0 {
                        metrics.release_request_buffer(req.body_buf_bytes);
                    }
                    req.body_buf.clear();
                    req.body_buf_bytes = 0;
                    req.body_tx = None;
                    break;
                }
            }
        }
    }

    fn try_acquire_owned_with_micro_wait(
        semaphore: Arc<Semaphore>,
        wait_budget: Duration,
    ) -> Result<(tokio::sync::OwnedSemaphorePermit, bool), tokio::sync::TryAcquireError> {
        match Arc::clone(&semaphore).try_acquire_owned() {
            Ok(permit) => return Ok((permit, false)),
            Err(err) if wait_budget.is_zero() => return Err(err),
            Err(_) => {}
        }

        let start = Instant::now();
        loop {
            if start.elapsed() >= wait_budget {
                return Err(tokio::sync::TryAcquireError::NoPermits);
            }
            std::thread::sleep(Duration::from_millis(1));
            if let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() {
                return Ok((permit, true));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_h3(
        connection: &mut QuicConnection,
        transport_pool: Arc<UpstreamTransportPool>,
        backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
        backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
        upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        upstream_inflight: &HashMap<String, Arc<Semaphore>>,
        global_inflight: Arc<Semaphore>,
        backend_timeout: Duration,
        backend_body_idle_timeout: Duration,
        backend_body_total_timeout: Duration,
        backend_total_request_timeout: Duration,
        routing_index: &RouteIndex,
        metrics: Arc<Metrics>,
        resilience: &RuntimeResilience,
        max_request_body_bytes: usize,
        max_response_body_bytes: usize,
        request_buffer_global_cap_bytes: usize,
        unknown_length_response_prebuffer_bytes: usize,
        client_body_idle_timeout: Duration,
        inflight_acquire_wait: Duration,
        tracing_enabled: bool,
        routing_transparency_enabled: bool,
        routing_transparency_include_reason: bool,
        listen_port: u16,
        max_streams_per_connection: usize,
    ) -> Result<(), quiche::h3::Error> {
        let mut body_buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];

        if connection.h3.is_none() {
            connection.h3 = Some(quiche::h3::Connection::with_transport(
                &mut connection.quic,
                &connection.h3_config,
            )?);
        }

        let h3 = match connection.h3.as_mut() {
            Some(h3) => h3,
            None => return Ok(()),
        };

        loop {
            match h3.poll(&mut connection.quic) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    let request = match validate_request_headers(&list, resilience) {
                        Ok(request) => request,
                        Err((status, body, is_policy)) => {
                            metrics.inc_failure();
                            metrics.inc_request_validation_reject();
                            if is_policy {
                                metrics.inc_policy_denied();
                            }
                            metrics.record_route(
                                "unrouted",
                                Duration::from_millis(0),
                                RouteOutcome::Failure,
                            );
                            let _ = Self::send_simple_response(
                                h3,
                                &mut connection.quic,
                                stream_id,
                                status,
                                body,
                            );
                            continue;
                        }
                    };
                    let method = request.method;
                    let path = request.path;
                    let authority = request.authority;
                    let content_length = request.content_length;

                    metrics.inc_total();
                    let request_start = Instant::now();

                    if connection.quic.is_in_early_data() {
                        if resilience.early_data_allowed_for(&method) {
                            metrics.inc_early_data_accepted();
                        } else {
                            metrics.inc_failure();
                            metrics.inc_early_data_rejected();
                            metrics.inc_policy_denied();
                            metrics.record_route(
                                "unrouted",
                                request_start.elapsed(),
                                RouteOutcome::Failure,
                            );
                            Self::send_simple_response(
                                h3,
                                &mut connection.quic,
                                stream_id,
                                http::StatusCode::TOO_EARLY,
                                b"request blocked by early-data policy\n",
                            )?;
                            continue;
                        }
                    }

                    // Route lookup — needed to start the H2 request immediately.
                    let sticky_cid_key = hex::encode(connection.primary_scid.as_ref());
                    let lb_header_lookup = |name: &str| {
                        list.iter()
                            .find(|header| header.name().eq_ignore_ascii_case(name.as_bytes()))
                            .and_then(|header| std::str::from_utf8(header.value()).ok())
                            .map(str::to_string)
                    };
                    let resolved = Self::resolve_backend(
                        &method,
                        &path,
                        authority.as_deref(),
                        Some(sticky_cid_key.as_str()),
                        upstream_pools,
                        routing_index,
                        Some(&lb_header_lookup),
                    );

                    let (
                        body_tx,
                        upstream_result_rx,
                        backend_addr,
                        backend_index,
                        upstream_name,
                        backend_lb,
                        route_path_len,
                        route_host_specific,
                        route_reason,
                        upstream_pool,
                        global_inflight_permit,
                        upstream_inflight_permit,
                        adaptive_admission_permit,
                        route_queue_permit,
                        request_fin_received,
                        bodyless_mode,
                        trace_id,
                        span_id,
                        traceparent,
                        trace_span,
                        request_id,
                    ) = match resolved {
                        Ok(ResolvedBackend {
                            upstream_name,
                            backend_addr: addr,
                            backend_index: idx,
                            upstream_pool,
                            backend_lb,
                            route_path_len,
                            route_host_specific,
                            route_reason,
                        }) => {
                            resilience.brownout.observe_admission_pressure(
                                resilience.adaptive_admission.inflight_percent(),
                            );
                            metrics.set_brownout_active(resilience.brownout.is_active());
                            if !resilience.brownout.route_allowed(&upstream_name) {
                                metrics.inc_failure();
                                metrics.inc_overload_shed_reason(OverloadShedReason::Brownout);
                                metrics.record_route(
                                    &upstream_name,
                                    request_start.elapsed(),
                                    RouteOutcome::OverloadShed,
                                );
                                Self::send_overload_response(
                                    h3,
                                    &mut connection.quic,
                                    stream_id,
                                    b"brownout active, non-core route shed\n",
                                    resilience.shed_retry_after_seconds,
                                )?;
                                resilience
                                    .adaptive_admission
                                    .observe(request_start.elapsed(), true);
                                continue;
                            }

                            let adaptive_permit = match resilience.adaptive_admission.try_acquire()
                            {
                                Some(permit) => permit,
                                None => {
                                    metrics.inc_failure();
                                    metrics.inc_overload_shed_reason(
                                        OverloadShedReason::AdaptiveAdmission,
                                    );
                                    metrics.record_route(
                                        &upstream_name,
                                        request_start.elapsed(),
                                        RouteOutcome::OverloadShed,
                                    );
                                    Self::send_overload_response(
                                        h3,
                                        &mut connection.quic,
                                        stream_id,
                                        b"adaptive admission overload\n",
                                        resilience.shed_retry_after_seconds,
                                    )?;
                                    resilience
                                        .adaptive_admission
                                        .observe(request_start.elapsed(), true);
                                    continue;
                                }
                            };

                            let route_queue_permit =
                                match resilience.route_queue.try_acquire(&upstream_name) {
                                    Ok(permit) => permit,
                                    Err(RouteQueueRejection::RouteCap) => {
                                        metrics.inc_failure();
                                        metrics
                                            .inc_overload_shed_reason(OverloadShedReason::RouteCap);
                                        metrics.record_route(
                                            &upstream_name,
                                            request_start.elapsed(),
                                            RouteOutcome::OverloadShed,
                                        );
                                        Self::send_overload_response(
                                            h3,
                                            &mut connection.quic,
                                            stream_id,
                                            b"route queue cap exceeded\n",
                                            resilience.shed_retry_after_seconds,
                                        )?;
                                        resilience
                                            .adaptive_admission
                                            .observe(request_start.elapsed(), true);
                                        continue;
                                    }
                                    Err(RouteQueueRejection::GlobalCap) => {
                                        metrics.inc_failure();
                                        metrics.inc_overload_shed_reason(
                                            OverloadShedReason::RouteGlobalCap,
                                        );
                                        metrics.record_route(
                                            &upstream_name,
                                            request_start.elapsed(),
                                            RouteOutcome::OverloadShed,
                                        );
                                        Self::send_overload_response(
                                            h3,
                                            &mut connection.quic,
                                            stream_id,
                                            b"global queue cap exceeded\n",
                                            resilience.shed_retry_after_seconds,
                                        )?;
                                        resilience
                                            .adaptive_admission
                                            .observe(request_start.elapsed(), true);
                                        continue;
                                    }
                                };

                            let global_permit = match Self::try_acquire_owned_with_micro_wait(
                                Arc::clone(&global_inflight),
                                inflight_acquire_wait,
                            ) {
                                Ok((permit, waited)) => {
                                    if waited {
                                        metrics.inc_inflight_wait_admit_global();
                                    }
                                    permit
                                }
                                Err(_) => {
                                    metrics.inc_failure();
                                    metrics.inc_overload_shed_reason(
                                        OverloadShedReason::GlobalInflight,
                                    );
                                    metrics.record_route(
                                        &upstream_name,
                                        request_start.elapsed(),
                                        RouteOutcome::OverloadShed,
                                    );
                                    Self::send_overload_response(
                                        h3,
                                        &mut connection.quic,
                                        stream_id,
                                        b"overloaded, retry later\n",
                                        resilience.shed_retry_after_seconds,
                                    )?;
                                    resilience
                                        .adaptive_admission
                                        .observe(request_start.elapsed(), true);
                                    continue;
                                }
                            };

                            let upstream_permit = match upstream_inflight
                                .get(&upstream_name)
                                .cloned()
                            {
                                Some(semaphore) => match Self::try_acquire_owned_with_micro_wait(
                                    semaphore,
                                    inflight_acquire_wait,
                                ) {
                                    Ok((permit, waited)) => {
                                        if waited {
                                            metrics.inc_inflight_wait_admit_upstream();
                                        }
                                        permit
                                    }
                                    Err(_) => {
                                        drop(global_permit);
                                        metrics.inc_failure();
                                        metrics.inc_overload_shed_reason(
                                            OverloadShedReason::UpstreamInflight,
                                        );
                                        metrics.record_route(
                                            &upstream_name,
                                            request_start.elapsed(),
                                            RouteOutcome::OverloadShed,
                                        );
                                        Self::send_overload_response(
                                            h3,
                                            &mut connection.quic,
                                            stream_id,
                                            b"upstream overloaded, retry later\n",
                                            resilience.shed_retry_after_seconds,
                                        )?;
                                        resilience
                                            .adaptive_admission
                                            .observe(request_start.elapsed(), true);
                                        continue;
                                    }
                                },
                                None => {
                                    drop(global_permit);
                                    metrics.inc_failure();
                                    metrics.inc_overload_shed_reason(
                                        OverloadShedReason::UpstreamInflight,
                                    );
                                    metrics.record_route(
                                        &upstream_name,
                                        request_start.elapsed(),
                                        RouteOutcome::OverloadShed,
                                    );
                                    Self::send_simple_response(
                                        h3,
                                        &mut connection.quic,
                                        stream_id,
                                        http::StatusCode::SERVICE_UNAVAILABLE,
                                        b"upstream admission limiter unavailable\n",
                                    )?;
                                    resilience
                                        .adaptive_admission
                                        .observe(request_start.elapsed(), true);
                                    continue;
                                }
                            };

                            let request_id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
                            let incoming_traceparent = extract_header_value(&list, b"traceparent")
                                .and_then(parse_traceparent);
                            let trace_id = incoming_traceparent
                                .as_ref()
                                .map(|(trace_id, _)| trace_id.clone())
                                .or_else(|| {
                                    tracing_enabled.then(|| {
                                        generated_trace_id(connection.quic.trace_id(), request_id)
                                    })
                                });
                            let span_id = trace_id.as_ref().map(|_| generated_span_id(request_id));
                            let traceparent = trace_id
                                .as_ref()
                                .zip(span_id.as_ref())
                                .map(|(trace_id, span_id)| format!("00-{trace_id}-{span_id}-01"));
                            let trace_span = trace_id.as_ref().zip(span_id.as_ref()).map(
                                |(trace_id, span_id)| {
                                    info_span!(
                                        "spooky.request",
                                        request_id = request_id,
                                        trace_id = %trace_id,
                                        span_id = %span_id,
                                        method = %method,
                                        path = %path
                                    )
                                },
                            );
                            let bodyless_mode = is_bodyless_request_mode(&method, content_length);
                            let (tx, boxed, request_fin_received) = if bodyless_mode {
                                (None, BoxBody::new(Full::new(Bytes::new())), true)
                            } else {
                                // Create a channel body so quiche Data chunks stream
                                // directly into the in-flight H2 request.
                                let (tx, channel_body) =
                                    ChannelBody::channel(REQUEST_CHUNK_CHANNEL_CAPACITY);
                                (Some(tx), channel_body.boxed(), false)
                            };
                            let backend_endpoint = match backend_endpoints.get(&addr).cloned() {
                                Some(endpoint) => endpoint,
                                None => {
                                    drop(upstream_permit);
                                    drop(global_permit);
                                    metrics.inc_failure();
                                    metrics.record_route(
                                        &upstream_name,
                                        request_start.elapsed(),
                                        RouteOutcome::Failure,
                                    );
                                    Self::send_simple_response(
                                        h3,
                                        &mut connection.quic,
                                        stream_id,
                                        http::StatusCode::BAD_GATEWAY,
                                        b"unknown backend endpoint\n",
                                    )?;
                                    error!("missing parsed backend endpoint for {}", addr);
                                    resilience
                                        .adaptive_admission
                                        .observe(request_start.elapsed(), true);
                                    continue;
                                }
                            };
                            let upstream_policy = upstream_policies
                                .get(&upstream_name)
                                .cloned()
                                .unwrap_or_default();
                            let request = match build_h2_request_for_endpoint_with_host_policy(
                                &backend_endpoint,
                                &upstream_policy.host.0,
                                &upstream_policy.forwarded_headers.0,
                                &method,
                                &path,
                                &list,
                                boxed,
                                None,
                                ForwardedContext {
                                    client_addr: connection.peer_address,
                                    request_authority: authority.as_deref(),
                                    request_id,
                                    traceparent: traceparent.as_deref(),
                                },
                            ) {
                                Ok(request) => request,
                                Err(err) => {
                                    drop(upstream_permit);
                                    drop(global_permit);
                                    metrics.inc_failure();
                                    metrics.record_route(
                                        &upstream_name,
                                        request_start.elapsed(),
                                        RouteOutcome::Failure,
                                    );
                                    Self::send_simple_response(
                                        h3,
                                        &mut connection.quic,
                                        stream_id,
                                        http::StatusCode::BAD_REQUEST,
                                        b"invalid request\n",
                                    )?;
                                    error!("failed to build upstream request: {}", err);
                                    resilience
                                        .adaptive_admission
                                        .observe(request_start.elapsed(), true);
                                    continue;
                                }
                            };

                            let transport = transport_pool.clone();
                            let fwd_addr = addr.clone();
                            let cb = Arc::clone(&resilience.circuit_breakers);
                            let retry_budget = Arc::clone(&resilience.retry_budget);
                            let route_name = upstream_name.clone();
                            let backend_endpoints = Arc::clone(&backend_endpoints);
                            let backend_resolutions = Arc::clone(&backend_resolution_store);
                            let send_metrics = Arc::clone(&metrics);
                            let allow_hedge = bodyless_mode
                                && resilience.hedging_allowed_for(&method, &upstream_name, true);
                            let hedge_delay = resilience.hedging_delay;
                            let alternate_backend =
                                Self::pick_alternate_backend(&upstream_pool, idx);
                            let forward_meta = bodyless_mode.then(|| {
                                Arc::new(ForwardRequestMeta {
                                    method: Arc::<str>::from(method.as_str()),
                                    path: Arc::<str>::from(path.as_str()),
                                    authority: authority.as_deref().map(Arc::<str>::from),
                                    headers: Arc::new(list.clone()),
                                    client_addr: connection.peer_address,
                                    request_id,
                                    traceparent: traceparent.as_deref().map(Arc::<str>::from),
                                    host_policy: upstream_policy.host.0.clone(),
                                    forwarded_header_policy: upstream_policy
                                        .forwarded_headers
                                        .0
                                        .clone(),
                                })
                            });
                            let trace_span_for_upstream = trace_span.clone();
                            let (result_tx, result_rx) = oneshot::channel::<UpstreamResult>();
                            let fut = async move {
                                let mut hedge_telemetry = crate::HedgeTelemetry::default();
                                let mut retry_count: u8 = 0;
                                let mut retry_attempt_reason: Option<RetryReason> = None;
                                let mut retry_denial_reason: Option<RetryReason> = None;
                                let result: ForwardResult = async {
                                    retry_budget.mark_primary(&route_name);

                                    let send_once =
                                        |backend: String,
                                         req: http::Request<
                                            BoxBody<Bytes, std::convert::Infallible>,
                                        >,
                                         cb: Arc<crate::resilience::CircuitBreakers>,
                                         transport: Arc<UpstreamTransportPool>,
                                         metrics: Arc<Metrics>,
                                         backend_resolutions: Arc<RuntimeBackendResolutionStore>| async move {
                                            if !cb.allow_request(&backend) {
                                                return Err(ProxyError::Pool(
                                                    PoolError::CircuitOpen(backend),
                                                ));
                                            }
                                            Self::record_backend_connect_attempt(
                                                &metrics,
                                                &backend_resolutions,
                                                &backend,
                                            );
                                            let send_result = tokio::time::timeout(
                                                backend_timeout,
                                                transport.send(&backend, req),
                                            )
                                            .await
                                            .map_err(|_| ProxyError::Timeout);
                                            match &send_result {
                                                Ok(Ok(_)) => cb.record_success(&backend),
                                                _ => cb.record_failure(&backend),
                                            }
                                            Ok(send_result??)
                                        };

                                    let response: Response<Incoming> = if allow_hedge {
                                        let hedge_candidate = alternate_backend
                                            .clone()
                                            .and_then(|(backend, _idx)| {
                                                let meta = forward_meta.as_ref()?;
                                                let endpoint = backend_endpoints.get(&backend)?;
                                                meta.build_bodyless_request(endpoint)
                                                    .ok()
                                                    .map(|req| (backend, req))
                                            });

                                        if let Some((hedge_backend, hedge_request)) =
                                            hedge_candidate
                                        {
                                            let primary_started = Instant::now();
                                            let primary_backend = fwd_addr.clone();
                                            let primary_fut = send_once(
                                                primary_backend,
                                                request,
                                                Arc::clone(&cb),
                                                Arc::clone(&transport),
                                                Arc::clone(&send_metrics),
                                                Arc::clone(&backend_resolutions),
                                            );
                                            tokio::pin!(primary_fut);
                                            let hedge_sleep = tokio::time::sleep(hedge_delay);
                                            tokio::pin!(hedge_sleep);

                                            if let Some(result) = tokio::select! {
                                                result = &mut primary_fut => Some(result),
                                                _ = &mut hedge_sleep => None,
                                            } {
                                                result?
                                            } else if retry_budget.allow_retry(&route_name).is_ok() {
                                                hedge_telemetry.launched = true;
                                                let hedge_fut = send_once(
                                                    hedge_backend,
                                                    hedge_request,
                                                    Arc::clone(&cb),
                                                    Arc::clone(&transport),
                                                    Arc::clone(&send_metrics),
                                                    Arc::clone(&backend_resolutions),
                                                );
                                                tokio::pin!(hedge_fut);
                                                tokio::select! {
                                                    result = &mut primary_fut => {
                                                        hedge_telemetry.primary_won_after_trigger = true;
                                                        hedge_telemetry.hedge_wasted = true;
                                                        result?
                                                    },
                                                    result = &mut hedge_fut => {
                                                        hedge_telemetry.hedge_won = true;
                                                        let elapsed_ms = primary_started.elapsed().as_millis() as u64;
                                                        let delay_ms = hedge_delay.as_millis() as u64;
                                                        hedge_telemetry.primary_late_ms = elapsed_ms.saturating_sub(delay_ms);
                                                        result?
                                                    },
                                                }
                                            } else {
                                                primary_fut.await?
                                            }
                                        } else {
                                            send_once(
                                                fwd_addr.clone(),
                                                request,
                                                Arc::clone(&cb),
                                                Arc::clone(&transport),
                                                Arc::clone(&send_metrics),
                                                Arc::clone(&backend_resolutions),
                                            )
                                            .await?
                                        }
                                    } else {
                                        match send_once(
                                            fwd_addr.clone(),
                                            request,
                                            Arc::clone(&cb),
                                            Arc::clone(&transport),
                                            Arc::clone(&send_metrics),
                                            Arc::clone(&backend_resolutions),
                                        )
                                        .await
                                        {
                                            Ok(response) => response,
                                            Err(primary_err) => {
                                                let retry_reason = classify_retry_reason(&primary_err);
                                                let is_retryable_err = is_retryable(&primary_err);
                                                let budget_ok = retry_budget.allow_retry(&route_name).is_ok();
                                                let can_retry = bodyless_mode
                                                    && is_retryable_err
                                                    && budget_ok
                                                    && alternate_backend.is_some();
                                                if !can_retry {
                                                    if !bodyless_mode {
                                                        retry_denial_reason = Some(RetryReason::NotBodylessMode);
                                                    } else if !is_retryable_err || !budget_ok {
                                                        retry_denial_reason = Some(RetryReason::BudgetDenied);
                                                    } else {
                                                        retry_denial_reason = Some(RetryReason::NoAlternateBackend);
                                                    }
                                                    return Err(primary_err);
                                                } else if let Some((retry_backend, _)) =
                                                        alternate_backend.clone()
                                                    && let Some(meta) = forward_meta.as_ref()
                                                    && let Some(endpoint) = backend_endpoints
                                                        .get(&retry_backend)
                                                    && let Ok(retry_request) =
                                                        meta.build_bodyless_request(endpoint)
                                                {
                                                    retry_count = retry_count.saturating_add(1);
                                                    retry_attempt_reason = Some(retry_reason);
                                                    info!(
                                                        "request_id={} retrying request on alternate backend: route={} reason={:?}",
                                                        request_id, route_name, retry_reason
                                                    );
                                                    send_once(
                                                        retry_backend,
                                                        retry_request,
                                                        Arc::clone(&cb),
                                                        Arc::clone(&transport),
                                                        Arc::clone(&send_metrics),
                                                        Arc::clone(&backend_resolutions),
                                                    )
                                                    .await?
                                                } else {
                                                    return Err(primary_err);
                                                }
                                            }
                                        }
                                    };

                                    let (parts, body) = response.into_parts();
                                    Ok((parts.status, parts.headers, body))
                                }
                                .await;
                                // Ignore send error: receiver dropped means the stream was reset.
                                let _ = result_tx.send(UpstreamResult {
                                    forward: result,
                                    hedge: hedge_telemetry,
                                    retry_count,
                                    retry_attempt_reason,
                                    retry_denial_reason,
                                });
                            };
                            let spawned = match trace_span_for_upstream {
                                Some(span) => spawn_async_task(fut.instrument(span), "upstream"),
                                None => spawn_async_task(fut, "upstream"),
                            };
                            if !spawned {
                                error!("dropping upstream task: no runtime available");
                            }
                            (
                                tx,
                                Some(result_rx),
                                Some(addr),
                                Some(idx),
                                Some(upstream_name),
                                Some(backend_lb),
                                Some(route_path_len),
                                Some(route_host_specific),
                                Some(format!("{route_reason:?}")),
                                Some(upstream_pool),
                                Some(global_permit),
                                Some(upstream_permit),
                                Some(adaptive_permit),
                                Some(route_queue_permit),
                                request_fin_received,
                                bodyless_mode,
                                trace_id,
                                span_id,
                                traceparent,
                                trace_span,
                                request_id,
                            )
                        }
                        Err(err) => {
                            metrics.inc_failure();
                            metrics.record_route(
                                "unrouted",
                                request_start.elapsed(),
                                RouteOutcome::Failure,
                            );
                            let (status, body): (http::StatusCode, &[u8]) = match err {
                                ProxyError::Transport(_) => (
                                    http::StatusCode::SERVICE_UNAVAILABLE,
                                    b"no upstream available\n",
                                ),
                                ProxyError::Bridge(_) => {
                                    (http::StatusCode::BAD_REQUEST, b"invalid request\n")
                                }
                                _ => (
                                    http::StatusCode::INTERNAL_SERVER_ERROR,
                                    b"internal proxy error\n",
                                ),
                            };
                            Self::send_simple_response(
                                h3,
                                &mut connection.quic,
                                stream_id,
                                status,
                                body,
                            )?;
                            resilience
                                .adaptive_admission
                                .observe(request_start.elapsed(), true);
                            continue;
                        }
                    };

                    // App-level stream count cap: mirrors the QUIC max_streams_bidi
                    // limit so the streams HashMap can never grow beyond what the
                    // transport layer allows even if a race or misconfiguration
                    // delivers a stream-open event before the flow-control frame
                    // reaches the client.
                    if connection.streams.len() >= max_streams_per_connection {
                        warn!(
                            "stream limit reached ({} streams), rejecting stream {}",
                            max_streams_per_connection, stream_id
                        );
                        // Dropping the permits and body_tx here releases inflight
                        // semaphore slots and signals the upstream task to abort.
                        drop(body_tx);
                        drop(global_inflight_permit);
                        drop(upstream_inflight_permit);
                        drop(adaptive_admission_permit);
                        drop(route_queue_permit);
                        drop(upstream_result_rx);
                        Self::send_simple_response(
                            h3,
                            &mut connection.quic,
                            stream_id,
                            http::StatusCode::SERVICE_UNAVAILABLE,
                            b"too many concurrent streams\n",
                        )?;
                        continue;
                    }

                    connection.streams.insert(
                        stream_id,
                        RequestEnvelope {
                            request_id,
                            trace_id,
                            span_id,
                            traceparent,
                            trace_span,
                            method,
                            path,
                            authority,
                            body_tx,
                            body_buf: std::collections::VecDeque::new(),
                            body_buf_bytes: 0,
                            body_bytes_received: 0,
                            last_body_activity: request_start,
                            backend_addr,
                            backend_index,
                            upstream_name,
                            route_reason,
                            route_path_len,
                            route_host_specific,
                            backend_lb,
                            upstream_pool,
                            routing_transparency_enabled,
                            routing_transparency_include_reason,
                            response_status: None,
                            backend_request_finished: false,
                            global_inflight_permit,
                            upstream_inflight_permit,
                            adaptive_admission_permit,
                            route_queue_permit,
                            start: request_start,
                            total_request_deadline: request_start + backend_total_request_timeout,
                            bodyless_mode,
                            retry_count: 0,
                            error_kind: None,
                            phase: StreamPhase::ReceivingRequest,
                            request_fin_received,
                            upstream_result_rx,
                            response_chunk_rx: None,
                            response_headers_sent: false,
                            pending_chunk: None,
                        },
                    );
                    if let Some(req) = connection.streams.get(&stream_id) {
                        debug!(
                            "request_id={} method={} path={} stream_id={}",
                            req.request_id, req.method, req.path, stream_id
                        );
                    }
                }
                Ok((stream_id, quiche::h3::Event::Data)) => loop {
                    match h3.recv_body(&mut connection.quic, stream_id, &mut body_buf) {
                        Ok(read) => {
                            let mut shed_due_to_buffer_pressure = false;
                            let mut reject_body_for_bodyless = None::<(String, Duration)>;
                            let mut payload_too_large = None::<(String, Duration)>;
                            if let Some(req) = connection.streams.get_mut(&stream_id) {
                                if read > 0 {
                                    req.last_body_activity = Instant::now();
                                }
                                if req.bodyless_mode && read > 0 {
                                    reject_body_for_bodyless = Some((
                                        req.upstream_name
                                            .clone()
                                            .unwrap_or_else(|| "unrouted".to_string()),
                                        req.start.elapsed(),
                                    ));
                                }
                                if reject_body_for_bodyless.is_none() {
                                    // Enforce cap on total bytes received for the stream,
                                    // including chunks already forwarded to the H2 body channel.
                                    let next_total = req.body_bytes_received.saturating_add(read);
                                    let request_is_connect = is_connect_method(&req.method);
                                    if !request_is_connect && next_total > max_request_body_bytes {
                                        payload_too_large = Some((
                                            req.upstream_name
                                                .clone()
                                                .unwrap_or_else(|| "unrouted".to_string()),
                                            req.start.elapsed(),
                                        ));
                                    } else {
                                        req.body_bytes_received = next_total;

                                        for chunk_slice in
                                            body_buf[..read].chunks(REQUEST_CHUNK_BYTES_LIMIT)
                                        {
                                            let chunk = Bytes::copy_from_slice(chunk_slice);
                                            if let Err(err) = Self::enqueue_request_chunk(
                                                req,
                                                chunk,
                                                &metrics,
                                                max_request_body_bytes,
                                                request_buffer_global_cap_bytes,
                                            ) {
                                                shed_due_to_buffer_pressure = true;
                                                metrics.inc_request_buffer_limit_reject();
                                                if err == RequestBufferError::GlobalCap {
                                                    debug!("global request buffer cap reached");
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some((route_label, elapsed)) = reject_body_for_bodyless {
                                metrics.inc_failure();
                                metrics.record_route(&route_label, elapsed, RouteOutcome::Failure);
                                Self::send_simple_response(
                                    h3,
                                    &mut connection.quic,
                                    stream_id,
                                    http::StatusCode::BAD_REQUEST,
                                    b"request body not allowed for this request\n",
                                )?;
                                if let Some(req) = connection.streams.get_mut(&stream_id) {
                                    abort_stream(req, &metrics);
                                }
                                connection.streams.remove(&stream_id);
                                resilience.adaptive_admission.observe(elapsed, true);
                                break;
                            }
                            if let Some((route_label, elapsed)) = payload_too_large {
                                metrics.inc_failure();
                                metrics.record_route(&route_label, elapsed, RouteOutcome::Failure);
                                Self::send_simple_response(
                                    h3,
                                    &mut connection.quic,
                                    stream_id,
                                    http::StatusCode::PAYLOAD_TOO_LARGE,
                                    b"request body too large\n",
                                )?;
                                if let Some(req) = connection.streams.get_mut(&stream_id) {
                                    abort_stream(req, &metrics);
                                }
                                connection.streams.remove(&stream_id);
                                resilience.adaptive_admission.observe(elapsed, true);
                                break;
                            }
                            if shed_due_to_buffer_pressure
                                && let Some(req) = connection.streams.get(&stream_id)
                            {
                                metrics.inc_failure();
                                metrics
                                    .inc_overload_shed_reason(OverloadShedReason::RequestBufferCap);
                                let route_label =
                                    req.upstream_name.as_deref().unwrap_or("unrouted");
                                metrics.record_route(
                                    route_label,
                                    req.start.elapsed(),
                                    RouteOutcome::OverloadShed,
                                );
                                Self::send_overload_response(
                                    h3,
                                    &mut connection.quic,
                                    stream_id,
                                    b"request body backpressure overload\n",
                                    resilience.shed_retry_after_seconds,
                                )?;
                                resilience
                                    .adaptive_admission
                                    .observe(req.start.elapsed(), true);
                                if let Some(req) = connection.streams.get_mut(&stream_id) {
                                    abort_stream(req, &metrics);
                                }
                                connection.streams.remove(&stream_id);
                                break;
                            }
                        }
                        Err(quiche::h3::Error::Done) => break,
                        Err(err) => {
                            let rid = connection.streams.get(&stream_id).map(|r| r.request_id);
                            error!(
                                "request_id={} HTTP/3 recv_body protocol error on stream {}: {:?}",
                                rid.map_or_else(|| "-".to_string(), |id| id.to_string()),
                                stream_id,
                                err
                            );
                            if let Some(req) = connection.streams.get(&stream_id) {
                                metrics.inc_failure();
                                let route_label =
                                    req.upstream_name.as_deref().unwrap_or("unrouted");
                                metrics.record_route(
                                    route_label,
                                    req.start.elapsed(),
                                    RouteOutcome::Failure,
                                );
                                resilience
                                    .adaptive_admission
                                    .observe(req.start.elapsed(), true);
                            }
                            if let Some(req) = connection.streams.get_mut(&stream_id) {
                                abort_stream(req, &metrics);
                            }
                            connection.streams.remove(&stream_id);
                            let _ = Self::send_simple_response(
                                h3,
                                &mut connection.quic,
                                stream_id,
                                http::StatusCode::BAD_REQUEST,
                                b"malformed request stream\n",
                            );
                            break;
                        }
                    }
                },
                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    if let Some(req) = connection.streams.get_mut(&stream_id) {
                        req.request_fin_received = true;

                        Self::flush_request_buffer(req, &metrics);
                        // If buffer is now empty, drop body_tx to signal end-of-body.
                        if req.body_buf.is_empty() {
                            req.body_tx = None;
                        }
                        // Request body fully handed off — now waiting on upstream.
                        req.phase = StreamPhase::AwaitingUpstream;
                        // Upstream polling and response dispatch are handled entirely
                        // by advance_streams_non_blocking, called unconditionally below.
                    }
                }
                Ok((stream_id, quiche::h3::Event::Reset(error_code))) => {
                    if let Some(req) = connection.streams.get_mut(&stream_id) {
                        let phase = abort_stream(req, &metrics);
                        debug!(
                            "stream {} reset by client (error_code={}, phase={:?}): resources released",
                            stream_id, error_code, phase
                        );
                    }
                    connection.streams.remove(&stream_id);
                }
                Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
                Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(e) => return Err(e),
            }
        }

        Self::advance_streams_non_blocking(
            &mut connection.streams,
            &mut connection.quic,
            h3,
            upstream_pools,
            routing_index,
            backend_body_idle_timeout,
            backend_body_total_timeout,
            &metrics,
            backend_total_request_timeout,
            resilience,
            max_response_body_bytes,
            unknown_length_response_prebuffer_bytes,
            client_body_idle_timeout,
            listen_port,
        )?;

        Ok(())
    }

    /// Advance all in-flight streams without blocking.
    ///
    /// Called after every packet-driven `handle_h3` pass and from
    /// `handle_timeouts` so progress continues even when no new client
    /// packets arrive.
    ///
    /// Per stream, in order:
    /// 1. Drain request body buffer → body channel (`try_send`).
    /// 2. Close body channel once FIN received and buffer empty.
    /// 3. Poll `upstream_result_rx` (`try_recv`).
    ///    - Error result  → send error response, mark terminal.
    ///    - Ok result     → send H3 response headers, spawn body-pump task,
    ///      store `response_chunk_rx`, transition to SendingResponse.
    /// 4. Flush `response_chunk_rx` chunks into H3 (`try_recv` loop).
    ///    - `Data`  → `h3.send_body(..., false)`
    ///    - `Trailers` → `h3.send_additional_headers(..., true, false)`
    ///    - `End`   → `h3.send_body(..., true)`, mark Completed
    ///    - `Error` → send 502, mark Failed
    /// 5. Remove streams in terminal phase (Completed / Failed).
    #[allow(clippy::too_many_arguments)]
    fn advance_streams_non_blocking(
        streams: &mut HashMap<u64, RequestEnvelope>,
        quic: &mut quiche::Connection,
        h3: &mut quiche::h3::Connection,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        routing_index: &RouteIndex,
        backend_body_idle_timeout: Duration,
        backend_body_total_timeout: Duration,
        metrics: &Metrics,
        _backend_total_request_timeout: Duration,
        resilience: &RuntimeResilience,
        max_response_body_bytes: usize,
        unknown_length_response_prebuffer_bytes: usize,
        client_body_idle_timeout: Duration,
        listen_port: u16,
    ) -> Result<(), quiche::h3::Error> {
        let stream_ids: Vec<u64> = streams.keys().copied().collect();

        for stream_id in stream_ids {
            if let Some(req) = streams.get(&stream_id)
                && Instant::now() >= req.total_request_deadline
            {
                if let Err(protocol_err) = Self::handle_forward_result(
                    h3,
                    quic,
                    stream_id,
                    req,
                    Err(ProxyError::Timeout),
                    upstream_pools,
                    routing_index,
                    metrics,
                    resilience.shed_retry_after_seconds,
                ) {
                    error!(
                        "failed to emit timeout response for stream {}: {:?}",
                        stream_id, protocol_err
                    );
                }
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                if let Some(req) = streams.get_mut(&stream_id) {
                    abort_stream(req, metrics);
                }
                streams.remove(&stream_id);
                continue;
            }

            if let Some(req) = streams.get(&stream_id)
                && req.phase == StreamPhase::ReceivingRequest
                && !req.request_fin_received
                && !req.bodyless_mode
                && Instant::now().saturating_duration_since(req.last_body_activity)
                    >= client_body_idle_timeout
            {
                metrics.inc_failure();
                metrics.inc_timeout();
                let route_label = req.upstream_name.as_deref().unwrap_or("unrouted");
                metrics.record_route(route_label, req.start.elapsed(), RouteOutcome::Timeout);
                let _ = Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::REQUEST_TIMEOUT,
                    b"request body idle timeout\n",
                );
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                if let Some(req) = streams.get_mut(&stream_id) {
                    abort_stream(req, metrics);
                }
                streams.remove(&stream_id);
                continue;
            }

            // ── 1 & 2: request body drain ────────────────────────────────────
            if let Some(req) = streams.get_mut(&stream_id) {
                Self::flush_request_buffer(req, metrics);
                if req.request_fin_received && req.body_buf.is_empty() {
                    req.body_tx = None; // signals EOF to the upstream H2 task
                }
            }

            // ── 3: poll upstream oneshot ──────────────────────────────────────
            // Only transition to response handling once request-body ingestion is
            // complete. This preserves request-size enforcement semantics:
            // oversized requests must still be able to terminate with 413 even if
            // upstream produced an early response. CONNECT is the exception:
            // successful CONNECT establishes a tunnel and must not wait for request FIN.
            let can_poll_upstream = streams
                .get(&stream_id)
                .is_some_and(can_poll_upstream_result);

            // upstream_ready: Option<UpstreamResult>
            //   None          → oneshot not yet resolved (or not eligible), skip
            //   Some(Ok(...)) → upstream responded successfully
            //   Some(Err(.))  → upstream error (or sender dropped)
            let upstream_ready: Option<UpstreamResult> = if can_poll_upstream {
                streams
                    .get_mut(&stream_id)
                    .and_then(|req| req.upstream_result_rx.as_mut())
                    .and_then(|rx| match rx.try_recv() {
                        Ok(result) => Some(result),
                        Err(oneshot::error::TryRecvError::Empty) => None,
                        Err(oneshot::error::TryRecvError::Closed) => Some(UpstreamResult {
                            forward: Err(ProxyError::Transport(
                                "upstream task dropped sender".into(),
                            )),
                            hedge: crate::HedgeTelemetry::default(),
                            retry_count: 0,
                            retry_attempt_reason: None,
                            retry_denial_reason: None,
                        }),
                    })
            } else {
                None
            };

            if let Some(forward_result) = upstream_ready {
                if forward_result.hedge.launched {
                    metrics.inc_hedge_triggered();
                }
                if forward_result.hedge.hedge_won {
                    metrics.inc_hedge_won();
                }
                if forward_result.hedge.hedge_wasted {
                    metrics.inc_hedge_wasted();
                }
                if forward_result.hedge.primary_won_after_trigger {
                    metrics.inc_hedge_primary_won_after_trigger();
                }
                if forward_result.hedge.primary_late_ms > 0 {
                    metrics.observe_hedge_primary_late_ms(forward_result.hedge.primary_late_ms);
                }
                if let Some(reason) = forward_result.retry_attempt_reason {
                    metrics.inc_retry(reason);
                }
                if let Some(reason) = forward_result.retry_denial_reason {
                    metrics.inc_retry(reason);
                }

                if let Some(req) = streams.get_mut(&stream_id) {
                    req.upstream_result_rx = None;
                    req.retry_count = forward_result.retry_count;
                    req.error_kind = match &forward_result.forward {
                        Err(ProxyError::Timeout) => Some("timeout"),
                        Err(ProxyError::Tls(_)) => Some("tls"),
                        Err(ProxyError::Transport(_)) => Some("transport"),
                        Err(ProxyError::Pool(_)) => Some("pool"),
                        Err(ProxyError::Protocol(_)) => Some("protocol"),
                        Err(ProxyError::Bridge(_)) => Some("bridge"),
                        Ok(_) => None,
                    };
                }
                match forward_result.forward {
                    Ok((status, resp_headers, body)) => {
                        let suppress_downstream_body = streams
                            .get(&stream_id)
                            .is_some_and(|req| is_head_method(&req.method));
                        let connect_tunnel = streams
                            .get(&stream_id)
                            .is_some_and(|req| is_connect_tunnel_response(&req.method, status));
                        // If upstream advertised a response length beyond our hard cap,
                        // fail fast with 503 before sending any downstream headers/body.
                        let upstream_content_length = resp_headers
                            .get(http::header::CONTENT_LENGTH)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<usize>().ok());
                        if !connect_tunnel
                            && !suppress_downstream_body
                            && upstream_content_length
                                .is_some_and(|len| len > max_response_body_bytes)
                        {
                            if let Some(req) = streams.get(&stream_id) {
                                metrics.inc_failure();
                                metrics.inc_overload_shed_reason(
                                    OverloadShedReason::ResponsePrebufferCap,
                                );
                                let route_label =
                                    req.upstream_name.as_deref().unwrap_or("unrouted");
                                metrics.record_route(
                                    route_label,
                                    req.start.elapsed(),
                                    RouteOutcome::OverloadShed,
                                );
                                resilience
                                    .adaptive_admission
                                    .observe(req.start.elapsed(), true);
                                warn!(
                                    "request_id={} upstream declared content-length over cap ({} > {}) on stream {}",
                                    req.request_id,
                                    upstream_content_length.unwrap_or_default(),
                                    max_response_body_bytes,
                                    stream_id
                                );
                                let _ = Self::send_simple_response(
                                    h3,
                                    quic,
                                    stream_id,
                                    http::StatusCode::SERVICE_UNAVAILABLE,
                                    b"upstream response body too large\n",
                                );
                            }
                            if let Some(req) = streams.get_mut(&stream_id) {
                                abort_stream(req, metrics);
                            }
                            streams.remove(&stream_id);
                            continue;
                        }

                        let mut owned_h3_headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
                        let response_connection_tokens = connection_header_tokens(&resp_headers);
                        for (name, value) in resp_headers.iter() {
                            if should_strip_h3_response_header(name, &response_connection_tokens) {
                                continue;
                            }
                            owned_h3_headers.push((
                                name.as_str().as_bytes().to_vec(),
                                value.as_bytes().to_vec(),
                            ));
                        }
                        owned_h3_headers.push((
                            b"alt-svc".to_vec(),
                            format!("h3=\":{}\"; ma=86400", listen_port).into_bytes(),
                        ));

                        let defer_headers_until_body_validated = upstream_content_length.is_none()
                            && !connect_tunnel
                            && !suppress_downstream_body;
                        let immediate_end = suppress_downstream_body
                            || (!connect_tunnel
                                && (upstream_content_length == Some(0)
                                    || status == http::StatusCode::NO_CONTENT
                                    || status == http::StatusCode::NOT_MODIFIED));
                        let mut immediate_terminal = false;

                        if !defer_headers_until_body_validated {
                            // For declared-length responses within cap, emit headers immediately
                            // and stream body progressively.
                            let mut h3_headers = Vec::with_capacity(owned_h3_headers.len() + 1);
                            h3_headers.push(quiche::h3::Header::new(
                                b":status",
                                status.as_str().as_bytes(),
                            ));
                            for (name, value) in &owned_h3_headers {
                                h3_headers.push(quiche::h3::Header::new(name, value));
                            }
                            if let Err(err) =
                                h3.send_response(quic, stream_id, &h3_headers, immediate_end)
                            {
                                if let Some(req) = streams.get(&stream_id) {
                                    let protocol = ProxyError::Protocol(format!(
                                        "failed to send HTTP/3 response headers: {:?}",
                                        err
                                    ));
                                    if let Err(protocol_err) = Self::handle_forward_result(
                                        h3,
                                        quic,
                                        stream_id,
                                        req,
                                        Err(protocol),
                                        upstream_pools,
                                        routing_index,
                                        metrics,
                                        resilience.shed_retry_after_seconds,
                                    ) {
                                        error!(
                                            "failed to emit protocol recovery response on stream {}: {:?}",
                                            stream_id, protocol_err
                                        );
                                    }
                                    resilience
                                        .adaptive_admission
                                        .observe(req.start.elapsed(), true);
                                }
                                if let Some(req) = streams.get_mut(&stream_id) {
                                    abort_stream(req, metrics);
                                }
                                streams.remove(&stream_id);
                                continue;
                            }
                        }

                        if immediate_end {
                            if defer_headers_until_body_validated {
                                let mut h3_headers = Vec::with_capacity(owned_h3_headers.len() + 1);
                                h3_headers.push(quiche::h3::Header::new(
                                    b":status",
                                    status.as_str().as_bytes(),
                                ));
                                for (name, value) in &owned_h3_headers {
                                    h3_headers.push(quiche::h3::Header::new(name, value));
                                }
                                if let Err(err) =
                                    h3.send_response(quic, stream_id, &h3_headers, true)
                                {
                                    if let Some(req) = streams.get(&stream_id) {
                                        let protocol = ProxyError::Protocol(format!(
                                            "failed to send HTTP/3 response headers: {:?}",
                                            err
                                        ));
                                        if let Err(protocol_err) = Self::handle_forward_result(
                                            h3,
                                            quic,
                                            stream_id,
                                            req,
                                            Err(protocol),
                                            upstream_pools,
                                            routing_index,
                                            metrics,
                                            resilience.shed_retry_after_seconds,
                                        ) {
                                            error!(
                                                "failed to emit protocol recovery response on stream {}: {:?}",
                                                stream_id, protocol_err
                                            );
                                        }
                                        resilience
                                            .adaptive_admission
                                            .observe(req.start.elapsed(), true);
                                    }
                                    if let Some(req) = streams.get_mut(&stream_id) {
                                        abort_stream(req, metrics);
                                    }
                                    streams.remove(&stream_id);
                                    continue;
                                }
                            }
                            if let Some(req) = streams.get_mut(&stream_id) {
                                req.response_chunk_rx = None;
                                req.response_headers_sent = true;
                                req.phase = StreamPhase::Completed;
                                req.response_status = Some(status.as_u16());
                            }
                            immediate_terminal = true;
                        } else {
                            // Spawn a task that pumps body frames into a ResponseChunk channel.
                            // Enforces body deadlines and a hard running body-size cap. For
                            // unknown-length responses it additionally prebuffers until size
                            // validation completes before emitting headers.
                            let (chunk_tx, chunk_rx) =
                                mpsc::channel::<ResponseChunk>(RESPONSE_CHUNK_CHANNEL_CAPACITY);
                            let fail_tx = chunk_tx.clone();
                            // `backend_body_total_timeout` is used as a pre-first-byte guard:
                            // once the upstream starts making body progress, the idle timeout
                            // governs pacing and the stream may continue until request deadline.
                            let first_byte_deadline =
                                tokio::time::Instant::now() + backend_body_total_timeout;
                            let deferred_status = status;
                            let deferred_headers = owned_h3_headers.clone();
                            let tunnel_mode = connect_tunnel;
                            let fut = async move {
                                use http_body_util::BodyExt;
                                let mut body: hyper::body::Incoming = body;
                                let mut response_bytes_received: usize = 0;
                                let mut buffered_chunks: Vec<Bytes> = Vec::new();
                                let mut buffered_trailers: Option<Vec<(Vec<u8>, Vec<u8>)>> = None;
                                let mut saw_body_progress = false;
                                loop {
                                    let frame_fut = BodyExt::frame(&mut body);
                                    let now = tokio::time::Instant::now();
                                    if !saw_body_progress && now >= first_byte_deadline {
                                        let _ = chunk_tx
                                            .send(ResponseChunk::Error(ProxyError::Timeout))
                                            .await;
                                        return;
                                    }
                                    let wait_timeout = if saw_body_progress {
                                        backend_body_idle_timeout
                                    } else {
                                        first_byte_deadline
                                            .saturating_duration_since(now)
                                            .min(backend_body_idle_timeout)
                                    };
                                    let result =
                                        tokio::time::timeout(wait_timeout, frame_fut).await;
                                    match result {
                                        Err(_elapsed) => {
                                            // Body read idle timeout — signal timeout to flush loop.
                                            let _ = chunk_tx
                                                .send(ResponseChunk::Error(ProxyError::Timeout))
                                                .await;
                                            return;
                                        }
                                        Ok(Some(Ok(f))) => match f.into_data() {
                                            Ok(data) => {
                                                if !data.is_empty() {
                                                    saw_body_progress = true;
                                                }
                                                if !tunnel_mode
                                                    && response_size_exceeded_after_chunk(
                                                        &mut response_bytes_received,
                                                        data.len(),
                                                        max_response_body_bytes,
                                                    )
                                                {
                                                    let _ = chunk_tx
                                                        .send(ResponseChunk::Error(ProxyError::Pool(
                                                            PoolError::BackendOverloaded(
                                                                "upstream response body too large"
                                                                    .into(),
                                                            ),
                                                        )))
                                                        .await;
                                                    return;
                                                }
                                                if defer_headers_until_body_validated {
                                                    if response_bytes_received
                                                        > unknown_length_response_prebuffer_bytes
                                                    {
                                                        let _ = chunk_tx
                                                            .send(ResponseChunk::Error(ProxyError::Pool(
                                                                PoolError::BackendOverloaded(
                                                                    "unknown-length response prebuffer limit exceeded"
                                                                        .into(),
                                                                ),
                                                            )))
                                                            .await;
                                                        return;
                                                    }
                                                    for start in (0..data.len())
                                                        .step_by(RESPONSE_CHUNK_BYTES_LIMIT)
                                                    {
                                                        let end = (start
                                                            + RESPONSE_CHUNK_BYTES_LIMIT)
                                                            .min(data.len());
                                                        buffered_chunks
                                                            .push(data.slice(start..end));
                                                    }
                                                } else {
                                                    for start in (0..data.len())
                                                        .step_by(RESPONSE_CHUNK_BYTES_LIMIT)
                                                    {
                                                        let end = (start
                                                            + RESPONSE_CHUNK_BYTES_LIMIT)
                                                            .min(data.len());
                                                        if chunk_tx
                                                            .send(ResponseChunk::Data(
                                                                data.slice(start..end),
                                                            ))
                                                            .await
                                                            .is_err()
                                                        {
                                                            return;
                                                        }
                                                    }
                                                }
                                            }
                                            Err(frame) => {
                                                if let Ok(trailers) = frame.into_trailers() {
                                                    let trailer_headers =
                                                        collect_h3_trailers(&trailers);
                                                    if !trailer_headers.is_empty() {
                                                        if defer_headers_until_body_validated {
                                                            buffered_trailers =
                                                                Some(trailer_headers);
                                                        } else if chunk_tx
                                                            .send(ResponseChunk::Trailers {
                                                                headers: trailer_headers,
                                                            })
                                                            .await
                                                            .is_err()
                                                        {
                                                            return;
                                                        }
                                                    }
                                                }
                                            }
                                        },
                                        Ok(Some(Err(_))) => {
                                            let _ = chunk_tx
                                                .send(ResponseChunk::Error(ProxyError::Transport(
                                                    "upstream body error".into(),
                                                )))
                                                .await;
                                            return;
                                        }
                                        Ok(None) => {
                                            if defer_headers_until_body_validated {
                                                if chunk_tx
                                                    .send(ResponseChunk::Start {
                                                        status: deferred_status,
                                                        headers: deferred_headers,
                                                    })
                                                    .await
                                                    .is_err()
                                                {
                                                    return;
                                                }
                                                for chunk in buffered_chunks {
                                                    if chunk_tx
                                                        .send(ResponseChunk::Data(chunk))
                                                        .await
                                                        .is_err()
                                                    {
                                                        return;
                                                    }
                                                }
                                            }
                                            if let Some(headers) = buffered_trailers
                                                && chunk_tx
                                                    .send(ResponseChunk::Trailers { headers })
                                                    .await
                                                    .is_err()
                                            {
                                                return;
                                            }
                                            let _ = chunk_tx.send(ResponseChunk::End).await;
                                            return;
                                        }
                                    }
                                }
                            };
                            let request_span = streams
                                .get(&stream_id)
                                .and_then(|req| req.trace_span.clone());
                            let spawned = match request_span {
                                Some(span) => spawn_async_task(fut.instrument(span), "body-pump"),
                                None => spawn_async_task(fut, "body-pump"),
                            };
                            if !spawned {
                                let _ = fail_tx.try_send(ResponseChunk::Error(
                                    ProxyError::Transport("runtime unavailable".into()),
                                ));
                            }

                            if let Some(req) = streams.get_mut(&stream_id) {
                                req.response_chunk_rx = Some(chunk_rx);
                                req.response_headers_sent = !defer_headers_until_body_validated;
                                req.phase = StreamPhase::SendingResponse;
                                req.response_status = Some(status.as_u16());
                            }
                        }

                        // Update health/metrics for successful upstream response.
                        if let Some(req) = streams.get(&stream_id) {
                            if let (Some(addr), Some(idx)) = (&req.backend_addr, req.backend_index)
                                && let Some(pool) = req.upstream_pool.as_ref()
                            {
                                let transition = pool.write().ok().and_then(|mut p| {
                                    match outcome_from_status(status) {
                                        crate::HealthClassification::Success => {
                                            p.pool.mark_success(idx)
                                        }
                                        crate::HealthClassification::Failure => {
                                            p.pool.mark_request_failure(
                                                idx,
                                                HealthFailureReason::HttpStatus5xx,
                                            )
                                        }
                                        crate::HealthClassification::Neutral => None,
                                    }
                                });
                                if let Some(t) = transition {
                                    Self::log_health_transition(addr, t);
                                }
                            }
                            metrics.inc_success();
                            let route_label = req.upstream_name.as_deref().unwrap_or("unrouted");
                            metrics.record_route(
                                route_label,
                                req.start.elapsed(),
                                RouteOutcome::Success,
                            );
                            resilience
                                .adaptive_admission
                                .observe(req.start.elapsed(), false);
                            Self::log_access(req, status.as_u16());
                        }
                        if immediate_terminal {
                            if let Some(req) = streams.get_mut(&stream_id) {
                                abort_stream(req, metrics);
                            }
                            streams.remove(&stream_id);
                            continue;
                        }
                    }
                    Err(err) => {
                        // Send error response first, then remove the stream so
                        // cleanup only happens after the response has been emitted.
                        if let Some(req) = streams.get(&stream_id) {
                            if let Err(protocol_err) = Self::handle_forward_result(
                                h3,
                                quic,
                                stream_id,
                                req,
                                Err(err),
                                upstream_pools,
                                routing_index,
                                metrics,
                                resilience.shed_retry_after_seconds,
                            ) {
                                error!(
                                    "failed to emit recoverable forward error response on stream {}: {:?}",
                                    stream_id, protocol_err
                                );
                            }
                            resilience
                                .adaptive_admission
                                .observe(req.start.elapsed(), true);
                        }
                        if let Some(req) = streams.get_mut(&stream_id) {
                            abort_stream(req, metrics);
                        }
                        streams.remove(&stream_id);
                        continue;
                    }
                }
            }

            // ── 4: flush response chunks ──────────────────────────────────────
            let mut terminal = false;
            if let Some(req) = streams.get_mut(&stream_id)
                && let Some(rx) = &mut req.response_chunk_rx
            {
                // Drain as many chunks as quiche will accept this iteration.
                loop {
                    // Retry any chunk that previously hit backpressure.
                    let chunk = match req.pending_chunk.take() {
                        Some(c) => c,
                        None => match rx.try_recv() {
                            Ok(c) => c,
                            Err(TryRecvError::Empty) => break,
                            Err(TryRecvError::Disconnected) => {
                                req.phase = StreamPhase::Failed;
                                terminal = true;
                                break;
                            }
                        },
                    };
                    match chunk {
                        ResponseChunk::Start { status, headers } => {
                            let mut h3_headers = Vec::with_capacity(headers.len() + 1);
                            h3_headers.push(quiche::h3::Header::new(
                                b":status",
                                status.as_str().as_bytes(),
                            ));
                            for (name, value) in &headers {
                                h3_headers.push(quiche::h3::Header::new(name, value));
                            }
                            match h3.send_response(quic, stream_id, &h3_headers, false) {
                                Ok(_) => {
                                    req.response_headers_sent = true;
                                }
                                Err(quiche::h3::Error::StreamBlocked) => {
                                    req.pending_chunk =
                                        Some(ResponseChunk::Start { status, headers });
                                    break;
                                }
                                Err(err) => {
                                    error!(
                                        "HTTP/3 send_response protocol error on stream {}: {:?}",
                                        stream_id, err
                                    );
                                    req.phase = StreamPhase::Failed;
                                    metrics.inc_failure();
                                    metrics.inc_backend_error();
                                    let route_label =
                                        req.upstream_name.as_deref().unwrap_or("unrouted");
                                    metrics.record_route(
                                        route_label,
                                        req.start.elapsed(),
                                        RouteOutcome::BackendError,
                                    );
                                    resilience
                                        .adaptive_admission
                                        .observe(req.start.elapsed(), true);
                                    terminal = true;
                                    break;
                                }
                            }
                        }
                        ResponseChunk::Data(data) => {
                            match h3.send_body(quic, stream_id, &data, false) {
                                Ok(_) => {}
                                Err(quiche::h3::Error::StreamBlocked) => {
                                    // QUIC flow-control backpressure — retry next poll.
                                    req.pending_chunk = Some(ResponseChunk::Data(data));
                                    break;
                                }
                                Err(err) => {
                                    error!(
                                        "HTTP/3 send_body data protocol error on stream {}: {:?}",
                                        stream_id, err
                                    );
                                    req.phase = StreamPhase::Failed;
                                    metrics.inc_failure();
                                    metrics.inc_backend_error();
                                    let route_label =
                                        req.upstream_name.as_deref().unwrap_or("unrouted");
                                    metrics.record_route(
                                        route_label,
                                        req.start.elapsed(),
                                        RouteOutcome::BackendError,
                                    );
                                    resilience
                                        .adaptive_admission
                                        .observe(req.start.elapsed(), true);
                                    terminal = true;
                                    break;
                                }
                            }
                        }
                        ResponseChunk::Trailers { headers } => {
                            let mut h3_headers = Vec::with_capacity(headers.len());
                            for (name, value) in &headers {
                                h3_headers.push(quiche::h3::Header::new(name, value));
                            }
                            match h3.send_additional_headers(
                                quic,
                                stream_id,
                                &h3_headers,
                                false,
                                false,
                            ) {
                                Ok(_) => {}
                                Err(quiche::h3::Error::StreamBlocked) => {
                                    req.pending_chunk = Some(ResponseChunk::Trailers { headers });
                                    break;
                                }
                                Err(err) => {
                                    error!(
                                        "HTTP/3 send_additional_headers protocol error on stream {}: {:?}",
                                        stream_id, err
                                    );
                                    req.phase = StreamPhase::Failed;
                                    metrics.inc_failure();
                                    metrics.inc_backend_error();
                                    let route_label =
                                        req.upstream_name.as_deref().unwrap_or("unrouted");
                                    metrics.record_route(
                                        route_label,
                                        req.start.elapsed(),
                                        RouteOutcome::BackendError,
                                    );
                                    resilience
                                        .adaptive_admission
                                        .observe(req.start.elapsed(), true);
                                    terminal = true;
                                    break;
                                }
                            }
                        }
                        ResponseChunk::End => match h3.send_body(quic, stream_id, b"", true) {
                            Ok(_) => {
                                req.phase = StreamPhase::Completed;
                                terminal = true;
                                break;
                            }
                            Err(quiche::h3::Error::StreamBlocked) => {
                                req.pending_chunk = Some(ResponseChunk::End);
                                break;
                            }
                            Err(err) => {
                                error!(
                                    "HTTP/3 send_body end protocol error on stream {}: {:?}",
                                    stream_id, err
                                );
                                req.phase = StreamPhase::Failed;
                                metrics.inc_failure();
                                metrics.inc_backend_error();
                                let route_label =
                                    req.upstream_name.as_deref().unwrap_or("unrouted");
                                metrics.record_route(
                                    route_label,
                                    req.start.elapsed(),
                                    RouteOutcome::BackendError,
                                );
                                resilience
                                    .adaptive_admission
                                    .observe(req.start.elapsed(), true);
                                terminal = true;
                                break;
                            }
                        },
                        ResponseChunk::Error(err) => {
                            // If headers are not emitted yet, return a deterministic
                            // HTTP error status instead of resetting or truncating.
                            if !req.response_headers_sent {
                                let (status, body): (http::StatusCode, &[u8]) = match &err {
                                    ProxyError::Timeout => (
                                        http::StatusCode::SERVICE_UNAVAILABLE,
                                        b"upstream timeout\n",
                                    ),
                                    ProxyError::Pool(PoolError::BackendOverloaded(_)) => (
                                        http::StatusCode::SERVICE_UNAVAILABLE,
                                        b"upstream response body too large\n",
                                    ),
                                    _ => (http::StatusCode::BAD_GATEWAY, b"upstream error\n"),
                                };
                                let _ =
                                    Self::send_simple_response(h3, quic, stream_id, status, body);
                            } else {
                                // Best-effort: close the stream.
                                let _ = h3.send_body(quic, stream_id, b"", true);
                            }
                            req.phase = StreamPhase::Failed;
                            // Mirror the health/metrics updates from the old
                            // send_backend_response timeout/error paths.
                            let upstream_name =
                                routing_index.lookup(&req.path, req.authority.as_deref());
                            if let (Some(idx), Some(pool)) = (
                                req.backend_index,
                                upstream_name.and_then(|n| upstream_pools.get(n)),
                            ) && let Some(t) = pool.write().ok().and_then(|mut p| {
                                p.pool
                                    .mark_request_failure(idx, HealthFailureReason::HttpStatus5xx)
                            }) && let Some(addr) = &req.backend_addr
                            {
                                Self::log_health_transition(addr, t);
                            }
                            match err {
                                ProxyError::Timeout => {
                                    metrics.inc_failure();
                                    metrics.inc_timeout();
                                    let route_label =
                                        req.upstream_name.as_deref().unwrap_or("unrouted");
                                    metrics.record_route(
                                        route_label,
                                        req.start.elapsed(),
                                        RouteOutcome::Timeout,
                                    );
                                    resilience
                                        .adaptive_admission
                                        .observe(req.start.elapsed(), true);
                                    debug!(
                                        "Upstream {} body timeout latency_ms {}",
                                        req.backend_addr.as_deref().unwrap_or("?"),
                                        req.start.elapsed().as_millis()
                                    );
                                }
                                ProxyError::Pool(PoolError::BackendOverloaded(reason)) => {
                                    metrics.inc_failure();
                                    if reason.contains(
                                        "unknown-length response prebuffer limit exceeded",
                                    ) {
                                        metrics.inc_response_prebuffer_limit_reject();
                                        metrics.inc_overload_shed_reason(
                                            OverloadShedReason::ResponsePrebufferCap,
                                        );
                                    } else {
                                        metrics.inc_overload_shed_reason(
                                            OverloadShedReason::BackendInflight,
                                        );
                                    }
                                    let route_label =
                                        req.upstream_name.as_deref().unwrap_or("unrouted");
                                    metrics.record_route(
                                        route_label,
                                        req.start.elapsed(),
                                        RouteOutcome::OverloadShed,
                                    );
                                    resilience
                                        .adaptive_admission
                                        .observe(req.start.elapsed(), true);
                                    error!(
                                        "Upstream {} overload in response body path: {}",
                                        req.backend_addr.as_deref().unwrap_or("?"),
                                        reason
                                    );
                                }
                                _ => {
                                    metrics.inc_failure();
                                    metrics.inc_backend_error();
                                    let route_label =
                                        req.upstream_name.as_deref().unwrap_or("unrouted");
                                    metrics.record_route(
                                        route_label,
                                        req.start.elapsed(),
                                        RouteOutcome::BackendError,
                                    );
                                    resilience
                                        .adaptive_admission
                                        .observe(req.start.elapsed(), true);
                                    error!(
                                        "Upstream {} body error: {:?}",
                                        req.backend_addr.as_deref().unwrap_or("?"),
                                        err
                                    );
                                }
                            }
                            terminal = true;
                            break;
                        }
                    }
                }
            }

            // ── 5: remove terminal streams ────────────────────────────────────
            if terminal {
                if let Some(req) = streams.get_mut(&stream_id) {
                    abort_stream(req, metrics);
                }
                streams.remove(&stream_id);
            }
        }

        Ok(())
    }

    /// Resolve routing + LB for a request, returning `(backend_addr, backend_index, pool)`.
    fn resolve_backend(
        method: &str,
        path: &str,
        authority: Option<&str>,
        cid_key: Option<&str>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        routing_index: &RouteIndex,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> Result<ResolvedBackend, ProxyError> {
        if method.is_empty() || path.is_empty() {
            return Err(ProxyError::Transport("empty method or path".into()));
        }

        let route_decision = routing_index
            .lookup_with_decision_for_method(path, authority, Some(method))
            .ok_or_else(|| ProxyError::Transport(format!("no route for {path}")))?;
        let upstream_name = route_decision.upstream;

        let upstream_pool = upstream_pools
            .get(upstream_name)
            .ok_or_else(|| ProxyError::Transport(format!("pool not found: {upstream_name}")))?
            .clone();

        let (backend_index, lb_type, backend_addr) = {
            let (read_lb_type, read_fast_selected) = {
                let pool = upstream_pool
                    .read()
                    .map_err(|_| ProxyError::Transport("upstream pool lock poisoned".into()))?;
                if pool.pool.is_empty() {
                    return Err(ProxyError::Transport("no servers in upstream".into()));
                }
                let lb_type = pool.lb_name();
                let key = Self::resolve_lb_request_key(
                    lb_type,
                    pool.lb_key(),
                    method,
                    path,
                    authority,
                    cid_key,
                    header_lookup,
                );
                let fast_pick = pool
                    .pick_readonly(key.as_str())
                    .and_then(|idx| pool.pool.address(idx).map(|addr| (idx, addr.to_string())));
                let fast_selected = fast_pick.and_then(|(idx, addr)| {
                    pool.begin_request_if_healthy(idx).then_some((idx, addr))
                });
                (lb_type, fast_selected)
            };

            if let Some((idx, addr)) = read_fast_selected {
                (idx, read_lb_type, addr)
            } else {
                let mut pool = upstream_pool
                    .write()
                    .map_err(|_| ProxyError::Transport("upstream pool lock poisoned".into()))?;
                if pool.pool.is_empty() {
                    return Err(ProxyError::Transport("no servers in upstream".into()));
                }
                let lb_type = pool.lb_name();
                let key = Self::resolve_lb_request_key(
                    lb_type,
                    pool.lb_key(),
                    method,
                    path,
                    authority,
                    cid_key,
                    header_lookup,
                );

                let idx = pool.pick(key.as_str()).ok_or_else(|| {
                    let total = pool.pool.len();
                    let healthy = pool.pool.healthy_len();
                    error!(
                        "no healthy backends available: {}/{} backends healthy",
                        healthy, total
                    );
                    ProxyError::Transport("no healthy servers".into())
                })?;
                let backend_addr = pool
                    .pool
                    .address(idx)
                    .map(str::to_string)
                    .ok_or_else(|| ProxyError::Transport("invalid server address".into()))?;
                (idx, lb_type, backend_addr)
            }
        };

        debug!(
            "Selected backend {} via {} route={} path_len={} host_specific={} reason={:?}",
            backend_addr,
            lb_type,
            upstream_name,
            route_decision.matched_path_len,
            route_decision.host_specific,
            route_decision.reason
        );
        Ok(ResolvedBackend {
            upstream_name: upstream_name.to_string(),
            backend_addr,
            backend_index,
            upstream_pool,
            backend_lb: lb_type.to_string(),
            route_path_len: route_decision.matched_path_len,
            route_host_specific: route_decision.host_specific,
            route_reason: route_decision.reason,
        })
    }

    fn resolve_lb_key_from_spec(
        lb_key_spec: &str,
        method: &str,
        path: &str,
        authority: Option<&str>,
        cid_key: Option<&str>,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> Option<String> {
        let spec = lb_key_spec.trim();
        if spec.is_empty() {
            return None;
        }

        if spec.eq_ignore_ascii_case("path") {
            let path_only = path.split_once('?').map(|(p, _)| p).unwrap_or(path);
            return Some(path_only.to_string());
        }
        if spec.eq_ignore_ascii_case("authority") {
            return authority.map(str::to_string);
        }
        if spec.eq_ignore_ascii_case("method") {
            return Some(method.to_string());
        }
        if spec.eq_ignore_ascii_case("cid") || spec.eq_ignore_ascii_case("sticky-cid") {
            return cid_key.map(str::to_string);
        }

        let (source, key_name) = spec.split_once(':')?;
        let key_name = key_name.trim();
        if key_name.is_empty() {
            return None;
        }

        if source.eq_ignore_ascii_case("header") {
            return header_lookup.and_then(|lookup| lookup(key_name));
        }

        if source.eq_ignore_ascii_case("cookie") {
            let cookie_header =
                header_lookup.and_then(|lookup| lookup(http::header::COOKIE.as_str()))?;
            return extract_cookie_value(cookie_header.as_str(), key_name);
        }

        if source.eq_ignore_ascii_case("query") {
            return extract_query_param(path, key_name);
        }

        None
    }

    fn default_lb_request_key(method: &str, path: &str, authority: Option<&str>) -> String {
        authority
            .unwrap_or(if !path.is_empty() { path } else { method })
            .to_string()
    }

    fn resolve_lb_request_key(
        lb_type: &str,
        lb_key_spec: Option<&str>,
        method: &str,
        path: &str,
        authority: Option<&str>,
        cid_key: Option<&str>,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> String {
        let default_key = Self::default_lb_request_key(method, path, authority);

        if let Some(spec) = lb_key_spec
            && let Some(value) = Self::resolve_lb_key_from_spec(
                spec,
                method,
                path,
                authority,
                cid_key,
                header_lookup,
            )
            && !value.is_empty()
        {
            return value;
        }

        if lb_type == "sticky-cid"
            && let Some(cid_key) = cid_key
        {
            return cid_key.to_string();
        }

        default_key
    }

    fn spawn_metrics_endpoint(
        config: &RuntimeConfig,
        metrics: Arc<Metrics>,
        runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
    ) -> Result<(), ProxyError> {
        let endpoint = &config.observability.metrics;
        if !endpoint.enabled {
            return Ok(());
        }
        let required = endpoint.required;

        let bind = format!("{}:{}", endpoint.address, endpoint.port);
        let metrics_path = endpoint.path.clone();
        let max_connections = endpoint.max_connections.max(1);
        let connection_timeout = Duration::from_millis(endpoint.connection_timeout_ms.max(1));

        let handle = match runtime_handle() {
            Some(handle) => handle,
            None => {
                let msg = "metrics endpoint disabled (no Tokio runtime available)".to_string();
                if required {
                    return Err(ProxyError::Transport(msg));
                }
                error!("{}", msg);
                return Ok(());
            }
        };

        // Bind synchronously so endpoint readiness does not race with task scheduling.
        let std_listener = match std::net::TcpListener::bind(&bind) {
            Ok(listener) => listener,
            Err(err) => {
                let msg = format!("failed to bind metrics endpoint {bind}: {err}");
                if required {
                    return Err(ProxyError::Transport(msg));
                }
                error!("{}", msg);
                return Ok(());
            }
        };
        if let Err(err) = std_listener.set_nonblocking(true) {
            let msg = format!(
                "failed to set metrics endpoint listener nonblocking ({}): {}",
                bind, err
            );
            if required {
                return Err(ProxyError::Transport(msg));
            }
            error!("{}", msg);
            return Ok(());
        }
        let listener = match tokio::net::TcpListener::from_std(std_listener) {
            Ok(listener) => listener,
            Err(err) => {
                let msg = format!(
                    "failed to register metrics endpoint listener {}: {}",
                    bind, err
                );
                if required {
                    return Err(ProxyError::Transport(msg));
                }
                error!("{}", msg);
                return Ok(());
            }
        };

        spawn_supervised_async_task(
            &handle,
            "metrics-endpoint",
            Some(Arc::clone(&metrics)),
            async move {
                info!(
                    "Metrics endpoint listening on http://{}{} (max_connections={}, connection_timeout_ms={})",
                    bind,
                    metrics_path,
                    max_connections,
                    connection_timeout.as_millis()
                );
                let active_connections = Arc::new(AtomicUsize::new(0));

                loop {
                    let (stream, _peer) = match listener.accept().await {
                        Ok(v) => v,
                        Err(err) => {
                            error!("Metrics endpoint accept failed: {}", err);
                            continue;
                        }
                    };
                    let runtime_state = Self::metrics_endpoint_state(
                        runtime_bundle.as_ref(),
                        metrics_path.clone(),
                        max_connections,
                        connection_timeout,
                        Arc::clone(&metrics),
                    );
                    let active_connections = Arc::clone(&active_connections);
                    if !Self::try_claim_runtime_connection_slot(
                        &active_connections,
                        runtime_state.max_connections,
                    ) {
                        continue;
                    }

                    let io = TokioIo::new(stream);
                    let metrics = Arc::clone(&runtime_state.metrics);
                    let metrics_path = runtime_state.metrics_path.clone();
                    let timeout = runtime_state.connection_timeout;

                    tokio::spawn(async move {
                        let _connection_guard = RuntimeConnectionSlotGuard::new(active_connections);
                        let service = service_fn(move |req: Request<Incoming>| {
                            let metrics = Arc::clone(&metrics);
                            let metrics_path = metrics_path.clone();
                            async move {
                                Ok::<_, hyper::Error>(Self::handle_metrics_request(
                                    req,
                                    &metrics_path,
                                    metrics,
                                ))
                            }
                        });

                        let serve = http1::Builder::new().serve_connection(io, service);
                        match tokio::time::timeout(timeout, serve).await {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) => {
                                error!("Metrics endpoint connection failed: {}", err);
                            }
                            Err(_) => {
                                debug!("Metrics endpoint connection timed out");
                            }
                        }
                    });
                }
            },
        );
        Ok(())
    }

    fn metrics_endpoint_state(
        runtime_bundle: Option<&Arc<RuntimeBundleHandle>>,
        startup_metrics_path: String,
        startup_max_connections: usize,
        startup_connection_timeout: Duration,
        startup_metrics: Arc<Metrics>,
    ) -> MetricsEndpointState {
        if let Some(handle) = runtime_bundle {
            let runtime = handle.current();
            let endpoint = &runtime.runtime_config.observability.metrics;
            return MetricsEndpointState {
                metrics_path: endpoint.path.clone(),
                max_connections: endpoint.max_connections.max(1),
                connection_timeout: Duration::from_millis(endpoint.connection_timeout_ms.max(1)),
                metrics: runtime.shared_state.metrics.clone(),
            };
        }

        MetricsEndpointState {
            metrics_path: startup_metrics_path,
            max_connections: startup_max_connections,
            connection_timeout: startup_connection_timeout,
            metrics: startup_metrics,
        }
    }

    fn load_tls_cert_chain_from_pem_file(
        path: &str,
        field_name: &str,
    ) -> Result<Vec<CertificateDer<'static>>, ProxyError> {
        CertificateDer::pem_file_iter(path)
            .map_err(|err| {
                ProxyError::Tls(format!("failed to read {field_name} '{}': {}", path, err))
            })?
            .collect::<Result<_, _>>()
            .map_err(|err| ProxyError::Tls(format!("failed to parse {field_name} PEM: {err}")))
    }

    fn load_tls_private_key_from_pem_file(
        path: &str,
        field_name: &str,
    ) -> Result<PrivateKeyDer<'static>, ProxyError> {
        PrivateKeyDer::from_pem_file(path).map_err(|err| {
            ProxyError::Tls(format!(
                "failed to parse {field_name} PEM from '{}': {err}",
                path
            ))
        })
    }

    fn load_certified_key(
        cert_path: &str,
        key_path: &str,
        cert_field: &str,
        key_field: &str,
    ) -> Result<CertifiedKey, ProxyError> {
        let certs = Self::load_tls_cert_chain_from_pem_file(cert_path, cert_field)?;
        let key = Self::load_tls_private_key_from_pem_file(key_path, key_field)?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|err| {
            ProxyError::Tls(format!(
                "failed to parse private key from {} '{}': {}",
                key_field, key_path, err
            ))
        })?;
        let certified = CertifiedKey::new(certs, signing_key);
        certified.keys_match().map_err(|err| {
            ProxyError::Tls(format!(
                "certificate/key mismatch for {} '{}' and {} '{}': {}",
                cert_field, cert_path, key_field, key_path, err
            ))
        })?;
        Ok(certified)
    }

    fn load_tls_certificate_metadata(
        cert: &CertificateDer<'static>,
        cert_field: &str,
        cert_path: &str,
    ) -> Result<RuntimeTlsCertificateMetadata, ProxyError> {
        let (_, certificate) = parse_x509_certificate(cert.as_ref()).map_err(|err| {
            ProxyError::Tls(format!(
                "failed to parse X.509 metadata from {cert_field} '{}': {}",
                cert_path, err
            ))
        })?;

        let validity = certificate.validity();
        let mut dns_names = Vec::new();
        if let Ok(Some(san)) = certificate.tbs_certificate.subject_alternative_name() {
            for general_name in &san.value.general_names {
                if let GeneralName::DNSName(name) = general_name {
                    dns_names.push(name.to_string());
                }
            }
        }
        for common_name in certificate.subject().iter_common_name() {
            if let Ok(name) = common_name.as_str() {
                dns_names.push(name.to_string());
            }
        }
        dns_names.sort();
        dns_names.dedup();

        Ok(RuntimeTlsCertificateMetadata {
            serial_hex: certificate.tbs_certificate.raw_serial_as_string(),
            not_before_unix_seconds: validity.not_before.timestamp(),
            not_after_unix_seconds: validity.not_after.timestamp(),
            dns_names,
        })
    }

    fn load_listener_identity(
        identity: &RuntimeTlsIdentity,
        cert_field: &str,
        key_field: &str,
    ) -> Result<LoadedListenerIdentity, ProxyError> {
        let certified_key = Arc::new(Self::load_certified_key(
            &identity.cert_path,
            &identity.key_path,
            cert_field,
            key_field,
        )?);
        let leaf = certified_key.cert.first().ok_or_else(|| {
            ProxyError::Tls(format!(
                "{cert_field} '{}' did not produce a leaf certificate",
                identity.cert_path
            ))
        })?;
        let metadata = Self::load_tls_certificate_metadata(leaf, cert_field, &identity.cert_path)?;

        Ok(LoadedListenerIdentity {
            identity: identity.clone(),
            certified_key,
            metadata,
        })
    }

    fn load_client_auth_ca(
        client_auth: &ClientAuth,
    ) -> Result<Option<LoadedClientAuthCa>, ProxyError> {
        if !client_auth.enabled {
            return Ok(None);
        }

        let ca_file = client_auth.ca_file.as_ref().ok_or_else(|| {
            ProxyError::Tls(
                "listen.tls.client_auth.ca_file is required when mTLS is enabled".to_string(),
            )
        })?;
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            CertificateDer::pem_file_iter(ca_file)
                .map_err(|err| {
                    ProxyError::Tls(format!(
                        "failed to read listen.tls.client_auth.ca_file '{}': {}",
                        ca_file, err
                    ))
                })?
                .collect::<Result<_, _>>()
                .map_err(|err| {
                    ProxyError::Tls(format!(
                        "failed to parse listen.tls.client_auth.ca_file PEM: {}",
                        err
                    ))
                })?;
        let mut roots = RootCertStore::empty();
        for cert in certs {
            roots.add(cert).map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to add certificate from listen.tls.client_auth.ca_file '{}': {}",
                    ca_file, err
                ))
            })?;
        }

        Ok(Some(LoadedClientAuthCa {
            ca_file: ca_file.clone(),
            certificate_count: roots.len(),
            roots: Arc::new(roots),
        }))
    }

    fn load_listener_tls_material(
        config: &ListenerRuntimeConfig,
    ) -> Result<LoadedListenerTlsMaterial, ProxyError> {
        let listener_tls = Self::runtime_listener_tls(config)?;
        let default_identity = Self::load_listener_identity(
            &listener_tls.default_identity,
            "listen.tls.default_identity.cert",
            "listen.tls.default_identity.key",
        )?;

        let mut sni_identities = HashMap::new();
        for (server_name, identity) in &listener_tls.sni_identities {
            let cert_field = format!("listen.tls.certificates['{server_name}'].cert");
            let key_field = format!("listen.tls.certificates['{server_name}'].key");
            let loaded_identity = Self::load_listener_identity(identity, &cert_field, &key_field)?;
            Self::validate_loaded_sni_identity(server_name, &loaded_identity)?;
            sni_identities.insert(server_name.clone(), loaded_identity);
        }

        Ok(LoadedListenerTlsMaterial {
            default_identity,
            sni_identities,
            client_auth_ca: Self::load_client_auth_ca(&listener_tls.client_auth)?,
            client_auth: listener_tls.client_auth,
        })
    }

    fn listener_tls_inventory(loaded_tls: &LoadedListenerTlsMaterial) -> ListenerTlsInventory {
        ListenerTlsInventory {
            listener_tls: RuntimeListenerTls {
                default_identity: loaded_tls.default_identity.identity.clone(),
                sni_identities: loaded_tls
                    .sni_identities
                    .iter()
                    .map(|(server_name, identity)| (server_name.clone(), identity.identity.clone()))
                    .collect(),
                client_auth: loaded_tls.client_auth.clone(),
            },
            default_identity: RuntimeLoadedTlsIdentity {
                identity: loaded_tls.default_identity.identity.clone(),
                metadata: loaded_tls.default_identity.metadata.clone(),
            },
            sni_identities: loaded_tls
                .sni_identities
                .iter()
                .map(|(server_name, identity)| {
                    (
                        server_name.clone(),
                        RuntimeLoadedTlsIdentity {
                            identity: identity.identity.clone(),
                            metadata: identity.metadata.clone(),
                        },
                    )
                })
                .collect(),
            client_auth_ca: loaded_tls.client_auth_ca.as_ref().map(|client_auth_ca| {
                RuntimeLoadedClientAuthCa {
                    ca_file: client_auth_ca.ca_file.clone(),
                    certificate_count: client_auth_ca.certificate_count,
                }
            }),
        }
    }

    fn build_server_tls_config_from_loaded(
        loaded_tls: &LoadedListenerTlsMaterial,
        enforce_client_auth: bool,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<RustlsServerConfig, ProxyError> {
        let builder = if enforce_client_auth && loaded_tls.client_auth.enabled {
            let client_auth_ca = loaded_tls.client_auth_ca.clone().ok_or_else(|| {
                ProxyError::Tls(
                    "listen.tls.client_auth.ca_file is required when mTLS is enabled".to_string(),
                )
            })?;

            let verifier_builder = WebPkiClientVerifier::builder(client_auth_ca.roots.clone());
            let verifier = if loaded_tls.client_auth.require_client_cert {
                verifier_builder.build()
            } else {
                verifier_builder.allow_unauthenticated().build()
            }
            .map_err(|err| {
                ProxyError::Tls(format!(
                    "failed to build downstream client certificate verifier: {}",
                    err
                ))
            })?;

            RustlsServerConfig::builder().with_client_cert_verifier(verifier)
        } else {
            RustlsServerConfig::builder().with_no_client_auth()
        };

        let mut sni_resolver = ResolvesServerCertUsingSni::new();
        for (server_name, identity) in &loaded_tls.sni_identities {
            Self::validate_loaded_sni_identity(server_name, identity)?;
            sni_resolver
                .add(
                    server_name.as_str(),
                    identity.certified_key.as_ref().clone(),
                )
                .map_err(|err| {
                    ProxyError::Tls(format!(
                        "failed to add SNI certificate mapping for '{server_name}': {}",
                        err
                    ))
                })?;
        }
        let resolver = Arc::new(FallbackServerCertResolver {
            sni_resolver,
            fallback: loaded_tls.default_identity.certified_key.clone(),
        });
        let mut tls_config = builder.with_cert_resolver(resolver);
        tls_config.alpn_protocols = alpn_protocols;
        Ok(tls_config)
    }

    fn validate_loaded_sni_identity(
        server_name: &str,
        identity: &LoadedListenerIdentity,
    ) -> Result<(), ProxyError> {
        if Self::certificate_covers_server_name(&identity.metadata, server_name) {
            return Ok(());
        }

        Err(ProxyError::Tls(format!(
            "failed to add SNI certificate mapping for '{server_name}': certificate SANs {:?} do not cover server name",
            identity.metadata.dns_names
        )))
    }

    fn certificate_covers_server_name(
        metadata: &RuntimeTlsCertificateMetadata,
        server_name: &str,
    ) -> bool {
        metadata
            .dns_names
            .iter()
            .any(|dns_name| Self::certificate_name_matches(dns_name, server_name))
    }

    fn certificate_name_matches(pattern: &str, server_name: &str) -> bool {
        if pattern.eq_ignore_ascii_case(server_name) {
            return true;
        }

        let Some(suffix) = pattern.strip_prefix("*.") else {
            return false;
        };
        let suffix = suffix.to_ascii_lowercase();
        let server_name = server_name.to_ascii_lowercase();
        let Some(prefix) = server_name.strip_suffix(&suffix) else {
            return false;
        };
        let Some(label) = prefix.strip_suffix('.') else {
            return false;
        };
        !label.is_empty() && !label.contains('.')
    }

    fn build_listener_tls_reload_state(
        config: &ListenerRuntimeConfig,
    ) -> Result<ListenerTlsReloadState, ProxyError> {
        let loaded_tls = Self::load_listener_tls_material(config)?;
        let inventory = Self::listener_tls_inventory(&loaded_tls);
        let bootstrap_server_config = Arc::new(Self::build_server_tls_config_from_loaded(
            &loaded_tls,
            true,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        )?);
        Ok(ListenerTlsReloadState {
            generation: 0,
            inventory,
            bootstrap_server_config,
        })
    }

    fn build_listener_tls_reload_store(
        config: &RuntimeConfig,
    ) -> Result<ListenerTlsReloadStore, ProxyError> {
        let mut listeners = HashMap::new();
        for listener_config in config.listener_runtime_configs() {
            let listener_label = Self::listener_label(&listener_config);
            let state = Self::build_listener_tls_reload_state(&listener_config)?;
            listeners.insert(listener_label, state);
        }
        Ok(ListenerTlsReloadStore::new(listeners))
    }

    #[cfg(test)]
    fn build_server_tls_acceptor(
        config: &ListenerRuntimeConfig,
        enforce_client_auth: bool,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<TlsAcceptor, ProxyError> {
        let loaded_tls = Self::load_listener_tls_material(config)?;
        debug!(
            "Building rustls downstream acceptor with default cert='{}' serial={} and {} explicit SNI identities",
            loaded_tls.default_identity.identity.cert_path,
            loaded_tls.default_identity.metadata.serial_hex,
            loaded_tls.sni_identities.len()
        );
        Ok(TlsAcceptor::from(Arc::new(
            Self::build_server_tls_config_from_loaded(
                &loaded_tls,
                enforce_client_auth,
                alpn_protocols,
            )?,
        )))
    }

    fn listener_label(config: &ListenerRuntimeConfig) -> String {
        format!(
            "{}:{}",
            config.listen.listen.address, config.listen.listen.port
        )
    }

    fn update_listener_tls_expiry_metrics(
        metrics: &Metrics,
        listener_label: &str,
        inventory: &ListenerTlsInventory,
    ) {
        let mut certs = Vec::with_capacity(inventory.sni_identities.len() + 1);
        certs.push((
            "__default__".to_string(),
            inventory.default_identity.metadata.not_after_unix_seconds,
        ));
        certs.extend(
            inventory
                .sni_identities
                .iter()
                .map(|(server_name, identity)| {
                    (
                        server_name.clone(),
                        identity.metadata.not_after_unix_seconds,
                    )
                }),
        );
        metrics.replace_downstream_tls_cert_expiry(listener_label, certs);
    }

    fn classify_downstream_tls_cert_selection<'a>(
        listener_tls: &'a RuntimeListenerTls,
        requested_sni: Option<&str>,
    ) -> (&'static str, &'a RuntimeTlsIdentity) {
        let normalized_sni =
            requested_sni.map(|value| value.trim().trim_end_matches('.').to_ascii_lowercase());
        if let Some(sni) = normalized_sni.as_deref()
            && let Some(identity) = listener_tls.sni_identities.get(sni)
        {
            return ("exact_sni", identity);
        }

        if requested_sni.is_none() {
            if listener_tls.sni_identities.is_empty() {
                ("default_only", &listener_tls.default_identity)
            } else {
                ("fallback_no_sni", &listener_tls.default_identity)
            }
        } else if listener_tls.sni_identities.is_empty() {
            ("default_only", &listener_tls.default_identity)
        } else {
            ("fallback_unmatched_sni", &listener_tls.default_identity)
        }
    }

    fn classify_downstream_tls_failure_reason(error: &str) -> &'static str {
        let lower = error.to_ascii_lowercase();
        if lower.contains("peer sent no certificates")
            || lower.contains("peer sent no certificate")
            || lower.contains("certificate required")
        {
            "missing_client_cert"
        } else if lower.contains("unknownissuer") || lower.contains("unknown issuer") {
            "unknown_issuer"
        } else if lower.contains("expired") || lower.contains("not yet valid") {
            "expired_client_cert"
        } else if lower.contains("certificate") || lower.contains("cert") {
            "invalid_client_cert"
        } else if lower.contains("alpn")
            || lower.contains("application protocol")
            || lower.contains("no application protocol")
        {
            "alpn"
        } else {
            "handshake"
        }
    }

    fn maybe_record_quic_tls_observation(&self, connection: &mut QuicConnection) {
        if connection.tls_observed || !connection.quic.is_established() {
            return;
        }

        let listener_label = Self::listener_label(&self.config);
        let listener_tls = match Self::runtime_listener_tls(&self.config) {
            Ok(listener_tls) => listener_tls,
            Err(err) => {
                debug!(
                    "Skipping QUIC TLS observation for listener {}: {}",
                    listener_label, err
                );
                return;
            }
        };
        let requested_sni = connection.quic.server_name();
        let (selection, identity) =
            Self::classify_downstream_tls_cert_selection(&listener_tls, requested_sni);
        let alpn = std::str::from_utf8(connection.quic.application_proto())
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or("none");
        let client_cert_present = connection.quic.peer_cert().is_some();

        self.metrics.inc_downstream_tls_handshake_success();
        self.metrics
            .record_downstream_tls_cert_selection(&listener_label, selection);
        self.metrics
            .record_downstream_tls_alpn(&listener_label, alpn);
        debug!(
            "QUIC TLS established listener={} peer={} sni={:?} selection={} cert='{}' alpn={} client_cert_present={}",
            listener_label,
            connection.peer_address,
            requested_sni,
            selection,
            identity.cert_path,
            alpn,
            client_cert_present
        );
        connection.tls_observed = true;
    }

    fn maybe_record_quic_tls_handshake_failure(&self, connection: &mut QuicConnection) {
        if connection.tls_observed
            || connection.tls_handshake_failure_recorded
            || connection.quic.is_established()
        {
            return;
        }

        // Record as soon as a connection error is present, not just when fully closed.
        // local_error() is set the moment quiche sends CONNECTION_CLOSE, which happens
        // during the draining period before is_closed() becomes true.
        let Some(err) = connection
            .quic
            .local_error()
            .or_else(|| connection.quic.peer_error())
        else {
            return;
        };

        let reason_text = if err.reason.is_empty() {
            // QUIC CRYPTO_ERRORs (0x100–0x1ff) encode a TLS alert in the low byte (RFC 9001 §4.8).
            // Map the alert to a description that classify_downstream_tls_failure_reason can match.
            if !err.is_app && (0x100..=0x1ff).contains(&err.error_code) {
                let tls_alert = err.error_code - 0x100;
                match tls_alert {
                    120 => "no application protocol".to_string(), // ALPN mismatch
                    42 => "bad certificate".to_string(),
                    45 => "certificate expired".to_string(),
                    48 => "unknown certificate authority".to_string(),
                    _ => format!("quic tls alert={}", tls_alert),
                }
            } else {
                format!(
                    "quic handshake error code={} is_app={}",
                    err.error_code, err.is_app
                )
            }
        } else {
            String::from_utf8_lossy(&err.reason).into_owned()
        };
        let reason = Self::classify_downstream_tls_failure_reason(&reason_text);
        self.metrics
            .record_downstream_tls_handshake_failure(&Self::listener_label(&self.config), reason);
        connection.tls_handshake_failure_recorded = true;
        debug!(
            "Recorded QUIC TLS handshake failure listener={} peer={} reason={} detail={}",
            Self::listener_label(&self.config),
            connection.peer_address,
            reason,
            reason_text
        );
    }

    pub fn spawn_bootstrap_tls_listener(
        config: &ListenerRuntimeConfig,
        shared_state: &SharedRuntimeState,
        runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
    ) -> Result<(), ProxyError> {
        let bind = format!(
            "{}:{}",
            config.listen.listen.address, config.listen.listen.port
        );
        let alt_svc_value = format!("h3=\":{}\"; ma=86400", config.listen.listen.port);
        let max_connections = config.performance.max_active_connections.max(1);
        let connection_timeout =
            Duration::from_millis(config.performance.client_body_idle_timeout_ms.max(1));
        let listener_label = Self::listener_label(config);
        shared_state
            .listener_tls_store
            .bootstrap_server_config(&listener_label)
            .ok_or_else(|| {
                ProxyError::Tls(format!(
                    "failed to initialize bootstrap TLS listener config for '{}': missing reload state",
                    listener_label
                ))
            })?;

        let transport_pool = Arc::clone(&shared_state.transport_pool);
        let backend_endpoints = Arc::clone(&shared_state.backend_endpoints);
        let backend_resolution_store = Arc::clone(&shared_state.backend_resolution_store);
        let upstream_policies = Arc::clone(&shared_state.upstream_policies);
        let metrics = Arc::clone(&shared_state.metrics);
        let resilience = Arc::clone(&shared_state.resilience);
        let upstream_pools = shared_state.upstream_pools.clone();
        let listener_tls_store = Arc::clone(&shared_state.listener_tls_store);
        let runtime_bundle = runtime_bundle.clone();
        let handle = match runtime_handle() {
            Some(h) => h,
            None => {
                return Err(ProxyError::Transport(
                    "failed to start bootstrap TLS listener: no Tokio runtime available"
                        .to_string(),
                ));
            }
        };

        let std_listener = std::net::TcpListener::bind(&bind).map_err(|err| {
            ProxyError::Transport(format!(
                "failed to bind bootstrap TLS listener on {}: {}",
                bind, err
            ))
        })?;
        if let Err(err) = std_listener.set_nonblocking(true) {
            return Err(ProxyError::Transport(format!(
                "failed to set bootstrap TLS listener nonblocking ({}): {}",
                bind, err
            )));
        }
        let listener = {
            let _guard = handle.enter();
            tokio::net::TcpListener::from_std(std_listener).map_err(|err| {
                ProxyError::Transport(format!(
                    "failed to register bootstrap TLS listener {}: {}",
                    bind, err
                ))
            })?
        };

        let startup_state = BootstrapStartupState {
            listener_config: config.clone(),
            listener_tls_store: Arc::clone(&listener_tls_store),
            transport_pool: Arc::clone(&transport_pool),
            backend_endpoints: Arc::clone(&backend_endpoints),
            backend_resolution_store: Arc::clone(&backend_resolution_store),
            upstream_policies: Arc::clone(&upstream_policies),
            metrics: Arc::clone(&metrics),
            resilience: Arc::clone(&resilience),
            upstream_pools: upstream_pools.clone(),
            routing_index: Arc::clone(&shared_state.routing_index),
        };

        spawn_supervised_async_task(&handle, "bootstrap-tls-listener", None, async move {
            info!(
                "Bootstrap TLS listener on https://{} (TCP+TLS) — advertising Alt-Svc: {} (max_connections={}, connection_timeout_ms={})",
                bind,
                alt_svc_value,
                max_connections,
                connection_timeout.as_millis()
            );
            let active_connections = Arc::new(AtomicUsize::new(0));
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(err) => {
                        error!("Bootstrap TLS listener accept failed: {}", err);
                        continue;
                    }
                };
                let Some(runtime_state) = Self::bootstrap_connection_state(
                    &listener_label,
                    runtime_bundle.as_ref(),
                    &startup_state,
                ) else {
                    error!(
                        "Bootstrap TLS listener missing live runtime state for listener {}",
                        listener_label
                    );
                    continue;
                };
                let active_connections = Arc::clone(&active_connections);
                if !Self::try_claim_runtime_connection_slot(
                    &active_connections,
                    runtime_state.max_connections,
                ) {
                    runtime_state.metrics.inc_connection_cap_reject();
                    debug!(
                        "Bootstrap TLS listener dropped connection from {}: max_connections reached",
                        peer
                    );
                    continue;
                }

                let alt_svc = runtime_state.alt_svc_value.clone();
                let transport_pool = Arc::clone(&runtime_state.transport_pool);
                let backend_endpoints = Arc::clone(&runtime_state.backend_endpoints);
                let backend_resolution_store = Arc::clone(&runtime_state.backend_resolution_store);
                let upstream_policies = Arc::clone(&runtime_state.upstream_policies);
                let metrics = Arc::clone(&runtime_state.metrics);
                let resilience = Arc::clone(&runtime_state.resilience);
                let upstream_pools = runtime_state.upstream_pools.clone();
                let routing_index = Arc::clone(&runtime_state.routing_index);
                let max_request_body_bytes = runtime_state.max_request_body_bytes;
                let max_response_body_bytes = runtime_state.max_response_body_bytes;
                let backend_timeout = runtime_state.backend_timeout;
                let timeout = runtime_state.connection_timeout;
                let listener_label = listener_label.clone();
                let listener_tls_store = Arc::clone(&runtime_state.listener_tls_store);

                tokio::spawn(async move {
                    let _connection_guard = RuntimeConnectionSlotGuard::new(active_connections);
                    let Some(server_config) =
                        listener_tls_store.bootstrap_server_config(&listener_label)
                    else {
                        error!(
                            "Bootstrap TLS listener missing live server config for listener {}",
                            listener_label
                        );
                        return;
                    };
                    let acceptor = TlsAcceptor::from(server_config);
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(err) => {
                            let err_text = err.to_string();
                            let reason = Self::classify_downstream_tls_failure_reason(&err_text);
                            metrics
                                .record_downstream_tls_handshake_failure(&listener_label, reason);
                            debug!(
                                "Bootstrap TLS handshake failed listener={} peer={} reason={} error={}",
                                listener_label, peer, reason, err_text
                            );
                            return;
                        }
                    };

                    let Some(listener_tls) = listener_tls_store.inventory(&listener_label) else {
                        error!(
                            "Bootstrap TLS listener missing live inventory for listener {}",
                            listener_label
                        );
                        return;
                    };
                    let requested_sni = tls_stream.get_ref().1.server_name().map(str::to_string);
                    let (selection, identity) = Self::classify_downstream_tls_cert_selection(
                        &listener_tls.listener_tls,
                        requested_sni.as_deref(),
                    );
                    let negotiated = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
                    let negotiated_label = negotiated
                        .as_deref()
                        .and_then(|value| std::str::from_utf8(value).ok())
                        .unwrap_or("none");
                    let client_cert_present = tls_stream
                        .get_ref()
                        .1
                        .peer_certificates()
                        .is_some_and(|certs| !certs.is_empty());
                    metrics.inc_downstream_tls_handshake_success();
                    metrics.record_downstream_tls_cert_selection(&listener_label, selection);
                    metrics.record_downstream_tls_alpn(&listener_label, negotiated_label);
                    debug!(
                        "Bootstrap TLS handshake success listener={} peer={} sni={:?} selection={} cert='{}' alpn={} client_cert_present={}",
                        listener_label,
                        peer,
                        requested_sni,
                        selection,
                        identity.cert_path,
                        negotiated_label,
                        client_cert_present
                    );
                    let use_h2 = negotiated.as_deref() == Some(b"h2");

                    let io = TokioIo::new(tls_stream);
                    let alt_svc_conn = alt_svc.clone();

                    let svc = service_fn(
                        move |mut req: Request<Incoming>| -> BootstrapServiceFuture {
                            let alt = alt_svc_conn.clone();
                            let transport_pool = Arc::clone(&transport_pool);
                            let backend_endpoints = Arc::clone(&backend_endpoints);
                            let backend_resolution_store = Arc::clone(&backend_resolution_store);
                            let upstream_policies = Arc::clone(&upstream_policies);
                            let metrics = Arc::clone(&metrics);
                            let resilience = Arc::clone(&resilience);
                            let upstream_pools = upstream_pools.clone();
                            let routing_index = Arc::clone(&routing_index);
                            let max_request_body_bytes = max_request_body_bytes;
                            let max_response_body_bytes = max_response_body_bytes;

                            Box::pin(async move {
                                let is_websocket_upgrade =
                                    is_websocket_upgrade_request(&req, use_h2);
                                let client_upgrade = if is_websocket_upgrade {
                                    Some(upgrade::on(&mut req))
                                } else {
                                    None
                                };

                                let request = match validate_http_request(&req, &resilience) {
                                    Ok(request) => request,
                                    Err((status, body, is_policy)) => {
                                        metrics.inc_failure();
                                        metrics.inc_request_validation_reject();
                                        if is_policy {
                                            metrics.inc_policy_denied();
                                        }
                                        metrics.record_route(
                                            "unrouted",
                                            Duration::from_millis(0),
                                            RouteOutcome::Failure,
                                        );
                                        return Ok(Response::builder()
                                            .status(status)
                                            .header("alt-svc", &alt)
                                            .body(boxed_full(Bytes::copy_from_slice(body)))
                                            .unwrap_or_else(|_| {
                                                Response::new(boxed_full(Bytes::new()))
                                            }));
                                    }
                                };
                                let method = request.method;
                                let path = request.path;
                                let authority = request.authority;
                                let content_length = request.content_length;
                                let suppress_downstream_body = is_head_method(&method);

                                let bootstrap_error = |status: StatusCode, body: &'static [u8]| {
                                    Ok(Response::builder()
                                        .status(status)
                                        .header("alt-svc", &alt)
                                        .body(boxed_full(Bytes::from_static(body)))
                                        .unwrap_or_else(|_| {
                                            Response::new(boxed_full(Bytes::from_static(
                                                b"error\n",
                                            )))
                                        }))
                                };

                                // Preserve the same route-lookup + tie-break semantics as the QUIC
                                // data plane by delegating bootstrap backend resolution here.
                                let lb_header_lookup = |name: &str| {
                                    req.headers()
                                        .get(name)
                                        .and_then(|value| value.to_str().ok())
                                        .map(str::to_string)
                                };
                                let resolved = Self::resolve_backend(
                                    &method,
                                    &path,
                                    authority.as_deref(),
                                    None,
                                    &upstream_pools,
                                    &routing_index,
                                    Some(&lb_header_lookup),
                                );
                                let (backend_addr, upstream_name) = match resolved {
                                    Ok(value) => (value.backend_addr, value.upstream_name),
                                    Err(ProxyError::Transport(reason)) => {
                                        let (status, body) =
                                            bootstrap_resolution_error_response(&reason);
                                        if status == StatusCode::BAD_GATEWAY
                                            && body == b"route/backend resolution failed\n"
                                        {
                                            warn!(
                                                "Bootstrap route/backend resolution failed: {}",
                                                reason
                                            );
                                        }
                                        return bootstrap_error(status, body);
                                    }
                                    Err(err) => {
                                        warn!("Bootstrap route/backend resolution failed: {}", err);
                                        return bootstrap_error(
                                            StatusCode::BAD_GATEWAY,
                                            b"route/backend resolution failed\n",
                                        );
                                    }
                                };

                                let endpoint = match backend_endpoints.get(&backend_addr) {
                                    Some(ep) => ep.clone(),
                                    None => {
                                        return Ok(Response::builder()
                                            .status(StatusCode::BAD_GATEWAY)
                                            .header("alt-svc", &alt)
                                            .body(boxed_full(Bytes::from_static(b"no endpoint\n")))
                                            .unwrap_or_else(|_| {
                                                Response::new(boxed_full(Bytes::from_static(
                                                    b"error\n",
                                                )))
                                            }));
                                    }
                                };

                                // Build upstream request
                                let request_path = if path.is_empty() { "/" } else { &path };
                                let upstream_policy = upstream_policies
                                    .get(&upstream_name)
                                    .cloned()
                                    .unwrap_or_default();
                                if !is_websocket_upgrade
                                    && content_length
                                        .is_some_and(|value| value > max_request_body_bytes)
                                {
                                    return Ok(Response::builder()
                                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                                        .header("alt-svc", &alt)
                                        .body(boxed_full(Bytes::from_static(
                                            b"request body too large\n",
                                        )))
                                        .unwrap_or_else(|_| {
                                            Response::new(boxed_full(Bytes::from_static(
                                                b"error\n",
                                            )))
                                        }));
                                }

                                let request_id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
                                let traceparent = req
                                    .headers()
                                    .get("traceparent")
                                    .and_then(|value| value.to_str().ok())
                                    .map(str::to_string);
                                let upstream_req = if is_websocket_upgrade {
                                    let upstream_uri = match http::Uri::try_from(
                                        endpoint.uri_for_path(request_path),
                                    ) {
                                        Ok(uri) => uri,
                                        Err(_) => {
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(b"bad uri\n")))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    };
                                    let request_host = req
                                        .headers()
                                        .get(http::header::HOST)
                                        .and_then(|value| value.to_str().ok());
                                    let upstream_host = match resolve_upstream_host_value(
                                        &endpoint,
                                        &upstream_policy.host.0,
                                        authority.as_deref(),
                                        request_host,
                                    ) {
                                        Ok(host) => host,
                                        Err(_) => {
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"invalid host policy\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    };

                                    let mut upstream_req = Request::builder()
                                        .method(method.as_str())
                                        .uri(upstream_uri);
                                    let mut forwarded_from_headers: Vec<Vec<u8>> = Vec::new();
                                    let mut x_forwarded_for_from_headers: Vec<Vec<u8>> = Vec::new();
                                    let mut x_forwarded_proto_from_headers: Vec<Vec<u8>> =
                                        Vec::new();
                                    let mut x_forwarded_host_from_headers: Vec<Vec<u8>> =
                                        Vec::new();
                                    for (name, value) in req.headers() {
                                        if name == http::header::HOST {
                                            continue;
                                        }
                                        if name.as_str().eq_ignore_ascii_case("forwarded") {
                                            forwarded_from_headers.push(value.as_bytes().to_vec());
                                            continue;
                                        }
                                        if name.as_str().eq_ignore_ascii_case("x-forwarded-for") {
                                            x_forwarded_for_from_headers
                                                .push(value.as_bytes().to_vec());
                                            continue;
                                        }
                                        if name.as_str().eq_ignore_ascii_case("x-forwarded-proto") {
                                            x_forwarded_proto_from_headers
                                                .push(value.as_bytes().to_vec());
                                            continue;
                                        }
                                        if name.as_str().eq_ignore_ascii_case("x-forwarded-host") {
                                            x_forwarded_host_from_headers
                                                .push(value.as_bytes().to_vec());
                                            continue;
                                        }
                                        if name == http::header::PROXY_AUTHORIZATION
                                            || name == http::header::PROXY_AUTHENTICATE
                                            || name
                                                .as_str()
                                                .eq_ignore_ascii_case("proxy-connection")
                                            || name == http::header::CONTENT_LENGTH
                                            || name == http::header::TE
                                            || name == http::header::TRAILER
                                            || name == http::header::TRANSFER_ENCODING
                                            || name.as_str().eq_ignore_ascii_case("keep-alive")
                                            || name.as_str().eq_ignore_ascii_case("forwarded")
                                            || name.as_str().eq_ignore_ascii_case("x-forwarded-for")
                                            || name
                                                .as_str()
                                                .eq_ignore_ascii_case("x-forwarded-proto")
                                            || name
                                                .as_str()
                                                .eq_ignore_ascii_case("x-forwarded-host")
                                        {
                                            continue;
                                        }
                                        upstream_req = upstream_req.header(name, value);
                                    }
                                    upstream_req =
                                        upstream_req.header(http::header::HOST, upstream_host);

                                    let forwarded_values = match build_forwarded_header_values(
                                        &upstream_policy.forwarded_headers.0,
                                        ForwardedHeaderChains {
                                            forwarded: &forwarded_from_headers,
                                            x_forwarded_for: &x_forwarded_for_from_headers,
                                            x_forwarded_proto: &x_forwarded_proto_from_headers,
                                            x_forwarded_host: &x_forwarded_host_from_headers,
                                        },
                                        peer.ip(),
                                        upstream_host,
                                    ) {
                                        Ok(values) => values,
                                        Err(err) => {
                                            warn!(
                                                "Bootstrap forwarded header policy failed: {}",
                                                err
                                            );
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"invalid forwarded headers\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    };
                                    if let Some(value) = forwarded_values.forwarded {
                                        upstream_req = upstream_req.header("forwarded", value);
                                    }
                                    if let Some(value) = forwarded_values.x_forwarded_for {
                                        upstream_req =
                                            upstream_req.header("x-forwarded-for", value);
                                    }
                                    if let Some(value) = forwarded_values.x_forwarded_proto {
                                        upstream_req =
                                            upstream_req.header("x-forwarded-proto", value);
                                    }
                                    if let Some(value) = forwarded_values.x_forwarded_host {
                                        upstream_req =
                                            upstream_req.header("x-forwarded-host", value);
                                    }

                                    match upstream_req.body(boxed_full(Bytes::new())) {
                                        Ok(request) => request,
                                        Err(_) => {
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"request build error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    }
                                } else {
                                    let bridge_headers: Vec<quiche::h3::Header> = req
                                        .headers()
                                        .iter()
                                        .map(|(name, value)| {
                                            quiche::h3::Header::new(
                                                name.as_str().as_bytes(),
                                                value.as_bytes(),
                                            )
                                        })
                                        .collect();
                                    match build_h2_request_for_endpoint_with_host_policy(
                                        &endpoint,
                                        &upstream_policy.host.0,
                                        &upstream_policy.forwarded_headers.0,
                                        &method,
                                        &path,
                                        &bridge_headers,
                                        BootstrapStreamingBody::new(req.into_body())
                                            .map_err(|never| match never {})
                                            .boxed(),
                                        None,
                                        ForwardedContext {
                                            client_addr: peer,
                                            request_authority: authority.as_deref(),
                                            request_id,
                                            traceparent: traceparent.as_deref(),
                                        },
                                    ) {
                                        Ok(request) => request,
                                        Err(err) => {
                                            warn!("Bootstrap request build failed: {}", err);
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"invalid request\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    }
                                };
                                let mut upstream_resp = if is_websocket_upgrade {
                                    if endpoint.scheme() != BackendScheme::Http {
                                        return Ok(Response::builder()
                                            .status(StatusCode::BAD_GATEWAY)
                                            .header("alt-svc", &alt)
                                            .body(boxed_full(Bytes::from_static(
                                                b"websocket bootstrap requires http upstream\n",
                                            )))
                                            .unwrap_or_else(|_| {
                                                Response::new(boxed_full(Bytes::from_static(
                                                    b"error\n",
                                                )))
                                            }));
                                    }
                                    let backend_target = endpoint.authority().to_string();
                                    let upstream_path_uri = match http::Uri::try_from(request_path)
                                    {
                                        Ok(uri) => uri,
                                        Err(_) => {
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(b"bad uri\n")))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    };
                                    let (mut parts, body) = upstream_req.into_parts();
                                    parts.uri = upstream_path_uri;
                                    let upstream_req = Request::from_parts(parts, body);

                                    let stream = match tokio::time::timeout(
                                        backend_timeout,
                                        tokio::net::TcpStream::connect(&backend_target),
                                    )
                                    .await
                                    {
                                        Ok(Ok(s)) => s,
                                        Ok(Err(err)) => {
                                            warn!("Bootstrap WebSocket connect error: {}", err);
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upstream error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                        Err(_) => {
                                            return Ok(Response::builder()
                                                .status(StatusCode::GATEWAY_TIMEOUT)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upstream timeout\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    };
                                    let io = TokioIo::new(stream);
                                    let (mut sender, conn) = match client_http1::handshake(io).await
                                    {
                                        Ok(v) => v,
                                        Err(err) => {
                                            warn!(
                                                "Bootstrap WebSocket handshake setup failed: {}",
                                                err
                                            );
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upstream error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    };
                                    tokio::spawn(async move {
                                        let _ = conn.with_upgrades().await;
                                    });
                                    match tokio::time::timeout(
                                        backend_timeout,
                                        sender.send_request(upstream_req),
                                    )
                                    .await
                                    {
                                        Ok(Ok(resp)) => resp,
                                        Ok(Err(err)) => {
                                            warn!("Bootstrap WebSocket upstream error: {}", err);
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upstream error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                        Err(_) => {
                                            return Ok(Response::builder()
                                                .status(StatusCode::GATEWAY_TIMEOUT)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upstream timeout\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    }
                                } else {
                                    Self::record_backend_connect_attempt(
                                        &metrics,
                                        &backend_resolution_store,
                                        &backend_addr,
                                    );
                                    match tokio::time::timeout(
                                        backend_timeout,
                                        transport_pool.send(&backend_addr, upstream_req),
                                    )
                                    .await
                                    {
                                        Ok(Ok(resp)) => resp,
                                        Ok(Err(err)) => {
                                            warn!("Bootstrap proxy upstream error: {}", err);
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upstream error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                        Err(_) => {
                                            return Ok(Response::builder()
                                                .status(StatusCode::GATEWAY_TIMEOUT)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upstream timeout\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    }
                                };

                                // Build downstream response with Alt-Svc injected
                                if !suppress_downstream_body
                                    && let Some(content_length) = upstream_resp
                                        .headers()
                                        .get(http::header::CONTENT_LENGTH)
                                        .and_then(|v| v.to_str().ok())
                                        .and_then(|s| s.parse::<usize>().ok())
                                    && content_length > max_response_body_bytes
                                {
                                    return Ok(Response::builder()
                                        .status(StatusCode::SERVICE_UNAVAILABLE)
                                        .header("alt-svc", &alt)
                                        .body(boxed_full(Bytes::from_static(
                                            b"upstream response body too large\n",
                                        )))
                                        .unwrap_or_else(|_| {
                                            Response::new(boxed_full(Bytes::from_static(
                                                b"error\n",
                                            )))
                                        }));
                                }

                                let status = upstream_resp.status();
                                let mut resp_builder = Response::builder().status(status);
                                let response_connection_tokens =
                                    connection_header_tokens(upstream_resp.headers());
                                for (name, value) in upstream_resp.headers() {
                                    if should_strip_bootstrap_response_header(
                                        name,
                                        &response_connection_tokens,
                                    ) {
                                        continue;
                                    }
                                    resp_builder = resp_builder.header(name, value);
                                }
                                resp_builder = resp_builder.header("alt-svc", &alt);
                                if is_websocket_upgrade
                                    && upstream_resp.status() == StatusCode::SWITCHING_PROTOCOLS
                                {
                                    let client_upgrade = match client_upgrade {
                                        Some(u) => u,
                                        None => {
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upgrade setup error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    };
                                    let upstream_upgrade = upgrade::on(&mut upstream_resp);
                                    tokio::spawn(async move {
                                        let (client, upstream) = match tokio::try_join!(
                                            client_upgrade,
                                            upstream_upgrade
                                        ) {
                                            Ok(v) => v,
                                            Err(err) => {
                                                debug!(
                                                    "Bootstrap WebSocket upgrade join failed: {}",
                                                    err
                                                );
                                                return;
                                            }
                                        };
                                        let mut client = TokioIo::new(client);
                                        let mut upstream = TokioIo::new(upstream);
                                        let _ = tokio::io::copy_bidirectional(
                                            &mut client,
                                            &mut upstream,
                                        )
                                        .await;
                                    });
                                    return Ok(resp_builder
                                        .body(boxed_full(Bytes::new()))
                                        .unwrap_or_else(|_| {
                                            Response::new(boxed_full(Bytes::new()))
                                        }));
                                }
                                let resp_body = if suppress_downstream_body {
                                    boxed_full(Bytes::new())
                                } else {
                                    BootstrapStreamingBody::with_max_bytes(
                                        upstream_resp.into_body(),
                                        max_response_body_bytes,
                                    )
                                    .map_err(|never| match never {})
                                    .boxed()
                                };

                                Ok(resp_builder
                                    .body(resp_body)
                                    .unwrap_or_else(|_| Response::new(boxed_full(Bytes::new()))))
                            })
                        },
                    );

                    if use_h2 {
                        let executor = hyper_util::rt::TokioExecutor::new();
                        let serve = http2::Builder::new(executor).serve_connection(io, svc);
                        match tokio::time::timeout(timeout, serve).await {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) => {
                                debug!("Bootstrap h2 connection from {} closed: {}", peer, err);
                            }
                            Err(_) => {
                                debug!("Bootstrap h2 connection from {} timed out", peer);
                            }
                        }
                    } else {
                        let serve = http1::Builder::new()
                            .serve_connection(io, svc)
                            .with_upgrades();
                        match tokio::time::timeout(timeout, serve).await {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) => {
                                debug!("Bootstrap h1 connection from {} closed: {}", peer, err);
                            }
                            Err(_) => {
                                debug!("Bootstrap h1 connection from {} timed out", peer);
                            }
                        }
                    }
                });
            }
        });

        Ok(())
    }

    fn bootstrap_connection_state(
        listener_label: &str,
        runtime_bundle: Option<&Arc<RuntimeBundleHandle>>,
        startup: &BootstrapStartupState,
    ) -> Option<BootstrapConnectionState> {
        let (
            listener_config,
            listener_tls_store,
            transport_pool,
            backend_endpoints,
            backend_resolution_store,
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
                runtime.shared_state.backend_resolution_store.clone(),
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
                Arc::clone(&startup.backend_resolution_store),
                Arc::clone(&startup.upstream_policies),
                Arc::clone(&startup.metrics),
                Arc::clone(&startup.resilience),
                startup.upstream_pools.clone(),
                Arc::clone(&startup.routing_index),
            )
        };

        Some(BootstrapConnectionState {
            alt_svc_value: format!("h3=\":{}\"; ma=86400", listener_config.listen.listen.port),
            backend_timeout: Duration::from_millis(listener_config.performance.backend_timeout_ms),
            max_request_body_bytes: listener_config.performance.max_request_body_bytes,
            max_response_body_bytes: listener_config.performance.max_response_body_bytes,
            max_connections: listener_config.performance.max_active_connections.max(1),
            connection_timeout: Duration::from_millis(
                listener_config
                    .performance
                    .client_body_idle_timeout_ms
                    .max(1),
            ),
            listener_tls_store,
            transport_pool,
            backend_endpoints,
            backend_resolution_store,
            upstream_policies,
            metrics,
            resilience,
            upstream_pools,
            routing_index,
        })
    }

    fn try_claim_runtime_connection_slot(
        active_connections: &Arc<AtomicUsize>,
        max_connections: usize,
    ) -> bool {
        loop {
            let current = active_connections.load(Ordering::Relaxed);
            if current >= max_connections {
                return false;
            }
            if active_connections
                .compare_exchange(
                    current,
                    current.saturating_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return true;
            }
        }
    }

    fn handle_metrics_request(
        req: Request<Incoming>,
        metrics_path: &str,
        metrics: Arc<Metrics>,
    ) -> Response<Full<Bytes>> {
        if req.uri().path() != metrics_path {
            return match Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from_static(b"not found\n")))
            {
                Ok(resp) => resp,
                Err(_) => Response::new(Full::new(Bytes::from_static(b"not found\n"))),
            };
        }

        let body = metrics.render_prometheus();
        match Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4")
            .body(Full::new(Bytes::from(body)))
        {
            Ok(resp) => resp,
            Err(_) => Response::new(Full::new(Bytes::from_static(b"failed to render metrics\n"))),
        }
    }
}

fn classify_retry_reason(err: &ProxyError) -> RetryReason {
    match err {
        ProxyError::Timeout => RetryReason::BackendTimeout,
        ProxyError::Transport(_) => RetryReason::BackendTransport,
        ProxyError::Pool(_) => RetryReason::BackendPool,
        _ => RetryReason::BackendTransport,
    }
}

fn is_benign_quic_close(err: &quiche::ConnectionError) -> bool {
    !err.is_app && err.error_code == 0 && err.reason.is_empty()
}

fn log_quic_connection_error(
    source: &str,
    peer: SocketAddr,
    trace_id: &str,
    err: &quiche::ConnectionError,
) {
    if is_benign_quic_close(err) {
        debug!(
            "QUIC {} close without error: peer={} trace_id={} is_app={} error_code={} reason_len={}",
            source,
            peer,
            trace_id,
            err.is_app,
            err.error_code,
            err.reason.len()
        );
        return;
    }

    if err.reason.is_empty() {
        error!(
            "QUIC {} error: peer={} trace_id={} is_app={} error_code={}",
            source, peer, trace_id, err.is_app, err.error_code
        );
    } else {
        error!(
            "QUIC {} error: peer={} trace_id={} is_app={} error_code={} reason={}",
            source,
            peer,
            trace_id,
            err.is_app,
            err.error_code,
            String::from_utf8_lossy(&err.reason)
        );
    }
}

fn maybe_log_quic_connection_error(
    source: &str,
    peer: SocketAddr,
    trace_id: &str,
    err: &quiche::ConnectionError,
    last_logged: &mut Option<QuicConnectionErrorSnapshot>,
) {
    let snapshot = QuicConnectionErrorSnapshot {
        is_app: err.is_app,
        error_code: err.error_code,
        reason: err.reason.clone(),
    };

    if last_logged.as_ref() == Some(&snapshot) {
        return;
    }

    *last_logged = Some(snapshot);
    log_quic_connection_error(source, peer, trace_id, err);
}

pub fn configure_async_runtime(worker_threads: usize) {
    let threads = worker_threads.max(1);
    if FALLBACK_RT.get().is_some() {
        warn!(
            "async runtime already initialized; ignoring new worker_threads={}",
            threads
        );
        return;
    }
    FALLBACK_RT_THREADS.store(threads, Ordering::Relaxed);
}

fn runtime_handle() -> Option<Handle> {
    if let Ok(handle) = Handle::try_current() {
        return Some(handle);
    }
    fallback_runtime().map(|rt| rt.handle().clone())
}

fn spawn_async_task<F>(fut: F, _task_name: &str) -> bool
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    if let Some(handle) = runtime_handle() {
        handle.spawn(fut);
        true
    } else {
        false
    }
}

fn spawn_supervised_async_task<F>(
    handle: &Handle,
    task_name: &'static str,
    metrics: Option<Arc<Metrics>>,
    fut: F,
) -> RuntimeTaskRegistration
where
    F: Future<Output = ()> + Send + 'static,
{
    let task_name = task_name.to_string();
    let (completion_tx, completion_rx) = oneshot::channel();
    let join = handle.spawn(fut);
    let abort = join.abort_handle();
    let monitor_handle = handle.clone();
    monitor_handle.spawn(async move {
        match join.await {
            Ok(()) => {}
            Err(err) => {
                if let Some(metrics) = metrics {
                    metrics.inc_runtime_panic();
                }
                if err.is_panic() {
                    error!("Background task '{}' panicked", task_name);
                } else {
                    warn!("Background task '{}' cancelled", task_name);
                }
            }
        }
        let _ = completion_tx.send(());
    });
    RuntimeTaskRegistration::new(abort, completion_rx)
}

fn fallback_runtime() -> Option<&'static tokio::runtime::Runtime> {
    FALLBACK_RT
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(FALLBACK_RT_THREADS.load(Ordering::Relaxed))
                .thread_name("spooky-edge-fallback-rt")
                .build()
                .ok()
        })
        .as_ref()
}

static FALLBACK_RT: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();
static FALLBACK_RT_THREADS: AtomicUsize = AtomicUsize::new(2);

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        path::Path,
        sync::{Arc, RwLock},
        time::Duration,
    };

    use rcgen::{Certificate, CertificateParams, SanType};
    use spooky_config::{
        config::{
            Backend, ClientAuth, Config as SpookyConfigConfig, Listen, LoadBalancing, Log,
            Observability, Performance, Resilience, RouteMatch, Security, Tls, TlsCertificate,
            Upstream, UpstreamTls,
        },
        runtime::{ListenerRuntimeConfig, RuntimeConfig},
    };
    use tempfile::tempdir;

    use super::is_bodyless_request_mode;

    use crate::REQUEST_ID_COUNTER;
    use crate::cid_radix::CidRadix;
    use http::{HeaderMap, HeaderValue, StatusCode};

    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::sync::atomic::Ordering;

    use super::{
        ConnectionRoutes, TokenBucket, abort_stream, can_poll_upstream_result,
        classify_active_health_check_response, collect_h3_trailers, connection_header_tokens,
        is_connect_tunnel_response, purge_connection_routes, resolve_primary_from_radix_prefix,
        response_size_exceeded_after_chunk, should_strip_bootstrap_request_header,
        should_strip_bootstrap_response_header, should_strip_h3_response_header,
        sweep_closed_connections,
    };
    use spooky_lb::HealthFailureReason;
    type RoutingMaps = (
        HashMap<Arc<[u8]>, Arc<[u8]>>,
        CidRadix,
        HashMap<SocketAddr, Arc<[u8]>>,
    );

    fn cid(bytes: &[u8]) -> Arc<[u8]> {
        Arc::from(bytes)
    }

    fn test_upstream(lb_type: &str) -> Upstream {
        test_upstream_with(lb_type, None, None)
    }

    fn test_upstream_with(lb_type: &str, lb_key: Option<&str>, method: Option<&str>) -> Upstream {
        Upstream {
            load_balancing: LoadBalancing {
                lb_type: lb_type.to_string(),
                key: lb_key.map(str::to_string),
            },
            host_policy: Default::default(),
            forwarded_headers: Default::default(),
            tls: None,
            route: RouteMatch {
                host: None,
                path_prefix: Some("/api".to_string()),
                method: method.map(str::to_string),
            },
            backends: vec![
                Backend {
                    id: "b1".to_string(),
                    address: "127.0.0.1:7001".to_string(),
                    weight: 1,
                    health_check: None,
                },
                Backend {
                    id: "b2".to_string(),
                    address: "127.0.0.1:7002".to_string(),
                    weight: 1,
                    health_check: None,
                },
            ],
        }
    }

    fn write_test_cert_for_name(dir: &Path, cert_name: &str, dns_name: &str) -> (String, String) {
        let mut params = CertificateParams::new(vec![dns_name.to_string()]);
        params
            .subject_alt_names
            .push(SanType::DnsName(dns_name.to_string()));
        let cert = Certificate::from_params(params).expect("failed to build cert");

        let cert_path = dir.join(format!("{cert_name}.pem"));
        let key_path = dir.join(format!("{cert_name}.key.pem"));

        std::fs::write(&cert_path, cert.serialize_pem().expect("serialize cert"))
            .expect("write cert");
        std::fs::write(&key_path, cert.serialize_private_key_pem()).expect("write key");
        (
            cert_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
        )
    }

    fn tls_test_config(
        cert: String,
        key: String,
        certificates: Vec<TlsCertificate>,
    ) -> SpookyConfigConfig {
        let mut upstreams = HashMap::new();
        upstreams.insert("api".to_string(), test_upstream("round-robin"));
        SpookyConfigConfig {
            version: 1,
            listen: Listen {
                protocol: "http3".to_string(),
                port: 9889,
                address: "127.0.0.1".to_string(),
                tls: Tls {
                    cert,
                    key,
                    certificates,
                    client_auth: ClientAuth::default(),
                },
            },
            listeners: vec![],
            upstream: upstreams,
            load_balancing: Some(LoadBalancing {
                lb_type: "round-robin".to_string(),
                key: None,
            }),
            upstream_tls: UpstreamTls::default(),
            log: Log::default(),
            performance: Performance::default(),
            observability: Observability::default(),
            resilience: Resilience::default(),
            security: Security::default(),
        }
    }

    fn tls_test_listener_config(config: &SpookyConfigConfig) -> ListenerRuntimeConfig {
        RuntimeConfig::from_config(config)
            .expect("runtime config")
            .primary_listener_runtime_config()
            .expect("listener runtime config")
    }

    fn dns_resolution_test_config(cert: String, key: String) -> SpookyConfigConfig {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "api".to_string(),
            Upstream {
                load_balancing: LoadBalancing {
                    lb_type: "round-robin".to_string(),
                    key: None,
                },
                host_policy: Default::default(),
                forwarded_headers: Default::default(),
                tls: None,
                route: RouteMatch {
                    host: Some("api.example.com".to_string()),
                    path_prefix: Some("/".to_string()),
                    method: None,
                },
                backends: vec![
                    Backend {
                        id: "dns".to_string(),
                        address: "backend.internal:8443".to_string(),
                        weight: 1,
                        health_check: None,
                    },
                    Backend {
                        id: "ip".to_string(),
                        address: "10.0.0.10:9443".to_string(),
                        weight: 1,
                        health_check: None,
                    },
                ],
            },
        );

        SpookyConfigConfig {
            version: 1,
            listen: Listen {
                protocol: "http3".to_string(),
                port: 9889,
                address: "127.0.0.1".to_string(),
                tls: Tls {
                    cert,
                    key,
                    certificates: Vec::new(),
                    client_auth: ClientAuth::default(),
                },
            },
            listeners: vec![],
            upstream: upstreams,
            load_balancing: Some(LoadBalancing {
                lb_type: "round-robin".to_string(),
                key: None,
            }),
            upstream_tls: UpstreamTls::default(),
            log: Log::default(),
            performance: Performance::default(),
            observability: Observability::default(),
            resilience: Resilience::default(),
            security: Security::default(),
        }
    }

    #[test]
    fn runtime_listener_tls_uses_first_sni_entry_when_legacy_pair_is_missing() {
        let dir = tempdir().expect("tempdir");
        let (api_cert, api_key) = write_test_cert_for_name(dir.path(), "api", "api.example.com");
        let (www_cert, www_key) = write_test_cert_for_name(dir.path(), "www", "www.example.com");
        let config = tls_test_config(
            String::new(),
            String::new(),
            vec![
                TlsCertificate {
                    server_name: "api.example.com".to_string(),
                    cert: api_cert.clone(),
                    key: api_key.clone(),
                },
                TlsCertificate {
                    server_name: "www.example.com".to_string(),
                    cert: www_cert,
                    key: www_key,
                },
            ],
        );

        let runtime_tls =
            super::QUICListener::runtime_listener_tls(&tls_test_listener_config(&config))
                .expect("runtime listener tls");
        assert_eq!(runtime_tls.default_identity.cert_path, api_cert);
        assert_eq!(runtime_tls.default_identity.key_path, api_key);
    }

    #[test]
    fn build_server_tls_acceptor_accepts_sni_certs_without_legacy_pair() {
        let dir = tempdir().expect("tempdir");
        let (api_cert, api_key) = write_test_cert_for_name(dir.path(), "api", "api.example.com");
        let config = tls_test_config(
            String::new(),
            String::new(),
            vec![TlsCertificate {
                server_name: "api.example.com".to_string(),
                cert: api_cert,
                key: api_key,
            }],
        );

        let acceptor = super::QUICListener::build_server_tls_acceptor(
            &tls_test_listener_config(&config),
            false,
            vec![b"h2".to_vec()],
        );
        assert!(acceptor.is_ok());
    }

    #[test]
    fn load_listener_tls_material_extracts_leaf_metadata() {
        let dir = tempdir().expect("tempdir");
        let (api_cert, api_key) = write_test_cert_for_name(dir.path(), "api", "api.example.com");
        let runtime_config = tls_test_listener_config(&tls_test_config(
            String::new(),
            String::new(),
            vec![TlsCertificate {
                server_name: "api.example.com".to_string(),
                cert: api_cert.clone(),
                key: api_key.clone(),
            }],
        ));

        let loaded = super::QUICListener::load_listener_tls_material(&runtime_config)
            .expect("loaded listener tls");
        let metadata = &loaded.default_identity.metadata;
        assert!(
            !metadata.serial_hex.is_empty(),
            "serial should be populated"
        );
        assert!(
            metadata.not_after_unix_seconds >= metadata.not_before_unix_seconds,
            "certificate validity should be ordered"
        );
        assert!(
            metadata
                .dns_names
                .iter()
                .any(|name| name == "api.example.com"),
            "expected SAN/CN metadata to include the configured hostname"
        );
    }

    #[test]
    fn load_listener_tls_material_loads_client_auth_ca_roots() {
        let dir = tempdir().expect("tempdir");
        let (server_cert, server_key) =
            write_test_cert_for_name(dir.path(), "server", "api.example.com");
        let (client_ca_cert, _client_ca_key) =
            write_test_cert_for_name(dir.path(), "client-ca", "client-ca.example.com");
        let mut config = tls_test_config(server_cert, server_key, Vec::new());
        config.listen.tls.client_auth = ClientAuth {
            enabled: true,
            require_client_cert: true,
            ca_file: Some(client_ca_cert.clone()),
        };

        let loaded =
            super::QUICListener::load_listener_tls_material(&tls_test_listener_config(&config))
                .expect("loaded listener tls");
        let client_auth_ca = loaded.client_auth_ca.expect("client auth ca");
        assert_eq!(client_auth_ca.ca_file, client_ca_cert);
        assert_eq!(client_auth_ca.certificate_count, 1);
    }

    #[test]
    fn listener_tls_reload_store_refreshes_inventory_and_generation() {
        let dir = tempdir().expect("tempdir");
        let (server_cert, server_key) =
            write_test_cert_for_name(dir.path(), "server", "api.example.com");
        let mut config = tls_test_config(server_cert, server_key, Vec::new());
        config.listen.port = 0;

        let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
        let shared = super::QUICListener::build_shared_state(&runtime).expect("shared state");
        let listener_label = "127.0.0.1:0";
        let initial_inventory = shared
            .listener_tls_store
            .inventory(listener_label)
            .expect("initial inventory");
        let initial_serial = initial_inventory
            .default_identity
            .metadata
            .serial_hex
            .clone();
        assert_eq!(
            shared.listener_tls_store.generation(listener_label),
            Some(0)
        );

        let (_rotated_cert, _rotated_key) =
            write_test_cert_for_name(dir.path(), "server", "api.example.com");
        let listener_config = shared
            .listener_runtime_configs
            .get(listener_label)
            .expect("listener runtime config");
        let reloaded_state = super::QUICListener::build_listener_tls_reload_state(listener_config)
            .expect("reloaded tls state");
        let generation = shared
            .listener_tls_store
            .replace_listener(
                listener_label,
                reloaded_state.inventory,
                reloaded_state.bootstrap_server_config,
            )
            .expect("replace listener");
        assert_eq!(generation, 1);

        let refreshed_inventory = shared
            .listener_tls_store
            .inventory(listener_label)
            .expect("refreshed inventory");
        assert_ne!(
            refreshed_inventory.default_identity.metadata.serial_hex,
            initial_serial
        );
    }

    #[test]
    fn quic_listener_syncs_tls_generation_after_reload() {
        let dir = tempdir().expect("tempdir");
        let (server_cert, server_key) =
            write_test_cert_for_name(dir.path(), "server", "api.example.com");
        let mut config = tls_test_config(server_cert, server_key, Vec::new());
        config.listen.port = 0;
        let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
        let shared = Arc::new(super::QUICListener::build_shared_state(&runtime).expect("shared"));
        let listener_config = runtime
            .primary_listener_runtime_config()
            .expect("listener runtime config");
        let listener_label = super::QUICListener::listener_label(&listener_config);
        assert_eq!(
            super::QUICListener::tls_reload_generation_if_needed(
                &listener_label,
                0,
                &shared.listener_tls_store
            )
            .expect("initial generation"),
            None
        );

        let (_rotated_cert, _rotated_key) =
            write_test_cert_for_name(dir.path(), "server", "api.example.com");
        let reloaded_state = super::QUICListener::build_listener_tls_reload_state(&listener_config)
            .expect("reloaded tls state");
        shared
            .listener_tls_store
            .replace_listener(
                &listener_label,
                reloaded_state.inventory,
                reloaded_state.bootstrap_server_config,
            )
            .expect("replace listener");

        assert_eq!(
            super::QUICListener::tls_reload_generation_if_needed(
                &listener_label,
                0,
                &shared.listener_tls_store
            )
            .expect("reloaded generation"),
            Some(1)
        );
    }

    #[test]
    fn bootstrap_connection_state_prefers_reloaded_runtime_settings() {
        let dir = tempdir().expect("tempdir");
        let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
        let startup = tls_test_config(cert.clone(), key.clone(), Vec::new());
        let startup_runtime = RuntimeConfig::from_config(&startup).expect("startup runtime");
        let startup_listener_config = startup_runtime
            .primary_listener_runtime_config()
            .expect("startup listener config");
        let startup_shared =
            Arc::new(super::QUICListener::build_shared_state(&startup_runtime).expect("shared"));
        let listener_label = super::QUICListener::listener_label(&startup_listener_config);
        let startup_state = super::BootstrapStartupState {
            listener_config: startup_listener_config.clone(),
            listener_tls_store: Arc::clone(&startup_shared.listener_tls_store),
            transport_pool: Arc::clone(&startup_shared.transport_pool),
            backend_endpoints: Arc::clone(&startup_shared.backend_endpoints),
            backend_resolution_store: Arc::clone(&startup_shared.backend_resolution_store),
            upstream_policies: Arc::clone(&startup_shared.upstream_policies),
            metrics: Arc::clone(&startup_shared.metrics),
            resilience: Arc::clone(&startup_shared.resilience),
            upstream_pools: startup_shared.upstream_pools.clone(),
            routing_index: Arc::clone(&startup_shared.routing_index),
        };

        let mut reloaded = startup.clone();
        reloaded.performance.backend_timeout_ms = 4321;
        reloaded.performance.max_request_body_bytes = 65_537;
        reloaded.performance.max_response_body_bytes = 98_765;
        reloaded.performance.max_active_connections = 37;
        reloaded.performance.client_body_idle_timeout_ms = 7654;

        let reloaded_runtime = RuntimeConfig::from_config(&reloaded).expect("reloaded runtime");
        let reloaded_bundle = super::QUICListener::build_runtime_bundle(
            "reloaded.yaml".to_string(),
            &reloaded_runtime,
        )
        .expect("reloaded bundle");
        let runtime_handle = Arc::new(super::RuntimeBundleHandle::new(reloaded_bundle));

        let state = super::QUICListener::bootstrap_connection_state(
            &listener_label,
            Some(&runtime_handle),
            &startup_state,
        )
        .expect("bootstrap state");

        assert_eq!(state.backend_timeout, Duration::from_millis(4321));
        assert_eq!(state.max_request_body_bytes, 65_537);
        assert_eq!(state.max_response_body_bytes, 98_765);
        assert_eq!(state.max_connections, 37);
        assert_eq!(state.connection_timeout, Duration::from_millis(7654));
    }

    #[test]
    fn metrics_endpoint_state_prefers_reloaded_runtime_settings() {
        let dir = tempdir().expect("tempdir");
        let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
        let startup = tls_test_config(cert.clone(), key.clone(), Vec::new());
        let startup_runtime = RuntimeConfig::from_config(&startup).expect("startup runtime");
        let startup_shared =
            Arc::new(super::QUICListener::build_shared_state(&startup_runtime).expect("shared"));

        let mut reloaded = startup.clone();
        reloaded.observability.metrics.enabled = true;
        reloaded.observability.metrics.path = "/metrics-live".to_string();
        reloaded.observability.metrics.max_connections = 29;
        reloaded.observability.metrics.connection_timeout_ms = 3456;

        let reloaded_runtime = RuntimeConfig::from_config(&reloaded).expect("reloaded runtime");
        let reloaded_bundle = super::QUICListener::build_runtime_bundle(
            "reloaded.yaml".to_string(),
            &reloaded_runtime,
        )
        .expect("reloaded bundle");
        let runtime_handle = Arc::new(super::RuntimeBundleHandle::new(reloaded_bundle));

        let state = super::QUICListener::metrics_endpoint_state(
            Some(&runtime_handle),
            "/metrics-startup".to_string(),
            5,
            Duration::from_millis(500),
            Arc::clone(&startup_shared.metrics),
        );

        assert_eq!(state.metrics_path, "/metrics-live");
        assert_eq!(state.max_connections, 29);
        assert_eq!(state.connection_timeout, Duration::from_millis(3456));
    }

    #[test]
    fn build_server_tls_acceptor_rejects_mismatched_sni_certificate_mapping() {
        let dir = tempdir().expect("tempdir");
        let (api_cert, api_key) = write_test_cert_for_name(dir.path(), "api", "api.example.com");
        let config = tls_test_config(
            String::new(),
            String::new(),
            vec![TlsCertificate {
                server_name: "other.example.com".to_string(),
                cert: api_cert,
                key: api_key,
            }],
        );

        let err = super::QUICListener::build_server_tls_acceptor(
            &tls_test_listener_config(&config),
            false,
            vec![b"h2".to_vec()],
        )
        .err()
        .expect("mismatched SNI cert mapping should fail");
        assert!(
            err.to_string()
                .contains("failed to add SNI certificate mapping"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn build_quic_config_accepts_sni_certs_without_legacy_pair() {
        let dir = tempdir().expect("tempdir");
        let (api_cert, api_key) = write_test_cert_for_name(dir.path(), "api", "api.example.com");
        let config = tls_test_config(
            String::new(),
            String::new(),
            vec![TlsCertificate {
                server_name: "api.example.com".to_string(),
                cert: api_cert,
                key: api_key,
            }],
        );

        let quic_config =
            super::QUICListener::build_quic_config(&tls_test_listener_config(&config));
        if let Err(err) = quic_config {
            panic!("unexpected error: {err}");
        }
    }

    #[test]
    fn build_quic_config_rejects_mismatched_sni_certificate_mapping() {
        let dir = tempdir().expect("tempdir");
        let (api_cert, api_key) = write_test_cert_for_name(dir.path(), "api", "api.example.com");
        let config = tls_test_config(
            String::new(),
            String::new(),
            vec![TlsCertificate {
                server_name: "other.example.com".to_string(),
                cert: api_cert,
                key: api_key,
            }],
        );

        let err = super::QUICListener::build_quic_config(&tls_test_listener_config(&config))
            .err()
            .expect("mismatched SNI cert mapping should fail");
        assert!(
            err.to_string()
                .contains("failed to add SNI certificate mapping"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn certificate_name_matches_single_label_wildcards_only() {
        assert!(super::QUICListener::certificate_name_matches(
            "*.example.com",
            "api.example.com"
        ));
        assert!(!super::QUICListener::certificate_name_matches(
            "*.example.com",
            "deep.api.example.com"
        ));
        assert!(!super::QUICListener::certificate_name_matches(
            "*.example.com",
            "example.com"
        ));
    }

    #[test]
    fn classify_upstream_failure_reason_distinguishes_tls_causes() {
        assert_eq!(
            super::QUICListener::classify_upstream_failure_reason(
                true,
                "tls handshake failed: UnknownIssuer"
            ),
            (HealthFailureReason::Tls, "unknown_issuer")
        );
        assert_eq!(
            super::QUICListener::classify_upstream_failure_reason(
                true,
                "certificate expired while verifying backend"
            ),
            (HealthFailureReason::Tls, "expired_certificate")
        );
        assert_eq!(
            super::QUICListener::classify_upstream_failure_reason(
                true,
                "certificate not valid for dns name api.example.com"
            ),
            (HealthFailureReason::Tls, "hostname_mismatch")
        );
        assert_eq!(
            super::QUICListener::classify_upstream_failure_reason(true, "ALPN negotiation failed"),
            (HealthFailureReason::Tls, "alpn")
        );
        assert_eq!(
            super::QUICListener::classify_upstream_failure_reason(false, "backend timed out"),
            (HealthFailureReason::Timeout, "timeout")
        );
    }

    #[test]
    fn classify_downstream_tls_failure_reason_distinguishes_client_auth_causes() {
        assert_eq!(
            super::QUICListener::classify_downstream_tls_failure_reason(
                "peer sent no certificates"
            ),
            "missing_client_cert"
        );
        assert_eq!(
            super::QUICListener::classify_downstream_tls_failure_reason(
                "certificate verify failed: UnknownIssuer"
            ),
            "unknown_issuer"
        );
        assert_eq!(
            super::QUICListener::classify_downstream_tls_failure_reason("certificate expired"),
            "expired_client_cert"
        );
        assert_eq!(
            super::QUICListener::classify_downstream_tls_failure_reason("bad certificate"),
            "invalid_client_cert"
        );
    }

    #[test]
    fn build_shared_state_separates_backend_identity_from_resolution_state() {
        let dir = tempdir().expect("tempdir");
        let (cert, key) = write_test_cert_for_name(dir.path(), "server", "api.example.com");
        let runtime =
            RuntimeConfig::from_config(&dns_resolution_test_config(cert, key)).expect("runtime");
        let shared = super::QUICListener::build_shared_state(&runtime).expect("shared state");
        let snapshot = shared.backend_resolution_store.snapshot();

        let dns_backend = snapshot
            .get("backend.internal:8443")
            .expect("dns backend resolution");
        assert!(dns_backend.is_hostname());
        assert_eq!(dns_backend.authority_host, "backend.internal");
        assert_eq!(dns_backend.authority_port, 8443);
        assert!(dns_backend.resolved_addrs.is_empty());

        let ip_backend = snapshot
            .get("10.0.0.10:9443")
            .expect("ip backend resolution");
        assert!(!ip_backend.is_hostname());
        assert_eq!(ip_backend.authority_host, "10.0.0.10");
        assert_eq!(ip_backend.authority_port, 9443);
        assert_eq!(
            ip_backend.resolved_addrs,
            vec!["10.0.0.10:9443".parse().expect("addr")]
        );
    }

    type TestRoutingContext = (
        HashMap<String, Arc<RwLock<super::UpstreamPool>>>,
        super::RouteIndex,
        Arc<RwLock<super::UpstreamPool>>,
    );

    fn test_routing_context(lb_type: &str) -> TestRoutingContext {
        let mut upstreams = HashMap::new();
        upstreams.insert("api_pool".to_string(), test_upstream(lb_type));
        let routing_index = super::RouteIndex::from_upstreams(&upstreams);
        let pool = super::UpstreamPool::from_upstream(upstreams.get("api_pool").expect("upstream"))
            .expect("pool");
        let pool = Arc::new(RwLock::new(pool));
        let mut upstream_pools = HashMap::new();
        upstream_pools.insert("api_pool".to_string(), Arc::clone(&pool));
        (upstream_pools, routing_index, pool)
    }

    #[test]
    fn resolve_backend_round_robin_is_not_pinned_to_first_backend() {
        let (upstream_pools, routing_index, _pool) = test_routing_context("round-robin");

        let mut picks = Vec::new();
        for _ in 0..4 {
            let resolved = super::QUICListener::resolve_backend(
                "GET",
                "/api/items",
                None,
                None,
                &upstream_pools,
                &routing_index,
                None,
            )
            .expect("resolve backend");
            picks.push(resolved.backend_addr);
        }

        assert!(
            picks.iter().any(|addr| addr == "127.0.0.1:7001")
                && picks.iter().any(|addr| addr == "127.0.0.1:7002"),
            "round-robin resolution should not pin all bootstrap picks to the first backend: {:?}",
            picks
        );
    }

    #[test]
    fn resolve_backend_skips_unhealthy_backends() {
        let (upstream_pools, routing_index, pool) = test_routing_context("round-robin");
        {
            let mut guard = pool.write().expect("pool write");
            guard.pool.mark_failure(0);
            guard.pool.mark_failure(0);
            guard.pool.mark_failure(0);
        }

        let resolved = super::QUICListener::resolve_backend(
            "GET",
            "/api/items",
            None,
            None,
            &upstream_pools,
            &routing_index,
            None,
        )
        .expect("resolve backend");

        assert_eq!(
            resolved.backend_addr, "127.0.0.1:7002",
            "unhealthy backend must be excluded from bootstrap backend selection"
        );
    }

    #[test]
    fn resolve_backend_respects_least_connections_strategy() {
        let (upstream_pools, routing_index, pool) = test_routing_context("least-connections");
        {
            let guard = pool.read().expect("pool read");
            guard.pool.begin_request(0);
            guard.pool.begin_request(0);
        }

        let resolved = super::QUICListener::resolve_backend(
            "GET",
            "/api/items",
            None,
            None,
            &upstream_pools,
            &routing_index,
            None,
        )
        .expect("resolve backend");

        assert_eq!(
            resolved.backend_addr, "127.0.0.1:7002",
            "least-connections should prefer lower in-flight backend in bootstrap selection"
        );
    }

    #[test]
    fn resolve_backend_prefers_method_specific_route() {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "all_methods".to_string(),
            test_upstream_with("round-robin", None, None),
        );
        let mut post_only = test_upstream_with("round-robin", None, Some("POST"));
        post_only.backends = vec![Backend {
            id: "post".to_string(),
            address: "127.0.0.1:7010".to_string(),
            weight: 1,
            health_check: None,
        }];
        upstreams.insert("post_only".to_string(), post_only);

        let routing_index = super::RouteIndex::from_upstreams(&upstreams);
        let mut upstream_pools = HashMap::new();
        for (name, upstream) in &upstreams {
            let pool = super::UpstreamPool::from_upstream(upstream).expect("pool");
            upstream_pools.insert(name.clone(), Arc::new(RwLock::new(pool)));
        }

        let resolved = super::QUICListener::resolve_backend(
            "GET",
            "/api/items",
            None,
            None,
            &upstream_pools,
            &routing_index,
            None,
        )
        .expect("GET resolve");
        assert_eq!(resolved.upstream_name, "all_methods");

        let resolved = super::QUICListener::resolve_backend(
            "POST",
            "/api/items",
            None,
            None,
            &upstream_pools,
            &routing_index,
            None,
        )
        .expect("POST resolve");
        assert_eq!(resolved.upstream_name, "post_only");
        assert_eq!(resolved.backend_addr, "127.0.0.1:7010");
    }

    #[test]
    fn resolve_backend_uses_configured_header_lb_key() {
        let (upstream_pools, routing_index, _pool) = {
            let mut upstreams = HashMap::new();
            upstreams.insert(
                "api_pool".to_string(),
                test_upstream_with("consistent-hash", Some("header:x-user-id"), None),
            );
            let routing_index = super::RouteIndex::from_upstreams(&upstreams);
            let pool =
                super::UpstreamPool::from_upstream(upstreams.get("api_pool").expect("upstream"))
                    .expect("pool");
            let pool = Arc::new(RwLock::new(pool));
            let mut upstream_pools = HashMap::new();
            upstream_pools.insert("api_pool".to_string(), Arc::clone(&pool));
            (upstream_pools, routing_index, pool)
        };

        let header_lookup = |name: &str| {
            if name.eq_ignore_ascii_case("x-user-id") {
                Some("alice".to_string())
            } else {
                None
            }
        };

        let first = super::QUICListener::resolve_backend(
            "GET",
            "/api/items",
            None,
            None,
            &upstream_pools,
            &routing_index,
            Some(&header_lookup),
        )
        .expect("first resolve");
        let second = super::QUICListener::resolve_backend(
            "GET",
            "/api/items",
            None,
            None,
            &upstream_pools,
            &routing_index,
            Some(&header_lookup),
        )
        .expect("second resolve");

        assert_eq!(
            first.backend_addr, second.backend_addr,
            "consistent-hash should remain stable when configured header key is constant"
        );
    }

    #[test]
    fn active_health_check_classification_matches_shared_policy() {
        assert!(matches!(
            classify_active_health_check_response(StatusCode::MOVED_PERMANENTLY),
            crate::HealthClassification::Success
        ));
        assert!(matches!(
            classify_active_health_check_response(StatusCode::BAD_REQUEST),
            crate::HealthClassification::Neutral
        ));
        assert!(matches!(
            classify_active_health_check_response(StatusCode::BAD_GATEWAY),
            crate::HealthClassification::Failure
        ));
    }

    #[test]
    fn bootstrap_connection_header_tokens_are_parsed_case_insensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive, X-Secret"),
        );
        headers.append(
            http::header::CONNECTION,
            HeaderValue::from_static("x-another"),
        );

        let tokens = connection_header_tokens(&headers);
        assert!(tokens.contains("keep-alive"));
        assert!(tokens.contains("x-secret"));
        assert!(tokens.contains("x-another"));
    }

    #[test]
    fn bootstrap_header_filter_strips_connection_nominated_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-secret"),
        );
        let tokens = connection_header_tokens(&headers);

        let header = http::HeaderName::from_static("x-secret");
        assert!(should_strip_bootstrap_request_header(&header, &tokens));
    }

    #[test]
    fn bootstrap_header_filter_keeps_non_nominated_custom_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
        let tokens = connection_header_tokens(&headers);

        let header = http::HeaderName::from_static("x-custom-keep");
        assert!(!should_strip_bootstrap_request_header(&header, &tokens));
    }

    #[test]
    fn h3_response_filter_strips_te_and_trailer() {
        let tokens = HashSet::new();
        assert!(should_strip_h3_response_header(&http::header::TE, &tokens));
        assert!(should_strip_h3_response_header(
            &http::header::TRAILER,
            &tokens
        ));
    }

    #[test]
    fn h3_trailer_collection_preserves_end_to_end_trailers() {
        let mut trailers = HeaderMap::new();
        trailers.insert(
            http::HeaderName::from_static("grpc-status"),
            HeaderValue::from_static("0"),
        );
        trailers.insert(
            http::HeaderName::from_static("grpc-message"),
            HeaderValue::from_static("ok"),
        );
        let collected = collect_h3_trailers(&trailers);
        assert_eq!(collected.len(), 2);
        assert!(
            collected
                .iter()
                .any(|(k, v)| k.as_slice() == b"grpc-status" && v.as_slice() == b"0")
        );
        assert!(
            collected
                .iter()
                .any(|(k, v)| k.as_slice() == b"grpc-message" && v.as_slice() == b"ok")
        );
    }

    #[test]
    fn h3_trailer_collection_strips_hop_by_hop_and_content_length() {
        let mut trailers = HeaderMap::new();
        trailers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_static("123"),
        );
        trailers.insert(http::header::TE, HeaderValue::from_static("trailers"));
        trailers.insert(http::header::TRAILER, HeaderValue::from_static("x-next"));
        trailers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("x-hop-token"),
        );
        trailers.insert(
            http::HeaderName::from_static("x-hop-token"),
            HeaderValue::from_static("secret"),
        );
        trailers.insert(
            http::HeaderName::from_static("grpc-status"),
            HeaderValue::from_static("0"),
        );
        let collected = collect_h3_trailers(&trailers);
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].0.as_slice(), b"grpc-status");
        assert_eq!(collected[0].1.as_slice(), b"0");
    }

    #[test]
    fn h3_response_filter_strips_connection_nominated_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-internal-hop"),
        );
        let tokens = connection_header_tokens(&headers);
        let nominated = http::HeaderName::from_static("x-internal-hop");
        assert!(should_strip_h3_response_header(&nominated, &tokens));
    }

    #[test]
    fn bootstrap_response_filter_strips_standard_hop_by_hop_headers() {
        let tokens = HashSet::new();
        assert!(should_strip_bootstrap_response_header(
            &http::header::CONNECTION,
            &tokens
        ));
        assert!(should_strip_bootstrap_response_header(
            &http::header::TE,
            &tokens
        ));
        assert!(should_strip_bootstrap_response_header(
            &http::header::TRAILER,
            &tokens
        ));
        assert!(should_strip_bootstrap_response_header(
            &http::header::TRANSFER_ENCODING,
            &tokens
        ));
        assert!(should_strip_bootstrap_response_header(
            &http::header::UPGRADE,
            &tokens
        ));
        assert!(should_strip_bootstrap_response_header(
            &http::header::PROXY_AUTHENTICATE,
            &tokens
        ));
        assert!(should_strip_bootstrap_response_header(
            &http::header::PROXY_AUTHORIZATION,
            &tokens
        ));
        let alt_svc = http::HeaderName::from_static("alt-svc");
        assert!(should_strip_bootstrap_response_header(&alt_svc, &tokens));
        let keep_alive = http::HeaderName::from_static("keep-alive");
        assert!(should_strip_bootstrap_response_header(&keep_alive, &tokens));
    }

    #[test]
    fn bootstrap_response_filter_strips_connection_nominated_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("x-hop-token, x-alt"),
        );
        let tokens = connection_header_tokens(&headers);
        let nominated = http::HeaderName::from_static("x-hop-token");
        assert!(should_strip_bootstrap_response_header(&nominated, &tokens));
    }

    #[test]
    fn bootstrap_response_filter_keeps_end_to_end_headers() {
        let tokens = HashSet::new();
        assert!(!should_strip_bootstrap_response_header(
            &http::header::CACHE_CONTROL,
            &tokens
        ));
    }

    #[test]
    fn response_size_cap_enforced_as_running_total() {
        let mut received = 0usize;
        assert!(!response_size_exceeded_after_chunk(&mut received, 4, 10));
        assert_eq!(received, 4);
        assert!(!response_size_exceeded_after_chunk(&mut received, 6, 10));
        assert_eq!(received, 10);
        assert!(response_size_exceeded_after_chunk(&mut received, 1, 10));
        assert_eq!(received, 11);
    }

    #[test]
    fn connect_tunnel_response_detected_only_for_success_status() {
        assert!(is_connect_tunnel_response("CONNECT", StatusCode::OK));
        assert!(is_connect_tunnel_response(
            "connect",
            StatusCode::NO_CONTENT
        ));
        assert!(!is_connect_tunnel_response(
            "CONNECT",
            StatusCode::BAD_GATEWAY
        ));
        assert!(!is_connect_tunnel_response("GET", StatusCode::OK));
    }

    #[test]
    fn bodyless_request_mode_only_applies_to_empty_get_and_head() {
        assert!(is_bodyless_request_mode("GET", None));
        assert!(is_bodyless_request_mode("HEAD", Some(0)));
        assert!(!is_bodyless_request_mode("GET", Some(1)));
        assert!(!is_bodyless_request_mode("POST", Some(0)));
        assert!(!is_bodyless_request_mode("HEAD", Some(1)));
    }

    #[test]
    fn connect_can_poll_upstream_before_request_fin() {
        let (_tx, rx) = oneshot::channel::<crate::UpstreamResult>();
        let mut req = make_envelope(StreamPhase::ReceivingRequest);
        req.method = "CONNECT".to_string();
        req.request_fin_received = false;
        req.upstream_result_rx = Some(rx);
        assert!(can_poll_upstream_result(&req));
    }

    #[test]
    fn non_connect_requires_request_completion_before_upstream_poll() {
        let (_tx, rx) = oneshot::channel::<crate::UpstreamResult>();
        let mut req = make_envelope(StreamPhase::AwaitingUpstream);
        req.method = "GET".to_string();
        req.request_fin_received = false;
        req.upstream_result_rx = Some(rx);
        assert!(!can_poll_upstream_result(&req));

        req.request_fin_received = true;
        assert!(can_poll_upstream_result(&req));
    }

    #[test]
    fn prefix_match_on_alias_resolves_to_primary_connection() {
        let primary = cid(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let alias = cid(&[9, 10, 11, 12, 13, 14, 15, 16]);

        let mut connections: HashMap<Arc<[u8]>, ()> = HashMap::new();
        connections.insert(Arc::clone(&primary), ());

        let mut cid_routes = HashMap::new();
        cid_routes.insert(Arc::clone(&alias), Arc::clone(&primary));

        let mut cid_radix = CidRadix::new();
        cid_radix.insert(Arc::clone(&alias));

        let mut dcid = alias.as_ref().to_vec();
        dcid.extend_from_slice(&[0xAA, 0xBB]);

        let resolved =
            resolve_primary_from_radix_prefix(&dcid, &connections, &mut cid_routes, &mut cid_radix)
                .expect("prefix lookup should resolve to active primary");

        assert_eq!(resolved.as_ref(), primary.as_ref());
        assert!(
            cid_routes.contains_key(alias.as_ref()),
            "live alias should remain mapped to active primary"
        );
        assert!(
            cid_radix.longest_prefix_match(&dcid).is_some(),
            "live alias should remain indexed in radix"
        );
    }

    #[test]
    fn stale_alias_prefix_match_is_cleaned_up() {
        let primary = cid(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let alias = cid(&[9, 10, 11, 12, 13, 14, 15, 16]);

        let connections: HashMap<Arc<[u8]>, ()> = HashMap::new();

        let mut cid_routes = HashMap::new();
        cid_routes.insert(Arc::clone(&alias), Arc::clone(&primary));

        let mut cid_radix = CidRadix::new();
        cid_radix.insert(Arc::clone(&alias));

        let mut dcid = alias.as_ref().to_vec();
        dcid.extend_from_slice(&[0xAA, 0xBB]);

        let resolved =
            resolve_primary_from_radix_prefix(&dcid, &connections, &mut cid_routes, &mut cid_radix);
        assert!(resolved.is_none(), "stale alias must not resolve");
        assert!(
            !cid_routes.contains_key(alias.as_ref()),
            "stale alias mapping should be removed"
        );
        assert!(
            cid_radix.longest_prefix_match(alias.as_ref()).is_none(),
            "stale alias should be removed from radix"
        );
    }

    // -----------------------------------------------------------------------
    // TokenBucket unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn token_bucket_allows_up_to_burst_immediately() {
        let mut tb = TokenBucket::new(100, 5);
        // Bucket starts full; first 5 tokens should all succeed.
        for i in 0..5 {
            assert!(
                tb.try_consume(),
                "token {} should be available (burst=5)",
                i
            );
        }
        // 6th token must fail — bucket is empty.
        assert!(
            !tb.try_consume(),
            "6th token must be denied when burst exhausted"
        );
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let mut tb = TokenBucket::new(10, 2); // 10 tokens/sec = 1 token per 100ms
        // Drain the bucket.
        assert!(tb.try_consume());
        assert!(tb.try_consume());
        assert!(!tb.try_consume());

        // Sleep slightly longer than one refill interval (100ms).
        std::thread::sleep(std::time::Duration::from_millis(120));

        // At least one token must have been refilled.
        assert!(
            tb.try_consume(),
            "bucket should have refilled at least one token after sleep"
        );
    }

    #[test]
    fn token_bucket_rate_zero_clamps_to_one() {
        // rate=0 is clamped to 1; burst=0 is clamped to 1.
        let mut tb = TokenBucket::new(0, 0);
        // Starts with 1 token (burst=1).
        assert!(
            tb.try_consume(),
            "first token should succeed with clamped burst=1"
        );
        assert!(!tb.try_consume(), "second token must fail when burst=1");
    }

    #[test]
    fn token_bucket_never_exceeds_burst() {
        // With rate=1/s a burst of 3 should yield exactly 3 tokens on a fresh
        // bucket, then nothing more (refill is 1ns per second — negligible in a
        // tight loop running for microseconds).
        let burst = 3u32;
        let mut tb = TokenBucket::new(1, burst); // 1 token/sec → ~1ns per token
        let mut consumed = 0;
        for _ in 0..(burst + 10) {
            if tb.try_consume() {
                consumed += 1;
            }
        }
        assert_eq!(
            consumed, burst as usize,
            "fresh bucket must yield exactly burst={} tokens in a tight loop, got {}",
            burst, consumed
        );
    }

    // -----------------------------------------------------------------------
    // purge_connection_routes / idle-timeout cleanup regression tests
    // -----------------------------------------------------------------------

    fn peer(port: u16) -> SocketAddr {
        format!("127.0.0.1:{}", port).parse().unwrap()
    }

    fn populated_routing_maps(
        primary: &Arc<[u8]>,
        aliases: &[Arc<[u8]>],
        addr: SocketAddr,
    ) -> RoutingMaps {
        let mut cid_routes: HashMap<Arc<[u8]>, Arc<[u8]>> = HashMap::new();
        let mut cid_radix = CidRadix::new();
        let mut peer_routes: HashMap<SocketAddr, Arc<[u8]>> = HashMap::new();

        cid_radix.insert(Arc::clone(primary));
        for alias in aliases {
            cid_routes.insert(Arc::clone(alias), Arc::clone(primary));
            cid_radix.insert(Arc::clone(alias));
        }
        peer_routes.insert(addr, Arc::clone(primary));

        (cid_routes, cid_radix, peer_routes)
    }

    #[test]
    fn purge_removes_primary_radix_entry() {
        let primary = cid(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let addr = peer(4433);
        let (mut cid_routes, mut cid_radix, mut peer_routes) =
            populated_routing_maps(&primary, &[], addr);

        purge_connection_routes(
            &mut cid_routes,
            &mut cid_radix,
            &mut peer_routes,
            &primary,
            &HashSet::new(),
            &addr,
        );

        assert!(
            cid_radix.longest_prefix_match(primary.as_ref()).is_none(),
            "primary SCID must be removed from radix after cleanup"
        );
        assert!(
            !peer_routes.contains_key(&addr),
            "peer_routes entry must be removed after cleanup"
        );
    }

    #[test]
    fn purge_removes_all_alias_entries() {
        let primary = cid(&[0xAA; 8]);
        let alias1 = cid(&[0xBB; 8]);
        let alias2 = cid(&[0xCC; 8]);
        let addr = peer(4434);

        let aliases = [Arc::clone(&alias1), Arc::clone(&alias2)];
        let (mut cid_routes, mut cid_radix, mut peer_routes) =
            populated_routing_maps(&primary, &aliases, addr);

        let routing_scids: HashSet<Arc<[u8]>> = aliases.iter().cloned().collect();
        purge_connection_routes(
            &mut cid_routes,
            &mut cid_radix,
            &mut peer_routes,
            &primary,
            &routing_scids,
            &addr,
        );

        assert!(
            !cid_routes.contains_key(alias1.as_ref()),
            "alias1 must be removed from cid_routes"
        );
        assert!(
            !cid_routes.contains_key(alias2.as_ref()),
            "alias2 must be removed from cid_routes"
        );
        assert!(
            cid_radix.longest_prefix_match(alias1.as_ref()).is_none(),
            "alias1 must be removed from radix"
        );
        assert!(
            cid_radix.longest_prefix_match(alias2.as_ref()).is_none(),
            "alias2 must be removed from radix"
        );
        assert!(
            !peer_routes.contains_key(&addr),
            "peer_routes entry must be removed"
        );
    }

    #[test]
    fn repeated_purge_churn_leaves_no_stale_entries() {
        // Simulate repeated connect/timeout/disconnect cycles on distinct
        // connections to verify no entries from prior connections bleed
        // across cycles.
        let mut cid_routes: HashMap<Arc<[u8]>, Arc<[u8]>> = HashMap::new();
        let mut cid_radix = CidRadix::new();
        let mut peer_routes: HashMap<SocketAddr, Arc<[u8]>> = HashMap::new();

        for i in 0u8..20 {
            let primary = cid(&[i, i, i, i, i, i, i, i]);
            let alias = cid(&[
                i | 0x80,
                i | 0x80,
                i | 0x80,
                i | 0x80,
                i | 0x80,
                i | 0x80,
                i | 0x80,
                i | 0x80,
            ]);
            let addr = peer(5000 + u16::from(i));

            // Register
            cid_radix.insert(Arc::clone(&primary));
            cid_radix.insert(Arc::clone(&alias));
            cid_routes.insert(Arc::clone(&alias), Arc::clone(&primary));
            peer_routes.insert(addr, Arc::clone(&primary));

            // Tear down
            let routing_scids: HashSet<Arc<[u8]>> = [Arc::clone(&alias)].into_iter().collect();
            purge_connection_routes(
                &mut cid_routes,
                &mut cid_radix,
                &mut peer_routes,
                &primary,
                &routing_scids,
                &addr,
            );
        }

        assert!(
            cid_routes.is_empty(),
            "cid_routes must be empty after all connections torn down"
        );
        assert!(
            peer_routes.is_empty(),
            "peer_routes must be empty after all connections torn down"
        );
    }

    #[test]
    fn purge_is_idempotent() {
        // Calling purge twice for the same connection must not panic or leave
        // phantom entries.
        let primary = cid(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);
        let alias = cid(&[0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81]);
        let addr = peer(4440);

        let (mut cid_routes, mut cid_radix, mut peer_routes) =
            populated_routing_maps(&primary, &[Arc::clone(&alias)], addr);

        let routing_scids: HashSet<Arc<[u8]>> = [Arc::clone(&alias)].into_iter().collect();

        for _ in 0..2 {
            purge_connection_routes(
                &mut cid_routes,
                &mut cid_radix,
                &mut peer_routes,
                &primary,
                &routing_scids,
                &addr,
            );
        }

        assert!(
            cid_routes.is_empty(),
            "cid_routes must be empty after double purge"
        );
        assert!(
            peer_routes.is_empty(),
            "peer_routes must be empty after double purge"
        );
    }

    // -----------------------------------------------------------------------
    // sweep_closed_connections churn tests
    //
    // These tests simulate the handle_timeouts removal sweep end-to-end:
    // connections are registered in all routing maps, marked as timed-out
    // (placed in to_remove), and swept via sweep_closed_connections.  After
    // each cycle the invariant is that no stale entries remain in any map.
    // -----------------------------------------------------------------------

    /// Minimal stand-in for QuicConnection — holds only the routing fields
    /// that sweep_closed_connections needs.
    struct StubConn {
        primary_scid: Arc<[u8]>,
        routing_scids: HashSet<Arc<[u8]>>,
        peer_address: SocketAddr,
    }

    fn stub_routes(c: &StubConn) -> ConnectionRoutes {
        ConnectionRoutes {
            primary_scid: Arc::clone(&c.primary_scid),
            routing_scids: c.routing_scids.clone(),
            peer_address: c.peer_address,
        }
    }

    fn register_stub(
        conn: &StubConn,
        cid_routes: &mut HashMap<Arc<[u8]>, Arc<[u8]>>,
        cid_radix: &mut CidRadix,
        peer_routes: &mut HashMap<SocketAddr, Arc<[u8]>>,
    ) {
        cid_radix.insert(Arc::clone(&conn.primary_scid));
        for alias in &conn.routing_scids {
            if alias.as_ref() != conn.primary_scid.as_ref() {
                cid_routes.insert(Arc::clone(alias), Arc::clone(&conn.primary_scid));
                cid_radix.insert(Arc::clone(alias));
            }
        }
        peer_routes.insert(conn.peer_address, Arc::clone(&conn.primary_scid));
    }

    fn assert_maps_empty(
        label: &str,
        connections: &HashMap<Arc<[u8]>, StubConn>,
        cid_routes: &HashMap<Arc<[u8]>, Arc<[u8]>>,
        peer_routes: &HashMap<SocketAddr, Arc<[u8]>>,
    ) {
        assert!(
            connections.is_empty(),
            "{}: connections must be empty",
            label
        );
        assert!(cid_routes.is_empty(), "{}: cid_routes must be empty", label);
        assert!(
            peer_routes.is_empty(),
            "{}: peer_routes must be empty",
            label
        );
    }

    #[test]
    fn sweep_removes_timed_out_connection_and_all_routes() {
        let primary = cid(&[0x01; 8]);
        let alias = cid(&[0x02; 8]);
        let addr = peer(6000);

        let conn = StubConn {
            primary_scid: Arc::clone(&primary),
            routing_scids: [Arc::clone(&primary), Arc::clone(&alias)]
                .into_iter()
                .collect(),
            peer_address: addr,
        };

        let mut connections: HashMap<Arc<[u8]>, StubConn> = HashMap::new();
        let mut cid_routes = HashMap::new();
        let mut cid_radix = CidRadix::new();
        let mut peer_routes = HashMap::new();

        register_stub(&conn, &mut cid_routes, &mut cid_radix, &mut peer_routes);
        connections.insert(Arc::clone(&primary), conn);

        sweep_closed_connections(
            &mut connections,
            &mut cid_routes,
            &mut cid_radix,
            &mut peer_routes,
            vec![Arc::clone(&primary)],
            stub_routes,
        );

        assert_maps_empty(
            "after single sweep",
            &connections,
            &cid_routes,
            &peer_routes,
        );
        assert!(
            cid_radix.longest_prefix_match(primary.as_ref()).is_none(),
            "primary must be removed from radix"
        );
        assert!(
            cid_radix.longest_prefix_match(alias.as_ref()).is_none(),
            "alias must be removed from radix"
        );
    }

    #[test]
    fn sweep_repeated_timeout_churn_leaves_no_stale_entries() {
        // Simulate N rounds of: connect → timeout → sweep.  After every round
        // all four routing maps must be fully empty — no entries from prior
        // connections bleed into subsequent rounds.
        let rounds = 30usize;

        let mut connections: HashMap<Arc<[u8]>, StubConn> = HashMap::new();
        let mut cid_routes: HashMap<Arc<[u8]>, Arc<[u8]>> = HashMap::new();
        let mut cid_radix = CidRadix::new();
        let mut peer_routes: HashMap<SocketAddr, Arc<[u8]>> = HashMap::new();

        for i in 0..rounds {
            let b = i as u8;
            let primary = cid(&[b, b, b, b, b, b, b, b]);
            let alias1 = cid(&[
                b | 0x80,
                b | 0x80,
                b | 0x80,
                b | 0x80,
                b | 0x80,
                b | 0x80,
                b | 0x80,
                b | 0x80,
            ]);
            let addr = peer(7000 + i as u16);

            let conn = StubConn {
                primary_scid: Arc::clone(&primary),
                routing_scids: [Arc::clone(&primary), Arc::clone(&alias1)]
                    .into_iter()
                    .collect(),
                peer_address: addr,
            };

            register_stub(&conn, &mut cid_routes, &mut cid_radix, &mut peer_routes);
            connections.insert(Arc::clone(&primary), conn);

            // Simulate handle_timeouts detecting this connection as closed.
            sweep_closed_connections(
                &mut connections,
                &mut cid_routes,
                &mut cid_radix,
                &mut peer_routes,
                vec![Arc::clone(&primary)],
                stub_routes,
            );

            assert_maps_empty(
                &format!("round {}", i),
                &connections,
                &cid_routes,
                &peer_routes,
            );
        }
    }

    #[test]
    fn sweep_partial_batch_clears_only_removed_entries() {
        // Two connections registered; only one timed out.  After sweep the
        // surviving connection's entries must remain intact.
        let p1 = cid(&[0xA1; 8]);
        let p2 = cid(&[0xB1; 8]);
        let addr1 = peer(8001);
        let addr2 = peer(8002);

        let conn1 = StubConn {
            primary_scid: Arc::clone(&p1),
            routing_scids: [Arc::clone(&p1)].into_iter().collect(),
            peer_address: addr1,
        };
        let conn2 = StubConn {
            primary_scid: Arc::clone(&p2),
            routing_scids: [Arc::clone(&p2)].into_iter().collect(),
            peer_address: addr2,
        };

        let mut connections: HashMap<Arc<[u8]>, StubConn> = HashMap::new();
        let mut cid_routes = HashMap::new();
        let mut cid_radix = CidRadix::new();
        let mut peer_routes = HashMap::new();

        register_stub(&conn1, &mut cid_routes, &mut cid_radix, &mut peer_routes);
        register_stub(&conn2, &mut cid_routes, &mut cid_radix, &mut peer_routes);
        connections.insert(Arc::clone(&p1), conn1);
        connections.insert(Arc::clone(&p2), conn2);

        // Only p1 times out.
        sweep_closed_connections(
            &mut connections,
            &mut cid_routes,
            &mut cid_radix,
            &mut peer_routes,
            vec![Arc::clone(&p1)],
            stub_routes,
        );

        assert!(
            !connections.contains_key(p1.as_ref()),
            "timed-out connection must be removed"
        );
        assert!(
            connections.contains_key(p2.as_ref()),
            "surviving connection must remain in connections"
        );
        assert!(
            peer_routes.contains_key(&addr2),
            "surviving connection peer_route must remain"
        );
        assert!(
            !peer_routes.contains_key(&addr1),
            "timed-out connection peer_route must be removed"
        );
        assert!(
            cid_radix.longest_prefix_match(p2.as_ref()).is_some(),
            "surviving connection must remain in radix"
        );
        assert!(
            cid_radix.longest_prefix_match(p1.as_ref()).is_none(),
            "timed-out connection must be removed from radix"
        );
    }

    // -----------------------------------------------------------------------
    // abort_stream / stream teardown path tests (4.2)
    //
    // These tests exercise the three teardown paths defined in the
    // connection-lifecycle spec:
    //   (A) client reset before upstream response  (ReceivingRequest /
    //       AwaitingUpstream phase)
    //   (B) client reset during upstream body streaming (SendingResponse)
    //   (C) upstream timeout / error
    //
    // Each test asserts that abort_stream releases all held resources
    // deterministically: permits are dropped, channels are closed, and
    // pending chunks are discarded.
    // -----------------------------------------------------------------------

    use crate::resilience::{AdaptiveAdmission, RouteQueueLimiter};
    use crate::{RequestEnvelope, StreamPhase};
    use std::time::Instant;
    use tokio::sync::{Semaphore, mpsc, oneshot};

    fn make_envelope(phase: StreamPhase) -> RequestEnvelope {
        RequestEnvelope {
            request_id: REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
            trace_id: None,
            span_id: None,
            traceparent: None,
            trace_span: None,
            method: "GET".into(),
            path: "/".into(),
            authority: None,
            body_tx: None,
            body_buf: std::collections::VecDeque::new(),
            body_buf_bytes: 0,
            body_bytes_received: 0,
            last_body_activity: Instant::now(),
            backend_addr: None,
            backend_index: None,
            upstream_name: None,
            route_reason: None,
            route_path_len: None,
            route_host_specific: None,
            backend_lb: None,
            upstream_pool: None,
            routing_transparency_enabled: false,
            routing_transparency_include_reason: false,
            response_status: None,
            backend_request_finished: false,
            global_inflight_permit: None,
            upstream_inflight_permit: None,
            adaptive_admission_permit: None,
            route_queue_permit: None,
            start: Instant::now(),
            total_request_deadline: Instant::now() + std::time::Duration::from_secs(30),
            bodyless_mode: false,
            retry_count: 0,
            error_kind: None,
            phase,
            request_fin_received: false,
            upstream_result_rx: None,
            response_chunk_rx: None,
            response_headers_sent: false,
            pending_chunk: None,
        }
    }

    /// Path A: client reset before upstream response (ReceivingRequest phase).
    /// Verifies permits are released and body_tx is dropped.
    #[test]
    fn abort_stream_receiving_request_releases_permits() {
        let metrics = crate::Metrics::default();
        let global_sem = Arc::new(Semaphore::new(1));
        let upstream_sem = Arc::new(Semaphore::new(1));
        let adaptive = Arc::new(AdaptiveAdmission::new(false, 1, 100, 1, 1, 1000));
        let route_limiter = Arc::new(RouteQueueLimiter::new(100, 1000, Default::default()));

        let global_permit = global_sem.clone().try_acquire_owned().unwrap();
        let upstream_permit = upstream_sem.clone().try_acquire_owned().unwrap();
        let adaptive_permit = adaptive.try_acquire().unwrap();
        let route_permit = route_limiter.try_acquire("test").unwrap();

        let (body_tx, body_rx) = mpsc::channel::<bytes::Bytes>(4);

        let mut req = make_envelope(StreamPhase::ReceivingRequest);
        req.global_inflight_permit = Some(global_permit);
        req.upstream_inflight_permit = Some(upstream_permit);
        req.adaptive_admission_permit = Some(adaptive_permit);
        req.route_queue_permit = Some(route_permit);
        req.body_tx = Some(body_tx);

        let phase = abort_stream(&mut req, &metrics);

        assert_eq!(phase, StreamPhase::ReceivingRequest);

        // Permits released: semaphores should be available again.
        assert_eq!(
            global_sem.available_permits(),
            1,
            "global semaphore must be freed"
        );
        assert_eq!(
            upstream_sem.available_permits(),
            1,
            "upstream semaphore must be freed"
        );

        // body_tx dropped: body_rx should see the channel as disconnected.
        drop(body_rx); // safe to drop receiver — just checking channel is closed

        // All option fields cleared.
        assert!(req.global_inflight_permit.is_none());
        assert!(req.upstream_inflight_permit.is_none());
        assert!(req.adaptive_admission_permit.is_none());
        assert!(req.route_queue_permit.is_none());
        assert!(req.body_tx.is_none());
    }

    /// Path A (variant): client reset while awaiting upstream response.
    /// Dropping upstream_result_rx cancels the oneshot — the upstream task's
    /// send will return Err and it will exit.
    #[test]
    fn abort_stream_awaiting_upstream_cancels_oneshot() {
        let metrics = crate::Metrics::default();
        let (result_tx, result_rx) = oneshot::channel::<crate::UpstreamResult>();

        let mut req = make_envelope(StreamPhase::AwaitingUpstream);
        req.upstream_result_rx = Some(result_rx);

        let phase = abort_stream(&mut req, &metrics);

        assert_eq!(phase, StreamPhase::AwaitingUpstream);
        assert!(
            req.upstream_result_rx.is_none(),
            "oneshot receiver must be cleared"
        );

        // Sending on the now-orphaned sender should return Err (closed).
        let send_result = result_tx.send(crate::UpstreamResult {
            forward: Err(spooky_errors::ProxyError::Transport("test".into())),
            hedge: crate::HedgeTelemetry::default(),
            retry_count: 0,
            retry_attempt_reason: None,
            retry_denial_reason: None,
        });
        assert!(
            send_result.is_err(),
            "upstream task send must fail after receiver dropped"
        );
    }

    /// Path B: client reset during body streaming (SendingResponse phase).
    /// Dropping response_chunk_rx causes the body-pump task's next send to
    /// return Err, making the task exit promptly.
    #[test]
    fn abort_stream_sending_response_closes_chunk_channel() {
        let metrics = crate::Metrics::default();
        let (chunk_tx, chunk_rx) = mpsc::channel::<crate::ResponseChunk>(4);

        let mut req = make_envelope(StreamPhase::SendingResponse);
        req.response_chunk_rx = Some(chunk_rx);
        req.pending_chunk = Some(crate::ResponseChunk::End);

        let phase = abort_stream(&mut req, &metrics);

        assert_eq!(phase, StreamPhase::SendingResponse);
        assert!(
            req.response_chunk_rx.is_none(),
            "chunk receiver must be cleared"
        );
        assert!(
            req.pending_chunk.is_none(),
            "pending chunk must be discarded"
        );

        // The body-pump task's sender should observe a closed channel.
        let send_result = chunk_tx.try_send(crate::ResponseChunk::End);
        assert!(
            send_result.is_err(),
            "body-pump task send must fail after receiver dropped"
        );
    }

    /// Path C: upstream timeout / error tears down all resources regardless
    /// of which fields are populated.
    #[test]
    fn abort_stream_upstream_error_releases_all_resources() {
        let metrics = crate::Metrics::default();
        let global_sem = Arc::new(Semaphore::new(2));
        let upstream_sem = Arc::new(Semaphore::new(2));

        let global_permit = global_sem.clone().try_acquire_owned().unwrap();
        let upstream_permit = upstream_sem.clone().try_acquire_owned().unwrap();

        let (_result_tx, result_rx) = oneshot::channel::<crate::UpstreamResult>();
        let (chunk_tx, chunk_rx) = mpsc::channel::<crate::ResponseChunk>(4);

        let mut req = make_envelope(StreamPhase::SendingResponse);
        req.global_inflight_permit = Some(global_permit);
        req.upstream_inflight_permit = Some(upstream_permit);
        req.upstream_result_rx = Some(result_rx);
        req.response_chunk_rx = Some(chunk_rx);
        req.pending_chunk = Some(crate::ResponseChunk::End);

        let phase = abort_stream(&mut req, &metrics);

        assert_eq!(phase, StreamPhase::SendingResponse);
        assert_eq!(
            global_sem.available_permits(),
            2,
            "global semaphore must be fully freed"
        );
        assert_eq!(
            upstream_sem.available_permits(),
            2,
            "upstream semaphore must be fully freed"
        );
        assert!(req.upstream_result_rx.is_none());
        assert!(req.response_chunk_rx.is_none());
        assert!(req.pending_chunk.is_none());

        // Body-pump task sender sees closed channel.
        assert!(chunk_tx.try_send(crate::ResponseChunk::End).is_err());
    }

    /// Verify abort_stream is idempotent: calling it twice must not panic or
    /// double-decrement any semaphore.
    #[test]
    fn abort_stream_is_idempotent() {
        let metrics = crate::Metrics::default();
        let global_sem = Arc::new(Semaphore::new(1));
        let permit = global_sem.clone().try_acquire_owned().unwrap();

        let mut req = make_envelope(StreamPhase::ReceivingRequest);
        req.global_inflight_permit = Some(permit);

        abort_stream(&mut req, &metrics);
        abort_stream(&mut req, &metrics); // second call must be a no-op

        assert_eq!(
            global_sem.available_permits(),
            1,
            "must not double-release permit"
        );
    }

    #[test]
    fn traceparent_parser_accepts_valid_value() {
        let parsed =
            super::parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
        assert!(parsed.is_some());
    }

    #[test]
    fn traceparent_parser_rejects_invalid_value() {
        let parsed = super::parse_traceparent("00-xyz-123-01");
        assert!(parsed.is_none());
    }

    #[test]
    fn inflight_micro_wait_acquires_when_permit_recovers() {
        let semaphore = Arc::new(Semaphore::new(1));
        let held = semaphore
            .clone()
            .try_acquire_owned()
            .expect("acquire initial permit");
        let semaphore_for_task = Arc::clone(&semaphore);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(2));
            drop(held);
        });

        let acquired = super::QUICListener::try_acquire_owned_with_micro_wait(
            semaphore_for_task,
            Duration::from_millis(10),
        );
        assert!(acquired.is_ok());
        let (_, waited) = acquired.expect("permit should be acquired");
        assert!(waited, "acquire should report that it waited");
    }

    #[test]
    fn inflight_micro_wait_times_out_without_permit() {
        let semaphore = Arc::new(Semaphore::new(1));
        let _held = semaphore
            .clone()
            .try_acquire_owned()
            .expect("acquire initial permit");

        let acquired = super::QUICListener::try_acquire_owned_with_micro_wait(
            Arc::clone(&semaphore),
            Duration::from_millis(1),
        );
        assert!(acquired.is_err());
    }
}
