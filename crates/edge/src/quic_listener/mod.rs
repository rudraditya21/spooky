use core::net::SocketAddr;
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

use boring::{
    pkey::{PKey, Private},
    ssl::{NameType, SelectCertError, SslContextBuilder, SslFiletype, SslMethod, SslVerifyMode},
    x509::X509,
};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    body::{Body, Frame, Incoming},
    client::conn::http1 as client_http1,
    upgrade,
};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use quiche::{Config, h3::NameValue};
use rand::RngCore;
use rustls::{
    RootCertStore, ServerConfig as RustlsServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni, WebPkiClientVerifier},
    sign::CertifiedKey,
};
use rustls_pki_types::pem::PemObject;
use serde_json::json;
use socket2::{Domain, Protocol, Socket, Type};
#[cfg(test)]
use spooky_bridge::response::should_strip_response_header;
use spooky_bridge::response::{
    ResponseBodyMode, ResponseBodyPolicy, ResponseNormalizationInput,
    ResponseNormalizationProtocol, ResponseProtocolConstraints, normalize_response_trailers,
    normalize_upstream_response,
};
use spooky_config::{
    backend_endpoint::{BackendEndpoint, BackendScheme},
    config::ClientAuth,
    runtime::{
        ListenerRuntimeConfig, RuntimeConfig, RuntimeListenerTls, RuntimeTlsIdentity,
        RuntimeBackendAddressKind, RuntimeUpstreamPolicy,
    },
};
use spooky_errors::{PoolError, ProxyError};
use spooky_lb::{health::HealthFailureReason, upstream_pool::UpstreamPool};
use spooky_transport::{
    h2_client::SharedDnsResolver,
    transport_pool::UpstreamTransportPool,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    runtime::Handle,
    sync::{Semaphore, mpsc, mpsc::error::TrySendError, oneshot},
};
#[cfg(test)]
use tokio_rustls::TlsAcceptor;
use tracing::{Instrument, info_span};

use crate::{
    ChannelBody, Metrics, OverloadShedReason, REQUEST_ID_COUNTER, RouteOutcome,
    cid_radix::CidRadix,
    constants::{
        DEFAULT_SCID_LEN_BYTES, MAX_DATAGRAM_SIZE_BYTES, MAX_UDP_PAYLOAD_BYTES, MIN_SCID_LEN_BYTES,
        REQUEST_CHUNK_BYTES_LIMIT, REQUEST_CHUNK_CHANNEL_CAPACITY, RESET_TOKEN_LEN_BYTES,
        RESPONSE_CHUNK_BYTES_LIMIT, RESPONSE_CHUNK_CHANNEL_CAPACITY,
        SCID_ROTATION_PACKET_THRESHOLD, UDP_READ_TIMEOUT_MS, scid_rotation_interval,
    },
    resilience::runtime::RuntimeResilience,
    routing::{decision::RouteDecisionReason, index::RouteIndex},
    runtime::{
        backend::{resolution::RuntimeBackendResolution, store::RuntimeBackendResolutionStore},
        bundle::{RuntimeBundle, RuntimeBundleHandle},
        connection::{
            guardrails::{
                BodyLimitKind, REQUEST_BODY_TOO_LARGE_BODY, RequestBodyGuardrailConfig,
                RequestBodyGuardrailDecision, RequestBodyGuardrailInput,
                ResponseBodyGuardrailConfig, ResponseBodyGuardrailInput,
                checked_request_body_ingress, checked_response_body_guardrails,
            },
            quic::{QuicConnection, QuicConnectionErrorSnapshot},
            request::RequestEnvelope,
            response::{ForwardResult, ForwardSuccess, ResponseChunk, UpstreamResult},
            stream::{StreamAdmissionState, StreamPhase, TunnelMode},
        },
        health::{HealthClassification, outcome_from_status},
        listener::QUICListener,
        shared_state::SharedRuntimeState,
        tasks::{RuntimeTaskRegistration, RuntimeTaskRegistry},
        tls::{
            inventory::{
                ListenerTlsInventory, RuntimeLoadedClientAuthCa, RuntimeLoadedTlsIdentity,
                RuntimeTlsCertificateMetadata,
            },
            store::{ListenerTlsReloadState, ListenerTlsReloadStore},
        },
    },
    watchdog::{config::WatchdogRuntimeConfig, coordinator::WatchdogCoordinator, time::now_millis},
};

mod admission;
mod backend_resolution;
mod bootstrap_tls;
mod connection;
mod control_api;
mod forwarding;
mod health_check;
mod metrics_endpoint;
mod runtime_endpoint;
mod tls_runtime;
mod token_bucket;
mod validation;

#[cfg(test)]
use bootstrap_tls::BootstrapStartupState;
use connection::resolve_primary_from_radix_prefix;
pub(crate) use connection::{ConnectionRoutes, purge_connection_routes, sweep_closed_connections};
use forwarding::{ForwardingExecutionCtx, ForwardingSharedCtx, StreamProgressConfig, abort_stream};
#[cfg(test)]
use health_check::classify_active_health_check_response;
pub(crate) use token_bucket::TokenBucket;
use validation::{
    RequestBufferError, extract_header_value, generated_span_id, generated_trace_id,
    parse_traceparent, validate_http_request, validate_request_headers,
};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

struct ListenerRuntimeSettings {
    backend_timeout: Duration,
    backend_body_idle_timeout: Duration,
    backend_body_total_timeout: Duration,
    client_body_idle_timeout: Duration,
    backend_total_request_timeout: Duration,
    inflight_acquire_wait: Duration,
    drain_timeout: Duration,
    max_active_connections: usize,
    max_streams_per_connection: usize,
    max_request_body_bytes: usize,
    max_response_body_bytes: usize,
    request_buffer_global_cap_bytes: usize,
    unknown_length_response_prebuffer_bytes: usize,
    new_connections_per_sec: u32,
    new_connections_burst: u32,
}

#[cfg(test)]
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

#[cfg(test)]
fn should_strip_h3_response_header(
    name: &http::header::HeaderName,
    connection_tokens: &HashSet<String>,
) -> bool {
    should_strip_response_header(
        name,
        connection_tokens,
        ResponseProtocolConstraints {
            protocol: ResponseNormalizationProtocol::Http3,
            strip_connection_headers: true,
            allow_trailers: true,
            preserve_upgrade: false,
        },
    )
}

fn collect_h3_trailers(trailers: &http::HeaderMap) -> Vec<(Vec<u8>, Vec<u8>)> {
    normalize_response_trailers(
        trailers,
        ResponseProtocolConstraints {
            protocol: ResponseNormalizationProtocol::Http3,
            strip_connection_headers: true,
            allow_trailers: true,
            preserve_upgrade: false,
        },
    )
    .into_iter()
    .map(|header| {
        (
            header.name.as_str().as_bytes().to_vec(),
            header.value.as_bytes().to_vec(),
        )
    })
    .collect()
}

#[cfg(test)]
fn should_strip_bootstrap_response_header(
    name: &http::header::HeaderName,
    connection_tokens: &HashSet<String>,
) -> bool {
    should_strip_response_header(
        name,
        connection_tokens,
        ResponseProtocolConstraints {
            protocol: ResponseNormalizationProtocol::Http1,
            strip_connection_headers: true,
            allow_trailers: false,
            preserve_upgrade: false,
        },
    )
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

fn is_tunnel_mode(tunnel_mode: TunnelMode) -> bool {
    tunnel_mode != TunnelMode::None
}

fn is_tunnel_response(tunnel_mode: TunnelMode, status: StatusCode) -> bool {
    is_tunnel_mode(tunnel_mode) && status.is_success()
}

#[cfg(test)]
fn is_connect_tunnel_response(method: &str, status: StatusCode) -> bool {
    is_connect_method(method) && status.is_success()
}

fn can_poll_upstream_result(req: &RequestEnvelope) -> bool {
    if req.admission_state != StreamAdmissionState::ReadyToForward {
        return false;
    }

    if is_tunnel_mode(req.tunnel_mode)
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

struct BootstrapStreamingBody {
    inner: Incoming,
    guardrails: Option<ResponseBodyGuardrailConfig>,
    declared_content_length: Option<usize>,
    bytes_seen: usize,
    prebuffered_bytes: usize,
    capped: bool,
    backend_accounting: Option<BootstrapBackendAccounting>,
}

struct BootstrapBackendAccounting {
    upstream_pool: Arc<RwLock<UpstreamPool>>,
    backend_index: usize,
    start: Instant,
    status: Option<u16>,
    finished: bool,
}

impl BootstrapStreamingBody {
    fn new(inner: Incoming) -> Self {
        Self {
            inner,
            guardrails: None,
            declared_content_length: None,
            bytes_seen: 0,
            prebuffered_bytes: 0,
            capped: false,
            backend_accounting: None,
        }
    }

    fn with_response_guardrails(
        inner: Incoming,
        max_body_bytes: usize,
        declared_content_length: Option<usize>,
        upstream_pool: Arc<RwLock<UpstreamPool>>,
        backend_index: usize,
        start: Instant,
        status: Option<u16>,
    ) -> Self {
        Self {
            inner,
            guardrails: Some(ResponseBodyGuardrailConfig {
                idle_timeout: Duration::MAX,
                total_timeout: Duration::MAX,
                max_body_bytes,
                unknown_length_prebuffer_bytes: max_body_bytes,
                chunk_bytes: usize::MAX,
            }),
            declared_content_length,
            bytes_seen: 0,
            prebuffered_bytes: 0,
            capped: false,
            backend_accounting: Some(BootstrapBackendAccounting {
                upstream_pool,
                backend_index,
                start,
                status,
                finished: false,
            }),
        }
    }

    fn finish_backend_accounting(&mut self) {
        if let Some(accounting) = self.backend_accounting.as_mut() {
            if accounting.finished {
                return;
            }
            crate::runtime::connection::outcome::finish_backend_request_accounting(
                crate::runtime::connection::outcome::BackendRequestFinishInput {
                    upstream_pool: Some(&accounting.upstream_pool),
                    backend_index: Some(accounting.backend_index),
                    elapsed: accounting.start.elapsed(),
                    status: accounting.status,
                },
            );
            accounting.finished = true;
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
                if let Some(guardrails) = self.guardrails
                    && let Some(data) = frame.data_ref()
                {
                    if let Ok(next_state) = checked_response_body_guardrails(
                        guardrails,
                        ResponseBodyGuardrailInput {
                            elapsed: Duration::ZERO,
                            idle_for: Duration::ZERO,
                            bytes_received: self.bytes_seen,
                            prebuffered_bytes: self.prebuffered_bytes,
                            next_chunk_bytes: data.len(),
                            declared_content_length: self.declared_content_length,
                            headers_emitted: true,
                            progressive_emission_allowed: true,
                            body_forwarding_enabled: true,
                            exempt_from_body_size_cap: false,
                        },
                    ) {
                        self.bytes_seen = next_state.next_state.bytes_received;
                        self.prebuffered_bytes = next_state.next_state.prebuffered_bytes;
                    } else {
                        self.capped = true;
                        self.finish_backend_accounting();
                        return Poll::Ready(None);
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(_))) => {
                self.finish_backend_accounting();
                Poll::Ready(None)
            }
            Poll::Ready(None) => {
                self.finish_backend_accounting();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for BootstrapStreamingBody {
    fn drop(&mut self) {
        self.finish_backend_accounting();
    }
}

fn boxed_full(body: Bytes) -> http_body_util::combinators::BoxBody<Bytes, Infallible> {
    Full::new(body).map_err(|never| match never {}).boxed()
}

impl QUICListener {
    fn listener_runtime_settings(config: &ListenerRuntimeConfig) -> ListenerRuntimeSettings {
        let transport_policy = &config.policies.transport;
        let timeout_policy = &config.policies.timeouts;
        ListenerRuntimeSettings {
            backend_timeout: timeout_policy.backend_request,
            backend_body_idle_timeout: timeout_policy.backend_body_idle,
            backend_body_total_timeout: timeout_policy.backend_body_total,
            client_body_idle_timeout: timeout_policy.client_body_idle,
            backend_total_request_timeout: timeout_policy.backend_total_request,
            inflight_acquire_wait: timeout_policy.inflight_acquire_wait,
            drain_timeout: timeout_policy.shutdown_drain,
            max_active_connections: transport_policy.connection_limits.max_active_connections.max(1),
            max_streams_per_connection: usize::try_from(
                transport_policy.quic_initial_max_streams_bidi,
            )
            .unwrap_or(usize::MAX)
            .max(1),
            max_request_body_bytes: transport_policy.max_request_body_bytes,
            max_response_body_bytes: transport_policy.max_response_body_bytes,
            request_buffer_global_cap_bytes: transport_policy.request_buffer_global_cap_bytes,
            unknown_length_response_prebuffer_bytes: transport_policy
                .unknown_length_response_prebuffer_bytes,
            new_connections_per_sec: transport_policy.new_connections_per_sec,
            new_connections_burst: transport_policy.new_connections_burst,
        }
    }

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

    fn record_backend_connect(
        metrics: &Metrics,
        backend: &str,
        hostname: &str,
        resolved_addr: StdSocketAddr,
    ) {
        metrics.record_backend_connect(backend, hostname, resolved_addr);
    }

    pub fn build_shared_state(config: &RuntimeConfig) -> Result<SharedRuntimeState, ProxyError> {
        let transport_policy = &config.policies.transport;
        let timeout_policy = &config.policies.timeouts;
        let worker_threads = transport_policy.worker_threads.max(1);
        let shard_count = transport_policy.packet_shards_per_worker.max(1);
        let active_worker_threads = if worker_threads > 1 && !transport_policy.reuseport {
            1
        } else {
            worker_threads
        };
        let worker_slots = active_worker_threads.saturating_mul(shard_count).max(1);
        let per_upstream_limit = transport_policy.connection_limits.per_upstream_inflight.max(1);
        let global_inflight_limit = transport_policy.connection_limits.global_inflight.max(1);
        info!(
            "Runtime performance concurrency worker_threads={} control_plane_threads={} packet_shards_per_worker={} reuseport={} pin_workers={}",
            worker_threads,
            transport_policy.control_plane_threads.max(1),
            shard_count,
            transport_policy.reuseport,
            transport_policy.pin_workers,
        );
        info!(
            "Runtime performance inflight_limits global_inflight_limit={} per_upstream_inflight_limit={} per_backend_inflight_limit={} max_active_connections={}",
            global_inflight_limit,
            per_upstream_limit,
            transport_policy.connection_limits.per_backend,
            transport_policy.connection_limits.max_active_connections,
        );
        info!(
            "Runtime performance upstream_timeouts backend_connect_timeout_ms={} backend_timeout_ms={} backend_body_idle_timeout_ms={} backend_body_total_timeout_ms={} backend_total_request_timeout_ms={}",
            timeout_policy.backend_connect.as_millis(),
            timeout_policy.backend_request.as_millis(),
            timeout_policy.backend_body_idle.as_millis(),
            timeout_policy.backend_body_total.as_millis(),
            timeout_policy.backend_total_request.as_millis(),
        );
        info!(
            "Runtime performance request_limits client_body_idle_timeout_ms={} max_request_body_bytes={} max_response_body_bytes={} request_buffer_global_cap_bytes={} unknown_length_response_prebuffer_bytes={}",
            timeout_policy.client_body_idle.as_millis(),
            transport_policy.max_request_body_bytes,
            transport_policy.max_response_body_bytes,
            transport_policy.request_buffer_global_cap_bytes,
            transport_policy.unknown_length_response_prebuffer_bytes,
        );
        info!(
            "Runtime performance transport_buffers udp_recv_buffer_bytes={} udp_send_buffer_bytes={} h2_pool_max_idle_per_backend={} h2_pool_idle_timeout_ms={}",
            transport_policy.udp_recv_buffer_bytes,
            transport_policy.udp_send_buffer_bytes,
            transport_policy.backend_connections.max_idle_per_backend,
            transport_policy.backend_connections.pool_idle_timeout.as_millis(),
        );

        let listener_runtime_configs = config
            .listener_runtime_configs()
            .into_iter()
            .map(|listener_config| (Self::listener_label(&listener_config), listener_config))
            .collect::<HashMap<_, _>>();
        let listener_tls_store = Arc::new(Self::build_listener_tls_reload_store(config)?);

        let mut backend_resolutions = Vec::new();
        let mut seen_backend_origins: HashMap<String, (String, String)> = HashMap::new();
        let mut backend_endpoints: HashMap<String, BackendEndpoint> = HashMap::new();
        let mut backend_health_checks = HashMap::new();
        for (upstream_name, upstream) in &config.upstreams {
            for backend in &upstream.backends {
                let endpoint = backend.endpoint.canonical.clone();
                let origin = backend.endpoint.origin.clone();
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
                let authority_host = backend.endpoint.authority_host.clone();
                let authority_port = backend.endpoint.authority_port;
                let resolution = if matches!(backend.endpoint.address_kind, RuntimeBackendAddressKind::IpLiteral) {
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
                let authority_kind = match backend.endpoint.address_kind {
                    RuntimeBackendAddressKind::IpLiteral => "ip_literal",
                    RuntimeBackendAddressKind::Hostname => "hostname",
                };
                debug!(
                    "Configured upstream TLS policy backend={} upstream={} verify_certificates={} strict_sni={} ca_file={:?} ca_dir={:?} authority_kind={}",
                    backend.backend.address,
                    upstream_name,
                    upstream.policy_set.transport.tls.verify_certificates,
                    upstream.policy_set.transport.tls.strict_sni,
                    upstream.policy_set.transport.tls.ca_file,
                    upstream.policy_set.transport.tls.ca_dir,
                    authority_kind
                );
                backend_endpoints.insert(backend.backend.address.clone(), endpoint);
                if let Some(health_check) = backend.health_check.clone() {
                    backend_health_checks.insert(backend.backend.address.clone(), health_check);
                }
            }
        }

        let mut route_labels = config.upstreams.keys().cloned().collect::<Vec<_>>();
        route_labels.push("unrouted".to_string());
        let routing_index = Arc::new(RouteIndex::from_runtime_upstreams(&config.upstreams));
        let metrics = Arc::new(Metrics::new(worker_slots, route_labels));
        let backend_dns_resolver = SharedDnsResolver::new();
        let backend_resolution_store =
            Arc::new(RuntimeBackendResolutionStore::new(backend_resolutions));
        let connect_metrics = Arc::clone(&metrics);
        let connect_observer: spooky_transport::h2_client::ConnectObserver = Arc::new(
            move |observation: spooky_transport::h2_client::ConnectObservation| {
                Self::record_backend_connect(
                    &connect_metrics,
                    &observation.backend,
                    &observation.hostname,
                    observation.resolved_addr,
                );
            },
        );
        let transport_pool = Arc::new(
            UpstreamTransportPool::from_runtime_upstreams(
                config.upstreams.values(),
                &transport_policy.backend_connections,
                backend_dns_resolver.clone(),
                Some(connect_observer),
            )
            .map_err(ProxyError::Tls)?,
        );
        let mut upstream_pools = HashMap::new();
        let mut upstream_inflight = HashMap::new();
        for (name, runtime_upstream) in &config.upstreams {
            let upstream_pool =
                UpstreamPool::from_runtime_upstream(runtime_upstream).map_err(|err| {
                    ProxyError::Transport(format!(
                        "failed to create upstream pool '{}': {}",
                        name, err
                    ))
                })?;
            upstream_pools.insert(name.clone(), Arc::new(RwLock::new(upstream_pool)));
            upstream_inflight.insert(name.clone(), Arc::new(Semaphore::new(per_upstream_limit)));
        }

        let mut effective_admission = config.policies.admission.clone();
        let default_route_cap_limit = per_upstream_limit.saturating_mul(2).max(1);
        if effective_admission.route_queue.default_cap > default_route_cap_limit {
            warn!(
                "resilience.route_queue.default_cap={} is above tuned limit {}; clamping for steadier timeout/admission behavior",
                effective_admission.route_queue.default_cap, default_route_cap_limit
            );
        }
        let global_route_cap_limit = global_inflight_limit.saturating_mul(2).max(1);
        if effective_admission.route_queue.global_cap > global_route_cap_limit {
            warn!(
                "resilience.route_queue.global_cap={} is above tuned limit {}; clamping for steadier timeout/admission behavior",
                effective_admission.route_queue.global_cap, global_route_cap_limit
            );
        }
        let backend_timeout_ms =
            u64::try_from(timeout_policy.backend_request.as_millis()).unwrap_or(u64::MAX);
        let tuned_high_latency = (backend_timeout_ms.saturating_mul(7) / 10).max(50);
        if effective_admission.adaptive_admission.high_latency
            > Duration::from_millis(tuned_high_latency)
        {
            warn!(
                "resilience.adaptive_admission.high_latency_ms={} is above tuned limit {}; clamping for faster overload reaction",
                effective_admission.adaptive_admission.high_latency.as_millis(),
                tuned_high_latency
            );
        }
        effective_admission = effective_admission.with_runtime_overrides(
            default_route_cap_limit,
            global_route_cap_limit,
            Duration::from_millis(tuned_high_latency),
        );
        let resilience = Arc::new(RuntimeResilience::from_policies(
            &effective_admission,
            &config.policies.rate_limits,
        ));
        let watchdog = Arc::new(WatchdogCoordinator::from_runtime_config(
            &WatchdogRuntimeConfig::from(&config.policies.admission.watchdog),
        ));
        for (listener_label, inventory) in listener_tls_store.snapshot() {
            Self::update_listener_tls_expiry_metrics(&metrics, &listener_label, &inventory);
        }

        Ok(SharedRuntimeState {
            listener_runtime_configs: Arc::new(listener_runtime_configs),
            listener_tls_store,
            transport_pool,
            backend_endpoints: Arc::new(backend_endpoints),
            backend_health_checks: Arc::new(backend_health_checks),
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
        log_config: spooky_config::config::Log,
        runtime_config: &RuntimeConfig,
    ) -> Result<RuntimeBundle, ProxyError> {
        let shared_state = Arc::new(Self::build_shared_state(runtime_config)?);
        Ok(RuntimeBundle {
            generation: 0,
            config_path,
            log_config,
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
                .policies
                .transport
                .worker_threads
                .max(1)
                .saturating_mul(config.policies.transport.packet_shards_per_worker.max(1))
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
            Arc::clone(&shared_state.backend_health_checks),
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
        let transport_policy = &config.policies.transport;
        let socket = Self::create_udp_socket(
            bind_addr,
            reuse_port,
            transport_policy.udp_recv_buffer_bytes,
            transport_policy.udp_send_buffer_bytes,
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
        let h3_config = Arc::new({
            let mut config = quiche::h3::Config::new().map_err(|err| {
                ProxyError::Transport(format!("failed to create h3 config: {err}"))
            })?;
            config.enable_extended_connect(true);
            config
        });
        let settings = Self::listener_runtime_settings(&config);
        let require_client_cert = Self::runtime_listener_tls(&config)?
            .client_auth
            .require_client_cert;
        let conn_rate_limiter = TokenBucket::new(
            settings.new_connections_per_sec,
            settings.new_connections_burst,
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
            drain_timeout: settings.drain_timeout,
            backend_timeout: settings.backend_timeout,
            backend_body_idle_timeout: settings.backend_body_idle_timeout,
            backend_body_total_timeout: settings.backend_body_total_timeout,
            client_body_idle_timeout: settings.client_body_idle_timeout,
            backend_total_request_timeout: settings.backend_total_request_timeout,
            inflight_acquire_wait: settings.inflight_acquire_wait,
            max_active_connections: settings.max_active_connections,
            max_streams_per_connection: settings.max_streams_per_connection,
            max_request_body_bytes: settings.max_request_body_bytes,
            max_response_body_bytes: settings.max_response_body_bytes,
            request_buffer_global_cap_bytes: settings.request_buffer_global_cap_bytes,
            unknown_length_response_prebuffer_bytes: settings
                .unknown_length_response_prebuffer_bytes,
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
            scid_bytes
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
                new_primary, current_primary
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
                let shared_ctx = ForwardingSharedCtx {
                    metrics: Arc::clone(&self.metrics),
                    resilience: &self.resilience,
                    routing_index: &self.routing_index,
                    upstream_pools: &self.upstream_pools,
                };
                let exec_ctx = ForwardingExecutionCtx {
                    transport_pool: Arc::clone(&self.transport_pool),
                    backend_endpoints: Arc::clone(&self.backend_endpoints),
                    backend_resolution_store: Arc::clone(&self.backend_resolution_store),
                    upstream_inflight: &self.upstream_inflight,
                    global_inflight: Arc::clone(&self.global_inflight),
                    backend_timeout: self.backend_timeout,
                    inflight_acquire_wait: self.inflight_acquire_wait,
                };
                let progress_config = StreamProgressConfig {
                    backend_body_idle_timeout: self.backend_body_idle_timeout,
                    backend_body_total_timeout: self.backend_body_total_timeout,
                    max_response_body_bytes: self.max_response_body_bytes,
                    unknown_length_response_prebuffer_bytes: self
                        .unknown_length_response_prebuffer_bytes,
                    client_body_idle_timeout: self.client_body_idle_timeout,
                    listen_port: self.config.listen.listen.port,
                };
                if let Err(e) = Self::advance_streams_non_blocking(
                    &mut connection.streams,
                    &mut connection.quic,
                    &mut h3,
                    &exec_ctx,
                    &shared_ctx,
                    &progress_config,
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
            return Err(RequestBufferError::Global);
        }

        let next_state = checked_request_body_ingress(
            RequestBodyGuardrailConfig {
                idle_timeout: Duration::ZERO,
                total_timeout: Duration::ZERO,
                max_body_bytes: max_request_body_bytes,
                max_buffered_bytes: max_request_body_bytes,
            },
            RequestBodyGuardrailInput {
                elapsed: Duration::ZERO,
                idle_for: Duration::ZERO,
                bytes_received: req.body_bytes_received,
                buffered_bytes: req.body_buf_bytes,
                next_chunk_bytes: chunk_len,
                declared_content_length: None,
                exempt_from_body_size_cap: false,
            },
        );
        let Ok(next_state) = next_state else {
            metrics.release_request_buffer(chunk_len);
            return Err(match next_state {
                Err(RequestBodyGuardrailDecision::Reject {
                    kind: BodyLimitKind::BodySize,
                }) => RequestBufferError::BodySize,
                Err(RequestBodyGuardrailDecision::Reject { .. }) => RequestBufferError::Stream,
                Err(other) => unreachable!(
                    "request ingress should not timeout in enqueue path: {:?}",
                    other
                ),
                Ok(_) => unreachable!("handled Ok state before request buffer error mapping"),
            });
        };
        req.body_buf_bytes = next_state.buffered_bytes;
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

    #[allow(clippy::too_many_arguments)]
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
mod tests;
