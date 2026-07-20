use core::net::SocketAddr;
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    future::Future,
    net::UdpSocket,
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
        RuntimeUpstreamPolicy,
    },
};
use spooky_errors::{PoolError, ProxyError};
use spooky_lb::{health::HealthFailureReason, upstream_pool::UpstreamPool};
use spooky_transport::{h2_client::SharedDnsResolver, transport_pool::UpstreamTransportPool};
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
        SCID_ROTATION_PACKET_THRESHOLD, scid_rotation_interval,
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
mod control_plane;
mod forwarding;
mod health_check;
mod metrics_endpoint;
mod runtime_endpoint;
mod shutdown;
mod startup;
mod tls_runtime;
mod token_bucket;
mod validation;
pub mod workers;

#[cfg(test)]
use bootstrap_tls::BootstrapStartupState;
#[cfg(test)]
pub(crate) use connection::purge_connection_routes;
#[cfg(test)]
use connection::resolve_primary_from_radix_prefix;
pub(crate) use connection::{ConnectionRoutes, sweep_closed_connections};
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
        let Some((mut connection, current_primary)) = self.acquire_connection_for_packet(
            peer,
            local_addr,
            packet_type,
            dcid,
            header_has_token,
        ) else {
            return;
        };

        let recv_info = quiche::RecvInfo {
            from: peer,
            to: local_addr,
        };

        if let Err(e) = connection.quic.recv(packet, recv_info) {
            error!("QUIC recv failed: {:?}", e);
            Self::release_connection_streams(&mut connection, &self.metrics);
            self.discard_connection(&connection);
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

        let mut send_buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];

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
            unknown_length_response_prebuffer_bytes: self.unknown_length_response_prebuffer_bytes,
            client_body_idle_timeout: self.client_body_idle_timeout,
            listen_port: self.config.listen.listen.port,
        };

        if !connection.quic.is_closed() {
            Self::advance_connection_streams(
                &self.socket,
                &mut connection,
                &mut send_buf,
                &shared_ctx,
                &exec_ctx,
                &progress_config,
                "packet path",
            );
        }

        Self::maybe_rotate_scid(&mut connection, &self.metrics);

        Self::flush_send(&self.socket, &mut send_buf, &mut connection);
        Self::handle_timeout(&self.socket, &mut send_buf, &mut connection);

        if !connection.quic.is_closed() {
            self.store_connection(&current_primary, connection);
        } else {
            Self::release_connection_streams(&mut connection, &self.metrics);
            self.discard_connection(&connection);
            debug!("Connection closed, not storing");
        }
    }

    fn handle_timeouts(&mut self) {
        if self.connections.is_empty() {
            return;
        }

        let mut send_buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];
        let mut to_remove = Vec::new();
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
            unknown_length_response_prebuffer_bytes: self.unknown_length_response_prebuffer_bytes,
            client_body_idle_timeout: self.client_body_idle_timeout,
            listen_port: self.config.listen.listen.port,
        };

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
            Self::advance_connection_streams(
                &self.socket,
                connection,
                &mut send_buf,
                &shared_ctx,
                &exec_ctx,
                &progress_config,
                "timeout path",
            );
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

    fn advance_connection_streams(
        socket: &UdpSocket,
        connection: &mut QuicConnection,
        send_buf: &mut [u8],
        shared_ctx: &ForwardingSharedCtx<'_>,
        exec_ctx: &ForwardingExecutionCtx<'_>,
        progress_config: &StreamProgressConfig,
        context: &str,
    ) {
        let Some(mut h3) = connection.h3.take() else {
            return;
        };

        if let Err(e) = Self::advance_streams_non_blocking(
            &mut connection.streams,
            &mut connection.quic,
            &mut h3,
            exec_ctx,
            shared_ctx,
            progress_config,
        ) {
            error!("advance_streams_non_blocking in {}: {:?}", context, e);
        }
        connection.h3 = Some(h3);
        Self::flush_send(socket, send_buf, connection);
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
