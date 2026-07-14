mod auth;
mod dispatch;
mod lb_key;
mod prepare;
mod resolve;
mod response;
mod stream_progress;

use self::prepare::{PreAuthRequest, PreparedRequest, StartedAuthRequest};

use std::{
    convert::Infallible,
    error::Error as StdError,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use spooky_config::{
    config::ScopedRateLimitScope,
    runtime::{RuntimeExternalAuth, RuntimeExternalAuthFailureMode},
};
use subtle::ConstantTimeEq;

use super::*;
use crate::runtime::connection::{
    auth::{
        ExternalAuthChallengeResponse, ExternalAuthDecision, ExternalAuthDenyResponse,
        ExternalAuthRedirectResponse, ExternalAuthResult, PendingHeaderMutation,
    },
    request::PendingForward,
    stream::StreamAdmissionState,
};

pub(crate) fn abort_stream(req: &mut RequestEnvelope, metrics: &Metrics) -> StreamPhase {
    let phase = req.phase.clone();
    if req.backend_request_started && !req.backend_request_finished {
        if let (Some(pool), Some(index)) = (&req.upstream_pool, req.backend_index)
            && let Ok(mut guard) = pool.write()
        {
            guard.finish_request(
                index,
                req.start.elapsed(),
                req.response_status.or(Some(503)),
            );
        }
        req.backend_request_finished = true;
    }
    if req.body_buf_bytes > 0 {
        metrics.release_request_buffer(req.body_buf_bytes);
        req.body_buf_bytes = 0;
    }
    req.body_buf.clear();
    req.body_tx = None;
    req.auth_result_rx = None;
    if let Some(abort) = req.auth_abort.take() {
        abort.abort();
    }
    req.upstream_result_rx = None;
    req.response_chunk_rx = None;
    req.pending_chunk = None;
    req.pending_forward = None;
    req.auth_deadline = None;
    req.global_inflight_permit = None;
    req.upstream_inflight_permit = None;
    req.adaptive_admission_permit = None;
    req.route_queue_permit = None;
    phase
}

impl QUICListener {
    pub(super) fn classify_upstream_failure_reason(
        is_connect: bool,
        detail: &str,
    ) -> (HealthFailureReason, &'static str) {
        let normalized = detail.to_ascii_lowercase();
        if normalized.contains("timeout") || normalized.contains("timed out") {
            return (HealthFailureReason::Timeout, "timeout");
        }

        if is_connect {
            if normalized.contains("unknownissuer") || normalized.contains("unknown issuer") {
                return (HealthFailureReason::Tls, "unknown_issuer");
            }
            if normalized.contains("expired")
                || normalized.contains("not yet valid")
                || normalized.contains("validity")
            {
                return (HealthFailureReason::Tls, "expired_certificate");
            }
            if normalized.contains("hostname")
                || normalized.contains("dns name")
                || normalized.contains("subjectaltname")
                || normalized.contains("not valid for")
            {
                return (HealthFailureReason::Tls, "hostname_mismatch");
            }
            if normalized.contains("alpn") {
                return (HealthFailureReason::Tls, "alpn");
            }
            if normalized.contains("invalidcertificate")
                || normalized.contains("certificate")
                || normalized.contains("x509")
                || normalized.contains("rustls")
                || normalized.contains("webpki")
                || normalized.contains("tls")
            {
                return (HealthFailureReason::Tls, "handshake");
            }
        }

        (HealthFailureReason::Transport, "transport")
    }

    pub(super) fn send_error_health_failure_reason(
        err: &hyper_util::client::legacy::Error,
    ) -> (HealthFailureReason, &'static str) {
        let detail = Self::format_error_chain(err);
        Self::classify_upstream_failure_reason(err.is_connect(), &detail)
    }

    pub(super) fn format_error_chain(err: &(dyn StdError + 'static)) -> String {
        let mut detail = err.to_string();
        let mut source = err.source();
        while let Some(cause) = source {
            detail.push_str(": ");
            detail.push_str(&cause.to_string());
            source = cause.source();
        }
        detail
    }

    fn is_internal_pool_control_error(error: &PoolError) -> bool {
        matches!(
            error,
            PoolError::InflightLimiterClosed | PoolError::UnknownBackend(_)
        )
    }

    fn request_metrics_outcome_for_status(status: StatusCode) -> (bool, RouteOutcome) {
        if status.is_server_error() {
            (false, RouteOutcome::Failure)
        } else {
            (true, RouteOutcome::Success)
        }
    }

    pub(super) fn log_access(req: &RequestEnvelope, status: u16) {
        let trace_id = req.trace_id.as_deref().unwrap_or("-");
        let span_id = req.span_id.as_deref().unwrap_or("-");
        let latency_ms = req.start.elapsed().as_millis() as u64;
        if req.routing_transparency_enabled {
            let reason = if req.routing_transparency_include_reason {
                req.route_reason.as_deref().unwrap_or("-")
            } else {
                "-"
            };
            info!(
                "request_id={} route_upstream={} route_path_len={} route_host_specific={} route_reason={} lb={}",
                req.request_id,
                req.upstream_name.as_deref().unwrap_or("-"),
                req.route_path_len.unwrap_or_default(),
                req.route_host_specific.unwrap_or(false),
                reason,
                req.backend_lb.as_deref().unwrap_or("-")
            );
        }

        if let Some(span) = req.trace_span.as_ref() {
            span.in_scope(|| match req.error_kind.as_ref() {
                Some(e) => tracing::warn!(
                    request_id = req.request_id,
                    trace_id = trace_id,
                    span_id = span_id,
                    method = %req.method,
                    path = %req.path,
                    status = status,
                    backend = %req.backend_addr.as_deref().unwrap_or("-"),
                    upstream = %req.upstream_name.as_deref().unwrap_or("-"),
                    latency_ms = latency_ms,
                    retries = req.retry_count,
                    error = %e,
                    "request completed with error"
                ),
                None => tracing::info!(
                    request_id = req.request_id,
                    trace_id = trace_id,
                    span_id = span_id,
                    method = %req.method,
                    path = %req.path,
                    status = status,
                    backend = %req.backend_addr.as_deref().unwrap_or("-"),
                    upstream = %req.upstream_name.as_deref().unwrap_or("-"),
                    latency_ms = latency_ms,
                    retries = req.retry_count,
                    "request completed"
                ),
            });
        }

        match req.error_kind {
            Some(e) => info!(
                "request_id={} trace_id={} span_id={} method={} path={} status={} backend={} upstream={} latency_ms={} retries={} error={}",
                req.request_id,
                trace_id,
                span_id,
                req.method,
                req.path,
                status,
                req.backend_addr.as_deref().unwrap_or("-"),
                req.upstream_name.as_deref().unwrap_or("-"),
                latency_ms,
                req.retry_count,
                e,
            ),
            None => info!(
                "request_id={} trace_id={} span_id={} method={} path={} status={} backend={} upstream={} latency_ms={} retries={}",
                req.request_id,
                trace_id,
                span_id,
                req.method,
                req.path,
                status,
                req.backend_addr.as_deref().unwrap_or("-"),
                req.upstream_name.as_deref().unwrap_or("-"),
                latency_ms,
                req.retry_count,
            ),
        }
    }

    fn record_request_observation(
        metrics: &Metrics,
        req: &RequestEnvelope,
        status: Option<u16>,
        outcome: RouteOutcome,
    ) {
        metrics.record_request_result(
            req.upstream_name.as_deref().unwrap_or("unrouted"),
            req.backend_addr.as_deref(),
            status,
            outcome,
            req.start.elapsed(),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn materialize_forward_after_auth(
        stream_id: u64,
        req: &mut RequestEnvelope,
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        transport_pool: Arc<UpstreamTransportPool>,
        backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
        backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
        upstream_inflight: &HashMap<String, Arc<Semaphore>>,
        global_inflight: Arc<Semaphore>,
        backend_timeout: Duration,
        resilience: &RuntimeResilience,
        metrics: Arc<Metrics>,
        inflight_acquire_wait: Duration,
    ) -> Result<bool, quiche::h3::Error> {
        let Some(pending_forward) = req.pending_forward.as_ref().cloned() else {
            metrics.inc_failure();
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                b"missing deferred forward snapshot\n",
            )?;
            return Ok(false);
        };
        let Some(upstream_name) = req.upstream_name.clone() else {
            metrics.inc_failure();
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                b"missing upstream route\n",
            )?;
            return Ok(false);
        };
        let header_lookup = |name: &str| {
            pending_forward
                .headers
                .iter()
                .find(|header| header.name().eq_ignore_ascii_case(name.as_bytes()))
                .and_then(|header| std::str::from_utf8(header.value()).ok())
                .map(str::to_string)
        };

        resilience
            .brownout
            .observe_admission_pressure(resilience.adaptive_admission.inflight_percent());
        metrics.set_brownout_active(resilience.brownout.is_active());
        if !resilience.brownout.route_allowed(&upstream_name) {
            metrics.inc_failure();
            metrics.inc_overload_shed_reason(OverloadShedReason::Brownout);
            metrics.record_route(
                &upstream_name,
                req.start.elapsed(),
                RouteOutcome::OverloadShed,
            );
            Self::send_overload_response(
                h3,
                quic,
                stream_id,
                b"brownout active, non-core route shed\n",
                resilience.shed_retry_after_seconds,
            )?;
            resilience
                .adaptive_admission
                .observe(req.start.elapsed(), true);
            return Ok(false);
        }

        if let Some(rejection) = resilience.scoped_rate_limits.check(&upstream_name, |rule| {
            Self::resolve_scoped_rate_limit_key(
                rule,
                &upstream_name,
                &req.method,
                &req.path,
                req.authority.as_deref(),
                pending_forward.client_addr,
                Some(&header_lookup),
            )
        }) {
            metrics.inc_failure();
            metrics.inc_request_rate_limited();
            metrics.record_route(
                &upstream_name,
                req.start.elapsed(),
                RouteOutcome::RateLimited,
            );
            warn!(
                "request_id={} route={} scoped rate limit exceeded by rule={}",
                req.request_id, rejection.route, rejection.rule_name
            );
            Self::send_rate_limited_response(
                h3,
                quic,
                stream_id,
                b"request rate limited\n",
                rejection.retry_after_seconds,
            )?;
            return Ok(false);
        }

        let adaptive_permit = match resilience.adaptive_admission.try_acquire() {
            Some(permit) => permit,
            None => {
                metrics.inc_failure();
                metrics.inc_overload_shed_reason(OverloadShedReason::AdaptiveAdmission);
                metrics.record_route(
                    &upstream_name,
                    req.start.elapsed(),
                    RouteOutcome::OverloadShed,
                );
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    b"adaptive admission overload\n",
                    resilience.shed_retry_after_seconds,
                )?;
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                return Ok(false);
            }
        };

        let route_queue_permit = match resilience.route_queue.try_acquire(&upstream_name) {
            Ok(permit) => permit,
            Err(RouteQueueRejection::RouteCap) => {
                metrics.inc_failure();
                metrics.inc_overload_shed_reason(OverloadShedReason::RouteCap);
                metrics.record_route(
                    &upstream_name,
                    req.start.elapsed(),
                    RouteOutcome::OverloadShed,
                );
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    b"route queue cap exceeded\n",
                    resilience.shed_retry_after_seconds,
                )?;
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                return Ok(false);
            }
            Err(RouteQueueRejection::GlobalCap) => {
                metrics.inc_failure();
                metrics.inc_overload_shed_reason(OverloadShedReason::RouteGlobalCap);
                metrics.record_route(
                    &upstream_name,
                    req.start.elapsed(),
                    RouteOutcome::OverloadShed,
                );
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    b"global queue cap exceeded\n",
                    resilience.shed_retry_after_seconds,
                )?;
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                return Ok(false);
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
                drop(route_queue_permit);
                drop(adaptive_permit);
                metrics.inc_failure();
                metrics.inc_overload_shed_reason(OverloadShedReason::GlobalInflight);
                metrics.record_route(
                    &upstream_name,
                    req.start.elapsed(),
                    RouteOutcome::OverloadShed,
                );
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    b"overloaded, retry later\n",
                    resilience.shed_retry_after_seconds,
                )?;
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                return Ok(false);
            }
        };

        let upstream_permit = match upstream_inflight.get(&upstream_name).cloned() {
            Some(semaphore) => {
                match Self::try_acquire_owned_with_micro_wait(semaphore, inflight_acquire_wait) {
                    Ok((permit, waited)) => {
                        if waited {
                            metrics.inc_inflight_wait_admit_upstream();
                        }
                        permit
                    }
                    Err(_) => {
                        drop(global_permit);
                        drop(route_queue_permit);
                        drop(adaptive_permit);
                        metrics.inc_failure();
                        metrics.inc_overload_shed_reason(OverloadShedReason::UpstreamInflight);
                        metrics.record_route(
                            &upstream_name,
                            req.start.elapsed(),
                            RouteOutcome::OverloadShed,
                        );
                        Self::send_overload_response(
                            h3,
                            quic,
                            stream_id,
                            b"upstream overloaded, retry later\n",
                            resilience.shed_retry_after_seconds,
                        )?;
                        resilience
                            .adaptive_admission
                            .observe(req.start.elapsed(), true);
                        return Ok(false);
                    }
                }
            }
            None => {
                drop(global_permit);
                drop(route_queue_permit);
                drop(adaptive_permit);
                metrics.inc_failure();
                metrics.inc_overload_shed_reason(OverloadShedReason::UpstreamInflight);
                metrics.record_route(
                    &upstream_name,
                    req.start.elapsed(),
                    RouteOutcome::OverloadShed,
                );
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    b"upstream admission limiter unavailable\n",
                )?;
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                return Ok(false);
            }
        };

        let backend_index = req.backend_index.unwrap_or(pending_forward.backend_index);
        let Some(upstream_pool) = req.upstream_pool.as_ref().cloned() else {
            drop(upstream_permit);
            drop(global_permit);
            drop(route_queue_permit);
            drop(adaptive_permit);
            metrics.inc_failure();
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                b"missing upstream pool\n",
            )?;
            return Ok(false);
        };
        let request_started = upstream_pool
            .read()
            .ok()
            .is_some_and(|pool| pool.begin_request_if_healthy(backend_index));
        if !request_started {
            drop(upstream_permit);
            drop(global_permit);
            drop(route_queue_permit);
            drop(adaptive_permit);
            metrics.inc_failure();
            metrics.record_route(&upstream_name, req.start.elapsed(), RouteOutcome::Failure);
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::SERVICE_UNAVAILABLE,
                b"selected backend no longer healthy\n",
            )?;
            return Ok(false);
        }

        let backend_addr = pending_forward.backend_addr.to_string();
        let Some(backend_endpoint) = backend_endpoints.get(&backend_addr).cloned() else {
            if let Ok(mut guard) = upstream_pool.write() {
                guard.finish_request(backend_index, req.start.elapsed(), Some(503));
            }
            drop(upstream_permit);
            drop(global_permit);
            drop(route_queue_permit);
            drop(adaptive_permit);
            metrics.inc_failure();
            metrics.record_route(&upstream_name, req.start.elapsed(), RouteOutcome::Failure);
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::BAD_GATEWAY,
                b"unknown backend endpoint\n",
            )?;
            return Ok(false);
        };

        let websocket_h1_tunnel = req.tunnel_mode == TunnelMode::Websocket
            && backend_endpoint.scheme() == BackendScheme::Http;
        let (body_tx, websocket_tunnel_body_rx, request_body) = if req.bodyless_mode {
            (None, None, Some(BoxBody::new(Full::new(Bytes::new()))))
        } else if websocket_h1_tunnel {
            let (tx, rx) = mpsc::channel::<Bytes>(REQUEST_CHUNK_CHANNEL_CAPACITY);
            (Some(tx), Some(rx), None)
        } else {
            let (tx, channel_body) = ChannelBody::channel(REQUEST_CHUNK_CHANNEL_CAPACITY);
            (Some(tx), None, Some(channel_body.boxed()))
        };

        let request = if websocket_h1_tunnel {
            None
        } else {
            match pending_forward.build_request(
                &backend_endpoint,
                // Non-websocket branches above always set a body; fall back to an
                // empty body rather than panicking if that invariant ever changes.
                request_body.unwrap_or_else(|| BoxBody::new(Full::new(Bytes::new()))),
                None,
            ) {
                Ok(request) => Some(request),
                Err(err) => {
                    if let Ok(mut guard) = upstream_pool.write() {
                        guard.finish_request(backend_index, req.start.elapsed(), Some(503));
                    }
                    metrics.inc_failure();
                    metrics.record_route(
                        &upstream_name,
                        req.start.elapsed(),
                        RouteOutcome::Failure,
                    );
                    Self::send_simple_response(
                        h3,
                        quic,
                        stream_id,
                        http::StatusCode::BAD_REQUEST,
                        b"invalid request\n",
                    )?;
                    error!("failed to build upstream request after auth: {}", err);
                    resilience
                        .adaptive_admission
                        .observe(req.start.elapsed(), true);
                    return Ok(false);
                }
            }
        };

        let result_rx = match Self::spawn_upstream_forward_task(
            req,
            Arc::clone(&pending_forward),
            backend_endpoint,
            request,
            websocket_tunnel_body_rx,
            transport_pool,
            backend_endpoints,
            backend_resolution_store,
            backend_timeout,
            Arc::clone(&metrics),
            resilience,
        ) {
            Ok(result_rx) => result_rx,
            Err(err) => {
                if let Ok(mut guard) = upstream_pool.write() {
                    guard.finish_request(backend_index, req.start.elapsed(), Some(503));
                }
                metrics.inc_failure();
                metrics.record_route(&upstream_name, req.start.elapsed(), RouteOutcome::Failure);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    b"upstream runtime unavailable
",
                )?;
                error!("failed to spawn upstream task after auth: {}", err);
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                return Ok(false);
            }
        };

        req.backend_request_started = true;
        req.backend_request_finished = false;
        req.body_tx = body_tx;
        req.upstream_result_rx = Some(result_rx);
        req.global_inflight_permit = Some(global_permit);
        req.upstream_inflight_permit = Some(upstream_permit);
        req.adaptive_admission_permit = Some(adaptive_permit);
        req.route_queue_permit = Some(route_queue_permit);
        req.admission_state = StreamAdmissionState::ReadyToForward;
        req.phase = if req.request_fin_received {
            StreamPhase::AwaitingUpstream
        } else {
            StreamPhase::ReceivingRequest
        };
        Self::flush_request_buffer(req, &metrics);
        if req.request_fin_received && req.body_buf.is_empty() {
            req.body_tx = None;
            req.phase = StreamPhase::AwaitingUpstream;
        }
        req.auth_abort = None;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn flush_send(
        socket: &UdpSocket,
        send_buf: &mut [u8],
        connection: &mut QuicConnection,
    ) {
        let mut packet_count = 0;

        loop {
            match connection.quic.send(send_buf) {
                Ok((write, send_info)) => {
                    packet_count += 1;
                    debug!("Sending {} bytes to {}", write, send_info.to);
                    if let Err(e) = socket.send_to(&send_buf[..write], send_info.to) {
                        error!("Failed to send UDP packet: {:?}", e);
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("QUIC send failed: {:?}", e);
                    break;
                }
            }
        }

        if packet_count > 0 {
            debug!("Sent {} packets", packet_count);
        }
    }

    pub(super) fn log_health_transition(addr: &str, transition: HealthTransition) {
        match transition {
            HealthTransition::BecameHealthy => {
                info!("Backend {} became healthy", addr);
            }
            HealthTransition::BecameUnhealthy => {
                error!("Backend {} became unhealthy", addr);
            }
        }
    }
}

impl QUICListener {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_h3(
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
                    let websocket_tunnel = request.websocket_tunnel;
                    let tunnel_mode = if websocket_tunnel {
                        TunnelMode::Websocket
                    } else if is_connect_method(&method) {
                        TunnelMode::Connect
                    } else {
                        TunnelMode::None
                    };

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
                        Self::send_simple_response(
                            h3,
                            &mut connection.quic,
                            stream_id,
                            http::StatusCode::SERVICE_UNAVAILABLE,
                            b"too many concurrent streams\n",
                        )?;
                        continue;
                    }

                    // Route lookup now only selects an upstream/backend; actual
                    // backend/inflight admission is deferred until local auth
                    // succeeds immediately or async external auth completes.
                    let sticky_cid_key = hex::encode(connection.primary_scid.as_ref());
                    let quic_trace_id = connection.quic.trace_id().to_string();
                    let pre_auth = match Self::prepare_request_for_auth(
                        stream_id,
                        h3,
                        &mut connection.quic,
                        connection.peer_address,
                        &quic_trace_id,
                        request_start,
                        &method,
                        &path,
                        authority.as_deref(),
                        content_length,
                        tunnel_mode,
                        &list,
                        sticky_cid_key.as_str(),
                        tracing_enabled,
                        routing_index,
                        &upstream_policies,
                        upstream_pools,
                        &metrics,
                        resilience,
                    )? {
                        Some(pre_auth) => pre_auth,
                        None => continue,
                    };
                    let started_auth = match Self::start_request_auth(
                        stream_id,
                        h3,
                        &mut connection.quic,
                        request_start,
                        &metrics,
                        pre_auth,
                    )? {
                        Some(started_auth) => started_auth,
                        None => continue,
                    };
                    let StartedAuthRequest {
                        request:
                            PreparedRequest {
                                upstream_name,
                                backend_addr,
                                backend_index,
                                upstream_pool,
                                backend_lb,
                                route_path_len,
                                route_host_specific,
                                route_reason,
                                request_id,
                                trace_id,
                                span_id,
                                traceparent,
                                trace_span,
                                bodyless_mode,
                                request_fin_received,
                                pending_forward,
                                auth_fail_open,
                            },
                        auth_start,
                        auth_requested,
                    } = started_auth;

                    let (
                        auth_result_rx,
                        auth_abort,
                        auth_deadline,
                        auth_fail_open,
                        admission_state,
                    ) = match auth_start {
                        Some(start) => (
                            Some(start.rx),
                            Some(start.abort),
                            Some(start.deadline),
                            start.fail_open,
                            StreamAdmissionState::WaitingForAuth,
                        ),
                        None => (
                            None,
                            None,
                            None,
                            auth_fail_open,
                            StreamAdmissionState::ReadyToForward,
                        ),
                    };
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
                            body_tx: None,
                            body_buf: std::collections::VecDeque::new(),
                            body_buf_bytes: 0,
                            body_bytes_received: 0,
                            last_body_activity: request_start,
                            backend_addr: Some(backend_addr),
                            backend_index: Some(backend_index),
                            upstream_name: Some(upstream_name),
                            route_reason: Some(route_reason),
                            route_path_len: Some(route_path_len),
                            route_host_specific: Some(route_host_specific),
                            backend_lb: Some(backend_lb),
                            upstream_pool: Some(upstream_pool),
                            routing_transparency_enabled,
                            routing_transparency_include_reason,
                            response_status: None,
                            backend_request_started: false,
                            backend_request_finished: false,
                            global_inflight_permit: None,
                            upstream_inflight_permit: None,
                            adaptive_admission_permit: None,
                            route_queue_permit: None,
                            start: request_start,
                            total_request_deadline: request_start + backend_total_request_timeout,
                            bodyless_mode,
                            tunnel_mode,
                            retry_count: 0,
                            error_kind: None,
                            pending_forward: Some(pending_forward),
                            auth_result_rx,
                            auth_abort,
                            auth_fail_open,
                            auth_deadline,
                            phase: StreamPhase::ReceivingRequest,
                            admission_state,
                            request_fin_received,
                            upstream_result_rx: None,
                            response_chunk_rx: None,
                            response_headers_sent: false,
                            pending_chunk: None,
                        },
                    );
                    if !auth_requested {
                        let keep_stream = if let Some(req) = connection.streams.get_mut(&stream_id)
                        {
                            Self::materialize_forward_after_auth(
                                stream_id,
                                req,
                                h3,
                                &mut connection.quic,
                                Arc::clone(&transport_pool),
                                Arc::clone(&backend_endpoints),
                                Arc::clone(&backend_resolution_store),
                                upstream_inflight,
                                Arc::clone(&global_inflight),
                                backend_timeout,
                                resilience,
                                Arc::clone(&metrics),
                                inflight_acquire_wait,
                            )?
                        } else {
                            false
                        };
                        if !keep_stream {
                            if let Some(req) = connection.streams.get_mut(&stream_id) {
                                abort_stream(req, &metrics);
                            }
                            connection.streams.remove(&stream_id);
                            continue;
                        }
                    }
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
                        // Only move to AwaitingUpstream once auth has allowed the request
                        // and an upstream task/body channel actually exists.
                        if req.admission_state == StreamAdmissionState::ReadyToForward {
                            req.phase = StreamPhase::AwaitingUpstream;
                        }
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
            Arc::clone(&transport_pool),
            Arc::clone(&backend_endpoints),
            Arc::clone(&backend_resolution_store),
            upstream_pools,
            upstream_inflight,
            Arc::clone(&global_inflight),
            backend_timeout,
            routing_index,
            backend_body_idle_timeout,
            backend_body_total_timeout,
            Arc::clone(&metrics),
            backend_total_request_timeout,
            resilience,
            max_response_body_bytes,
            unknown_length_response_prebuffer_bytes,
            client_body_idle_timeout,
            inflight_acquire_wait,
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
    pub(super) fn advance_streams_non_blocking(
        streams: &mut HashMap<u64, RequestEnvelope>,
        quic: &mut quiche::Connection,
        h3: &mut quiche::h3::Connection,
        transport_pool: Arc<UpstreamTransportPool>,
        backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
        backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        upstream_inflight: &HashMap<String, Arc<Semaphore>>,
        global_inflight: Arc<Semaphore>,
        backend_timeout: Duration,
        routing_index: &RouteIndex,
        backend_body_idle_timeout: Duration,
        backend_body_total_timeout: Duration,
        metrics: Arc<Metrics>,
        _backend_total_request_timeout: Duration,
        resilience: &RuntimeResilience,
        max_response_body_bytes: usize,
        unknown_length_response_prebuffer_bytes: usize,
        client_body_idle_timeout: Duration,
        inflight_acquire_wait: Duration,
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
                    &metrics,
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
                    abort_stream(req, &metrics);
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
                    abort_stream(req, &metrics);
                }
                streams.remove(&stream_id);
                continue;
            }

            // ── 1 & 2: request body drain ────────────────────────────────────
            if let Some(req) = streams.get_mut(&stream_id) {
                Self::flush_request_buffer(req, &metrics);
                if req.request_fin_received && req.body_buf.is_empty() {
                    req.body_tx = None; // signals EOF to the upstream H2 task
                }
            }

            // ── 3: poll external auth first, then upstream oneshot ─────────────
            let auth_ready: Option<ExternalAuthResult> = if streams
                .get(&stream_id)
                .is_some_and(|req| req.admission_state == StreamAdmissionState::WaitingForAuth)
            {
                if streams
                    .get(&stream_id)
                    .and_then(|req| req.auth_deadline)
                    .is_some_and(|deadline| Instant::now() >= deadline)
                {
                    Some(Err(ProxyError::Timeout))
                } else {
                    streams
                        .get_mut(&stream_id)
                        .and_then(|req| req.auth_result_rx.as_mut())
                        .and_then(|rx| match rx.try_recv() {
                            Ok(result) => Some(result),
                            Err(oneshot::error::TryRecvError::Empty) => None,
                            Err(oneshot::error::TryRecvError::Closed) => Some(Err(
                                ProxyError::Transport("external auth task dropped sender".into()),
                            )),
                        })
                }
            } else {
                None
            };

            if let Some(auth_result) = auth_ready {
                let keep_stream = if let Some(req) = streams.get_mut(&stream_id) {
                    Self::complete_auth_result(
                        stream_id,
                        req,
                        auth_result,
                        h3,
                        quic,
                        Arc::clone(&transport_pool),
                        Arc::clone(&backend_endpoints),
                        Arc::clone(&backend_resolution_store),
                        upstream_inflight,
                        Arc::clone(&global_inflight),
                        backend_timeout,
                        resilience,
                        Arc::clone(&metrics),
                        inflight_acquire_wait,
                    )?
                } else {
                    false
                };
                if !keep_stream {
                    if let Some(req) = streams.get_mut(&stream_id) {
                        abort_stream(req, &metrics);
                    }
                    streams.remove(&stream_id);
                    continue;
                }
            }

            let can_poll_upstream = streams
                .get(&stream_id)
                .is_some_and(can_poll_upstream_result);
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
                            hedge: crate::runtime::connection::response::HedgeTelemetry::default(),
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
                    metrics.inc_retry_attempt(reason);
                }
                if let Some(reason) = forward_result.retry_denial_reason {
                    metrics.inc_retry_denied(reason);
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
                    Ok(success) => {
                        let (status, resp_headers, response_body, prebuilt_response_chunk_rx) =
                            match success {
                                ForwardSuccess::Response {
                                    status,
                                    headers,
                                    body,
                                } => (status, headers, Some(body), None),
                                ForwardSuccess::Tunnel {
                                    status,
                                    headers,
                                    response_chunk_rx,
                                } => (status, headers, None, Some(response_chunk_rx)),
                            };
                        let suppress_downstream_body = streams
                            .get(&stream_id)
                            .is_some_and(|req| is_head_method(&req.method));
                        let tunnel_response = streams
                            .get(&stream_id)
                            .is_some_and(|req| is_tunnel_response(req.tunnel_mode, status));
                        // If upstream advertised a response length beyond our hard cap,
                        // fail fast with 503 before sending any downstream headers/body.
                        let upstream_content_length = resp_headers
                            .get(http::header::CONTENT_LENGTH)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<usize>().ok());
                        if !tunnel_response
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
                                abort_stream(req, &metrics);
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
                            && !tunnel_response
                            && !suppress_downstream_body;
                        let immediate_end = suppress_downstream_body
                            || (!tunnel_response
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
                                        &metrics,
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
                                    abort_stream(req, &metrics);
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
                                            &metrics,
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
                                        abort_stream(req, &metrics);
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
                            if let Some(chunk_rx) = prebuilt_response_chunk_rx {
                                if let Some(req) = streams.get_mut(&stream_id) {
                                    req.response_chunk_rx = Some(chunk_rx);
                                    req.response_headers_sent = true;
                                    req.phase = StreamPhase::SendingResponse;
                                    req.response_status = Some(status.as_u16());
                                }
                            } else {
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
                                let tunnel_mode = tunnel_response;
                                let fut = async move {
                                    use http_body_util::BodyExt;
                                    let Some(mut body) = response_body else {
                                        let _ = chunk_tx
                                            .send(ResponseChunk::Error(ProxyError::Transport(
                                                "non-tunnel responses must carry an HTTP body stream".into(),
                                            )))
                                            .await;
                                        return;
                                    };
                                    let mut response_bytes_received: usize = 0;
                                    let mut buffered_chunks: Vec<Bytes> = Vec::new();
                                    let mut buffered_trailers: Option<Vec<(Vec<u8>, Vec<u8>)>> =
                                        None;
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
                                                    .send(ResponseChunk::Error(
                                                        ProxyError::Transport(
                                                            "upstream body error".into(),
                                                        ),
                                                    ))
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
                                    Some(span) => {
                                        spawn_async_task(fut.instrument(span), "body-pump")
                                    }
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
                        }

                        // Update health/metrics for upstream response.
                        if let Some(req) = streams.get(&stream_id) {
                            if let (Some(addr), Some(idx)) = (&req.backend_addr, req.backend_index)
                                && let Some(pool) = req.upstream_pool.as_ref()
                            {
                                let transition = pool.write().ok().and_then(|mut p| {
                                    match outcome_from_status(status) {
                                        crate::runtime::health::HealthClassification::Success => {
                                            p.pool.mark_success(idx)
                                        }
                                        crate::runtime::health::HealthClassification::Failure => {
                                            p.pool.mark_request_failure(
                                                idx,
                                                HealthFailureReason::HttpStatus5xx,
                                            )
                                        }
                                        crate::runtime::health::HealthClassification::Neutral => {
                                            None
                                        }
                                    }
                                });
                                if let Some(t) = transition {
                                    Self::log_health_transition(addr, t);
                                }
                            }
                            let (is_success, route_outcome) =
                                Self::request_metrics_outcome_for_status(status);
                            if is_success {
                                metrics.inc_success();
                            } else {
                                metrics.inc_failure();
                            }
                            let route_label = req.upstream_name.as_deref().unwrap_or("unrouted");
                            metrics.record_route(route_label, req.start.elapsed(), route_outcome);
                            Self::record_request_observation(
                                &metrics,
                                req,
                                Some(status.as_u16()),
                                route_outcome,
                            );
                            resilience
                                .adaptive_admission
                                .observe(req.start.elapsed(), false);
                            Self::log_access(req, status.as_u16());
                        }
                        if immediate_terminal {
                            if let Some(req) = streams.get_mut(&stream_id) {
                                abort_stream(req, &metrics);
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
                                &metrics,
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
                            abort_stream(req, &metrics);
                        }
                        streams.remove(&stream_id);
                        continue;
                    }
                }
            }

            // ── 4: flush response chunks ──────────────────────────────────────
            let terminal = if let Some(req) = streams.get_mut(&stream_id) {
                Self::flush_response_chunks(
                    stream_id,
                    req,
                    quic,
                    h3,
                    upstream_pools,
                    routing_index,
                    &metrics,
                    resilience,
                )
            } else {
                false
            };

            // ── 5: remove terminal streams ────────────────────────────────────
            if terminal {
                if let Some(req) = streams.get_mut(&stream_id) {
                    abort_stream(req, &metrics);
                }
                streams.remove(&stream_id);
            }
        }

        Ok(())
    }

    pub(super) fn api_key_is_authorized(
        policy: &RuntimeUpstreamPolicy,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> bool {
        let Some(api_key) = policy.upstream_auth.api_key.as_ref() else {
            return true;
        };
        let Some(provided) = header_lookup.and_then(|lookup| lookup(api_key.header_name.as_str()))
        else {
            return false;
        };
        let provided = provided.trim();
        !provided.is_empty()
            && api_key
                .keys
                .iter()
                .any(|expected| bool::from(provided.as_bytes().ct_eq(expected.as_bytes())))
    }

    pub(super) fn jwt_is_authorized(
        policy: &RuntimeUpstreamPolicy,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> bool {
        let Some(jwt) = policy.upstream_auth.jwt.as_ref() else {
            return true;
        };
        let Some(raw) =
            header_lookup.and_then(|lookup| lookup(http::header::AUTHORIZATION.as_str()))
        else {
            return false;
        };
        let Some(token) = Self::bearer_token_from_authorization_value(&raw) else {
            return false;
        };
        let Some(claims) = Self::validated_hs256_jwt_claims(token.as_str(), jwt, SystemTime::now())
        else {
            return false;
        };
        Self::jwt_claims_satisfy_rbac(policy, &claims)
    }

    fn validated_hs256_jwt_claims(
        token: &str,
        jwt: &spooky_config::runtime::RuntimeJwtAuth,
        now: SystemTime,
    ) -> Option<Value> {
        let mut parts = token.split('.');
        let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        let Ok(header_bytes) = URL_SAFE_NO_PAD.decode(header_b64) else {
            return None;
        };
        let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(payload_b64) else {
            return None;
        };
        let Ok(signature) = URL_SAFE_NO_PAD.decode(signature_b64) else {
            return None;
        };
        let Ok(header) = serde_json::from_slice::<Value>(&header_bytes) else {
            return None;
        };
        if header.get("alg").and_then(Value::as_str) != Some("HS256") {
            return None;
        }

        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(jwt.secret.as_bytes()) else {
            return None;
        };
        mac.update(format!("{header_b64}.{payload_b64}").as_bytes());
        let expected = mac.finalize().into_bytes();
        if expected.len() != signature.len()
            || !bool::from(expected.as_slice().ct_eq(signature.as_slice()))
        {
            return None;
        }

        let Ok(claims) = serde_json::from_slice::<Value>(&payload_bytes) else {
            return None;
        };
        let Ok(now_secs) = now.duration_since(UNIX_EPOCH).map(|value| value.as_secs()) else {
            return None;
        };
        let exp = claims.get("exp").and_then(Value::as_u64)?;
        if now_secs > exp.saturating_add(jwt.clock_skew_secs) {
            return None;
        }
        if claims
            .get("nbf")
            .and_then(Value::as_u64)
            .is_some_and(|nbf| now_secs.saturating_add(jwt.clock_skew_secs) < nbf)
        {
            return None;
        }
        if claims
            .get("iat")
            .and_then(Value::as_u64)
            .is_some_and(|iat| now_secs.saturating_add(jwt.clock_skew_secs) < iat)
        {
            return None;
        }
        if jwt
            .issuer
            .as_deref()
            .is_some_and(|issuer| claims.get("iss").and_then(Value::as_str) != Some(issuer))
        {
            return None;
        }
        if let Some(audience) = jwt.audience.as_deref() {
            let claim_aud = claims.get("aud")?;
            match claim_aud {
                Value::String(value) if value == audience => {}
                Value::Array(values)
                    if values
                        .iter()
                        .any(|value| value.as_str().is_some_and(|value| value == audience)) => {}
                _ => return None,
            }
        }

        Some(claims)
    }

    fn jwt_claims_satisfy_rbac(policy: &RuntimeUpstreamPolicy, claims: &Value) -> bool {
        let scopes = Self::jwt_string_claim_values(claims, &["scope", "scp"]);
        let roles = Self::jwt_string_claim_values(claims, &["roles", "role"]);
        policy
            .upstream_auth
            .required_scopes
            .iter()
            .all(|required| scopes.contains(required))
            && policy
                .upstream_auth
                .required_roles
                .iter()
                .all(|required| roles.contains(required))
    }

    fn jwt_string_claim_values(
        claims: &Value,
        claim_names: &[&str],
    ) -> std::collections::HashSet<String> {
        let mut values = std::collections::HashSet::new();
        for claim_name in claim_names {
            let Some(value) = claims.get(*claim_name) else {
                continue;
            };
            match value {
                Value::String(value) => {
                    for item in value.split_whitespace() {
                        if !item.is_empty() {
                            values.insert(item.to_string());
                        }
                    }
                }
                Value::Array(items) => {
                    for item in items {
                        if let Some(item) = item.as_str()
                            && !item.is_empty()
                        {
                            values.insert(item.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        values
    }

    pub(super) fn resolve_scoped_rate_limit_key(
        rule: &crate::resilience::scoped_rate_limit::ScopedRateLimitRule,
        route: &str,
        method: &str,
        path: &str,
        authority: Option<&str>,
        client_addr: SocketAddr,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> Option<String> {
        match rule.scope() {
            ScopedRateLimitScope::Route => Some(route.to_string()),
            ScopedRateLimitScope::Client => Self::resolve_lb_key_from_spec(
                rule.key_spec().unwrap_or("peer_ip"),
                method,
                path,
                authority,
                None,
                Some(client_addr),
                header_lookup,
            ),
            ScopedRateLimitScope::Tenant => rule.key_spec().and_then(|key_spec| {
                Self::resolve_lb_key_from_spec(
                    key_spec,
                    method,
                    path,
                    authority,
                    None,
                    Some(client_addr),
                    header_lookup,
                )
            }),
            ScopedRateLimitScope::Token => Self::resolve_lb_key_from_spec(
                rule.key_spec().unwrap_or("bearer_token"),
                method,
                path,
                authority,
                None,
                Some(client_addr),
                header_lookup,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use spooky_config::{
        config::{ScopedRateLimit, ScopedRateLimitScope},
        runtime::{
            RuntimeApiKeyAuth, RuntimeAuthPolicy, RuntimeExternalAuth,
            RuntimeExternalAuthFailureMode, RuntimeJwtAuth, RuntimeUpstreamPolicy,
        },
    };

    use super::auth::{
        allowed_auth_headers, append_auth_request_headers, auth_allow_mutations, auth_failure_mode,
        auth_timeout_ms, fail_open, map_http_external_auth_response, oidc_audience_matches,
        oidc_scope_satisfied,
    };
    use super::*;

    fn sample_pending_forward(headers: Vec<quiche::h3::Header>) -> PendingForward {
        PendingForward {
            method: Arc::<str>::from("GET"),
            path: Arc::<str>::from("/"),
            authority: Some(Arc::<str>::from("example.com")),
            headers: Arc::new(headers),
            upstream_name: Arc::<str>::from("api"),
            route_reason: Arc::<str>::from("path_prefix"),
            route_path_len: 1,
            route_host_specific: false,
            backend_addr: Arc::<str>::from("http://127.0.0.1:8080"),
            backend_index: 0,
            backend_lb: None,
            client_addr: "127.0.0.1:443".parse().expect("client addr"),
            request_id: 7,
            trace_id: None,
            span_id: None,
            traceparent: None,
            host_policy: Default::default(),
            forwarded_header_policy: Default::default(),
            auth_header_mutations: Vec::new(),
        }
    }

    fn test_hs256_jwt(secret: &str, claims: serde_json::Value, alg: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({ "alg": alg, "typ": "JWT" }))
                .expect("serialize header"),
        );
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("serialize claims"));
        let signing_input = format!("{header}.{payload}");
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("mac");
        mac.update(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{signing_input}.{signature}")
    }

    #[test]
    fn internal_pool_errors_are_classified_as_control_plane_only() {
        assert!(QUICListener::is_internal_pool_control_error(
            &PoolError::InflightLimiterClosed
        ));
        assert!(QUICListener::is_internal_pool_control_error(
            &PoolError::UnknownBackend("missing".to_string())
        ));
    }

    #[test]
    fn backend_overload_is_not_classified_as_internal_pool_error() {
        assert!(!QUICListener::is_internal_pool_control_error(
            &PoolError::BackendOverloaded("busy".to_string())
        ));
    }

    #[test]
    fn circuit_open_is_not_classified_as_internal_pool_error() {
        assert!(!QUICListener::is_internal_pool_control_error(
            &PoolError::CircuitOpen("open".to_string())
        ));
    }

    #[test]
    fn send_connect_error_with_tls_details_maps_to_tls_health_failure() {
        assert_eq!(
            QUICListener::classify_upstream_failure_reason(
                true,
                "client error (Connect): tls handshake failed: invalid certificate"
            ),
            (HealthFailureReason::Tls, "handshake")
        );
    }

    #[test]
    fn send_connect_error_without_tls_details_maps_to_transport_health_failure() {
        assert_eq!(
            QUICListener::classify_upstream_failure_reason(
                true,
                "client error (Connect): connection refused"
            ),
            (HealthFailureReason::Transport, "transport")
        );
    }

    #[test]
    fn send_error_with_timeout_detail_maps_to_timeout_health_failure() {
        assert_eq!(
            QUICListener::classify_upstream_failure_reason(false, "request timed out"),
            (HealthFailureReason::Timeout, "timeout")
        );
    }

    #[test]
    fn request_metrics_treat_server_error_as_failure() {
        let (is_success, route_outcome) =
            QUICListener::request_metrics_outcome_for_status(StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!is_success);
        match route_outcome {
            RouteOutcome::Failure => {}
            _ => panic!("unexpected route outcome"),
        }
    }

    #[test]
    fn request_metrics_treat_success_response_as_success() {
        let (is_success, route_outcome) =
            QUICListener::request_metrics_outcome_for_status(StatusCode::OK);
        assert!(is_success);
        match route_outcome {
            RouteOutcome::Success => {}
            _ => panic!("unexpected route outcome"),
        }
    }

    #[derive(Debug)]
    struct OuterErr(InnerErr);

    #[derive(Debug)]
    struct InnerErr;

    impl std::fmt::Display for OuterErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "outer")
        }
    }

    impl std::fmt::Display for InnerErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "inner")
        }
    }

    impl StdError for OuterErr {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(&self.0)
        }
    }

    impl StdError for InnerErr {}

    #[test]
    fn format_error_chain_includes_nested_causes() {
        let msg = QUICListener::format_error_chain(&OuterErr(InnerErr));
        assert_eq!(msg, "outer: inner");
    }

    #[test]
    fn api_key_authorization_requires_exact_configured_match() {
        let policy = RuntimeUpstreamPolicy {
            upstream_auth: RuntimeAuthPolicy {
                api_key: Some(RuntimeApiKeyAuth {
                    header_name: "x-api-key".to_string(),
                    keys: vec!["secret-key".to_string()],
                }),
                jwt: None,
                external_auth: None,
                required_scopes: Vec::new(),
                required_roles: Vec::new(),
            },
            host: Default::default(),
            forwarded_headers: Default::default(),
            protocol: Default::default(),
        };
        let headers = [("x-api-key".to_string(), "secret-key".to_string())]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();
        let wrong_lookup = |_: &str| Some("wrong-key".to_string());

        assert!(QUICListener::api_key_is_authorized(&policy, Some(&lookup)));
        assert!(!QUICListener::api_key_is_authorized(
            &policy,
            Some(&wrong_lookup)
        ));
        assert!(!QUICListener::api_key_is_authorized(&policy, None));
    }

    #[test]
    fn hs256_jwt_validation_enforces_signature_and_claims() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let token = test_hs256_jwt(
            "jwt-secret",
            serde_json::json!({
                "sub": "user-1",
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
                "nbf": 1_699_999_900u64,
            }),
            "HS256",
        );
        let policy = RuntimeUpstreamPolicy {
            upstream_auth: RuntimeAuthPolicy {
                api_key: None,
                jwt: Some(RuntimeJwtAuth {
                    secret: "jwt-secret".to_string(),
                    issuer: Some("issuer-1".to_string()),
                    audience: Some("aud-1".to_string()),
                    clock_skew_secs: 30,
                }),
                external_auth: None,
                required_scopes: Vec::new(),
                required_roles: Vec::new(),
            },
            host: Default::default(),
            forwarded_headers: Default::default(),
            protocol: Default::default(),
        };
        let headers = [("authorization".to_string(), format!("Bearer {token}"))]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();

        assert!(QUICListener::jwt_is_authorized(&policy, Some(&lookup)));
        assert!(
            QUICListener::validated_hs256_jwt_claims(
                token.as_str(),
                policy.upstream_auth.jwt.as_ref().expect("jwt policy"),
                now
            )
            .is_some()
        );

        let wrong_secret = RuntimeJwtAuth {
            secret: "wrong".to_string(),
            issuer: Some("issuer-1".to_string()),
            audience: Some("aud-1".to_string()),
            clock_skew_secs: 30,
        };
        assert!(
            QUICListener::validated_hs256_jwt_claims(token.as_str(), &wrong_secret, now).is_none()
        );

        let expired = test_hs256_jwt(
            "jwt-secret",
            serde_json::json!({ "exp": 1_699_999_900u64 }),
            "HS256",
        );
        assert!(
            QUICListener::validated_hs256_jwt_claims(
                expired.as_str(),
                &RuntimeJwtAuth {
                    secret: "jwt-secret".to_string(),
                    issuer: None,
                    audience: None,
                    clock_skew_secs: 0,
                },
                now
            )
            .is_none()
        );
    }

    #[test]
    fn jwt_rbac_requires_configured_scopes_and_roles() {
        let policy = RuntimeUpstreamPolicy {
            upstream_auth: RuntimeAuthPolicy {
                api_key: None,
                jwt: None,
                external_auth: None,
                required_scopes: vec!["read:fast".to_string()],
                required_roles: vec!["admin".to_string()],
            },
            host: Default::default(),
            forwarded_headers: Default::default(),
            protocol: Default::default(),
        };
        let allowed_claims = serde_json::json!({
            "scope": "read:fast write:slow",
            "roles": ["admin", "operator"]
        });
        let denied_claims = serde_json::json!({
            "scope": "write:slow",
            "roles": ["operator"]
        });

        assert!(QUICListener::jwt_claims_satisfy_rbac(
            &policy,
            &allowed_claims
        ));
        assert!(!QUICListener::jwt_claims_satisfy_rbac(
            &policy,
            &denied_claims
        ));
    }

    #[test]
    fn resolve_lb_key_from_spec_supports_peer_ip_and_bearer_token() {
        let headers = [("authorization".to_string(), "Bearer token-1".to_string())]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();
        let client_addr = "203.0.113.9:443".parse().expect("client addr");

        assert_eq!(
            QUICListener::resolve_lb_key_from_spec(
                "peer_ip",
                "GET",
                "/",
                Some("api.example.com"),
                None,
                Some(client_addr),
                Some(&lookup),
            )
            .as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(
            QUICListener::resolve_lb_key_from_spec(
                "bearer_token",
                "GET",
                "/",
                Some("api.example.com"),
                None,
                Some(client_addr),
                Some(&lookup),
            )
            .as_deref(),
            Some("token-1")
        );
    }

    #[test]
    fn resolve_scoped_rate_limit_key_defaults_match_scope() {
        let client_rule = crate::resilience::scoped_rate_limit::ScopedRateLimitRule::from_config(
            &ScopedRateLimit {
                name: "client".to_string(),
                scope: ScopedRateLimitScope::Client,
                requests_per_sec: 10,
                burst: 10,
                key: None,
                route_allowlist: Vec::new(),
                idle_ttl_secs: 300,
            },
        );
        let token_rule = crate::resilience::scoped_rate_limit::ScopedRateLimitRule::from_config(
            &ScopedRateLimit {
                name: "token".to_string(),
                scope: ScopedRateLimitScope::Token,
                requests_per_sec: 10,
                burst: 10,
                key: None,
                route_allowlist: Vec::new(),
                idle_ttl_secs: 300,
            },
        );
        let headers = [("authorization".to_string(), "Bearer token-2".to_string())]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();
        let client_addr = "198.51.100.10:443".parse().expect("client addr");

        assert_eq!(
            QUICListener::resolve_scoped_rate_limit_key(
                &client_rule,
                "api",
                "GET",
                "/resource",
                Some("api.example.com"),
                client_addr,
                Some(&lookup),
            )
            .as_deref(),
            Some("198.51.100.10")
        );
        assert_eq!(
            QUICListener::resolve_scoped_rate_limit_key(
                &token_rule,
                "api",
                "GET",
                "/resource",
                Some("api.example.com"),
                client_addr,
                Some(&lookup),
            )
            .as_deref(),
            Some("token-2")
        );
    }

    #[test]
    fn pending_forward_request_headers_apply_auth_mutations() {
        let pending_forward = PendingForward {
            auth_header_mutations: vec![
                PendingHeaderMutation::Upsert {
                    name: b"x-user-id".to_vec(),
                    value: b"fresh".to_vec(),
                },
                PendingHeaderMutation::Remove {
                    name: b"x-remove-me".to_vec(),
                },
            ],
            ..sample_pending_forward(vec![
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b"x-user-id", b"stale"),
                quiche::h3::Header::new(b"x-remove-me", b"1"),
            ])
        };

        let headers = pending_forward.request_headers();
        assert!(headers.iter().any(|header| header.name() == b":method"));
        assert!(
            headers
                .iter()
                .any(|header| header.name() == b"x-user-id" && header.value() == b"fresh")
        );
        assert!(
            !headers
                .iter()
                .any(|header| header.name() == b"x-user-id" && header.value() == b"stale")
        );
        assert!(!headers.iter().any(|header| header.name() == b"x-remove-me"));
    }

    #[test]
    fn auth_header_allowlist_is_case_insensitive() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-auth-user", http::HeaderValue::from_static("alice"));
        headers.insert("x-ignore", http::HeaderValue::from_static("nope"));
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("12"),
        );

        assert_eq!(
            allowed_auth_headers(&headers, &["X-Auth-User".to_string()]),
            vec![("x-auth-user".to_string(), "alice".to_string())]
        );

        assert_eq!(
            auth_allow_mutations(&headers, &["x-auth-user".to_string()]),
            vec![PendingHeaderMutation::Upsert {
                name: b"x-auth-user".to_vec(),
                value: b"alice".to_vec(),
            }]
        );
    }

    #[test]
    fn auth_allow_mutations_drops_unsafe_request_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-auth-user", http::HeaderValue::from_static("alice"));
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer test"),
        );
        headers.insert(
            http::header::LOCATION,
            http::HeaderValue::from_static("https://login"),
        );
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("12"),
        );

        assert_eq!(
            auth_allow_mutations(
                &headers,
                &[
                    "x-auth-user".to_string(),
                    "authorization".to_string(),
                    "location".to_string(),
                    "content-length".to_string(),
                ],
            ),
            vec![PendingHeaderMutation::Upsert {
                name: b"x-auth-user".to_vec(),
                value: b"alice".to_vec(),
            }]
        );
    }

    #[test]
    fn append_auth_request_headers_strips_hop_by_hop_and_framing_headers() {
        let pending_forward = sample_pending_forward(vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b"host", b"client.example.com"),
            quiche::h3::Header::new(b"content-length", b"42"),
            quiche::h3::Header::new(b"connection", b"keep-alive"),
            quiche::h3::Header::new(b"cookie", b"session=1"),
            quiche::h3::Header::new(b"authorization", b"Bearer token"),
        ]);
        let mut builder = Request::builder()
            .method(http::Method::GET)
            .uri("https://auth.internal/check");

        append_auth_request_headers(&mut builder, &pending_forward, &[]);

        let headers = builder.headers_ref().expect("headers");
        assert!(!headers.contains_key(http::header::HOST));
        assert!(!headers.contains_key(http::header::CONTENT_LENGTH));
        assert!(!headers.contains_key(http::header::CONNECTION));
        assert_eq!(
            headers
                .get(http::header::COOKIE)
                .and_then(|value| value.to_str().ok()),
            Some("session=1")
        );
        assert_eq!(
            headers
                .get(http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer token")
        );
    }

    #[test]
    fn http_external_auth_response_mapping_preserves_allowlisted_denial_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-auth-reason", http::HeaderValue::from_static("policy"));
        headers.insert("x-drop", http::HeaderValue::from_static("secret"));

        let decision = map_http_external_auth_response(
            http::StatusCode::FORBIDDEN,
            &headers,
            b"denied
"
            .to_vec(),
            &["x-auth-reason".to_string()],
        )
        .expect("deny decision");

        match decision {
            ExternalAuthDecision::Deny(response) => {
                assert_eq!(response.status, http::StatusCode::FORBIDDEN);
                assert_eq!(response.body, b"denied\n".to_vec());
                assert_eq!(
                    response.headers,
                    vec![("x-auth-reason".to_string(), "policy".to_string())]
                );
            }
            other => panic!("unexpected decision: {other:?}"),
        }
    }

    #[test]
    fn http_external_auth_response_mapping_builds_challenge_from_401() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::WWW_AUTHENTICATE,
            http::HeaderValue::from_static("Bearer realm=\"spooky\""),
        );
        headers.insert("x-auth-reason", http::HeaderValue::from_static("expired"));

        let decision = map_http_external_auth_response(
            http::StatusCode::UNAUTHORIZED,
            &headers,
            b"challenge\n".to_vec(),
            &["x-auth-reason".to_string()],
        )
        .expect("challenge decision");

        match decision {
            ExternalAuthDecision::Challenge(response) => {
                assert_eq!(response.status, http::StatusCode::UNAUTHORIZED);
                assert_eq!(response.www_authenticate, "Bearer realm=\"spooky\"");
                assert_eq!(response.body, b"challenge\n".to_vec());
                assert_eq!(
                    response.headers,
                    vec![("x-auth-reason".to_string(), "expired".to_string())]
                );
            }
            other => panic!("unexpected decision: {other:?}"),
        }
    }

    #[test]
    fn http_external_auth_response_mapping_dedupes_standard_redirect_and_challenge_headers() {
        let mut redirect_headers = http::HeaderMap::new();
        redirect_headers.insert(
            http::header::LOCATION,
            http::HeaderValue::from_static("https://login.example.com/"),
        );
        let redirect = map_http_external_auth_response(
            http::StatusCode::FOUND,
            &redirect_headers,
            Vec::new(),
            &["location".to_string()],
        )
        .expect("redirect decision");
        match redirect {
            ExternalAuthDecision::Redirect(response) => {
                assert!(response.headers.is_empty());
                assert_eq!(response.location, "https://login.example.com/");
            }
            other => panic!("unexpected decision: {other:?}"),
        }

        let mut challenge_headers = http::HeaderMap::new();
        challenge_headers.insert(
            http::header::WWW_AUTHENTICATE,
            http::HeaderValue::from_static("Bearer realm=\"spooky\""),
        );
        let challenge = map_http_external_auth_response(
            http::StatusCode::UNAUTHORIZED,
            &challenge_headers,
            b"challenge\n".to_vec(),
            &["www-authenticate".to_string()],
        )
        .expect("challenge decision");
        match challenge {
            ExternalAuthDecision::Challenge(response) => {
                assert!(response.headers.is_empty());
                assert_eq!(response.www_authenticate, "Bearer realm=\"spooky\"");
            }
            other => panic!("unexpected decision: {other:?}"),
        }
    }

    #[test]
    fn http_external_auth_response_mapping_requires_redirect_location() {
        let headers = http::HeaderMap::new();
        let err =
            map_http_external_auth_response(http::StatusCode::FOUND, &headers, Vec::new(), &[])
                .expect_err("redirect without location must fail");
        assert!(matches!(err, ProxyError::Transport(_)));
    }

    #[test]
    fn oidc_helper_predicates_match_expected_scope_and_audience_shapes() {
        assert!(oidc_scope_satisfied(
            &["read".to_string(), "write".to_string()],
            "read write admin"
        ));
        assert!(!oidc_scope_satisfied(
            &["read".to_string(), "write".to_string()],
            "read"
        ));

        assert!(oidc_audience_matches(
            Some("api://edge"),
            Some(&serde_json::Value::String("api://edge".to_string()))
        ));
        assert!(oidc_audience_matches(
            Some("api://edge"),
            Some(&serde_json::json!(["other", "api://edge"]))
        ));
        assert!(!oidc_audience_matches(
            Some("api://edge"),
            Some(&serde_json::Value::String("api://other".to_string()))
        ));
        assert!(oidc_audience_matches(None, None));
    }

    #[test]
    fn external_auth_failure_mode_helpers_track_fail_open() {
        let auth = RuntimeExternalAuth::Http {
            endpoint: "http://127.0.0.1:9000/auth".to_string(),
            request_headers: Vec::new(),
            response_header_allowlist: Vec::new(),
            timeout_ms: 250,
            failure_mode: RuntimeExternalAuthFailureMode::FailOpen,
        };

        assert_eq!(auth_timeout_ms(&auth), 250);
        assert!(fail_open(auth_failure_mode(&auth)));
    }
}
