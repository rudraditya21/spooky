mod auth;
mod dispatch;
mod lb_key;
mod prepare;
mod resolve;
mod response;
mod stream_progress;

use std::{convert::Infallible, error::Error as StdError};

use spooky_config::config::ScopedRateLimitScope;

pub(in crate::quic_listener) use self::lb_key::{
    LbKeyRequestParts, LbKeyResolutionInput, ResolvedLbKey,
};
use self::prepare::{PreparedRequest, StartedAuthRequest};
pub(in crate::quic_listener) use self::resolve::BootstrapResolutionInput;
#[cfg(test)]
pub(in crate::quic_listener) use self::resolve::RouteResolutionRequest as TestRouteResolutionRequest;
use super::*;
use crate::runtime::connection::{request::PendingForward, stream::StreamAdmissionState};

pub(super) fn abort_stream(req: &mut RequestEnvelope, metrics: &Metrics) -> StreamPhase {
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

// Shared forwarding dependencies passed through extracted submodules.
pub(crate) struct ForwardingSharedCtx<'a> {
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) resilience: &'a RuntimeResilience,
    pub(crate) routing_index: &'a RouteIndex,
    pub(crate) upstream_pools: &'a HashMap<String, Arc<RwLock<UpstreamPool>>>,
}

pub(crate) struct ForwardingExecutionCtx<'a> {
    pub(crate) transport_pool: Arc<UpstreamTransportPool>,
    pub(crate) backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub(crate) backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
    pub(crate) upstream_inflight: &'a HashMap<String, Arc<Semaphore>>,
    pub(crate) global_inflight: Arc<Semaphore>,
    pub(crate) backend_timeout: Duration,
    pub(crate) inflight_acquire_wait: Duration,
}

pub(crate) struct StreamProgressConfig {
    pub(crate) backend_body_idle_timeout: Duration,
    pub(crate) backend_body_total_timeout: Duration,
    pub(crate) max_response_body_bytes: usize,
    pub(crate) unknown_length_response_prebuffer_bytes: usize,
    pub(crate) client_body_idle_timeout: Duration,
    pub(crate) listen_port: u16,
}

impl QUICListener {
    pub fn classify_upstream_failure_reason(
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

    pub(crate) fn send_error_health_failure_reason(
        err: &hyper_util::client::legacy::Error,
    ) -> (HealthFailureReason, &'static str) {
        let detail = Self::format_error_chain(err);
        Self::classify_upstream_failure_reason(err.is_connect(), &detail)
    }

    pub(crate) fn format_error_chain(err: &(dyn StdError + 'static)) -> String {
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

    fn log_access(req: &RequestEnvelope, status: u16) {
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

    fn materialize_forward_after_auth(
        stream_id: u64,
        req: &mut RequestEnvelope,
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        exec_ctx: &ForwardingExecutionCtx<'_>,
        shared_ctx: &ForwardingSharedCtx<'_>,
    ) -> Result<bool, quiche::h3::Error> {
        let metrics = shared_ctx.metrics.as_ref();
        let resilience = shared_ctx.resilience;
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

        let (
            backend_index,
            upstream_pool,
            global_permit,
            upstream_permit,
            adaptive_permit,
            route_queue_permit,
        ) = match crate::quic_listener::admission::execute_forwarding_post_auth_admission(
            resilience,
            &upstream_name,
            req.upstream_pool.as_ref(),
            req.backend_index,
            pending_forward.backend_index,
            exec_ctx.upstream_inflight,
            Arc::clone(&exec_ctx.global_inflight),
            exec_ctx.inflight_acquire_wait,
        ) {
            crate::quic_listener::admission::PostAuthAdmissionExecution::Ready(ready) => {
                if ready.waited_for_global_permit {
                    metrics.inc_inflight_wait_admit_global();
                }
                if ready.waited_for_upstream_permit {
                    metrics.inc_inflight_wait_admit_upstream();
                }
                (
                    ready.backend_index,
                    ready.upstream_pool,
                    ready.global_permit,
                    ready.upstream_permit,
                    ready.adaptive_permit,
                    ready.route_queue_permit,
                )
            }
            crate::quic_listener::admission::PostAuthAdmissionExecution::Rejected(
                crate::quic_listener::admission::PostAuthAdmissionRejection::Overloaded(decision),
            ) => {
                metrics.inc_failure();
                metrics.inc_overload_shed_reason(decision.reason.metrics_reason());
                metrics.record_route(
                    &upstream_name,
                    req.start.elapsed(),
                    RouteOutcome::OverloadShed,
                );
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    decision.body,
                    decision.retry_after_seconds,
                )?;
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                return Ok(false);
            }
            crate::quic_listener::admission::PostAuthAdmissionExecution::Rejected(
                crate::quic_listener::admission::PostAuthAdmissionRejection::Failed(decision),
            ) => {
                metrics.inc_failure();
                if let Some(reason) = decision.overload_reason {
                    metrics.inc_overload_shed_reason(reason.metrics_reason());
                }
                if let Some(route_outcome) = decision.route_outcome {
                    metrics.record_route(&upstream_name, req.start.elapsed(), route_outcome);
                }
                Self::send_simple_response(h3, quic, stream_id, decision.status, decision.body)?;
                if decision.observe_adaptive_overload {
                    resilience
                        .adaptive_admission
                        .observe(req.start.elapsed(), true);
                }
                return Ok(false);
            }
        };

        let Some(backend_endpoint) = exec_ctx
            .backend_endpoints
            .get(pending_forward.backend_addr.as_ref())
            .cloned()
        else {
            if let Ok(mut guard) = upstream_pool.write() {
                guard.finish_request(backend_index, req.start.elapsed(), Some(503));
            }
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
            exec_ctx,
            shared_ctx,
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
        Self::flush_request_buffer(req, metrics);
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

    pub(crate) fn log_health_transition(addr: &str, transition: HealthTransition) {
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
        let shared_ctx = ForwardingSharedCtx {
            metrics: Arc::clone(&metrics),
            resilience,
            routing_index,
            upstream_pools,
        };
        let exec_ctx = ForwardingExecutionCtx {
            transport_pool: Arc::clone(&transport_pool),
            backend_endpoints: Arc::clone(&backend_endpoints),
            backend_resolution_store: Arc::clone(&backend_resolution_store),
            upstream_inflight,
            global_inflight: Arc::clone(&global_inflight),
            backend_timeout,
            inflight_acquire_wait,
        };
        let progress_config = StreamProgressConfig {
            backend_body_idle_timeout,
            backend_body_total_timeout,
            max_response_body_bytes,
            unknown_length_response_prebuffer_bytes,
            client_body_idle_timeout,
            listen_port,
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
                                &exec_ctx,
                                &shared_ctx,
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
            &exec_ctx,
            &shared_ctx,
            &progress_config,
        )?;

        Ok(())
    }

    pub(crate) fn resolve_scoped_rate_limit_key(
        rule: &crate::resilience::scoped_rate_limit::ScopedRateLimitRule,
        route: &str,
        method: &str,
        path: &str,
        authority: Option<&str>,
        client_addr: SocketAddr,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> Option<String> {
        let request = LbKeyRequestParts::new(
            method,
            path,
            authority,
            None,
            Some(client_addr),
            header_lookup,
        );
        match rule.scope() {
            ScopedRateLimitScope::Route => Some(route.to_string()),
            ScopedRateLimitScope::Client => {
                Self::resolve_lb_key_from_parts(rule.key_spec().unwrap_or("peer_ip"), &request)
            }
            ScopedRateLimitScope::Tenant => rule
                .key_spec()
                .and_then(|key_spec| Self::resolve_lb_key_from_parts(key_spec, &request)),
            ScopedRateLimitScope::Token => {
                Self::resolve_lb_key_from_parts(rule.key_spec().unwrap_or("bearer_token"), &request)
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::time::UNIX_EPOCH;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use spooky_config::{
        config::{ScopedRateLimit, ScopedRateLimitScope},
        runtime::{
            RuntimeApiKeyAuth, RuntimeAuthPolicy, RuntimeExternalAuth,
            RuntimeExternalAuthFailureMode, RuntimeJwtAuth, RuntimeUpstreamPolicy,
        },
    };

    use super::{
        auth::{
            allowed_auth_headers, append_auth_request_headers, auth_allow_mutations,
            auth_failure_mode, auth_timeout_ms, fail_open, map_http_external_auth_response,
            oidc_audience_matches, oidc_scope_satisfied,
        },
        *,
    };
    use crate::runtime::connection::auth::{ExternalAuthDecision, PendingHeaderMutation};

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

        assert!(super::super::admission::api_key_is_authorized(
            &policy,
            Some(&lookup)
        ));
        assert!(!super::super::admission::api_key_is_authorized(
            &policy,
            Some(&wrong_lookup)
        ));
        assert!(!super::super::admission::api_key_is_authorized(
            &policy, None
        ));
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

        assert!(super::super::admission::jwt_is_authorized(
            &policy,
            Some(&lookup)
        ));
        assert!(
            super::super::admission::validated_hs256_jwt_claims(
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
            super::super::admission::validated_hs256_jwt_claims(token.as_str(), &wrong_secret, now)
                .is_none()
        );

        let expired = test_hs256_jwt(
            "jwt-secret",
            serde_json::json!({ "exp": 1_699_999_900u64 }),
            "HS256",
        );
        assert!(
            super::super::admission::validated_hs256_jwt_claims(
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

        assert!(super::super::admission::jwt_claims_satisfy_rbac(
            &policy,
            &allowed_claims
        ));
        assert!(!super::super::admission::jwt_claims_satisfy_rbac(
            &policy,
            &denied_claims
        ));
    }

    #[test]
    fn resolve_lb_key_from_parts_supports_peer_ip_and_bearer_token() {
        let headers = [("authorization".to_string(), "Bearer token-1".to_string())]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();
        let client_addr = "203.0.113.9:443".parse().expect("client addr");
        let request = LbKeyRequestParts::new(
            "GET",
            "/",
            Some("api.example.com"),
            None,
            Some(client_addr),
            Some(&lookup),
        );

        assert_eq!(
            QUICListener::resolve_lb_key_from_parts("peer_ip", &request).as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(
            QUICListener::resolve_lb_key_from_parts("bearer_token", &request).as_deref(),
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
