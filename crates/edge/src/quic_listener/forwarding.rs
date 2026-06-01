use super::*;
use std::error::Error as StdError;

#[derive(Clone)]
pub(super) struct ForwardRequestMeta {
    pub(super) method: Arc<str>,
    pub(super) path: Arc<str>,
    pub(super) authority: Option<Arc<str>>,
    pub(super) headers: Arc<Vec<quiche::h3::Header>>,
    pub(super) client_addr: SocketAddr,
    pub(super) request_id: u64,
    pub(super) traceparent: Option<Arc<str>>,
    pub(super) host_policy: UpstreamHostPolicy,
    pub(super) forwarded_header_policy: ForwardedHeaderPolicy,
}

impl ForwardRequestMeta {
    pub(super) fn build_bodyless_request(
        &self,
        endpoint: &BackendEndpoint,
    ) -> Result<Request<BoxBody<Bytes, std::convert::Infallible>>, ProxyError> {
        build_h2_request_for_endpoint_with_host_policy(
            endpoint,
            &self.host_policy,
            &self.forwarded_header_policy,
            &self.method,
            &self.path,
            self.headers.as_slice(),
            BoxBody::new(Full::new(Bytes::new())),
            Some(0),
            ForwardedContext {
                client_addr: self.client_addr,
                request_authority: self.authority.as_deref(),
                request_id: self.request_id,
                traceparent: self.traceparent.as_deref(),
            },
        )
        .map_err(ProxyError::from)
    }
}

pub(crate) fn abort_stream(req: &mut RequestEnvelope, metrics: &Metrics) -> StreamPhase {
    let phase = req.phase.clone();
    if !req.backend_request_finished {
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
    req.upstream_result_rx = None;
    req.response_chunk_rx = None;
    req.pending_chunk = None;
    req.global_inflight_permit = None;
    req.upstream_inflight_permit = None;
    req.adaptive_admission_permit = None;
    req.route_queue_permit = None;
    phase
}

impl QUICListener {
    fn classify_send_error_detail(is_connect: bool, detail: &str) -> HealthFailureReason {
        let normalized = detail.to_ascii_lowercase();
        if normalized.contains("timeout") || normalized.contains("timed out") {
            return HealthFailureReason::Timeout;
        }

        if is_connect
            && (normalized.contains("tls")
                || normalized.contains("rustls")
                || normalized.contains("webpki")
                || normalized.contains("certificate")
                || normalized.contains("x509")
                || normalized.contains("hostname")
                || normalized.contains("dns name")
                || normalized.contains("subjectaltname")
                || normalized.contains("unknownissuer")
                || normalized.contains("invalidcertificate")
                || normalized.contains("alpn"))
        {
            return HealthFailureReason::Tls;
        }

        HealthFailureReason::Transport
    }

    fn send_error_health_failure_reason(
        err: &hyper_util::client::legacy::Error,
    ) -> HealthFailureReason {
        let detail = Self::format_error_chain(err);
        Self::classify_send_error_detail(err.is_connect(), &detail)
    }

    fn format_error_chain(err: &(dyn StdError + 'static)) -> String {
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

    pub(super) fn pick_alternate_backend(
        upstream_pool: &Arc<RwLock<UpstreamPool>>,
        primary_index: usize,
    ) -> Option<(String, usize)> {
        let pool = upstream_pool.read().ok()?;
        for index in pool.pool.healthy_indices_iter() {
            if index == primary_index {
                continue;
            }
            if let Some(address) = pool.pool.address(index) {
                return Some((address.to_string(), index));
            }
        }
        None
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

    /// Handle an already-resolved `ForwardResult`, applying health transitions
    /// and sending the H3 response.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_forward_result(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        req: &RequestEnvelope,
        result: ForwardResult,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        routing_index: &RouteIndex,
        metrics: &Metrics,
        overload_retry_after_seconds: u32,
    ) -> Result<(), quiche::h3::Error> {
        let start = req.start;
        let route_label = req.upstream_name.as_deref().unwrap_or("unrouted");

        // If routing failed at Headers time, return an appropriate error now.
        let (backend_addr, backend_index) = match (&req.backend_addr, req.backend_index) {
            (Some(a), Some(i)) => (a.as_str(), i),
            _ => {
                metrics.inc_failure();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::Failure);
                return Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    if req.method.is_empty() || req.path.is_empty() {
                        http::StatusCode::BAD_REQUEST
                    } else {
                        http::StatusCode::SERVICE_UNAVAILABLE
                    },
                    b"no upstream available\n",
                );
            }
        };

        // Re-acquire the upstream pool for health marking.
        let upstream_name = routing_index.lookup(&req.path, req.authority.as_deref());
        let upstream_pool = req
            .upstream_pool
            .as_ref()
            .cloned()
            .or_else(|| upstream_name.and_then(|n| upstream_pools.get(n)).cloned());

        match result {
            Ok(_) => {
                error!("Unexpected successful forward result in error handler path");
                metrics.inc_failure();
                metrics.inc_backend_error();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::BackendError);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_GATEWAY,
                    b"unexpected upstream state\n",
                )
            }
            Err(ProxyError::Bridge(err)) => {
                error!("Bridge error: {:?}", err);
                metrics.inc_failure();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::Failure);
                Self::log_access(req, 400);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_REQUEST,
                    b"invalid request\n",
                )
            }
            Err(ProxyError::Pool(PoolError::BackendOverloaded(reason))) => {
                metrics.inc_failure();
                if reason.contains("unknown-length response prebuffer limit exceeded") {
                    metrics.inc_response_prebuffer_limit_reject();
                    metrics.inc_overload_shed_reason(OverloadShedReason::ResponsePrebufferCap);
                } else {
                    metrics.inc_overload_shed_reason(OverloadShedReason::BackendInflight);
                }
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::OverloadShed);
                Self::log_access(req, 503);
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    b"backend overloaded, retry later\n",
                    overload_retry_after_seconds,
                )
            }
            Err(ProxyError::Pool(PoolError::CircuitOpen(_))) => {
                metrics.inc_failure();
                metrics.inc_circuit_breaker_rejected();
                metrics.inc_overload_shed_reason(OverloadShedReason::CircuitOpen);
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::OverloadShed);
                Self::log_access(req, 503);
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    b"backend circuit open, retry later\n",
                    overload_retry_after_seconds,
                )
            }
            Err(ProxyError::Pool(PoolError::Send(ref send_err))) => {
                // Log full upstream send/connect detail and map it into a backend
                // health failure reason so repeated failures can eject unhealthy backends.
                let send_err_detail = Self::format_error_chain(send_err);
                let failure_reason = Self::send_error_health_failure_reason(send_err);
                error!(
                    "Upstream send failed for {} (health_reason={:?}): {}",
                    backend_addr, failure_reason, send_err_detail
                );
                metrics.inc_health_failure(failure_reason);
                if let Some(pool) = &upstream_pool
                    && let Some(t) = pool.write().ok().and_then(|mut p| {
                        p.pool.mark_request_failure(backend_index, failure_reason)
                    })
                {
                    Self::log_health_transition(backend_addr, t);
                }
                metrics.inc_failure();
                metrics.inc_backend_error();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::BackendError);
                Self::log_access(req, 502);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_GATEWAY,
                    b"upstream error\n",
                )
            }
            Err(ProxyError::Transport(err)) => {
                error!(
                    "request_id={} upstream={} backend={} Upstream transport error: {}",
                    req.request_id,
                    req.upstream_name.as_deref().unwrap_or("-"),
                    backend_addr,
                    err
                );
                metrics.inc_health_failure(HealthFailureReason::Transport);
                if let Some(pool) = &upstream_pool
                    && let Some(t) = pool.write().ok().and_then(|mut p| {
                        p.pool
                            .mark_request_failure(backend_index, HealthFailureReason::Transport)
                    })
                {
                    Self::log_health_transition(backend_addr, t);
                }
                metrics.inc_failure();
                metrics.inc_backend_error();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::BackendError);
                Self::log_access(req, 502);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_GATEWAY,
                    b"upstream error\n",
                )
            }
            Err(ProxyError::Pool(pool_err @ PoolError::InflightLimiterClosed))
            | Err(ProxyError::Pool(pool_err @ PoolError::UnknownBackend(_))) => {
                debug_assert!(Self::is_internal_pool_control_error(&pool_err));
                match &pool_err {
                    PoolError::InflightLimiterClosed => {
                        error!("Upstream pool inflight limiter closed");
                    }
                    PoolError::UnknownBackend(_) => {
                        error!("Upstream pool unknown backend");
                    }
                    _ => {}
                }
                metrics.inc_failure();
                metrics.inc_backend_error();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::BackendError);
                Self::log_access(req, 502);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_GATEWAY,
                    b"upstream error\n",
                )
            }
            Err(ProxyError::Protocol(err)) => {
                error!("request_id={} Protocol error: {}", req.request_id, err);
                metrics.inc_failure();
                metrics.inc_backend_error();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::BackendError);
                Self::log_access(req, 502);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_GATEWAY,
                    b"upstream protocol error\n",
                )
            }
            Err(ProxyError::Timeout) => {
                error!("request_id={} Upstream request timed out", req.request_id);
                metrics.inc_health_failure(HealthFailureReason::Timeout);
                if let Some(pool) = &upstream_pool
                    && let Some(t) = pool.write().ok().and_then(|mut p| {
                        p.pool
                            .mark_request_failure(backend_index, HealthFailureReason::Timeout)
                    })
                {
                    Self::log_health_transition(backend_addr, t);
                }
                metrics.inc_failure();
                metrics.inc_timeout();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::Timeout);
                Self::log_access(req, 503);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    b"upstream timeout\n",
                )
            }
            Err(ProxyError::Tls(err)) => {
                error!("TLS error: {}", err);
                metrics.inc_health_failure(HealthFailureReason::Tls);
                metrics.inc_failure();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::Failure);
                Self::log_access(req, 500);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    b"internal server error\n",
                )
            }
        }
    }

    pub(super) fn send_simple_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        status: http::StatusCode,
        body: &[u8],
    ) -> Result<(), quiche::h3::Error> {
        let resp_headers = vec![
            quiche::h3::Header::new(b":status", status.as_str().as_bytes()),
            quiche::h3::Header::new(b"content-type", b"text/plain"),
            quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
        ];

        h3.send_response(quic, stream_id, &resp_headers, false)?;
        h3.send_body(quic, stream_id, body, true)?;
        Ok(())
    }

    pub(super) fn send_overload_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        body: &[u8],
        retry_after_seconds: u32,
    ) -> Result<(), quiche::h3::Error> {
        let retry_after = retry_after_seconds.max(1).to_string();
        let resp_headers = vec![
            quiche::h3::Header::new(
                b":status",
                http::StatusCode::SERVICE_UNAVAILABLE.as_str().as_bytes(),
            ),
            quiche::h3::Header::new(b"content-type", b"text/plain"),
            quiche::h3::Header::new(b"retry-after", retry_after.as_bytes()),
            quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
        ];

        h3.send_response(quic, stream_id, &resp_headers, false)?;
        h3.send_body(quic, stream_id, body, true)?;
        Ok(())
    }

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

#[cfg(test)]
mod tests {
    use super::*;

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
            QUICListener::classify_send_error_detail(
                true,
                "client error (Connect): tls handshake failed: invalid certificate"
            ),
            HealthFailureReason::Tls
        );
    }

    #[test]
    fn send_connect_error_without_tls_details_maps_to_transport_health_failure() {
        assert_eq!(
            QUICListener::classify_send_error_detail(
                true,
                "client error (Connect): connection refused"
            ),
            HealthFailureReason::Transport
        );
    }

    #[test]
    fn send_error_with_timeout_detail_maps_to_timeout_health_failure() {
        assert_eq!(
            QUICListener::classify_send_error_detail(false, "request timed out"),
            HealthFailureReason::Timeout
        );
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
}
