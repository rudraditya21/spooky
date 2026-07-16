use spooky_errors::{UpstreamProxyErrorKind, classify_upstream_proxy_error};
use tokio::sync::mpsc::error::TryRecvError;

use super::*;
use crate::runtime::connection::{
    auth::ExternalAuthDecision, guardrails::is_unknown_length_response_prebuffer_reason,
};

impl QUICListener {
    /// Handle an already-resolved `ForwardResult`, applying health transitions
    /// and sending the H3 response.
    pub(super) fn handle_forward_result(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        req: &RequestEnvelope,
        result: ForwardResult,
        shared_ctx: &ForwardingSharedCtx<'_>,
    ) -> Result<(), quiche::h3::Error> {
        let metrics = shared_ctx.metrics.as_ref();
        let routing_index = shared_ctx.routing_index;
        let upstream_pools = shared_ctx.upstream_pools;
        let overload_retry_after_seconds = shared_ctx.resilience.shed_retry_after_seconds;

        let (backend_addr, backend_index) = match (&req.backend_addr, req.backend_index) {
            (Some(a), Some(i)) => (a.as_str(), i),
            _ => {
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(if req.method.is_empty() || req.path.is_empty() {
                        http::StatusCode::BAD_REQUEST.as_u16()
                    } else {
                        http::StatusCode::SERVICE_UNAVAILABLE.as_u16()
                    }),
                    RouteOutcome::Failure,
                    None,
                );
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

        let upstream_name = routing_index.lookup(&req.path, req.authority.as_deref());
        let upstream_pool = req
            .upstream_pool
            .as_ref()
            .cloned()
            .or_else(|| upstream_name.and_then(|n| upstream_pools.get(n)).cloned());

        match result {
            Ok(_) => {
                error!("Unexpected successful forward result in error handler path");
                metrics.inc_backend_error();
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(http::StatusCode::BAD_GATEWAY.as_u16()),
                    RouteOutcome::BackendError,
                    None,
                );
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
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(http::StatusCode::BAD_REQUEST.as_u16()),
                    RouteOutcome::Failure,
                    None,
                );
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
                let overload_reason =
                    if is_unknown_length_response_prebuffer_reason(&reason) {
                        metrics.inc_response_prebuffer_limit_reject();
                        OverloadShedReason::ResponsePrebufferCap
                    } else {
                        OverloadShedReason::BackendInflight
                    };
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(http::StatusCode::SERVICE_UNAVAILABLE.as_u16()),
                    RouteOutcome::OverloadShed,
                    Some(overload_reason),
                );
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
                metrics.inc_circuit_breaker_rejected();
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(http::StatusCode::SERVICE_UNAVAILABLE.as_u16()),
                    RouteOutcome::OverloadShed,
                    Some(OverloadShedReason::CircuitOpen),
                );
                Self::log_access(req, 503);
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    b"backend circuit open, retry later\n",
                    overload_retry_after_seconds,
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
                metrics.inc_backend_error();
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(http::StatusCode::BAD_GATEWAY.as_u16()),
                    RouteOutcome::BackendError,
                    None,
                );
                Self::log_access(req, 502);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_GATEWAY,
                    b"upstream error\n",
                )
            }
            Err(err) => {
                let Some(classified) = classify_upstream_proxy_error(&err) else {
                    error!(
                        "request_id={} upstream={} backend={} unclassified forward error: {:?}",
                        req.request_id,
                        req.upstream_name.as_deref().unwrap_or("-"),
                        backend_addr,
                        err
                    );
                    metrics.inc_backend_error();
                    Self::record_request_observation(
                        metrics,
                        req,
                        Some(http::StatusCode::BAD_GATEWAY.as_u16()),
                        RouteOutcome::BackendError,
                        None,
                    );
                    Self::log_access(req, 502);
                    return Self::send_simple_response(
                        h3,
                        quic,
                        stream_id,
                        http::StatusCode::BAD_GATEWAY,
                        b"upstream error\n",
                    );
                };
                Self::log_classified_upstream_failure(
                    "data_plane",
                    Some(req.request_id),
                    req.upstream_name.as_deref(),
                    backend_addr,
                    &classified,
                );
                Self::mark_classified_upstream_health_failure(
                    "data_plane",
                    backend_addr,
                    backend_index,
                    upstream_pool.as_ref(),
                    metrics,
                    &classified,
                );

                match classified.kind {
                    UpstreamProxyErrorKind::Timeout => {
                        metrics.inc_timeout();
                        Self::record_request_observation(
                            metrics,
                            req,
                            Some(http::StatusCode::SERVICE_UNAVAILABLE.as_u16()),
                            RouteOutcome::Timeout,
                            None,
                        );
                        Self::log_access(req, 503);
                        Self::send_simple_response(
                            h3,
                            quic,
                            stream_id,
                            http::StatusCode::SERVICE_UNAVAILABLE,
                            b"upstream timeout\n",
                        )
                    }
                    UpstreamProxyErrorKind::Tls => {
                        Self::record_request_observation(
                            metrics,
                            req,
                            Some(http::StatusCode::INTERNAL_SERVER_ERROR.as_u16()),
                            RouteOutcome::Failure,
                            None,
                        );
                        Self::log_access(req, 500);
                        Self::send_simple_response(
                            h3,
                            quic,
                            stream_id,
                            http::StatusCode::INTERNAL_SERVER_ERROR,
                            b"internal server error\n",
                        )
                    }
                    UpstreamProxyErrorKind::Protocol => {
                        metrics.inc_backend_error();
                        Self::record_request_observation(
                            metrics,
                            req,
                            Some(http::StatusCode::BAD_GATEWAY.as_u16()),
                            RouteOutcome::BackendError,
                            None,
                        );
                        Self::log_access(req, 502);
                        Self::send_simple_response(
                            h3,
                            quic,
                            stream_id,
                            http::StatusCode::BAD_GATEWAY,
                            b"upstream protocol error\n",
                        )
                    }
                    UpstreamProxyErrorKind::Send | UpstreamProxyErrorKind::Transport => {
                        metrics.inc_backend_error();
                        Self::record_request_observation(
                            metrics,
                            req,
                            Some(http::StatusCode::BAD_GATEWAY.as_u16()),
                            RouteOutcome::BackendError,
                            None,
                        );
                        Self::log_access(req, 502);
                        Self::send_simple_response(
                            h3,
                            quic,
                            stream_id,
                            http::StatusCode::BAD_GATEWAY,
                            b"upstream error\n",
                        )
                    }
                }
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

    pub(super) fn send_admission_rejection_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        response: &crate::quic_listener::admission::AdmissionRejectionResponse,
    ) -> Result<(), quiche::h3::Error> {
        let mut headers = vec![
            quiche::h3::Header::new(b":status", response.status.as_str().as_bytes()),
            quiche::h3::Header::new(b"content-type", b"text/plain"),
        ];
        if let Some(challenge) = response.www_authenticate {
            headers.push(quiche::h3::Header::new(
                b"www-authenticate",
                challenge.as_bytes(),
            ));
        }
        if let Some(retry_after_seconds) = response.retry_after_seconds {
            let retry_after = retry_after_seconds.max(1).to_string();
            headers.push(quiche::h3::Header::new(
                b"retry-after",
                retry_after.as_bytes(),
            ));
        }
        headers.push(quiche::h3::Header::new(
            b"content-length",
            response.body.len().to_string().as_bytes(),
        ));

        h3.send_response(quic, stream_id, &headers, false)?;
        h3.send_body(quic, stream_id, response.body, true)?;
        Ok(())
    }

    pub(super) fn send_response_with_headers(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        status: http::StatusCode,
        body: &[u8],
        headers: &[(String, String)],
    ) -> Result<(), quiche::h3::Error> {
        let mut resp_headers = vec![quiche::h3::Header::new(
            b":status",
            status.as_str().as_bytes(),
        )];
        let mut has_content_type = false;
        let mut has_content_length = false;
        for (name, value) in headers {
            if name.eq_ignore_ascii_case(http::header::CONTENT_TYPE.as_str()) {
                has_content_type = true;
            }
            if name.eq_ignore_ascii_case(http::header::CONTENT_LENGTH.as_str()) {
                has_content_length = true;
            }
            resp_headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
        }
        if !has_content_type {
            resp_headers.push(quiche::h3::Header::new(b"content-type", b"text/plain"));
        }
        if !has_content_length {
            resp_headers.push(quiche::h3::Header::new(
                b"content-length",
                body.len().to_string().as_bytes(),
            ));
        }
        h3.send_response(quic, stream_id, &resp_headers, false)?;
        h3.send_body(quic, stream_id, body, true)?;
        Ok(())
    }

    pub(super) fn send_external_auth_decision_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        decision: &ExternalAuthDecision,
    ) -> Result<(), quiche::h3::Error> {
        match decision {
            ExternalAuthDecision::Allow { .. } => Ok(()),
            ExternalAuthDecision::Deny(response) => Self::send_response_with_headers(
                h3,
                quic,
                stream_id,
                response.status,
                &response.body,
                &response.headers,
            ),
            ExternalAuthDecision::Redirect(response) => {
                let mut headers = response.headers.clone();
                headers.push((
                    http::header::LOCATION.as_str().to_string(),
                    response.location.clone(),
                ));
                Self::send_response_with_headers(
                    h3,
                    quic,
                    stream_id,
                    response.status,
                    &[],
                    &headers,
                )
            }
            ExternalAuthDecision::Challenge(response) => {
                let mut headers = response.headers.clone();
                headers.push((
                    http::header::WWW_AUTHENTICATE.as_str().to_string(),
                    response.www_authenticate.clone(),
                ));
                Self::send_response_with_headers(
                    h3,
                    quic,
                    stream_id,
                    response.status,
                    &response.body,
                    &headers,
                )
            }
        }
    }

    pub(super) fn flush_response_chunks(
        stream_id: u64,
        req: &mut RequestEnvelope,
        quic: &mut quiche::Connection,
        h3: &mut quiche::h3::Connection,
        shared_ctx: &ForwardingSharedCtx<'_>,
    ) -> bool {
        let metrics = shared_ctx.metrics.as_ref();
        let resilience = shared_ctx.resilience;
        let routing_index = shared_ctx.routing_index;
        let upstream_pools = shared_ctx.upstream_pools;
        let Some(rx) = &mut req.response_chunk_rx else {
            return false;
        };

        let mut terminal = false;
        loop {
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
                            req.pending_chunk = Some(ResponseChunk::Start { status, headers });
                            break;
                        }
                        Err(err) => {
                            error!(
                                "HTTP/3 send_response protocol error on stream {}: {:?}",
                                stream_id, err
                            );
                            req.phase = StreamPhase::Failed;
                            metrics.inc_backend_error();
                            Self::record_request_observation(
                                metrics,
                                req,
                                Some(status.as_u16()),
                                RouteOutcome::BackendError,
                                None,
                            );
                            resilience
                                .adaptive_admission
                                .observe(req.start.elapsed(), true);
                            terminal = true;
                            break;
                        }
                    }
                }
                ResponseChunk::Data(data) => match h3.send_body(quic, stream_id, &data, false) {
                    Ok(_) => {}
                    Err(quiche::h3::Error::StreamBlocked) => {
                        req.pending_chunk = Some(ResponseChunk::Data(data));
                        break;
                    }
                    Err(err) => {
                        error!(
                            "HTTP/3 send_body data protocol error on stream {}: {:?}",
                            stream_id, err
                        );
                        req.phase = StreamPhase::Failed;
                        metrics.inc_backend_error();
                        Self::record_request_observation(
                            metrics,
                            req,
                            req.response_status,
                            RouteOutcome::BackendError,
                            None,
                        );
                        resilience
                            .adaptive_admission
                            .observe(req.start.elapsed(), true);
                        terminal = true;
                        break;
                    }
                },
                ResponseChunk::Trailers { headers } => {
                    let mut h3_headers = Vec::with_capacity(headers.len());
                    for (name, value) in &headers {
                        h3_headers.push(quiche::h3::Header::new(name, value));
                    }
                    match h3.send_additional_headers(quic, stream_id, &h3_headers, false, false) {
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
                            metrics.inc_backend_error();
                            Self::record_request_observation(
                                metrics,
                                req,
                                req.response_status,
                                RouteOutcome::BackendError,
                                None,
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
                        metrics.inc_backend_error();
                        Self::record_request_observation(
                            metrics,
                            req,
                            req.response_status,
                            RouteOutcome::BackendError,
                            None,
                        );
                        resilience
                            .adaptive_admission
                            .observe(req.start.elapsed(), true);
                        terminal = true;
                        break;
                    }
                },
                ResponseChunk::Error(err) => {
                    let classified = classify_upstream_proxy_error(&err);
                    if !req.response_headers_sent {
                        let (status, body): (http::StatusCode, &[u8]) =
                            match (&err, classified.as_ref()) {
                                (ProxyError::Pool(PoolError::BackendOverloaded(_)), _) => (
                                    http::StatusCode::SERVICE_UNAVAILABLE,
                                    b"upstream response body too large\n",
                                ),
                                (_, Some(classified))
                                    if classified.kind == UpstreamProxyErrorKind::Timeout =>
                                {
                                    (http::StatusCode::SERVICE_UNAVAILABLE, b"upstream timeout\n")
                                }
                                _ => (http::StatusCode::BAD_GATEWAY, b"upstream error\n"),
                            };
                        let _ = Self::send_simple_response(h3, quic, stream_id, status, body);
                    } else {
                        let _ = h3.send_body(quic, stream_id, b"", true);
                    }
                    req.phase = StreamPhase::Failed;
                    let upstream_name = routing_index.lookup(&req.path, req.authority.as_deref());
                    let upstream_pool = upstream_name.and_then(|n| upstream_pools.get(n));
                    if let (Some(addr), Some(idx), Some(classified)) = (
                        req.backend_addr.as_deref(),
                        req.backend_index,
                        classified.as_ref(),
                    ) {
                        Self::mark_classified_upstream_health_failure(
                            "data_plane",
                            addr,
                            idx,
                            upstream_pool,
                            metrics,
                            classified,
                        );
                    } else if let (Some(idx), Some(pool)) = (req.backend_index, upstream_pool)
                        && let Some(t) = pool.write().ok().and_then(|mut p| {
                            p.pool
                                .mark_request_failure(idx, HealthFailureReason::HttpStatus5xx)
                        })
                        && let Some(addr) = &req.backend_addr
                    {
                        Self::log_health_transition(addr, t);
                    }
                    match err {
                        ProxyError::Timeout => {
                            metrics.inc_timeout();
                            Self::record_request_observation(
                                metrics,
                                req,
                                req.response_status
                                    .or(Some(http::StatusCode::SERVICE_UNAVAILABLE.as_u16())),
                                RouteOutcome::Timeout,
                                None,
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
                            let overload_reason =
                                if is_unknown_length_response_prebuffer_reason(&reason) {
                                    metrics.inc_response_prebuffer_limit_reject();
                                    OverloadShedReason::ResponsePrebufferCap
                                } else {
                                    OverloadShedReason::BackendInflight
                                };
                            Self::record_request_observation(
                                metrics,
                                req,
                                req.response_status
                                    .or(Some(http::StatusCode::SERVICE_UNAVAILABLE.as_u16())),
                                RouteOutcome::OverloadShed,
                                Some(overload_reason),
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
                            metrics.inc_backend_error();
                            Self::record_request_observation(
                                metrics,
                                req,
                                req.response_status
                                    .or(Some(http::StatusCode::BAD_GATEWAY.as_u16())),
                                RouteOutcome::BackendError,
                                None,
                            );
                            resilience
                                .adaptive_admission
                                .observe(req.start.elapsed(), true);
                            if let (Some(addr), Some(classified)) =
                                (req.backend_addr.as_deref(), classified.as_ref())
                            {
                                Self::log_classified_upstream_failure(
                                    "data_plane",
                                    Some(req.request_id),
                                    req.upstream_name.as_deref(),
                                    addr,
                                    classified,
                                );
                            } else {
                                error!(
                                    "Upstream {} body error: {:?}",
                                    req.backend_addr.as_deref().unwrap_or("?"),
                                    err
                                );
                            }
                        }
                    }
                    terminal = true;
                    break;
                }
            }
        }

        terminal
    }
}
