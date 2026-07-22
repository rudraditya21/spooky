use super::*;
use crate::runtime::connection::{
    auth::ExternalAuthResult,
    guardrails::{
        BodyLimitKind, BodyTimeoutKind, ProgressiveEmissionPolicy, RESPONSE_BODY_TOO_LARGE_BODY,
        RequestBodyGuardrailConfig, RequestBodyGuardrailDecision, RequestBodyGuardrailInput,
        ResponseBodyGuardrailConfig, ResponseBodyGuardrailDecision, ResponseBodyGuardrailInput,
        checked_request_body_ingress, checked_response_body_guardrails,
        evaluate_request_body_timeouts, response_body_limit_reason, response_chunk_ranges,
    },
    response::ForwardingPolicyTelemetry,
};

fn record_forwarding_policy_metrics(metrics: &Metrics, policy: &ForwardingPolicyTelemetry) {
    if let Some(reason) = policy.hedge.trigger_reason {
        metrics.inc_hedge_trigger(reason);
    }
    if let Some(reason) = policy.hedge.outcome_reason {
        metrics.inc_hedge_outcome(reason);
    }
    if policy.hedge.primary_late_ms > 0 {
        metrics.observe_hedge_primary_late_ms(policy.hedge.primary_late_ms);
    }
    if let Some(reason) = policy.retry.attempt_reason {
        metrics.inc_retry_attempt(reason);
    }
    if let Some(reason) = policy.retry.denial_reason {
        metrics.inc_retry_denied(reason);
    }
}

fn response_body_guardrail_error(decision: ResponseBodyGuardrailDecision) -> Option<ProxyError> {
    match decision {
        ResponseBodyGuardrailDecision::Continue { .. } => None,
        ResponseBodyGuardrailDecision::Timeout { .. } => Some(ProxyError::Timeout),
        ResponseBodyGuardrailDecision::Reject {
            kind: BodyLimitKind::BodySize,
        } => Some(ProxyError::Pool(PoolError::BackendOverloaded(
            response_body_limit_reason(BodyLimitKind::BodySize).into(),
        ))),
        ResponseBodyGuardrailDecision::Reject {
            kind: BodyLimitKind::UnknownLengthPrebuffer,
        } => Some(ProxyError::Pool(PoolError::BackendOverloaded(
            response_body_limit_reason(BodyLimitKind::UnknownLengthPrebuffer).into(),
        ))),
        ResponseBodyGuardrailDecision::Reject { .. } => {
            Some(ProxyError::Pool(PoolError::BackendOverloaded(
                response_body_limit_reason(BodyLimitKind::BufferedBody).into(),
            )))
        }
    }
}

impl QUICListener {
    pub(in crate::quic_listener) fn push_request_chunk(
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
                bytes_received: req.body_bytes_received(),
                buffered_bytes: req.body_buf_bytes(),
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
        req.set_body_buf_bytes(next_state.buffered_bytes);
        req.body_buf_mut().push_back(chunk);
        Ok(())
    }

    pub(in crate::quic_listener) fn enqueue_request_chunk(
        req: &mut RequestEnvelope,
        chunk: Bytes,
        metrics: &Metrics,
        max_request_body_bytes: usize,
        request_buffer_global_cap_bytes: usize,
    ) -> Result<(), RequestBufferError> {
        if let Some(tx) = req.body_tx().cloned() {
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
                    if req.body_buf_bytes() > 0 {
                        metrics.release_request_buffer(req.body_buf_bytes());
                    }
                    req.clear_body_tx();
                    req.body_buf_mut().clear();
                    req.set_body_buf_bytes(0);
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

    pub(in crate::quic_listener) fn flush_request_buffer(
        req: &mut RequestEnvelope,
        metrics: &Metrics,
    ) {
        let Some(tx) = req.body_tx().cloned() else {
            return;
        };

        loop {
            let Some(chunk) = req.body_buf_mut().pop_front() else {
                break;
            };
            let len = chunk.len();
            match tx.try_send(chunk) {
                Ok(()) => {
                    req.set_body_buf_bytes(req.body_buf_bytes().saturating_sub(len));
                    metrics.release_request_buffer(len);
                }
                Err(TrySendError::Full(chunk)) => {
                    req.body_buf_mut().push_front(chunk);
                    break;
                }
                Err(TrySendError::Closed(_chunk)) => {
                    if req.body_buf_bytes() > 0 {
                        metrics.release_request_buffer(req.body_buf_bytes());
                    }
                    req.body_buf_mut().clear();
                    req.set_body_buf_bytes(0);
                    req.clear_body_tx();
                    break;
                }
            }
        }
    }

    /// Advance all in-flight streams without blocking.
    ///
    /// Called after every packet-driven `handle_h3` pass and from
    /// `handle_timeouts` so progress continues even when no new client
    /// packets arrive.
    ///
    /// Per stream, in order:
    /// 1. Drain request body buffer -> body channel (`try_send`).
    /// 2. Close body channel once FIN received and buffer empty.
    /// 3. Poll `upstream_result_rx` (`try_recv`).
    ///    - Error result  -> send error response, mark terminal.
    ///    - Ok result     -> send H3 response headers, spawn body-pump task,
    ///      store `response_chunk_rx`, transition to SendingResponse.
    /// 4. Flush `response_chunk_rx` chunks into H3 (`try_recv` loop).
    ///    - `Data`     -> `h3.send_body(..., false)`
    ///    - `Trailers` -> `h3.send_additional_headers(..., true, false)`
    ///    - `End`      -> `h3.send_body(..., true)`, mark Completed
    ///    - `Error`    -> send 502, mark Failed
    /// 5. Remove streams in terminal phase (Completed / Failed).
    pub(in crate::quic_listener) fn advance_streams_non_blocking(
        streams: &mut HashMap<u64, RequestEnvelope>,
        quic: &mut quiche::Connection,
        h3: &mut quiche::h3::Connection,
        exec_ctx: &ForwardingExecutionCtx<'_>,
        shared_ctx: &ForwardingSharedCtx<'_>,
        progress_config: &StreamProgressConfig,
    ) -> Result<(), quiche::h3::Error> {
        let metrics = shared_ctx.metrics.as_ref();
        let resilience = shared_ctx.resilience;
        let stream_ids: Vec<u64> = streams.keys().copied().collect();

        for stream_id in stream_ids {
            let now = Instant::now();
            if let Some(req) = streams.get(&stream_id)
                && req.phase() == StreamPhase::ReceivingRequest
                && !req.request_fin_received()
                && !req.bodyless_mode
            {
                let timeout_decision = evaluate_request_body_timeouts(
                    RequestBodyGuardrailConfig {
                        idle_timeout: progress_config.client_body_idle_timeout,
                        total_timeout: req
                            .total_request_deadline
                            .checked_duration_since(req.start)
                            .unwrap_or_default(),
                        max_body_bytes: usize::MAX,
                        max_buffered_bytes: usize::MAX,
                    },
                    RequestBodyGuardrailInput {
                        elapsed: req.start.elapsed(),
                        idle_for: now.saturating_duration_since(req.last_body_activity()),
                        bytes_received: req.body_bytes_received(),
                        buffered_bytes: req.body_buf_bytes(),
                        next_chunk_bytes: 0,
                        declared_content_length: None,
                        exempt_from_body_size_cap: false,
                    },
                );

                if matches!(
                    timeout_decision,
                    RequestBodyGuardrailDecision::Timeout {
                        kind: BodyTimeoutKind::Total,
                    }
                ) {
                    if let Err(protocol_err) = Self::handle_forward_result(
                        h3,
                        quic,
                        stream_id,
                        req,
                        Err(ProxyError::Timeout),
                        shared_ctx,
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

                if matches!(
                    timeout_decision,
                    RequestBodyGuardrailDecision::Timeout {
                        kind: BodyTimeoutKind::Idle,
                    }
                ) {
                    metrics.inc_timeout();
                    let _ = crate::runtime::connection::outcome::observe_proxy_error_outcome(
                        metrics,
                        crate::runtime::connection::outcome::OutcomeRouteTarget {
                            route: req.upstream_name.as_deref().unwrap_or("unrouted"),
                        },
                        Some(crate::runtime::connection::outcome::OutcomeBackendTarget {
                            upstream: req.upstream_name.as_deref().unwrap_or("unrouted"),
                            backend_addr: req.backend_addr.as_deref(),
                            backend_index: req.backend_index,
                        }),
                        req.start.elapsed(),
                        Some(http::StatusCode::REQUEST_TIMEOUT),
                        &ProxyError::Timeout,
                        None,
                    );
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
            }

            if let Some(req) = streams.get(&stream_id)
                && now >= req.total_request_deadline
            {
                if let Err(protocol_err) = Self::handle_forward_result(
                    h3,
                    quic,
                    stream_id,
                    req,
                    Err(ProxyError::Timeout),
                    shared_ctx,
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

            if let Some(req) = streams.get_mut(&stream_id) {
                Self::flush_request_buffer(req, metrics);
                if req.request_fin_received() && req.body_buf().is_empty() {
                    req.clear_body_tx();
                }
            }

            let auth_ready: Option<ExternalAuthResult> = if streams
                .get(&stream_id)
                .is_some_and(|req| req.admission_state() == StreamAdmissionState::WaitingForAuth)
            {
                if streams
                    .get(&stream_id)
                    .and_then(RequestEnvelope::auth_deadline)
                    .is_some_and(|deadline| Instant::now() >= deadline)
                {
                    Some(Err(ProxyError::Timeout))
                } else {
                    streams
                        .get_mut(&stream_id)
                        .and_then(RequestEnvelope::auth_result_rx_mut)
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
                        exec_ctx,
                        shared_ctx,
                    )?
                } else {
                    false
                };
                if !keep_stream {
                    if let Some(req) = streams.get_mut(&stream_id) {
                        abort_stream(req, metrics);
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
                    .and_then(RequestEnvelope::upstream_result_rx_mut)
                    .and_then(|rx| match rx.try_recv() {
                        Ok(result) => Some(result),
                        Err(oneshot::error::TryRecvError::Empty) => None,
                        Err(oneshot::error::TryRecvError::Closed) => Some(UpstreamResult {
                            forward: Err(ProxyError::Transport(
                                "upstream task dropped sender".into(),
                            )),
                            policy: ForwardingPolicyTelemetry::default(),
                        }),
                    })
            } else {
                None
            };

            if let Some(forward_result) = upstream_ready {
                record_forwarding_policy_metrics(metrics, &forward_result.policy);

                if let Some(req) = streams.get_mut(&stream_id) {
                    req.clear_upstream_result_rx();
                    req.retry_count = forward_result.policy.retry.count;
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
                        let response_body_mode = if tunnel_response {
                            ResponseBodyMode::TunnelSuccess
                        } else if suppress_downstream_body {
                            ResponseBodyMode::HeadRequest
                        } else {
                            ResponseBodyMode::Normal
                        };
                        let upstream_content_length = resp_headers
                            .get(http::header::CONTENT_LENGTH)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<usize>().ok());
                        let normalized_response =
                            normalize_upstream_response(ResponseNormalizationInput {
                                upstream: spooky_bridge::response::UpstreamResponseView {
                                    status,
                                    headers: &resp_headers,
                                    trailers: None,
                                },
                                body_mode: response_body_mode,
                                constraints: ResponseProtocolConstraints {
                                    protocol: ResponseNormalizationProtocol::Http3,
                                    strip_connection_headers: true,
                                    allow_trailers: true,
                                    preserve_upgrade: false,
                                },
                            });
                        let body_forwarding_enabled = matches!(
                            normalized_response.emission.body,
                            ResponseBodyPolicy::Forward
                        );
                        let progressive_body_emission_allowed =
                            !normalized_response.emission.emit_end_stream_on_headers;
                        let response_guardrails = ResponseBodyGuardrailConfig {
                            idle_timeout: progress_config.backend_body_idle_timeout,
                            total_timeout: progress_config.backend_body_total_timeout,
                            max_body_bytes: progress_config.max_response_body_bytes,
                            unknown_length_prebuffer_bytes: progress_config
                                .unknown_length_response_prebuffer_bytes,
                            chunk_bytes: RESPONSE_CHUNK_BYTES_LIMIT,
                        };
                        let preflight_guardrail = checked_response_body_guardrails(
                            response_guardrails,
                            ResponseBodyGuardrailInput {
                                elapsed: Duration::ZERO,
                                idle_for: Duration::ZERO,
                                bytes_received: 0,
                                prebuffered_bytes: 0,
                                next_chunk_bytes: 0,
                                declared_content_length: upstream_content_length,
                                headers_emitted: false,
                                progressive_emission_allowed: progressive_body_emission_allowed,
                                body_forwarding_enabled,
                                exempt_from_body_size_cap: tunnel_response,
                            },
                        );
                        if matches!(
                            preflight_guardrail,
                            Err(ResponseBodyGuardrailDecision::Reject {
                                kind: BodyLimitKind::BodySize,
                            })
                        ) {
                            if let Some(req) = streams.get(&stream_id) {
                                let _ = crate::runtime::connection::outcome::observe_proxy_error_outcome(
                                    metrics,
                                    crate::runtime::connection::outcome::OutcomeRouteTarget {
                                        route: req.upstream_name.as_deref().unwrap_or("unrouted"),
                                    },
                                    Some(crate::runtime::connection::outcome::OutcomeBackendTarget {
                                        upstream: req.upstream_name.as_deref().unwrap_or("unrouted"),
                                        backend_addr: req.backend_addr.as_deref(),
                                        backend_index: req.backend_index,
                                    }),
                                    req.start.elapsed(),
                                    Some(http::StatusCode::SERVICE_UNAVAILABLE),
                                    &ProxyError::Pool(PoolError::BackendOverloaded(
                                        "response prebuffer cap".into(),
                                    )),
                                    Some(OverloadShedReason::ResponsePrebufferCap),
                                );
                                resilience
                                    .adaptive_admission
                                    .observe(req.start.elapsed(), true);
                                warn!(
                                    "request_id={} upstream declared content-length over cap ({} > {}) on stream {}",
                                    req.request_id,
                                    upstream_content_length.unwrap_or_default(),
                                    progress_config.max_response_body_bytes,
                                    stream_id
                                );
                                let _ = Self::send_simple_response(
                                    h3,
                                    quic,
                                    stream_id,
                                    http::StatusCode::SERVICE_UNAVAILABLE,
                                    RESPONSE_BODY_TOO_LARGE_BODY,
                                );
                            }
                            if let Some(req) = streams.get_mut(&stream_id) {
                                abort_stream(req, metrics);
                            }
                            streams.remove(&stream_id);
                            continue;
                        }
                        let mut owned_h3_headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
                        for header in &normalized_response.head.headers {
                            owned_h3_headers.push((
                                header.name.as_str().as_bytes().to_vec(),
                                header.value.as_bytes().to_vec(),
                            ));
                        }
                        owned_h3_headers.push((
                            b"alt-svc".to_vec(),
                            format!("h3=\":{}\"; ma=86400", progress_config.listen_port)
                                .into_bytes(),
                        ));

                        let defer_headers_until_body_validated = matches!(
                            preflight_guardrail,
                            Ok(crate::runtime::connection::guardrails::EvaluatedResponseBodyGuardrail {
                                streaming,
                                ..
                            })
                                if matches!(
                                    streaming.emission,
                                    ProgressiveEmissionPolicy::PrebufferUntilValidated
                                )
                        );
                        let immediate_end = normalized_response.emission.emit_end_stream_on_headers;
                        let mut immediate_terminal = false;

                        if !defer_headers_until_body_validated {
                            let mut h3_headers = Vec::with_capacity(owned_h3_headers.len() + 1);
                            h3_headers.push(quiche::h3::Header::new(
                                b":status",
                                normalized_response.head.status.as_str().as_bytes(),
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
                                        shared_ctx,
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
                                    normalized_response.head.status.as_str().as_bytes(),
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
                                            shared_ctx,
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
                                req.transition_to_streaming_response(
                                    None,
                                    true,
                                    StreamPhase::Completed,
                                );
                                req.response_status = Some(status.as_u16());
                            }
                            immediate_terminal = true;
                        } else if let Some(chunk_rx) = prebuilt_response_chunk_rx {
                            if let Some(req) = streams.get_mut(&stream_id) {
                                req.transition_to_streaming_response(
                                    Some(chunk_rx),
                                    true,
                                    StreamPhase::SendingResponse,
                                );
                                req.response_status = Some(status.as_u16());
                            }
                        } else {
                            let (chunk_tx, chunk_rx) =
                                mpsc::channel::<ResponseChunk>(RESPONSE_CHUNK_CHANNEL_CAPACITY);
                            let fail_tx = chunk_tx.clone();
                            let deferred_status = status;
                            let deferred_headers = owned_h3_headers.clone();
                            let tunnel_mode = tunnel_response;
                            let progressive_emission_allowed = progressive_body_emission_allowed;
                            let fut = async move {
                                use http_body_util::BodyExt;
                                let Some(mut body) = response_body else {
                                    let _ = chunk_tx
                                        .send(ResponseChunk::Error(ProxyError::Transport(
                                            "non-tunnel responses must carry an HTTP body stream"
                                                .into(),
                                        )))
                                        .await;
                                    return;
                                };
                                let body_started_at = tokio::time::Instant::now();
                                let mut last_body_progress_at = body_started_at;
                                let mut response_bytes_received: usize = 0;
                                let mut prebuffered_bytes: usize = 0;
                                let mut buffered_chunks: Vec<Bytes> = Vec::new();
                                let mut buffered_trailers: Option<Vec<(Vec<u8>, Vec<u8>)>> = None;
                                loop {
                                    let wait_decision = checked_response_body_guardrails(
                                        response_guardrails,
                                        ResponseBodyGuardrailInput {
                                            elapsed: body_started_at.elapsed(),
                                            idle_for: last_body_progress_at.elapsed(),
                                            bytes_received: response_bytes_received,
                                            prebuffered_bytes,
                                            next_chunk_bytes: 0,
                                            declared_content_length: upstream_content_length,
                                            headers_emitted: !defer_headers_until_body_validated,
                                            progressive_emission_allowed,
                                            body_forwarding_enabled,
                                            exempt_from_body_size_cap: tunnel_mode,
                                        },
                                    );
                                    let streaming = match wait_decision {
                                        Ok(evaluated) => evaluated.streaming,
                                        other => {
                                            if let Err(other) = other
                                                && let Some(err) =
                                                    response_body_guardrail_error(other)
                                            {
                                                let _ =
                                                    chunk_tx.send(ResponseChunk::Error(err)).await;
                                            }
                                            return;
                                        }
                                    };
                                    let frame_fut = BodyExt::frame(&mut body);
                                    let result =
                                        tokio::time::timeout(streaming.wait_timeout, frame_fut)
                                            .await;
                                    match result {
                                        Err(_elapsed) => {
                                            let _ = chunk_tx
                                                .send(ResponseChunk::Error(ProxyError::Timeout))
                                                .await;
                                            return;
                                        }
                                        Ok(Some(Ok(f))) => {
                                            match f.into_data() {
                                                Ok(data) => {
                                                    if !data.is_empty() {
                                                        last_body_progress_at =
                                                            tokio::time::Instant::now();
                                                    }
                                                    let data_decision = checked_response_body_guardrails(
                                                    response_guardrails,
                                                    ResponseBodyGuardrailInput {
                                                        elapsed: body_started_at.elapsed(),
                                                        idle_for: last_body_progress_at.elapsed(),
                                                        bytes_received: response_bytes_received,
                                                        prebuffered_bytes,
                                                        next_chunk_bytes: data.len(),
                                                        declared_content_length: upstream_content_length,
                                                        headers_emitted: !defer_headers_until_body_validated,
                                                        progressive_emission_allowed,
                                                        body_forwarding_enabled,
                                                        exempt_from_body_size_cap: tunnel_mode,
                                                    },
                                                );
                                                    let evaluated =
                                                        match data_decision {
                                                            Ok(evaluated) => evaluated,
                                                            other => {
                                                                if let Err(other) = other
                                                            && let Some(err) =
                                                                response_body_guardrail_error(other)
                                                        {
                                                            let _ = chunk_tx
                                                                .send(ResponseChunk::Error(err))
                                                                .await;
                                                        }
                                                                return;
                                                            }
                                                        };
                                                    let streaming = evaluated.streaming;
                                                    response_bytes_received =
                                                        evaluated.next_state.bytes_received;
                                                    prebuffered_bytes =
                                                        evaluated.next_state.prebuffered_bytes;
                                                    for (start, end) in response_chunk_ranges(
                                                        data.len(),
                                                        streaming.chunk_emission,
                                                    ) {
                                                        let chunk = data.slice(start..end);
                                                        match streaming.emission {
                                                        ProgressiveEmissionPolicy::PrebufferUntilValidated => {
                                                            buffered_chunks.push(chunk);
                                                        }
                                                        ProgressiveEmissionPolicy::StreamProgressively => {
                                                            if chunk_tx
                                                                .send(ResponseChunk::Data(chunk))
                                                                .await
                                                                .is_err()
                                                            {
                                                                return;
                                                            }
                                                        }
                                                        ProgressiveEmissionPolicy::SuppressBody => {}
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
                                            }
                                        }
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
                                req.transition_to_streaming_response(
                                    Some(chunk_rx),
                                    !defer_headers_until_body_validated,
                                    StreamPhase::SendingResponse,
                                );
                                req.response_status = Some(status.as_u16());
                            }
                        }

                        if let Some(req) = streams.get(&stream_id) {
                            if let (Some(addr), Some(idx)) = (&req.backend_addr, req.backend_index)
                            {
                                let _ = crate::runtime::connection::outcome::observe_backend_response_status_and_log(
                                    crate::runtime::connection::outcome::BackendHealthObservationInput {
                                        backend_addr: addr,
                                        backend_index: idx,
                                        upstream_pool: req.upstream_pool.as_ref(),
                                        status,
                                    },
                                );
                            }
                            let _ = crate::runtime::connection::outcome::observe_status_outcome(
                                metrics,
                                Self::request_outcome_route_target(req),
                                Self::request_outcome_backend_target(req),
                                req.start.elapsed(),
                                status,
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
                        if let Some(req) = streams.get(&stream_id) {
                            if let Err(protocol_err) = Self::handle_forward_result(
                                h3,
                                quic,
                                stream_id,
                                req,
                                Err(err),
                                shared_ctx,
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

            let terminal = if let Some(req) = streams.get_mut(&stream_id) {
                Self::flush_response_chunks(stream_id, req, quic, h3, shared_ctx)
            } else {
                false
            };

            if terminal {
                if let Some(req) = streams.get_mut(&stream_id) {
                    abort_stream(req, metrics);
                }
                streams.remove(&stream_id);
            }
        }

        Ok(())
    }
}
