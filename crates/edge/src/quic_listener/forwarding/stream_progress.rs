use super::*;
use crate::runtime::connection::auth::ExternalAuthResult;

impl QUICListener {
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
    pub(crate) fn advance_streams_non_blocking(
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
            if let Some(req) = streams.get(&stream_id)
                && Instant::now() >= req.total_request_deadline
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

            if let Some(req) = streams.get(&stream_id)
                && req.phase == StreamPhase::ReceivingRequest
                && !req.request_fin_received
                && !req.bodyless_mode
                && Instant::now().saturating_duration_since(req.last_body_activity)
                    >= progress_config.client_body_idle_timeout
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

            if let Some(req) = streams.get_mut(&stream_id) {
                Self::flush_request_buffer(req, metrics);
                if req.request_fin_received && req.body_buf.is_empty() {
                    req.body_tx = None;
                }
            }

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
                        let upstream_content_length = resp_headers
                            .get(http::header::CONTENT_LENGTH)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<usize>().ok());
                        if !tunnel_response
                            && !suppress_downstream_body
                            && upstream_content_length
                                .is_some_and(|len| len > progress_config.max_response_body_bytes)
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
                                    progress_config.max_response_body_bytes,
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
                            format!("h3=\":{}\"; ma=86400", progress_config.listen_port)
                                .into_bytes(),
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
                                req.response_chunk_rx = None;
                                req.response_headers_sent = true;
                                req.phase = StreamPhase::Completed;
                                req.response_status = Some(status.as_u16());
                            }
                            immediate_terminal = true;
                        } else {
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
                                let body_idle_timeout = progress_config.backend_body_idle_timeout;
                                let max_response_body_bytes =
                                    progress_config.max_response_body_bytes;
                                let unknown_length_response_prebuffer_bytes =
                                    progress_config.unknown_length_response_prebuffer_bytes;
                                let first_byte_deadline = tokio::time::Instant::now()
                                    + progress_config.backend_body_total_timeout;
                                let deferred_status = status;
                                let deferred_headers = owned_h3_headers.clone();
                                let tunnel_mode = tunnel_response;
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
                                            body_idle_timeout
                                        } else {
                                            first_byte_deadline
                                                .saturating_duration_since(now)
                                                .min(body_idle_timeout)
                                        };
                                        let result =
                                            tokio::time::timeout(wait_timeout, frame_fut).await;
                                        match result {
                                            Err(_elapsed) => {
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
                                                            .send(ResponseChunk::Error(
                                                                ProxyError::Pool(
                                                                    PoolError::BackendOverloaded(
                                                                        "upstream response body too large"
                                                                            .into(),
                                                                    ),
                                                                ),
                                                            ))
                                                            .await;
                                                        return;
                                                    }
                                                    if defer_headers_until_body_validated {
                                                        if response_bytes_received
                                                            > unknown_length_response_prebuffer_bytes
                                                        {
                                                            let _ = chunk_tx
                                                                .send(ResponseChunk::Error(
                                                                    ProxyError::Pool(
                                                                        PoolError::BackendOverloaded(
                                                                            "unknown-length response prebuffer limit exceeded"
                                                                                .into(),
                                                                        ),
                                                                    ),
                                                                ))
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
                                metrics,
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
