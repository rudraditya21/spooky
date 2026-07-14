use super::*;

impl QUICListener {
    #[allow(clippy::too_many_arguments)]
    async fn forward_http1_websocket_tunnel(
        endpoint: BackendEndpoint,
        pending_forward: Arc<PendingForward>,
        mut body_rx: mpsc::Receiver<Bytes>,
        backend_timeout: Duration,
        metrics: Arc<Metrics>,
    ) -> ForwardResult {
        let request = pending_forward.build_http1_websocket_tunnel_request(&endpoint)?;

        let stream = tokio::time::timeout(
            backend_timeout,
            tokio::net::TcpStream::connect(endpoint.authority()),
        )
        .await
        .map_err(|_| ProxyError::Timeout)?
        .map_err(|err| ProxyError::Transport(err.to_string()))?;
        let resolved_addr = stream
            .peer_addr()
            .map_err(|err| ProxyError::Transport(err.to_string()))?;
        metrics.record_backend_connect(
            endpoint.authority(),
            endpoint.authority_host(),
            resolved_addr,
        );
        let io = TokioIo::new(stream);
        let (mut sender, conn) = client_http1::handshake(io)
            .await
            .map_err(|err| ProxyError::Transport(err.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });

        let mut response = tokio::time::timeout(backend_timeout, sender.send_request(request))
            .await
            .map_err(|_| ProxyError::Timeout)?
            .map_err(|err| ProxyError::Transport(err.to_string()))?;

        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            let status = response.status();
            let headers = response.headers().clone();
            return Ok(ForwardSuccess::Response {
                status,
                headers,
                body: response.into_body(),
            });
        }

        let upgraded = upgrade::on(&mut response);
        let headers = response.headers().clone();
        let (chunk_tx, chunk_rx) = mpsc::channel(RESPONSE_CHUNK_CHANNEL_CAPACITY);
        let fut = async move {
            let upgraded = match upgraded.await {
                Ok(upgraded) => upgraded,
                Err(err) => {
                    let _ = chunk_tx
                        .send(ResponseChunk::Error(ProxyError::Transport(err.to_string())))
                        .await;
                    return;
                }
            };
            let io = TokioIo::new(upgraded);
            let (mut reader, mut writer) = tokio::io::split(io);
            let write_fut = async {
                while let Some(chunk) = body_rx.recv().await {
                    writer.write_all(&chunk).await?;
                }
                writer.shutdown().await
            };
            let read_fut = async {
                let mut buf = [0u8; RESPONSE_CHUNK_BYTES_LIMIT];
                loop {
                    match reader.read(&mut buf).await {
                        Ok(0) => return Ok::<(), std::io::Error>(()),
                        Ok(read) => {
                            if chunk_tx
                                .send(ResponseChunk::Data(Bytes::copy_from_slice(&buf[..read])))
                                .await
                                .is_err()
                            {
                                return Ok(());
                            }
                        }
                        Err(err) => return Err(err),
                    }
                }
            };
            match tokio::try_join!(write_fut, read_fut) {
                Ok(((), ())) => {
                    let _ = chunk_tx.send(ResponseChunk::End).await;
                }
                Err(err) => {
                    let _ = chunk_tx
                        .send(ResponseChunk::Error(ProxyError::Transport(err.to_string())))
                        .await;
                }
            }
        };
        let _ = spawn_async_task(fut, "ws-h1-tunnel");

        Ok(ForwardSuccess::Tunnel {
            status: StatusCode::OK,
            headers,
            response_chunk_rx: chunk_rx,
        })
    }

    fn pick_alternate_backend(
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

    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn_upstream_forward_task(
        req: &RequestEnvelope,
        pending_forward: Arc<PendingForward>,
        backend_endpoint: BackendEndpoint,
        request: Option<Request<BoxBody<Bytes, Infallible>>>,
        websocket_tunnel_body_rx: Option<mpsc::Receiver<Bytes>>,
        transport_pool: Arc<UpstreamTransportPool>,
        backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
        backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
        backend_timeout: Duration,
        metrics: Arc<Metrics>,
        resilience: &RuntimeResilience,
    ) -> Result<oneshot::Receiver<UpstreamResult>, ProxyError> {
        let fwd_addr = pending_forward.backend_addr.to_string();
        let cb = Arc::clone(&resilience.circuit_breakers);
        let retry_budget = Arc::clone(&resilience.retry_budget);
        let route_name = pending_forward.upstream_name.to_string();
        let _backend_resolutions = Arc::clone(&backend_resolution_store);
        let transport = Arc::clone(&transport_pool);
        let allow_hedge = req.tunnel_mode == TunnelMode::None
            && req.bodyless_mode
            && resilience.hedging_allowed_for(&req.method, &route_name, true);
        let hedge_delay = resilience.hedging_delay;
        let alternate_backend = req.upstream_pool.as_ref().and_then(|upstream_pool| {
            Self::pick_alternate_backend(upstream_pool, pending_forward.backend_index)
        });
        let trace_span_for_upstream = req.trace_span.clone();
        let pending_forward_for_upstream = Arc::clone(&pending_forward);
        let (result_tx, result_rx) = oneshot::channel::<UpstreamResult>();
        let tunnel_mode = req.tunnel_mode;
        let bodyless_mode = req.bodyless_mode;
        let request_id = req.request_id;
        let fut = async move {
            let mut hedge_telemetry =
                crate::runtime::connection::response::HedgeTelemetry::default();
            let mut retry_count: u8 = 0;
            let mut retry_attempt_reason: Option<RetryReason> = None;
            let mut retry_denial_reason: Option<RetryReason> = None;
            let result: ForwardResult = async {
                retry_budget.mark_primary(&route_name);

                let send_once =
                    |backend: String,
                     req: http::Request<BoxBody<Bytes, std::convert::Infallible>>,
                     cb: Arc<crate::resilience::circuit_breaker::CircuitBreakers>,
                     transport: Arc<UpstreamTransportPool>| async move {
                        if !cb.allow_request(&backend) {
                            return Err(ProxyError::Pool(PoolError::CircuitOpen(backend)));
                        }
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

                let forward_success: ForwardSuccess = if tunnel_mode == TunnelMode::Websocket
                    && backend_endpoint.scheme() == BackendScheme::Http
                {
                    let Some(body_rx) = websocket_tunnel_body_rx else {
                        return Err(ProxyError::Transport(
                            "websocket H1 tunnels require a downstream body channel".into(),
                        ));
                    };
                    Self::forward_http1_websocket_tunnel(
                        backend_endpoint.clone(),
                        Arc::clone(&pending_forward_for_upstream),
                        body_rx,
                        backend_timeout,
                        Arc::clone(&metrics),
                    )
                    .await?
                } else {
                    let request = request.ok_or_else(|| {
                        ProxyError::Transport(
                            "missing upstream request for non-websocket forward".into(),
                        )
                    })?;
                    let response: Response<Incoming> = if allow_hedge {
                        let hedge_candidate = alternate_backend.clone().and_then(|(backend, _idx)| {
                            let endpoint = backend_endpoints.get(&backend)?;
                            pending_forward_for_upstream
                                .build_bodyless_request(endpoint)
                                .ok()
                                .map(|req| (backend, req))
                        });

                        if let Some((hedge_backend, hedge_request)) = hedge_candidate {
                            let primary_started = Instant::now();
                            let primary_backend = fwd_addr.clone();
                            let primary_fut = send_once(
                                primary_backend,
                                request,
                                Arc::clone(&cb),
                                Arc::clone(&transport),
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
                            )
                            .await?
                        }
                    } else {
                        match send_once(
                            fwd_addr.clone(),
                            request,
                            Arc::clone(&cb),
                            Arc::clone(&transport),
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
                                    } else if !is_retryable_err {
                                        retry_denial_reason = None;
                                    } else if !budget_ok {
                                        retry_denial_reason = Some(RetryReason::BudgetDenied);
                                    } else {
                                        retry_denial_reason = Some(RetryReason::NoAlternateBackend);
                                    }
                                    return Err(primary_err);
                                }
                                if let Some((retry_backend, _)) = alternate_backend.clone()
                                    && let Some(endpoint) = backend_endpoints.get(&retry_backend)
                                    && let Ok(retry_request) =
                                        pending_forward_for_upstream.build_bodyless_request(endpoint)
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
                                    )
                                    .await?
                                } else {
                                    return Err(primary_err);
                                }
                            }
                        }
                    };

                    let (parts, body) = response.into_parts();
                    ForwardSuccess::Response {
                        status: parts.status,
                        headers: parts.headers,
                        body,
                    }
                };
                Ok(forward_success)
            }
            .await;
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
            return Err(ProxyError::Transport(
                "dropping upstream task: no runtime available".into(),
            ));
        }
        Ok(result_rx)
    }
}
