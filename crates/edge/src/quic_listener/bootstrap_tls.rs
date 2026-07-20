use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use hyper::{
    body::Incoming,
    server::conn::{http1, http2},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use spooky_config::runtime::ListenerRuntimeConfig;
use spooky_errors::ProxyError;

pub(super) use super::bootstrap::{BootstrapConnectionState, BootstrapStartupState};
use super::{
    QUICListener,
    bootstrap::{
        BootstrapBuildRequestInput, BootstrapDispatchInput, BootstrapPolicyEvaluationInput,
        BootstrapPreparedRoute, BootstrapRequestIntake, BootstrapWritebackInput, boxed_full,
        build_bootstrap_upstream_request, dispatch_bootstrap_upstream,
        evaluate_bootstrap_request_policy, prepare_bootstrap_request_intake,
        write_bootstrap_response,
    },
    bootstrap::{
        PreparedBootstrapListenerStartup, prepare_bootstrap_listener_startup,
        spawn_bootstrap_listener_task,
    },
    runtime_endpoint::RuntimeConnectionSlotGuard,
};
use crate::{
    REQUEST_ID_COUNTER,
    runtime::{
        bundle::RuntimeBundleHandle,
        connection::{
            guardrails::{
                BodyLimitKind, REQUEST_BODY_TOO_LARGE_BODY, RequestBodyGuardrailConfig,
                RequestBodyGuardrailDecision, RequestBodyGuardrailInput,
                checked_request_body_ingress,
            },
            outcome::{OutcomeBackendTarget, OutcomeRouteTarget, observe_proxy_error_outcome},
        },
        shared_state::SharedRuntimeState,
    },
};

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

fn bootstrap_route_target<'a>(route: &'a str) -> OutcomeRouteTarget<'a> {
    OutcomeRouteTarget { route }
}

fn bootstrap_backend_target<'a>(
    upstream_name: &'a str,
    backend_addr: &'a str,
    backend_index: usize,
) -> OutcomeBackendTarget<'a> {
    OutcomeBackendTarget {
        upstream: upstream_name,
        backend_addr: Some(backend_addr),
        backend_index: Some(backend_index),
    }
}

impl QUICListener {
    pub fn spawn_bootstrap_tls_listener(
        config: &ListenerRuntimeConfig,
        shared_state: &SharedRuntimeState,
        runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
        shutdown_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), ProxyError> {
        let PreparedBootstrapListenerStartup {
            bind,
            alt_svc_value,
            max_connections,
            connection_timeout,
            listener_label,
            listener,
            runtime_handle,
            runtime_bundle,
            shutdown_signal,
            startup_state,
        } = prepare_bootstrap_listener_startup(
            config,
            shared_state,
            runtime_bundle,
            shutdown_signal,
        )?;

        spawn_bootstrap_listener_task(&runtime_handle, async move {
            info!(
                "Bootstrap TLS listener ready bind=https://{} protocol=tcp+tls",
                bind,
            );
            info!(
                "Bootstrap TLS listener alt_svc bind={} value={}",
                bind, alt_svc_value,
            );
            info!(
                "Bootstrap TLS listener limits bind={} max_connections={} connection_timeout_ms={}",
                bind,
                max_connections,
                connection_timeout.as_millis()
            );
            let active_connections = Arc::new(AtomicUsize::new(0));
            loop {
                let accept_result = if let Some(shutdown_signal) = shutdown_signal.as_ref() {
                    tokio::select! {
                        accept = listener.accept() => Some(accept),
                        _ = tokio::time::sleep(Duration::from_millis(200)) => {
                            if shutdown_signal.load(Ordering::Relaxed) {
                                None
                            } else {
                                continue;
                            }
                        }
                    }
                } else {
                    Some(listener.accept().await)
                };
                let Some(accept_result) = accept_result else {
                    info!(
                        "Bootstrap TLS listener on {} stopping due to runtime group shutdown",
                        bind
                    );
                    break;
                };
                let (stream, peer) = match accept_result {
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
                    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
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
                            let _backend_resolution_store = Arc::clone(&backend_resolution_store);
                            let upstream_policies = Arc::clone(&upstream_policies);
                            let metrics = Arc::clone(&metrics);
                            let resilience = Arc::clone(&resilience);
                            let upstream_pools = upstream_pools.clone();
                            let routing_index = Arc::clone(&routing_index);
                            let max_request_body_bytes = max_request_body_bytes;
                            let max_response_body_bytes = max_response_body_bytes;
                            let peer = peer;

                            Box::pin(async move {
                                let request_start = Instant::now();
                                let BootstrapRequestIntake {
                                    method,
                                    path,
                                    authority,
                                    content_length,
                                    suppress_downstream_body,
                                    is_websocket_upgrade,
                                    client_upgrade,
                                } = match prepare_bootstrap_request_intake(
                                    &mut req,
                                    use_h2,
                                    resilience.as_ref(),
                                    metrics.as_ref(),
                                    &alt,
                                    request_start,
                                ) {
                                    Ok(intake) => intake,
                                    Err(response) => return Ok(response),
                                };

                                let BootstrapPreparedRoute {
                                    endpoint,
                                    backend_addr,
                                    backend_index,
                                    upstream_name,
                                    upstream_policy,
                                    upstream_pool,
                                } = match evaluate_bootstrap_request_policy(
                                    BootstrapPolicyEvaluationInput {
                                        intake: &BootstrapRequestIntake {
                                            method: method.clone(),
                                            path: path.clone(),
                                            authority: authority.clone(),
                                            content_length,
                                            suppress_downstream_body,
                                            is_websocket_upgrade,
                                            client_upgrade: None,
                                        },
                                        peer,
                                        headers: req.headers(),
                                        routing_index: &routing_index,
                                        upstream_pools: &upstream_pools,
                                        upstream_policies: &upstream_policies,
                                        backend_endpoints: &backend_endpoints,
                                        metrics: metrics.as_ref(),
                                        resilience: resilience.as_ref(),
                                        request_start,
                                        alt_svc: &alt,
                                    },
                                ) {
                                    Ok(prepared) => prepared,
                                    Err(response) => return Ok(response),
                                };

                                let request_path = if path.is_empty() { "/" } else { &path };
                                let request_size_decision = checked_request_body_ingress(
                                    RequestBodyGuardrailConfig {
                                        idle_timeout: Duration::ZERO,
                                        total_timeout: Duration::ZERO,
                                        max_body_bytes: max_request_body_bytes,
                                        max_buffered_bytes: usize::MAX,
                                    },
                                    RequestBodyGuardrailInput {
                                        elapsed: Duration::ZERO,
                                        idle_for: Duration::ZERO,
                                        bytes_received: 0,
                                        buffered_bytes: 0,
                                        next_chunk_bytes: 0,
                                        declared_content_length: content_length,
                                        exempt_from_body_size_cap: is_websocket_upgrade,
                                    },
                                );
                                if matches!(
                                    request_size_decision,
                                    Err(RequestBodyGuardrailDecision::Reject {
                                        kind: BodyLimitKind::BodySize,
                                    })
                                ) {
                                    let _ = observe_proxy_error_outcome(
                                        metrics.as_ref(),
                                        bootstrap_route_target(&upstream_name),
                                        Some(bootstrap_backend_target(
                                            &upstream_name,
                                            &backend_addr,
                                            backend_index,
                                        )),
                                        request_start.elapsed(),
                                        Some(StatusCode::PAYLOAD_TOO_LARGE),
                                        &ProxyError::Transport("request body too large".into()),
                                        None,
                                    );
                                    return Ok(Response::builder()
                                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                                        .header("alt-svc", &alt)
                                        .body(boxed_full(Bytes::from_static(
                                            REQUEST_BODY_TOO_LARGE_BODY,
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
                                let intake_for_build = BootstrapRequestIntake {
                                    method: method.clone(),
                                    path: path.clone(),
                                    authority: authority.clone(),
                                    content_length,
                                    suppress_downstream_body,
                                    is_websocket_upgrade,
                                    client_upgrade: None,
                                };
                                let upstream_req = match build_bootstrap_upstream_request(
                                    BootstrapBuildRequestInput {
                                        request: req,
                                        intake: &intake_for_build,
                                        prepared_route: &BootstrapPreparedRoute {
                                            endpoint: endpoint.clone(),
                                            backend_addr: backend_addr.clone(),
                                            backend_index,
                                            upstream_name: upstream_name.clone(),
                                            upstream_policy: upstream_policy.clone(),
                                            upstream_pool: Arc::clone(&upstream_pool),
                                        },
                                        request_id,
                                        traceparent: traceparent.as_deref(),
                                        peer,
                                    },
                                ) {
                                    Ok(request) => request,
                                    Err(err) => {
                                        warn!("Bootstrap request build failed: {}", err);
                                        let (status, body) = if is_websocket_upgrade
                                            && matches!(err, spooky_bridge::BridgeError::Build(_))
                                        {
                                            (
                                                StatusCode::BAD_GATEWAY,
                                                b"request build error\n".as_slice(),
                                            )
                                        } else {
                                            (
                                                StatusCode::BAD_REQUEST,
                                                b"invalid request\n".as_slice(),
                                            )
                                        };
                                        let proxy_err = ProxyError::from(err);
                                        let _ = observe_proxy_error_outcome(
                                            metrics.as_ref(),
                                            bootstrap_route_target(&upstream_name),
                                            Some(bootstrap_backend_target(
                                                &upstream_name,
                                                &backend_addr,
                                                backend_index,
                                            )),
                                            request_start.elapsed(),
                                            Some(status),
                                            &proxy_err,
                                            None,
                                        );
                                        return Ok(Response::builder()
                                            .status(status)
                                            .header("alt-svc", &alt)
                                            .body(boxed_full(Bytes::copy_from_slice(body)))
                                            .unwrap_or_else(|_| {
                                                Response::new(boxed_full(Bytes::from_static(
                                                    b"error\n",
                                                )))
                                            }));
                                    }
                                };
                                let upstream_resp =
                                    match dispatch_bootstrap_upstream(BootstrapDispatchInput {
                                        upstream_req,
                                        prepared_route: &BootstrapPreparedRoute {
                                            endpoint: endpoint.clone(),
                                            backend_addr: backend_addr.clone(),
                                            backend_index,
                                            upstream_name: upstream_name.clone(),
                                            upstream_policy: upstream_policy.clone(),
                                            upstream_pool: Arc::clone(&upstream_pool),
                                        },
                                        transport_pool: transport_pool.as_ref(),
                                        metrics: metrics.as_ref(),
                                        request_start,
                                        request_id,
                                        backend_timeout,
                                        request_path,
                                        is_websocket_upgrade,
                                        alt_svc: &alt,
                                    })
                                    .await
                                    {
                                        Ok(resp) => resp,
                                        Err(response) => return Ok(response),
                                    };

                                write_bootstrap_response(BootstrapWritebackInput {
                                    upstream_resp,
                                    prepared_route: &BootstrapPreparedRoute {
                                        endpoint: endpoint.clone(),
                                        backend_addr: backend_addr.clone(),
                                        backend_index,
                                        upstream_name: upstream_name.clone(),
                                        upstream_policy: upstream_policy.clone(),
                                        upstream_pool: Arc::clone(&upstream_pool),
                                    },
                                    metrics: metrics.as_ref(),
                                    request_start,
                                    alt_svc: &alt,
                                    suppress_downstream_body,
                                    is_websocket_upgrade,
                                    client_upgrade,
                                    max_response_body_bytes,
                                })
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

    pub(super) fn bootstrap_connection_state(
        listener_label: &str,
        runtime_bundle: Option<&Arc<RuntimeBundleHandle>>,
        startup: &BootstrapStartupState,
    ) -> Option<BootstrapConnectionState> {
        super::bootstrap::bootstrap_connection_state(listener_label, runtime_bundle, startup)
    }
}
