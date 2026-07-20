use std::{
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    body::{Body, Frame, Incoming},
    client::conn::http1 as client_http1,
    server::conn::{http1, http2},
    service::service_fn,
    upgrade,
};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use spooky_bridge::{
    h3_to_h1::build_h1_request,
    h3_to_h2::build_h2_request_for_target,
    request::{
        RequestBuildInput, RequestBuildPolicies, RequestBuildTarget, RequestForwardedContext,
        RequestTraceContext,
    },
    response::{
        ResponseBodyMode, ResponseBodyPolicy, ResponseNormalizationInput,
        ResponseNormalizationProtocol, ResponseProtocolConstraints, normalize_upstream_response,
    },
};
use spooky_config::{
    backend_endpoint::{BackendEndpoint, BackendScheme},
    runtime::{ListenerRuntimeConfig, RuntimeUpstreamPolicy},
};
use spooky_errors::{BridgeError, ProxyError, classify_upstream_proxy_error};
use spooky_lb::upstream_pool::UpstreamPool;

pub(super) use super::bootstrap::{BootstrapConnectionState, BootstrapStartupState};
use super::{
    QUICListener,
    admission::{
        AdmissionPolicyDecision, admission_rejection_response,
        evaluate_forwarding_pre_admission_policy,
    },
    bootstrap::{
        PreparedBootstrapListenerStartup, prepare_bootstrap_listener_startup,
        spawn_bootstrap_listener_task,
    },
    is_head_method, is_websocket_upgrade_request,
    runtime_endpoint::RuntimeConnectionSlotGuard,
    validate_http_request,
};
use crate::{
    REQUEST_ID_COUNTER,
    runtime::{
        bundle::RuntimeBundleHandle,
        connection::{
            guardrails::{
                BodyLimitKind, REQUEST_BODY_TOO_LARGE_BODY, RESPONSE_BODY_TOO_LARGE_BODY,
                RequestBodyGuardrailConfig, RequestBodyGuardrailDecision,
                RequestBodyGuardrailInput, ResponseBodyGuardrailConfig,
                ResponseBodyGuardrailDecision, ResponseBodyGuardrailInput,
                checked_request_body_ingress, checked_response_body_guardrails,
            },
            outcome::{
                AdmissionOutcomeClass, OutcomeBackendTarget, OutcomeRouteTarget,
                observe_admission_outcome, observe_backend_response_status,
                observe_proxy_error_outcome, observe_status_outcome,
            },
        },
        shared_state::SharedRuntimeState,
    },
};

type BootstrapServiceFuture = Pin<
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

pub(super) fn boxed_full(body: Bytes) -> http_body_util::combinators::BoxBody<Bytes, Infallible> {
    Full::new(body).map_err(|never| match never {}).boxed()
}

fn bootstrap_bridge_headers(headers: &http::HeaderMap) -> Vec<quiche::h3::Header> {
    headers
        .iter()
        .map(|(name, value)| quiche::h3::Header::new(name.as_str().as_bytes(), value.as_bytes()))
        .collect()
}

fn bootstrap_request_build_target<'a>(
    endpoint: &'a BackendEndpoint,
    upstream_policy: &'a RuntimeUpstreamPolicy,
) -> RequestBuildTarget<'a> {
    RequestBuildTarget {
        endpoint,
        policies: RequestBuildPolicies {
            host_policy: &upstream_policy.host.0,
            forwarded_header_policy: &upstream_policy.forwarded_headers.0,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn bootstrap_request_build_input<'a>(
    method: &'a str,
    path: &'a str,
    authority: Option<&'a str>,
    headers: &'a [quiche::h3::Header],
    body: BoxBody<Bytes, Infallible>,
    content_length: Option<usize>,
    request_id: u64,
    traceparent: Option<&'a str>,
    peer: SocketAddr,
) -> RequestBuildInput<'a, BoxBody<Bytes, Infallible>> {
    RequestBuildInput {
        method,
        path,
        authority,
        headers,
        body,
        content_length,
        body_mode: RequestBuildInput::<BoxBody<Bytes, Infallible>>::body_mode_for_length(
            content_length,
        ),
        trace: RequestTraceContext {
            request_id,
            traceparent,
        },
        forwarded: RequestForwardedContext { client_addr: peer },
    }
}

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
                                let is_websocket_upgrade =
                                    is_websocket_upgrade_request(&req, use_h2);
                                let client_upgrade = if is_websocket_upgrade {
                                    Some(upgrade::on(&mut req))
                                } else {
                                    None
                                };

                                let request = match validate_http_request(&req, &resilience) {
                                    Ok(request) => request,
                                    Err((status, body, is_policy)) => {
                                        metrics.inc_request_validation_reject();
                                        if is_policy {
                                            metrics.inc_policy_denied();
                                        }
                                        let _ = observe_proxy_error_outcome(
                                            metrics.as_ref(),
                                            OutcomeRouteTarget::UNROUTED,
                                            None,
                                            request_start.elapsed(),
                                            Some(status),
                                            &ProxyError::Bridge(BridgeError::InvalidHeader),
                                            None,
                                        );
                                        return Ok(Response::builder()
                                            .status(status)
                                            .header("alt-svc", &alt)
                                            .body(boxed_full(Bytes::copy_from_slice(body)))
                                            .unwrap_or_else(|_| {
                                                Response::new(boxed_full(Bytes::new()))
                                            }));
                                    }
                                };
                                let method = request.method;
                                let path = request.path;
                                let authority = request.authority;
                                let content_length = request.content_length;
                                let suppress_downstream_body = is_head_method(&method);

                                let bootstrap_error = |status: StatusCode, body: &'static [u8]| {
                                    Ok(Response::builder()
                                        .status(status)
                                        .header("alt-svc", &alt)
                                        .body(boxed_full(Bytes::from_static(body)))
                                        .unwrap_or_else(|_| {
                                            Response::new(boxed_full(Bytes::from_static(
                                                b"error\n",
                                            )))
                                        }))
                                };

                                let lb_header_lookup = |name: &str| {
                                    req.headers()
                                        .get(name)
                                        .and_then(|value| value.to_str().ok())
                                        .map(str::to_string)
                                };
                                let (
                                    backend_addr,
                                    backend_index,
                                    upstream_name,
                                    upstream_policy,
                                    upstream_pool,
                                ) = match Self::resolve_bootstrap_target(
                                    super::forwarding::BootstrapResolutionInput {
                                        method: &method,
                                        path: &path,
                                        authority: authority.as_deref(),
                                        header_lookup: Some(&lb_header_lookup),
                                        routing_index: &routing_index,
                                        upstream_pools: &upstream_pools,
                                        upstream_policies: &upstream_policies,
                                        metrics: &metrics,
                                        elapsed: Duration::from_millis(0),
                                    },
                                ) {
                                    Ok(value) => (
                                        value.backend_addr,
                                        value.backend_index,
                                        value.upstream_name,
                                        value.upstream_policy,
                                        value.upstream_pool,
                                    ),
                                    Err(err) => {
                                        let (status, body) =
                                            Self::bootstrap_route_resolution_error_response(&err);
                                        return bootstrap_error(status, body);
                                    }
                                };

                                let admission = evaluate_forwarding_pre_admission_policy(
                                    &upstream_policy,
                                    Some(&lb_header_lookup),
                                    &resilience.brownout,
                                    resilience.adaptive_admission.inflight_percent(),
                                    &upstream_name,
                                    resilience.shed_retry_after_seconds,
                                    &resilience.scoped_rate_limits,
                                    |rule| {
                                        Self::resolve_scoped_rate_limit_key(
                                            rule,
                                            &upstream_name,
                                            &method,
                                            &path,
                                            authority.as_deref(),
                                            peer,
                                            Some(&lb_header_lookup),
                                        )
                                    },
                                );
                                metrics.set_brownout_active(resilience.brownout.is_active());
                                let rejection_response = admission_rejection_response(&admission);
                                match admission {
                                    AdmissionPolicyDecision::AdmitReady => {}
                                    AdmissionPolicyDecision::Unauthorized(_) => {
                                        metrics.inc_policy_denied();
                                        let _ = observe_admission_outcome(
                                            metrics.as_ref(),
                                            bootstrap_route_target(&upstream_name),
                                            Some(bootstrap_backend_target(
                                                &upstream_name,
                                                &backend_addr,
                                                backend_index,
                                            )),
                                            request_start.elapsed(),
                                            StatusCode::UNAUTHORIZED,
                                            AdmissionOutcomeClass::AuthDenied,
                                        );
                                        warn!(
                                            "Bootstrap request route={} denied by auth policy",
                                            upstream_name
                                        );
                                        let Some(response) = rejection_response.as_ref() else {
                                            warn!(
                                                "Bootstrap request route={} missing admission rejection response for unauthorized decision",
                                                upstream_name
                                            );
                                            return Ok(Response::builder()
                                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"internal proxy error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        };
                                        let Some(challenge) = response.www_authenticate else {
                                            warn!(
                                                "Bootstrap request route={} missing auth challenge in admission rejection response",
                                                upstream_name
                                            );
                                            return Ok(Response::builder()
                                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"internal proxy error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        };
                                        return Ok(Response::builder()
                                            .status(response.status)
                                            .header("alt-svc", &alt)
                                            .header("www-authenticate", challenge)
                                            .body(boxed_full(Bytes::from_static(response.body)))
                                            .unwrap_or_else(|_| {
                                                Response::new(boxed_full(Bytes::from_static(
                                                    b"error\n",
                                                )))
                                            }));
                                    }
                                    AdmissionPolicyDecision::RateLimited(decision) => {
                                        metrics.inc_request_rate_limited();
                                        let _ = observe_admission_outcome(
                                            metrics.as_ref(),
                                            bootstrap_route_target(&upstream_name),
                                            Some(bootstrap_backend_target(
                                                &upstream_name,
                                                &backend_addr,
                                                backend_index,
                                            )),
                                            request_start.elapsed(),
                                            StatusCode::TOO_MANY_REQUESTS,
                                            AdmissionOutcomeClass::RateLimited,
                                        );
                                        warn!(
                                            "Bootstrap request route={} scoped rate limit exceeded by rule={}",
                                            decision.route, decision.rule_name
                                        );
                                        let Some(response) = rejection_response.as_ref() else {
                                            warn!(
                                                "Bootstrap request route={} missing admission rejection response for rate-limited decision",
                                                upstream_name
                                            );
                                            return Ok(Response::builder()
                                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"internal proxy error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        };
                                        let Some(retry_after_seconds) =
                                            response.retry_after_seconds
                                        else {
                                            warn!(
                                                "Bootstrap request route={} missing retry-after in rate-limited admission rejection response",
                                                upstream_name
                                            );
                                            return Ok(Response::builder()
                                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"internal proxy error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        };
                                        return Ok(Response::builder()
                                            .status(response.status)
                                            .header("alt-svc", &alt)
                                            .header("retry-after", retry_after_seconds.to_string())
                                            .body(boxed_full(Bytes::from_static(response.body)))
                                            .unwrap_or_else(|_| {
                                                Response::new(boxed_full(Bytes::from_static(
                                                    b"error\n",
                                                )))
                                            }));
                                    }
                                    AdmissionPolicyDecision::Overloaded(decision) => {
                                        let _ = observe_admission_outcome(
                                            metrics.as_ref(),
                                            bootstrap_route_target(&upstream_name),
                                            Some(bootstrap_backend_target(
                                                &upstream_name,
                                                &backend_addr,
                                                backend_index,
                                            )),
                                            request_start.elapsed(),
                                            StatusCode::SERVICE_UNAVAILABLE,
                                            AdmissionOutcomeClass::OverloadShed {
                                                reason: Some(decision.reason.metrics_reason()),
                                            },
                                        );
                                        resilience
                                            .adaptive_admission
                                            .observe(request_start.elapsed(), true);
                                        let Some(response) = rejection_response.as_ref() else {
                                            warn!(
                                                "Bootstrap request route={} missing admission rejection response for overload decision",
                                                upstream_name
                                            );
                                            return Ok(Response::builder()
                                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"internal proxy error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        };
                                        let Some(retry_after_seconds) =
                                            response.retry_after_seconds
                                        else {
                                            warn!(
                                                "Bootstrap request route={} missing retry-after in overload admission rejection response",
                                                upstream_name
                                            );
                                            return Ok(Response::builder()
                                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"internal proxy error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        };
                                        return Ok(Response::builder()
                                            .status(response.status)
                                            .header("alt-svc", &alt)
                                            .header("retry-after", retry_after_seconds.to_string())
                                            .body(boxed_full(Bytes::from_static(response.body)))
                                            .unwrap_or_else(|_| {
                                                Response::new(boxed_full(Bytes::from_static(
                                                    b"error\n",
                                                )))
                                            }));
                                    }
                                }

                                let endpoint = match backend_endpoints.get(&backend_addr) {
                                    Some(ep) => ep.clone(),
                                    None => {
                                        let _ = observe_proxy_error_outcome(
                                            metrics.as_ref(),
                                            bootstrap_route_target(&upstream_name),
                                            Some(bootstrap_backend_target(
                                                &upstream_name,
                                                &backend_addr,
                                                backend_index,
                                            )),
                                            request_start.elapsed(),
                                            Some(StatusCode::BAD_GATEWAY),
                                            &ProxyError::Transport("no endpoint".into()),
                                            None,
                                        );
                                        return Ok(Response::builder()
                                            .status(StatusCode::BAD_GATEWAY)
                                            .header("alt-svc", &alt)
                                            .body(boxed_full(Bytes::from_static(b"no endpoint\n")))
                                            .unwrap_or_else(|_| {
                                                Response::new(boxed_full(Bytes::from_static(
                                                    b"error\n",
                                                )))
                                            }));
                                    }
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
                                let bridge_headers = bootstrap_bridge_headers(req.headers());
                                let request_target =
                                    bootstrap_request_build_target(&endpoint, &upstream_policy);
                                let upstream_req = if is_websocket_upgrade {
                                    match build_h1_request(
                                        request_target,
                                        bootstrap_request_build_input(
                                            &method,
                                            &path,
                                            authority.as_deref(),
                                            &bridge_headers,
                                            boxed_full(Bytes::new()),
                                            None,
                                            request_id,
                                            traceparent.as_deref(),
                                            peer,
                                        ),
                                    ) {
                                        Ok(request) => request,
                                        Err(err) => {
                                            warn!("Bootstrap request build failed: {}", err);
                                            let (status, body) = match err {
                                                spooky_bridge::BridgeError::Build(_) => (
                                                    StatusCode::BAD_GATEWAY,
                                                    b"request build error\n".as_slice(),
                                                ),
                                                _ => (
                                                    StatusCode::BAD_REQUEST,
                                                    b"invalid request\n".as_slice(),
                                                ),
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
                                    }
                                } else {
                                    let bridge_body = BootstrapStreamingBody::new(req.into_body())
                                        .map_err(|never| match never {})
                                        .boxed();
                                    let build_result = if endpoint.scheme() == BackendScheme::Http {
                                        build_h1_request(
                                            request_target,
                                            bootstrap_request_build_input(
                                                &method,
                                                &path,
                                                authority.as_deref(),
                                                &bridge_headers,
                                                bridge_body,
                                                None,
                                                request_id,
                                                traceparent.as_deref(),
                                                peer,
                                            ),
                                        )
                                    } else {
                                        build_h2_request_for_target(
                                            request_target,
                                            bootstrap_request_build_input(
                                                &method,
                                                &path,
                                                authority.as_deref(),
                                                &bridge_headers,
                                                bridge_body,
                                                None,
                                                request_id,
                                                traceparent.as_deref(),
                                                peer,
                                            ),
                                        )
                                    };
                                    match build_result {
                                        Ok(request) => request,
                                        Err(err) => {
                                            warn!("Bootstrap request build failed: {}", err);
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
                                                Some(StatusCode::BAD_REQUEST),
                                                &proxy_err,
                                                None,
                                            );
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"invalid request\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    }
                                };
                                let mut upstream_resp = if is_websocket_upgrade {
                                    if endpoint.scheme() != BackendScheme::Http {
                                        return Ok(Response::builder()
                                            .status(StatusCode::BAD_GATEWAY)
                                            .header("alt-svc", &alt)
                                            .body(boxed_full(Bytes::from_static(
                                                b"websocket bootstrap requires http upstream\n",
                                            )))
                                            .unwrap_or_else(|_| {
                                                Response::new(boxed_full(Bytes::from_static(
                                                    b"error\n",
                                                )))
                                            }));
                                    }
                                    let backend_target = endpoint.authority().to_string();
                                    let upstream_path_uri = match http::Uri::try_from(request_path)
                                    {
                                        Ok(uri) => uri,
                                        Err(_) => {
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(b"bad uri\n")))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    };
                                    let (mut parts, body) = upstream_req.into_parts();
                                    parts.uri = upstream_path_uri;
                                    let upstream_req = Request::from_parts(parts, body);

                                    let stream = match tokio::time::timeout(
                                        backend_timeout,
                                        tokio::net::TcpStream::connect(&backend_target),
                                    )
                                    .await
                                    {
                                        Ok(Ok(s)) => {
                                            if let Ok(resolved_addr) = s.peer_addr() {
                                                metrics.record_backend_connect(
                                                    &backend_target,
                                                    endpoint.authority_host(),
                                                    resolved_addr,
                                                );
                                            }
                                            s
                                        }
                                        Ok(Err(err)) => {
                                            warn!("Bootstrap WebSocket connect error: {}", err);
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upstream error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                        Err(_) => {
                                            return Ok(Response::builder()
                                                .status(StatusCode::GATEWAY_TIMEOUT)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upstream timeout\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    };
                                    let io = TokioIo::new(stream);
                                    let (mut sender, conn) = match client_http1::handshake(io).await
                                    {
                                        Ok(v) => v,
                                        Err(err) => {
                                            warn!(
                                                "Bootstrap WebSocket handshake setup failed: {}",
                                                err
                                            );
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upstream error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    };
                                    tokio::spawn(async move {
                                        let _ = conn.with_upgrades().await;
                                    });
                                    match tokio::time::timeout(
                                        backend_timeout,
                                        sender.send_request(upstream_req),
                                    )
                                    .await
                                    {
                                        Ok(Ok(resp)) => resp,
                                        Ok(Err(err)) => {
                                            let proxy_err = ProxyError::Transport(err.to_string());
                                            let _ = observe_proxy_error_outcome(
                                                metrics.as_ref(),
                                                bootstrap_route_target(&upstream_name),
                                                Some(bootstrap_backend_target(
                                                    &upstream_name,
                                                    &backend_addr,
                                                    backend_index,
                                                )),
                                                request_start.elapsed(),
                                                Some(StatusCode::BAD_GATEWAY),
                                                &proxy_err,
                                                None,
                                            );
                                            if let Some(classified) =
                                                classify_upstream_proxy_error(&proxy_err)
                                            {
                                                Self::log_classified_upstream_failure(
                                                    "bootstrap",
                                                    Some(request_id),
                                                    Some(&upstream_name),
                                                    &backend_addr,
                                                    &classified,
                                                );
                                                if let Some(transition) = crate::runtime::connection::outcome::observe_classified_backend_failure(
                                                    crate::runtime::connection::outcome::ClassifiedBackendFailureInput {
                                                        metrics_phase: "bootstrap",
                                                        backend_addr: &backend_addr,
                                                        backend_index,
                                                        upstream_pool: Some(&upstream_pool),
                                                        metrics: metrics.as_ref(),
                                                        classified: &classified,
                                                    },
                                                ) {
                                                    crate::runtime::connection::outcome::log_backend_health_transition(
                                                        &backend_addr,
                                                        transition,
                                                    );
                                                }
                                            } else {
                                                warn!(
                                                    "Bootstrap WebSocket upstream error route={} backend={}: {}",
                                                    upstream_name, backend_addr, err
                                                );
                                            }
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upstream error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                        Err(_) => {
                                            let _ = observe_proxy_error_outcome(
                                                metrics.as_ref(),
                                                bootstrap_route_target(&upstream_name),
                                                Some(bootstrap_backend_target(
                                                    &upstream_name,
                                                    &backend_addr,
                                                    backend_index,
                                                )),
                                                request_start.elapsed(),
                                                Some(StatusCode::GATEWAY_TIMEOUT),
                                                &ProxyError::Timeout,
                                                None,
                                            );
                                            if let Some(classified) =
                                                classify_upstream_proxy_error(&ProxyError::Timeout)
                                            {
                                                Self::log_classified_upstream_failure(
                                                    "bootstrap",
                                                    Some(request_id),
                                                    Some(&upstream_name),
                                                    &backend_addr,
                                                    &classified,
                                                );
                                                if let Some(transition) = crate::runtime::connection::outcome::observe_classified_backend_failure(
                                                    crate::runtime::connection::outcome::ClassifiedBackendFailureInput {
                                                        metrics_phase: "bootstrap",
                                                        backend_addr: &backend_addr,
                                                        backend_index,
                                                        upstream_pool: Some(&upstream_pool),
                                                        metrics: metrics.as_ref(),
                                                        classified: &classified,
                                                    },
                                                ) {
                                                    crate::runtime::connection::outcome::log_backend_health_transition(
                                                        &backend_addr,
                                                        transition,
                                                    );
                                                }
                                            }
                                            return Ok(Response::builder()
                                                .status(StatusCode::GATEWAY_TIMEOUT)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upstream timeout\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    }
                                } else {
                                    match tokio::time::timeout(
                                        backend_timeout,
                                        transport_pool.send(&backend_addr, upstream_req),
                                    )
                                    .await
                                    {
                                        Ok(Ok(resp)) => resp,
                                        Ok(Err(err)) => {
                                            let proxy_err = ProxyError::Pool(err);
                                            let _ = observe_proxy_error_outcome(
                                                metrics.as_ref(),
                                                bootstrap_route_target(&upstream_name),
                                                Some(bootstrap_backend_target(
                                                    &upstream_name,
                                                    &backend_addr,
                                                    backend_index,
                                                )),
                                                request_start.elapsed(),
                                                Some(StatusCode::BAD_GATEWAY),
                                                &proxy_err,
                                                None,
                                            );
                                            if let Some(classified) =
                                                classify_upstream_proxy_error(&proxy_err)
                                            {
                                                Self::log_classified_upstream_failure(
                                                    "bootstrap",
                                                    Some(request_id),
                                                    Some(&upstream_name),
                                                    &backend_addr,
                                                    &classified,
                                                );
                                                if let Some(transition) = crate::runtime::connection::outcome::observe_classified_backend_failure(
                                                    crate::runtime::connection::outcome::ClassifiedBackendFailureInput {
                                                        metrics_phase: "bootstrap",
                                                        backend_addr: &backend_addr,
                                                        backend_index,
                                                        upstream_pool: Some(&upstream_pool),
                                                        metrics: metrics.as_ref(),
                                                        classified: &classified,
                                                    },
                                                ) {
                                                    crate::runtime::connection::outcome::log_backend_health_transition(
                                                        &backend_addr,
                                                        transition,
                                                    );
                                                }
                                            } else {
                                                warn!(
                                                    "Bootstrap proxy upstream error route={} backend={}: {}",
                                                    upstream_name, backend_addr, proxy_err
                                                );
                                            }
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upstream error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                        Err(_) => {
                                            let _ = observe_proxy_error_outcome(
                                                metrics.as_ref(),
                                                bootstrap_route_target(&upstream_name),
                                                Some(bootstrap_backend_target(
                                                    &upstream_name,
                                                    &backend_addr,
                                                    backend_index,
                                                )),
                                                request_start.elapsed(),
                                                Some(StatusCode::GATEWAY_TIMEOUT),
                                                &ProxyError::Timeout,
                                                None,
                                            );
                                            if let Some(classified) =
                                                classify_upstream_proxy_error(&ProxyError::Timeout)
                                            {
                                                Self::log_classified_upstream_failure(
                                                    "bootstrap",
                                                    Some(request_id),
                                                    Some(&upstream_name),
                                                    &backend_addr,
                                                    &classified,
                                                );
                                                if let Some(transition) = crate::runtime::connection::outcome::observe_classified_backend_failure(
                                                    crate::runtime::connection::outcome::ClassifiedBackendFailureInput {
                                                        metrics_phase: "bootstrap",
                                                        backend_addr: &backend_addr,
                                                        backend_index,
                                                        upstream_pool: Some(&upstream_pool),
                                                        metrics: metrics.as_ref(),
                                                        classified: &classified,
                                                    },
                                                ) {
                                                    crate::runtime::connection::outcome::log_backend_health_transition(
                                                        &backend_addr,
                                                        transition,
                                                    );
                                                }
                                            }
                                            return Ok(Response::builder()
                                                .status(StatusCode::GATEWAY_TIMEOUT)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upstream timeout\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    }
                                };

                                let status = upstream_resp.status();
                                let normalized_response =
                                    normalize_upstream_response(ResponseNormalizationInput {
                                        upstream: spooky_bridge::response::UpstreamResponseView {
                                            status,
                                            headers: upstream_resp.headers(),
                                            trailers: None,
                                        },
                                        body_mode: if suppress_downstream_body {
                                            ResponseBodyMode::HeadRequest
                                        } else {
                                            ResponseBodyMode::Normal
                                        },
                                        constraints: ResponseProtocolConstraints {
                                            protocol: ResponseNormalizationProtocol::Http1,
                                            strip_connection_headers: true,
                                            allow_trailers: false,
                                            preserve_upgrade: is_websocket_upgrade
                                                && status == StatusCode::SWITCHING_PROTOCOLS,
                                        },
                                    });
                                let upstream_content_length = upstream_resp
                                    .headers()
                                    .get(http::header::CONTENT_LENGTH)
                                    .and_then(|v| v.to_str().ok())
                                    .and_then(|s| s.parse::<usize>().ok());
                                let response_size_decision = checked_response_body_guardrails(
                                    ResponseBodyGuardrailConfig {
                                        idle_timeout: Duration::ZERO,
                                        total_timeout: Duration::MAX,
                                        max_body_bytes: max_response_body_bytes,
                                        unknown_length_prebuffer_bytes: max_response_body_bytes,
                                        chunk_bytes: 1,
                                    },
                                    ResponseBodyGuardrailInput {
                                        elapsed: Duration::ZERO,
                                        idle_for: Duration::ZERO,
                                        bytes_received: 0,
                                        prebuffered_bytes: 0,
                                        next_chunk_bytes: 0,
                                        declared_content_length: upstream_content_length,
                                        headers_emitted: false,
                                        progressive_emission_allowed: !normalized_response
                                            .emission
                                            .emit_end_stream_on_headers,
                                        body_forwarding_enabled: matches!(
                                            normalized_response.emission.body,
                                            ResponseBodyPolicy::Forward
                                        ),
                                        exempt_from_body_size_cap: is_websocket_upgrade
                                            && status == StatusCode::SWITCHING_PROTOCOLS,
                                    },
                                );
                                if matches!(
                                    response_size_decision,
                                    Err(ResponseBodyGuardrailDecision::Reject {
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
                                        Some(StatusCode::SERVICE_UNAVAILABLE),
                                        &ProxyError::Pool(
                                            spooky_errors::PoolError::BackendOverloaded(
                                                "response prebuffer cap".into(),
                                            ),
                                        ),
                                        Some(crate::OverloadShedReason::ResponsePrebufferCap),
                                    );
                                    return Ok(Response::builder()
                                        .status(StatusCode::SERVICE_UNAVAILABLE)
                                        .header("alt-svc", &alt)
                                        .body(boxed_full(Bytes::from_static(
                                            RESPONSE_BODY_TOO_LARGE_BODY,
                                        )))
                                        .unwrap_or_else(|_| {
                                            Response::new(boxed_full(Bytes::from_static(
                                                b"error\n",
                                            )))
                                        }));
                                }
                                let _ = observe_status_outcome(
                                    metrics.as_ref(),
                                    bootstrap_route_target(&upstream_name),
                                    Some(bootstrap_backend_target(
                                        &upstream_name,
                                        &backend_addr,
                                        backend_index,
                                    )),
                                    request_start.elapsed(),
                                    status,
                                );
                                if let Some(transition) = observe_backend_response_status(
                                    crate::runtime::connection::outcome::BackendHealthObservationInput {
                                        backend_addr: &backend_addr,
                                        backend_index,
                                        upstream_pool: Some(&upstream_pool),
                                        status,
                                    },
                                ) {
                                    crate::runtime::connection::outcome::log_backend_health_transition(
                                        &backend_addr,
                                        transition,
                                    );
                                }
                                let mut resp_builder =
                                    Response::builder().status(normalized_response.head.status);
                                for header in &normalized_response.head.headers {
                                    resp_builder = resp_builder.header(&header.name, &header.value);
                                }
                                resp_builder = resp_builder.header("alt-svc", &alt);
                                if is_websocket_upgrade
                                    && upstream_resp.status() == StatusCode::SWITCHING_PROTOCOLS
                                {
                                    let client_upgrade = match client_upgrade {
                                        Some(u) => u,
                                        None => {
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"upgrade setup error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    };
                                    let upstream_upgrade = upgrade::on(&mut upstream_resp);
                                    tokio::spawn(async move {
                                        let (client, upstream) = match tokio::try_join!(
                                            client_upgrade,
                                            upstream_upgrade
                                        ) {
                                            Ok(v) => v,
                                            Err(err) => {
                                                debug!(
                                                    "Bootstrap WebSocket upgrade join failed: {}",
                                                    err
                                                );
                                                return;
                                            }
                                        };
                                        let mut client = TokioIo::new(client);
                                        let mut upstream = TokioIo::new(upstream);
                                        let _ = tokio::io::copy_bidirectional(
                                            &mut client,
                                            &mut upstream,
                                        )
                                        .await;
                                    });
                                    crate::runtime::connection::outcome::finish_backend_request_accounting(
                                        crate::runtime::connection::outcome::BackendRequestFinishInput {
                                            upstream_pool: Some(&upstream_pool),
                                            backend_index: Some(backend_index),
                                            elapsed: request_start.elapsed(),
                                            status: Some(status.as_u16()),
                                        },
                                    );
                                    return Ok(resp_builder
                                        .body(boxed_full(Bytes::new()))
                                        .unwrap_or_else(|_| {
                                            Response::new(boxed_full(Bytes::new()))
                                        }));
                                }
                                let resp_body = if matches!(
                                    normalized_response.emission.body,
                                    ResponseBodyPolicy::Suppress
                                ) {
                                    crate::runtime::connection::outcome::finish_backend_request_accounting(
                                        crate::runtime::connection::outcome::BackendRequestFinishInput {
                                            upstream_pool: Some(&upstream_pool),
                                            backend_index: Some(backend_index),
                                            elapsed: request_start.elapsed(),
                                            status: Some(status.as_u16()),
                                        },
                                    );
                                    boxed_full(Bytes::new())
                                } else {
                                    BootstrapStreamingBody::with_response_guardrails(
                                        upstream_resp.into_body(),
                                        max_response_body_bytes,
                                        upstream_content_length,
                                        Arc::clone(&upstream_pool),
                                        backend_index,
                                        request_start,
                                        Some(status.as_u16()),
                                    )
                                    .map_err(|never| match never {})
                                    .boxed()
                                };

                                Ok(resp_builder
                                    .body(resp_body)
                                    .unwrap_or_else(|_| Response::new(boxed_full(Bytes::new()))))
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
