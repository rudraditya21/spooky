use std::collections::HashMap;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::upgrade;
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use spooky_bridge::context::{ForwardedContext, ForwardedHeaderChains};
use spooky_bridge::forwarded::build_forwarded_header_values;
use spooky_bridge::h3_to_h1::build_h1_request_for_endpoint_with_host_policy;
use spooky_bridge::h3_to_h2::build_h2_request_for_endpoint_with_host_policy;
use spooky_bridge::host::resolve_upstream_host_value;
use spooky_config::{
    backend_endpoint::{BackendEndpoint, BackendScheme},
    runtime::{ListenerRuntimeConfig, RuntimeUpstreamPolicy},
};
use spooky_errors::ProxyError;
use spooky_lb::upstream_pool::UpstreamPool;
use spooky_transport::transport_pool::UpstreamTransportPool;

use crate::{
    Metrics, REQUEST_ID_COUNTER, RouteOutcome, SharedRuntimeState,
    resilience::runtime::RuntimeResilience,
    routing::index::RouteIndex,
    types::{ListenerTlsReloadStore, RuntimeBackendResolutionStore, RuntimeBundleHandle},
};

use super::runtime_endpoint::RuntimeConnectionSlotGuard;
use super::{
    BootstrapServiceFuture, BootstrapStreamingBody, QUICListener,
    bootstrap_resolution_error_response, boxed_full, connection_header_tokens, is_head_method,
    is_websocket_upgrade_request, runtime_handle, should_strip_bootstrap_response_header,
    spawn_supervised_async_task, validate_http_request,
};

pub(super) struct BootstrapConnectionState {
    pub(super) alt_svc_value: String,
    pub(super) backend_timeout: Duration,
    pub(super) max_request_body_bytes: usize,
    pub(super) max_response_body_bytes: usize,
    pub(super) max_connections: usize,
    pub(super) connection_timeout: Duration,
    pub(super) listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub(super) transport_pool: Arc<UpstreamTransportPool>,
    pub(super) backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub(super) backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
    pub(super) upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    pub(super) metrics: Arc<Metrics>,
    pub(super) resilience: Arc<RuntimeResilience>,
    pub(super) upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(super) routing_index: Arc<RouteIndex>,
}

pub(super) struct BootstrapStartupState {
    pub(super) listener_config: ListenerRuntimeConfig,
    pub(super) listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub(super) transport_pool: Arc<UpstreamTransportPool>,
    pub(super) backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub(super) backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
    pub(super) upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    pub(super) metrics: Arc<Metrics>,
    pub(super) resilience: Arc<RuntimeResilience>,
    pub(super) upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(super) routing_index: Arc<RouteIndex>,
}

impl QUICListener {
    pub fn spawn_bootstrap_tls_listener(
        config: &ListenerRuntimeConfig,
        shared_state: &SharedRuntimeState,
        runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
        shutdown_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), ProxyError> {
        let bind = format!(
            "{}:{}",
            config.listen.listen.address, config.listen.listen.port
        );
        let alt_svc_value = format!("h3=\":{}\"; ma=86400", config.listen.listen.port);
        let max_connections = config.performance.max_active_connections.max(1);
        let connection_timeout =
            Duration::from_millis(config.performance.client_body_idle_timeout_ms.max(1));
        let listener_label = Self::listener_label(config);
        shared_state
            .listener_tls_store
            .bootstrap_server_config(&listener_label)
            .ok_or_else(|| {
                ProxyError::Tls(format!(
                    "failed to initialize bootstrap TLS listener config for '{}': missing reload state",
                    listener_label
                ))
            })?;

        let transport_pool = Arc::clone(&shared_state.transport_pool);
        let backend_endpoints = Arc::clone(&shared_state.backend_endpoints);
        let backend_resolution_store = Arc::clone(&shared_state.backend_resolution_store);
        let upstream_policies = Arc::clone(&shared_state.upstream_policies);
        let metrics = Arc::clone(&shared_state.metrics);
        let resilience = Arc::clone(&shared_state.resilience);
        let upstream_pools = shared_state.upstream_pools.clone();
        let listener_tls_store = Arc::clone(&shared_state.listener_tls_store);
        let runtime_bundle = runtime_bundle.clone();
        let handle = match runtime_handle() {
            Some(h) => h,
            None => {
                return Err(ProxyError::Transport(
                    "failed to start bootstrap TLS listener: no Tokio runtime available"
                        .to_string(),
                ));
            }
        };

        let std_listener = std::net::TcpListener::bind(&bind).map_err(|err| {
            ProxyError::Transport(format!(
                "failed to bind bootstrap TLS listener on {}: {}",
                bind, err
            ))
        })?;
        if let Err(err) = std_listener.set_nonblocking(true) {
            return Err(ProxyError::Transport(format!(
                "failed to set bootstrap TLS listener nonblocking ({}): {}",
                bind, err
            )));
        }
        let listener = {
            let _guard = handle.enter();
            tokio::net::TcpListener::from_std(std_listener).map_err(|err| {
                ProxyError::Transport(format!(
                    "failed to register bootstrap TLS listener {}: {}",
                    bind, err
                ))
            })?
        };

        let startup_state = BootstrapStartupState {
            listener_config: config.clone(),
            listener_tls_store: Arc::clone(&listener_tls_store),
            transport_pool: Arc::clone(&transport_pool),
            backend_endpoints: Arc::clone(&backend_endpoints),
            backend_resolution_store: Arc::clone(&backend_resolution_store),
            upstream_policies: Arc::clone(&upstream_policies),
            metrics: Arc::clone(&metrics),
            resilience: Arc::clone(&resilience),
            upstream_pools: upstream_pools.clone(),
            routing_index: Arc::clone(&shared_state.routing_index),
        };

        spawn_supervised_async_task(&handle, "bootstrap-tls-listener", None, async move {
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
                                let resolved = Self::resolve_backend(
                                    &method,
                                    &path,
                                    authority.as_deref(),
                                    None,
                                    &upstream_pools,
                                    &routing_index,
                                    Some(&lb_header_lookup),
                                );
                                let (backend_addr, upstream_name) = match resolved {
                                    Ok(value) => (value.backend_addr, value.upstream_name),
                                    Err(ProxyError::Transport(reason)) => {
                                        let (status, body) =
                                            bootstrap_resolution_error_response(&reason);
                                        if status == StatusCode::BAD_GATEWAY
                                            && body == b"route/backend resolution failed\n"
                                        {
                                            warn!(
                                                "Bootstrap route/backend resolution failed: {}",
                                                reason
                                            );
                                        }
                                        return bootstrap_error(status, body);
                                    }
                                    Err(err) => {
                                        warn!("Bootstrap route/backend resolution failed: {}", err);
                                        return bootstrap_error(
                                            StatusCode::BAD_GATEWAY,
                                            b"route/backend resolution failed\n",
                                        );
                                    }
                                };

                                if let Some(policy) = upstream_policies.get(&upstream_name) {
                                    let denied_challenge = if !Self::api_key_is_authorized(
                                        policy,
                                        Some(&lb_header_lookup),
                                    ) {
                                        Some("ApiKey")
                                    } else if !Self::jwt_is_authorized(
                                        policy,
                                        Some(&lb_header_lookup),
                                    ) {
                                        Some("Bearer")
                                    } else {
                                        None
                                    };
                                    if let Some(challenge) = denied_challenge {
                                        metrics.inc_failure();
                                        metrics.inc_policy_denied();
                                        metrics.record_route(
                                            &upstream_name,
                                            Duration::from_millis(0),
                                            RouteOutcome::Failure,
                                        );
                                        warn!(
                                            "Bootstrap request route={} denied by auth policy",
                                            upstream_name
                                        );
                                        return Ok(Response::builder()
                                            .status(StatusCode::UNAUTHORIZED)
                                            .header("alt-svc", &alt)
                                            .header("www-authenticate", challenge)
                                            .body(boxed_full(Bytes::from_static(b"unauthorized\n")))
                                            .unwrap_or_else(|_| {
                                                Response::new(boxed_full(Bytes::from_static(
                                                    b"error\n",
                                                )))
                                            }));
                                    }
                                }

                                if let Some(rejection) =
                                    resilience.scoped_rate_limits.check(&upstream_name, |rule| {
                                        Self::resolve_scoped_rate_limit_key(
                                            rule,
                                            &upstream_name,
                                            &method,
                                            &path,
                                            authority.as_deref(),
                                            peer,
                                            Some(&lb_header_lookup),
                                        )
                                    })
                                {
                                    metrics.inc_failure();
                                    metrics.inc_request_rate_limited();
                                    metrics.record_route(
                                        &upstream_name,
                                        Duration::from_millis(0),
                                        RouteOutcome::RateLimited,
                                    );
                                    warn!(
                                        "Bootstrap request route={} scoped rate limit exceeded by rule={}",
                                        rejection.route, rejection.rule_name
                                    );
                                    return Ok(Response::builder()
                                        .status(StatusCode::TOO_MANY_REQUESTS)
                                        .header("alt-svc", &alt)
                                        .header(
                                            "retry-after",
                                            rejection.retry_after_seconds.max(1).to_string(),
                                        )
                                        .body(boxed_full(Bytes::from_static(
                                            b"request rate limited\n",
                                        )))
                                        .unwrap_or_else(|_| {
                                            Response::new(boxed_full(Bytes::from_static(
                                                b"error\n",
                                            )))
                                        }));
                                }

                                let endpoint = match backend_endpoints.get(&backend_addr) {
                                    Some(ep) => ep.clone(),
                                    None => {
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
                                let upstream_policy = upstream_policies
                                    .get(&upstream_name)
                                    .cloned()
                                    .unwrap_or_default();
                                if !is_websocket_upgrade
                                    && content_length
                                        .is_some_and(|value| value > max_request_body_bytes)
                                {
                                    return Ok(Response::builder()
                                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                                        .header("alt-svc", &alt)
                                        .body(boxed_full(Bytes::from_static(
                                            b"request body too large\n",
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
                                let upstream_req = if is_websocket_upgrade {
                                    let upstream_uri = match http::Uri::try_from(
                                        endpoint.uri_for_path(request_path),
                                    ) {
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
                                    let request_host = req
                                        .headers()
                                        .get(http::header::HOST)
                                        .and_then(|value| value.to_str().ok());
                                    let upstream_host = match resolve_upstream_host_value(
                                        &endpoint,
                                        &upstream_policy.host.0,
                                        authority.as_deref(),
                                        request_host,
                                    ) {
                                        Ok(host) => host,
                                        Err(_) => {
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"invalid host policy\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    };

                                    let mut upstream_req = Request::builder()
                                        .method(method.as_str())
                                        .uri(upstream_uri);
                                    let mut forwarded_from_headers: Vec<Vec<u8>> = Vec::new();
                                    let mut x_forwarded_for_from_headers: Vec<Vec<u8>> = Vec::new();
                                    let mut x_forwarded_proto_from_headers: Vec<Vec<u8>> =
                                        Vec::new();
                                    let mut x_forwarded_host_from_headers: Vec<Vec<u8>> =
                                        Vec::new();
                                    for (name, value) in req.headers() {
                                        if name == http::header::HOST {
                                            continue;
                                        }
                                        if name.as_str().eq_ignore_ascii_case("forwarded") {
                                            forwarded_from_headers.push(value.as_bytes().to_vec());
                                            continue;
                                        }
                                        if name.as_str().eq_ignore_ascii_case("x-forwarded-for") {
                                            x_forwarded_for_from_headers
                                                .push(value.as_bytes().to_vec());
                                            continue;
                                        }
                                        if name.as_str().eq_ignore_ascii_case("x-forwarded-proto") {
                                            x_forwarded_proto_from_headers
                                                .push(value.as_bytes().to_vec());
                                            continue;
                                        }
                                        if name.as_str().eq_ignore_ascii_case("x-forwarded-host") {
                                            x_forwarded_host_from_headers
                                                .push(value.as_bytes().to_vec());
                                            continue;
                                        }
                                        if name == http::header::PROXY_AUTHORIZATION
                                            || name == http::header::PROXY_AUTHENTICATE
                                            || name
                                                .as_str()
                                                .eq_ignore_ascii_case("proxy-connection")
                                            || name == http::header::CONTENT_LENGTH
                                            || name == http::header::TE
                                            || name == http::header::TRAILER
                                            || name == http::header::TRANSFER_ENCODING
                                            || name.as_str().eq_ignore_ascii_case("keep-alive")
                                            || name.as_str().eq_ignore_ascii_case("forwarded")
                                            || name.as_str().eq_ignore_ascii_case("x-forwarded-for")
                                            || name
                                                .as_str()
                                                .eq_ignore_ascii_case("x-forwarded-proto")
                                            || name
                                                .as_str()
                                                .eq_ignore_ascii_case("x-forwarded-host")
                                        {
                                            continue;
                                        }
                                        upstream_req = upstream_req.header(name, value);
                                    }
                                    upstream_req =
                                        upstream_req.header(http::header::HOST, upstream_host);

                                    let forwarded_values = match build_forwarded_header_values(
                                        &upstream_policy.forwarded_headers.0,
                                        ForwardedHeaderChains {
                                            forwarded: &forwarded_from_headers,
                                            x_forwarded_for: &x_forwarded_for_from_headers,
                                            x_forwarded_proto: &x_forwarded_proto_from_headers,
                                            x_forwarded_host: &x_forwarded_host_from_headers,
                                        },
                                        peer.ip(),
                                        upstream_host,
                                    ) {
                                        Ok(values) => values,
                                        Err(err) => {
                                            warn!(
                                                "Bootstrap forwarded header policy failed: {}",
                                                err
                                            );
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"invalid forwarded headers\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    };
                                    if let Some(value) = forwarded_values.forwarded {
                                        upstream_req = upstream_req.header("forwarded", value);
                                    }
                                    if let Some(value) = forwarded_values.x_forwarded_for {
                                        upstream_req =
                                            upstream_req.header("x-forwarded-for", value);
                                    }
                                    if let Some(value) = forwarded_values.x_forwarded_proto {
                                        upstream_req =
                                            upstream_req.header("x-forwarded-proto", value);
                                    }
                                    if let Some(value) = forwarded_values.x_forwarded_host {
                                        upstream_req =
                                            upstream_req.header("x-forwarded-host", value);
                                    }

                                    match upstream_req.body(boxed_full(Bytes::new())) {
                                        Ok(request) => request,
                                        Err(_) => {
                                            return Ok(Response::builder()
                                                .status(StatusCode::BAD_GATEWAY)
                                                .header("alt-svc", &alt)
                                                .body(boxed_full(Bytes::from_static(
                                                    b"request build error\n",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(boxed_full(Bytes::from_static(
                                                        b"error\n",
                                                    )))
                                                }));
                                        }
                                    }
                                } else {
                                    let bridge_headers: Vec<quiche::h3::Header> = req
                                        .headers()
                                        .iter()
                                        .map(|(name, value)| {
                                            quiche::h3::Header::new(
                                                name.as_str().as_bytes(),
                                                value.as_bytes(),
                                            )
                                        })
                                        .collect();
                                    let bridge_body = BootstrapStreamingBody::new(req.into_body())
                                        .map_err(|never| match never {})
                                        .boxed();
                                    let bridge_ctx = ForwardedContext {
                                        client_addr: peer,
                                        request_authority: authority.as_deref(),
                                        request_id,
                                        traceparent: traceparent.as_deref(),
                                    };
                                    let build_result = if endpoint.scheme() == BackendScheme::Http {
                                        build_h1_request_for_endpoint_with_host_policy(
                                            &endpoint,
                                            &upstream_policy.host.0,
                                            &upstream_policy.forwarded_headers.0,
                                            &method,
                                            &path,
                                            &bridge_headers,
                                            bridge_body,
                                            None,
                                            bridge_ctx,
                                        )
                                    } else {
                                        build_h2_request_for_endpoint_with_host_policy(
                                            &endpoint,
                                            &upstream_policy.host.0,
                                            &upstream_policy.forwarded_headers.0,
                                            &method,
                                            &path,
                                            &bridge_headers,
                                            bridge_body,
                                            None,
                                            bridge_ctx,
                                        )
                                    };
                                    match build_result {
                                        Ok(request) => request,
                                        Err(err) => {
                                            warn!("Bootstrap request build failed: {}", err);
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
                                            warn!("Bootstrap WebSocket upstream error: {}", err);
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
                                            warn!("Bootstrap proxy upstream error: {}", err);
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
                                    }
                                };

                                if !suppress_downstream_body
                                    && let Some(content_length) = upstream_resp
                                        .headers()
                                        .get(http::header::CONTENT_LENGTH)
                                        .and_then(|v| v.to_str().ok())
                                        .and_then(|s| s.parse::<usize>().ok())
                                    && content_length > max_response_body_bytes
                                {
                                    return Ok(Response::builder()
                                        .status(StatusCode::SERVICE_UNAVAILABLE)
                                        .header("alt-svc", &alt)
                                        .body(boxed_full(Bytes::from_static(
                                            b"upstream response body too large\n",
                                        )))
                                        .unwrap_or_else(|_| {
                                            Response::new(boxed_full(Bytes::from_static(
                                                b"error\n",
                                            )))
                                        }));
                                }

                                let status = upstream_resp.status();
                                let mut resp_builder = Response::builder().status(status);
                                let response_connection_tokens =
                                    connection_header_tokens(upstream_resp.headers());
                                let preserve_upgrade_response_headers = is_websocket_upgrade
                                    && status == StatusCode::SWITCHING_PROTOCOLS;
                                for (name, value) in upstream_resp.headers() {
                                    let preserve_upgrade_header = preserve_upgrade_response_headers
                                        && (*name == http::header::CONNECTION
                                            || *name == http::header::UPGRADE);
                                    if should_strip_bootstrap_response_header(
                                        name,
                                        &response_connection_tokens,
                                    ) && !preserve_upgrade_header
                                    {
                                        continue;
                                    }
                                    resp_builder = resp_builder.header(name, value);
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
                                    return Ok(resp_builder
                                        .body(boxed_full(Bytes::new()))
                                        .unwrap_or_else(|_| {
                                            Response::new(boxed_full(Bytes::new()))
                                        }));
                                }
                                let resp_body = if suppress_downstream_body {
                                    boxed_full(Bytes::new())
                                } else {
                                    BootstrapStreamingBody::with_max_bytes(
                                        upstream_resp.into_body(),
                                        max_response_body_bytes,
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
        let (
            listener_config,
            listener_tls_store,
            transport_pool,
            backend_endpoints,
            backend_resolution_store,
            upstream_policies,
            metrics,
            resilience,
            upstream_pools,
            routing_index,
        ) = if let Some(handle) = runtime_bundle {
            let runtime = handle.current();
            (
                runtime.listener_runtime_config(listener_label)?,
                runtime.shared_state.listener_tls_store.clone(),
                runtime.shared_state.transport_pool.clone(),
                runtime.shared_state.backend_endpoints.clone(),
                runtime.shared_state.backend_resolution_store.clone(),
                runtime.shared_state.upstream_policies.clone(),
                runtime.shared_state.metrics.clone(),
                runtime.shared_state.resilience.clone(),
                runtime.shared_state.upstream_pools.clone(),
                runtime.shared_state.routing_index.clone(),
            )
        } else {
            (
                startup.listener_config.clone(),
                Arc::clone(&startup.listener_tls_store),
                Arc::clone(&startup.transport_pool),
                Arc::clone(&startup.backend_endpoints),
                Arc::clone(&startup.backend_resolution_store),
                Arc::clone(&startup.upstream_policies),
                Arc::clone(&startup.metrics),
                Arc::clone(&startup.resilience),
                startup.upstream_pools.clone(),
                Arc::clone(&startup.routing_index),
            )
        };

        Some(BootstrapConnectionState {
            alt_svc_value: format!("h3=\":{}\"; ma=86400", listener_config.listen.listen.port),
            backend_timeout: Duration::from_millis(listener_config.performance.backend_timeout_ms),
            max_request_body_bytes: listener_config.performance.max_request_body_bytes,
            max_response_body_bytes: listener_config.performance.max_response_body_bytes,
            max_connections: listener_config.performance.max_active_connections.max(1),
            connection_timeout: Duration::from_millis(
                listener_config
                    .performance
                    .client_body_idle_timeout_ms
                    .max(1),
            ),
            listener_tls_store,
            transport_pool,
            backend_endpoints,
            backend_resolution_store,
            upstream_policies,
            metrics,
            resilience,
            upstream_pools,
            routing_index,
        })
    }
}
