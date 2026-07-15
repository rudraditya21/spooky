use std::convert::Infallible;

use spooky_config::runtime::RuntimeExternalAuth;
use tracing::Span;

use super::{
    auth::{AuthStart, auth_failure_mode, fail_open, start_external_auth_task},
    resolve::{ResolvedBackend, ResolvedRoute, RouteResolutionRequest, SelectedBackend},
    *,
};
use crate::{
    quic_listener::admission::{
        AdmissionPolicyDecision, admission_rejection_response,
        evaluate_forwarding_pre_admission_policy,
    },
    runtime::connection::{auth::PendingHeaderMutation, request::PendingForward},
};

pub(super) struct PreparedRequest {
    pub(super) upstream_name: String,
    pub(super) backend_addr: String,
    pub(super) backend_index: usize,
    pub(super) upstream_pool: Arc<RwLock<UpstreamPool>>,
    pub(super) backend_lb: String,
    pub(super) route_path_len: usize,
    pub(super) route_host_specific: bool,
    pub(super) route_reason: String,
    pub(super) request_id: u64,
    pub(super) trace_id: Option<String>,
    pub(super) span_id: Option<String>,
    pub(super) traceparent: Option<String>,
    pub(super) trace_span: Option<Span>,
    pub(super) bodyless_mode: bool,
    pub(super) request_fin_received: bool,
    pub(super) pending_forward: Arc<PendingForward>,
    pub(super) auth_fail_open: bool,
}

pub(super) struct PreAuthRequest {
    pub(super) request: PreparedRequest,
    pub(super) external_auth: Option<RuntimeExternalAuth>,
}

pub(super) struct StartedAuthRequest {
    pub(super) request: PreparedRequest,
    pub(super) auth_start: Option<AuthStart>,
    pub(super) auth_requested: bool,
}

impl PendingForward {
    pub(super) fn request_headers(&self) -> Vec<quiche::h3::Header> {
        let mut headers = self.headers.as_ref().clone();
        for mutation in &self.auth_header_mutations {
            match mutation {
                PendingHeaderMutation::Upsert { name, value } => {
                    headers.retain(|header| !header.name().eq_ignore_ascii_case(name.as_slice()));
                    headers.push(quiche::h3::Header::new(name.as_slice(), value.as_slice()));
                }
                PendingHeaderMutation::Remove { name } => {
                    headers.retain(|header| !header.name().eq_ignore_ascii_case(name.as_slice()));
                }
            }
        }
        headers
    }

    fn forwarded_context(&self) -> ForwardedContext<'_> {
        ForwardedContext {
            client_addr: self.client_addr,
            request_authority: self.authority.as_deref(),
            request_id: self.request_id,
            traceparent: self.traceparent.as_deref(),
        }
    }

    pub(super) fn build_request(
        &self,
        endpoint: &BackendEndpoint,
        body: BoxBody<Bytes, Infallible>,
        content_length: Option<usize>,
    ) -> Result<Request<BoxBody<Bytes, Infallible>>, ProxyError> {
        let headers = self.request_headers();
        if endpoint.scheme() == BackendScheme::Http {
            build_h1_request_for_endpoint_with_host_policy(
                endpoint,
                &self.host_policy,
                &self.forwarded_header_policy,
                &self.method,
                &self.path,
                &headers,
                body,
                content_length,
                self.forwarded_context(),
            )
            .map_err(ProxyError::from)
        } else {
            build_h2_request_for_endpoint_with_host_policy(
                endpoint,
                &self.host_policy,
                &self.forwarded_header_policy,
                &self.method,
                &self.path,
                &headers,
                body,
                content_length,
                self.forwarded_context(),
            )
            .map_err(ProxyError::from)
        }
    }

    pub(super) fn build_bodyless_request(
        &self,
        endpoint: &BackendEndpoint,
    ) -> Result<Request<BoxBody<Bytes, Infallible>>, ProxyError> {
        self.build_request(endpoint, BoxBody::new(Full::new(Bytes::new())), Some(0))
    }

    pub(super) fn build_http1_websocket_tunnel_request(
        &self,
        endpoint: &BackendEndpoint,
    ) -> Result<Request<BoxBody<Bytes, Infallible>>, ProxyError> {
        let mut request_headers = self.request_headers();
        let has_upgrade = request_headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case(b"upgrade"));
        if !has_upgrade {
            request_headers.push(quiche::h3::Header::new(b"upgrade", b"websocket"));
        }
        let has_connection = request_headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case(b"connection"));
        if !has_connection {
            request_headers.push(quiche::h3::Header::new(b"connection", b"upgrade"));
        }

        build_h1_request_for_endpoint_with_host_policy(
            endpoint,
            &self.host_policy,
            &self.forwarded_header_policy,
            "GET",
            &self.path,
            &request_headers,
            BoxBody::new(Full::new(Bytes::new())),
            None,
            self.forwarded_context(),
        )
        .map_err(ProxyError::from)
    }
}

impl QUICListener {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_request_for_auth(
        stream_id: u64,
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        peer_address: SocketAddr,
        quic_trace_id: &str,
        request_start: Instant,
        method: &str,
        path: &str,
        authority: Option<&str>,
        content_length: Option<usize>,
        tunnel_mode: TunnelMode,
        headers: &[quiche::h3::Header],
        sticky_cid_key: &str,
        tracing_enabled: bool,
        routing_index: &RouteIndex,
        upstream_policies: &HashMap<String, RuntimeUpstreamPolicy>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        metrics: &Metrics,
        resilience: &RuntimeResilience,
    ) -> Result<Option<PreAuthRequest>, quiche::h3::Error> {
        let lb_header_lookup = |name: &str| {
            headers
                .iter()
                .find(|header| header.name().eq_ignore_ascii_case(name.as_bytes()))
                .and_then(|header| std::str::from_utf8(header.value()).ok())
                .map(str::to_string)
        };
        let route_method = if matches!(tunnel_mode, TunnelMode::Websocket) {
            "GET"
        } else {
            method
        };
        let resolution_request = RouteResolutionRequest::new(
            route_method,
            path,
            authority,
            Some(sticky_cid_key),
            Some(&lb_header_lookup),
        );
        let resolved = Self::resolve_backend_without_inflight_request(
            &resolution_request,
            upstream_pools,
            routing_index,
        );

        let prepared = match resolved {
            Ok(ResolvedBackend { route, backend }) => {
                let ResolvedRoute {
                    upstream_name,
                    upstream_pool,
                    route_path_len,
                    route_host_specific,
                    route_reason,
                } = route;
                let SelectedBackend {
                    backend_addr,
                    backend_index,
                    backend_lb,
                } = backend;
                let upstream_policy = upstream_policies
                    .get(&upstream_name)
                    .cloned()
                    .unwrap_or_default();
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
                            method,
                            path,
                            authority,
                            peer_address,
                            Some(&lb_header_lookup),
                        )
                    },
                );
                metrics.set_brownout_active(resilience.brownout.is_active());
                let rejection_response = admission_rejection_response(&admission);
                match admission {
                    AdmissionPolicyDecision::AdmitReady => {}
                    AdmissionPolicyDecision::Unauthorized(_) => {
                        metrics.inc_failure();
                        metrics.inc_policy_denied();
                        metrics.record_route(
                            &upstream_name,
                            request_start.elapsed(),
                            RouteOutcome::Failure,
                        );
                        warn!(
                            "request_id=unassigned route={} denied by local auth policy",
                            upstream_name
                        );
                        let Some(response) = rejection_response.as_ref() else {
                            warn!(
                                "request_id=unassigned route={} missing admission rejection response for unauthorized decision",
                                upstream_name
                            );
                            Self::send_simple_response(
                                h3,
                                quic,
                                stream_id,
                                http::StatusCode::INTERNAL_SERVER_ERROR,
                                b"internal proxy error\n",
                            )?;
                            return Ok(None);
                        };
                        Self::send_admission_rejection_response(h3, quic, stream_id, response)?;
                        return Ok(None);
                    }
                    AdmissionPolicyDecision::RateLimited(decision) => {
                        metrics.inc_failure();
                        metrics.inc_request_rate_limited();
                        metrics.record_route(
                            &upstream_name,
                            request_start.elapsed(),
                            RouteOutcome::RateLimited,
                        );
                        warn!(
                            "request_id=unassigned route={} scoped rate limit exceeded by rule={}",
                            decision.route, decision.rule_name
                        );
                        let Some(response) = rejection_response.as_ref() else {
                            warn!(
                                "request_id=unassigned route={} missing admission rejection response for rate-limited decision",
                                upstream_name
                            );
                            Self::send_simple_response(
                                h3,
                                quic,
                                stream_id,
                                http::StatusCode::INTERNAL_SERVER_ERROR,
                                b"internal proxy error\n",
                            )?;
                            return Ok(None);
                        };
                        Self::send_admission_rejection_response(h3, quic, stream_id, response)?;
                        return Ok(None);
                    }
                    AdmissionPolicyDecision::Overloaded(decision) => {
                        metrics.inc_failure();
                        metrics.inc_overload_shed_reason(decision.reason.metrics_reason());
                        metrics.record_route(
                            &upstream_name,
                            request_start.elapsed(),
                            RouteOutcome::OverloadShed,
                        );
                        let Some(response) = rejection_response.as_ref() else {
                            warn!(
                                "request_id=unassigned route={} missing admission rejection response for overload decision",
                                upstream_name
                            );
                            Self::send_simple_response(
                                h3,
                                quic,
                                stream_id,
                                http::StatusCode::INTERNAL_SERVER_ERROR,
                                b"internal proxy error\n",
                            )?;
                            return Ok(None);
                        };
                        Self::send_admission_rejection_response(h3, quic, stream_id, response)?;
                        resilience
                            .adaptive_admission
                            .observe(request_start.elapsed(), true);
                        return Ok(None);
                    }
                }

                let request_id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
                let incoming_traceparent =
                    extract_header_value(headers, b"traceparent").and_then(parse_traceparent);
                let trace_id = incoming_traceparent
                    .as_ref()
                    .map(|(trace_id, _)| trace_id.clone())
                    .or_else(|| {
                        tracing_enabled.then(|| generated_trace_id(quic_trace_id, request_id))
                    });
                let span_id = trace_id.as_ref().map(|_| generated_span_id(request_id));
                let traceparent = trace_id
                    .as_ref()
                    .zip(span_id.as_ref())
                    .map(|(trace_id, span_id)| format!("00-{trace_id}-{span_id}-01"));
                let trace_span =
                    trace_id
                        .as_ref()
                        .zip(span_id.as_ref())
                        .map(|(trace_id, span_id)| {
                            info_span!(
                                "spooky.request",
                                request_id = request_id,
                                trace_id = %trace_id,
                                span_id = %span_id,
                                method = %method,
                                path = %path
                            )
                        });
                let bodyless_mode = !is_tunnel_mode(tunnel_mode)
                    && is_bodyless_request_mode(method, content_length);
                let request_fin_received = bodyless_mode;
                let route_reason = format!("{route_reason:?}");
                let external_auth = upstream_policy.upstream_auth.external_auth.clone();
                let auth_fail_open = external_auth
                    .as_ref()
                    .map(|auth| fail_open(auth_failure_mode(auth)))
                    .unwrap_or(false);
                let pending_forward = Arc::new(PendingForward {
                    method: Arc::<str>::from(method),
                    path: Arc::<str>::from(path),
                    authority: authority.map(Arc::<str>::from),
                    headers: Arc::new(headers.to_vec()),
                    upstream_name: Arc::<str>::from(upstream_name.as_str()),
                    route_reason: Arc::<str>::from(route_reason.as_str()),
                    route_path_len,
                    route_host_specific,
                    backend_addr: Arc::<str>::from(backend_addr.as_str()),
                    backend_index,
                    backend_lb: Some(Arc::<str>::from(backend_lb.as_str())),
                    client_addr: peer_address,
                    request_id,
                    trace_id: trace_id.as_deref().map(Arc::<str>::from),
                    span_id: span_id.as_deref().map(Arc::<str>::from),
                    traceparent: traceparent.as_deref().map(Arc::<str>::from),
                    host_policy: upstream_policy.host.0.clone(),
                    forwarded_header_policy: upstream_policy.forwarded_headers.0.clone(),
                    auth_header_mutations: Vec::new(),
                });

                Some(PreAuthRequest {
                    request: PreparedRequest {
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
                    external_auth,
                })
            }
            Err(err) => {
                metrics.inc_failure();
                metrics.record_route("unrouted", request_start.elapsed(), RouteOutcome::Failure);
                let (status, body): (http::StatusCode, &[u8]) = match err {
                    ProxyError::Transport(_) => (
                        http::StatusCode::SERVICE_UNAVAILABLE,
                        b"no upstream available\n",
                    ),
                    ProxyError::Bridge(_) => (http::StatusCode::BAD_REQUEST, b"invalid request\n"),
                    _ => (
                        http::StatusCode::INTERNAL_SERVER_ERROR,
                        b"internal proxy error\n",
                    ),
                };
                Self::send_simple_response(h3, quic, stream_id, status, body)?;
                resilience
                    .adaptive_admission
                    .observe(request_start.elapsed(), true);
                None
            }
        };

        Ok(prepared)
    }

    pub(super) fn start_request_auth(
        stream_id: u64,
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        request_start: Instant,
        metrics: &Metrics,
        pre_auth: PreAuthRequest,
    ) -> Result<Option<StartedAuthRequest>, quiche::h3::Error> {
        let PreAuthRequest {
            request,
            external_auth,
        } = pre_auth;
        let auth_fail_open = request.auth_fail_open;
        let auth_start = if let Some(external_auth) = external_auth {
            match start_external_auth_task(Arc::clone(&request.pending_forward), external_auth) {
                Ok(start) => Some(start),
                Err(err) if auth_fail_open => {
                    metrics.inc_external_auth_error();
                    warn!(
                        "request_id={} route={} external auth startup failed open: {:?}",
                        request.request_id, request.upstream_name, err
                    );
                    None
                }
                Err(err) => {
                    metrics.inc_failure();
                    metrics.inc_external_auth_error();
                    metrics.record_route(
                        &request.upstream_name,
                        request_start.elapsed(),
                        RouteOutcome::Failure,
                    );
                    error!(
                        "request_id={} route={} external auth startup failed: {:?}",
                        request.request_id, request.upstream_name, err
                    );
                    Self::send_simple_response(
                        h3,
                        quic,
                        stream_id,
                        http::StatusCode::SERVICE_UNAVAILABLE,
                        b"external auth unavailable\n",
                    )?;
                    return Ok(None);
                }
            }
        } else {
            None
        };
        let auth_requested = auth_start.is_some();

        Ok(Some(StartedAuthRequest {
            request,
            auth_start,
            auth_requested,
        }))
    }
}
