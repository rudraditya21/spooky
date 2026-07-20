use std::convert::Infallible;

use http_body_util::Full;
use spooky_config::runtime::RuntimeExternalAuth;
use tracing::Span;

use super::{
    auth::{AuthStart, start_external_auth_task},
    resolve::ForwardingResolvedTarget,
    *,
};
use crate::{
    quic_listener::admission::{
        AdmissionPolicyDecision, admission_rejection_response,
        evaluate_forwarding_pre_admission_policy,
    },
    runtime::connection::{
        auth::{
            ExternalAuthCompletion, ExternalAuthFailureDisposition, ExternalAuthTaskConfig,
            apply_auth_request_mutations, evaluate_external_auth_completion,
        },
        outcome::{
            AdmissionOutcomeClass, OutcomeBackendTarget, OutcomeRouteTarget,
            observe_admission_outcome,
        },
        request::PendingForward,
    },
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
        apply_auth_request_mutations(&mut headers, &self.auth_header_mutations);
        headers
    }

    fn request_build_target<'a>(
        &'a self,
        endpoint: &'a BackendEndpoint,
    ) -> spooky_bridge::request::RequestBuildTarget<'a> {
        spooky_bridge::request::RequestBuildTarget {
            endpoint,
            policies: spooky_bridge::request::RequestBuildPolicies {
                host_policy: &self.host_policy,
                forwarded_header_policy: &self.forwarded_header_policy,
            },
        }
    }

    fn request_build_input<'a>(
        &'a self,
        method: &'a str,
        headers: &'a [quiche::h3::Header],
        body: BoxBody<Bytes, Infallible>,
        content_length: Option<usize>,
    ) -> spooky_bridge::request::RequestBuildInput<'a, BoxBody<Bytes, Infallible>> {
        spooky_bridge::request::RequestBuildInput {
            method,
            path: &self.path,
            authority: self.authority.as_deref(),
            headers,
            body,
            content_length,
            body_mode:
                spooky_bridge::request::RequestBuildInput::<BoxBody<Bytes, Infallible>>::body_mode_for_length(content_length),
            trace: spooky_bridge::request::RequestTraceContext {
                request_id: self.request_id,
                traceparent: self.traceparent.as_deref(),
            },
            forwarded: spooky_bridge::request::RequestForwardedContext {
                client_addr: self.client_addr,
            },
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
            spooky_bridge::h3_to_h1::build_h1_request(
                self.request_build_target(endpoint),
                self.request_build_input(&self.method, &headers, body, content_length),
            )
            .map_err(ProxyError::from)
        } else {
            spooky_bridge::h3_to_h2::build_h2_request_for_target(
                self.request_build_target(endpoint),
                self.request_build_input(&self.method, &headers, body, content_length),
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

        spooky_bridge::h3_to_h1::build_h1_request(
            self.request_build_target(endpoint),
            self.request_build_input(
                "GET",
                &request_headers,
                BoxBody::new(Full::new(Bytes::new())),
                None,
            ),
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
        let resolved = Self::resolve_forwarding_target(
            method,
            path,
            authority,
            tunnel_mode,
            sticky_cid_key,
            Some(&lb_header_lookup),
            routing_index,
            upstream_pools,
            upstream_policies,
            metrics,
            request_start.elapsed(),
        );

        let prepared = match resolved {
            Ok(ForwardingResolvedTarget {
                upstream_name,
                upstream_pool,
                upstream_policy,
                route_path_len,
                route_host_specific,
                route_reason,
                backend_addr,
                backend_index,
                backend_lb,
            }) => {
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
                        metrics.inc_policy_denied();
                        let _ = observe_admission_outcome(
                            metrics,
                            OutcomeRouteTarget {
                                route: &upstream_name,
                            },
                            Some(OutcomeBackendTarget {
                                upstream: &upstream_name,
                                backend_addr: Some(backend_addr.as_str()),
                                backend_index: Some(backend_index),
                            }),
                            request_start.elapsed(),
                            http::StatusCode::UNAUTHORIZED,
                            AdmissionOutcomeClass::AuthDenied,
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
                        metrics.inc_request_rate_limited();
                        let _ = observe_admission_outcome(
                            metrics,
                            OutcomeRouteTarget {
                                route: &upstream_name,
                            },
                            Some(OutcomeBackendTarget {
                                upstream: &upstream_name,
                                backend_addr: Some(backend_addr.as_str()),
                                backend_index: Some(backend_index),
                            }),
                            request_start.elapsed(),
                            http::StatusCode::TOO_MANY_REQUESTS,
                            AdmissionOutcomeClass::RateLimited,
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
                        let _ = observe_admission_outcome(
                            metrics,
                            OutcomeRouteTarget {
                                route: &upstream_name,
                            },
                            Some(OutcomeBackendTarget {
                                upstream: &upstream_name,
                                backend_addr: Some(backend_addr.as_str()),
                                backend_index: Some(backend_index),
                            }),
                            request_start.elapsed(),
                            http::StatusCode::SERVICE_UNAVAILABLE,
                            AdmissionOutcomeClass::OverloadShed {
                                reason: Some(decision.reason.metrics_reason()),
                            },
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
                let external_auth = upstream_policy.upstream_auth.external_auth.clone();
                let auth_fail_open = external_auth
                    .as_ref()
                    .map(|auth| {
                        ExternalAuthTaskConfig::from_external_auth(auth)
                            .disposition
                            .fail_open()
                    })
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
                Err(err) => {
                    match evaluate_external_auth_completion(
                        Err(err),
                        ExternalAuthFailureDisposition::from_fail_open(auth_fail_open),
                    ) {
                        ExternalAuthCompletion::FailOpen { timed_out, error } => {
                            metrics.inc_external_auth_error();
                            if timed_out {
                                warn!(
                                    "request_id={} route={} external auth startup failed open: timeout",
                                    request.request_id, request.upstream_name
                                );
                            } else if let Some(error) = error {
                                warn!(
                                    "request_id={} route={} external auth startup failed open: {:?}",
                                    request.request_id, request.upstream_name, error
                                );
                            }
                            None
                        }
                        ExternalAuthCompletion::Reject {
                            status,
                            body,
                            timed_out,
                            error,
                        } => {
                            metrics.inc_external_auth_error();
                            let _ = observe_admission_outcome(
                                metrics,
                                OutcomeRouteTarget {
                                    route: &request.upstream_name,
                                },
                                Some(OutcomeBackendTarget {
                                    upstream: &request.upstream_name,
                                    backend_addr: Some(request.backend_addr.as_str()),
                                    backend_index: Some(request.backend_index),
                                }),
                                request_start.elapsed(),
                                status,
                                AdmissionOutcomeClass::Failed { timed_out },
                            );
                            if let Some(error) = error {
                                error!(
                                    "request_id={} route={} external auth startup failed: {:?}",
                                    request.request_id, request.upstream_name, error
                                );
                            } else {
                                error!(
                                    "request_id={} route={} external auth startup failed",
                                    request.request_id, request.upstream_name
                                );
                            }
                            Self::send_simple_response(h3, quic, stream_id, status, body)?;
                            return Ok(None);
                        }
                        ExternalAuthCompletion::Allow { .. }
                        | ExternalAuthCompletion::Respond(_) => {
                            unreachable!("startup failure must resolve to fail-open or rejection")
                        }
                    }
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
