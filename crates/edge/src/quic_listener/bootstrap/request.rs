use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::body::Incoming;
use log::warn;
use spooky_bridge::{
    BridgeError,
    h3_to_h1::build_h1_request,
    h3_to_h2::build_h2_request_for_target,
    request::{
        RequestBuildInput, RequestBuildPolicies, RequestBuildTarget, RequestForwardedContext,
        RequestTraceContext,
    },
};
use spooky_config::{
    backend_endpoint::{BackendEndpoint, BackendScheme},
    runtime::RuntimeUpstreamPolicy,
};
use spooky_errors::ProxyError;
use spooky_lb::upstream_pool::UpstreamPool;

use crate::{
    Metrics,
    resilience::runtime::RuntimeResilience,
    routing::index::RouteIndex,
    runtime::connection::outcome::{
        AdmissionOutcomeClass, OutcomeBackendTarget, OutcomeRouteTarget, observe_admission_outcome,
        observe_proxy_error_outcome,
    },
};

use super::{
    super::{
        QUICListener,
        admission::{
            AdmissionPolicyDecision, admission_rejection_response,
            evaluate_forwarding_pre_admission_policy,
        },
        bootstrap_tls::{BootstrapStreamingBody, boxed_full},
        forwarding::BootstrapResolutionInput,
    },
    bootstrap_error_response,
    intake::BootstrapRequestIntake,
};

pub(in crate::quic_listener) struct BootstrapPreparedRoute {
    pub(in crate::quic_listener) endpoint: BackendEndpoint,
    pub(in crate::quic_listener) backend_addr: String,
    pub(in crate::quic_listener) backend_index: usize,
    pub(in crate::quic_listener) upstream_name: String,
    pub(in crate::quic_listener) upstream_policy: RuntimeUpstreamPolicy,
    pub(in crate::quic_listener) upstream_pool: Arc<RwLock<UpstreamPool>>,
}

pub(in crate::quic_listener) struct BootstrapPolicyEvaluationInput<'a> {
    pub(in crate::quic_listener) intake: &'a BootstrapRequestIntake,
    pub(in crate::quic_listener) peer: SocketAddr,
    pub(in crate::quic_listener) headers: &'a HeaderMap,
    pub(in crate::quic_listener) routing_index: &'a RouteIndex,
    pub(in crate::quic_listener) upstream_pools: &'a HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(in crate::quic_listener) upstream_policies: &'a HashMap<String, RuntimeUpstreamPolicy>,
    pub(in crate::quic_listener) backend_endpoints: &'a HashMap<String, BackendEndpoint>,
    pub(in crate::quic_listener) metrics: &'a Metrics,
    pub(in crate::quic_listener) resilience: &'a RuntimeResilience,
    pub(in crate::quic_listener) request_start: Instant,
    pub(in crate::quic_listener) alt_svc: &'a str,
}

pub(in crate::quic_listener) struct BootstrapBuildRequestInput<'a> {
    pub(in crate::quic_listener) request: Request<Incoming>,
    pub(in crate::quic_listener) intake: &'a BootstrapRequestIntake,
    pub(in crate::quic_listener) prepared_route: &'a BootstrapPreparedRoute,
    pub(in crate::quic_listener) request_id: u64,
    pub(in crate::quic_listener) traceparent: Option<&'a str>,
    pub(in crate::quic_listener) peer: SocketAddr,
}

fn bootstrap_bridge_headers(headers: &HeaderMap) -> Vec<quiche::h3::Header> {
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

fn bootstrap_request_build_input<'a>(
    intake: &'a BootstrapRequestIntake,
    headers: &'a [quiche::h3::Header],
    body: BoxBody<Bytes, Infallible>,
    content_length: Option<usize>,
    request_id: u64,
    traceparent: Option<&'a str>,
    peer: SocketAddr,
) -> RequestBuildInput<'a, BoxBody<Bytes, Infallible>> {
    RequestBuildInput {
        method: &intake.method,
        path: &intake.path,
        authority: intake.authority.as_deref(),
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

fn internal_proxy_error_response(alt_svc: &str) -> Response<BoxBody<Bytes, Infallible>> {
    bootstrap_error_response(
        alt_svc,
        StatusCode::INTERNAL_SERVER_ERROR,
        b"internal proxy error\n",
    )
}

fn resolve_scoped_rate_limit_key_for_bootstrap(
    rule: &crate::resilience::scoped_rate_limit::ScopedRateLimitRule,
    upstream_name: &str,
    intake: &BootstrapRequestIntake,
    peer: SocketAddr,
    lb_header_lookup: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    QUICListener::resolve_scoped_rate_limit_key(
        rule,
        upstream_name,
        &intake.method,
        &intake.path,
        intake.authority.as_deref(),
        peer,
        Some(lb_header_lookup),
    )
}

pub(in crate::quic_listener) fn evaluate_bootstrap_request_policy(
    input: BootstrapPolicyEvaluationInput<'_>,
) -> Result<BootstrapPreparedRoute, Response<BoxBody<Bytes, Infallible>>> {
    let lb_header_lookup = |name: &str| {
        input
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    };

    let resolved = match QUICListener::resolve_bootstrap_target(BootstrapResolutionInput {
        method: &input.intake.method,
        path: &input.intake.path,
        authority: input.intake.authority.as_deref(),
        header_lookup: Some(&lb_header_lookup),
        routing_index: input.routing_index,
        upstream_pools: input.upstream_pools,
        upstream_policies: input.upstream_policies,
        metrics: input.metrics,
        elapsed: Duration::ZERO,
    }) {
        Ok(value) => value,
        Err(err) => {
            let (status, body) = QUICListener::bootstrap_route_resolution_error_response(&err);
            return Err(bootstrap_error_response(input.alt_svc, status, body));
        }
    };

    let admission = evaluate_forwarding_pre_admission_policy(
        &resolved.upstream_policy,
        Some(&lb_header_lookup),
        &input.resilience.brownout,
        input.resilience.adaptive_admission.inflight_percent(),
        &resolved.upstream_name,
        input.resilience.shed_retry_after_seconds,
        &input.resilience.scoped_rate_limits,
        |rule| {
            resolve_scoped_rate_limit_key_for_bootstrap(
                rule,
                &resolved.upstream_name,
                input.intake,
                input.peer,
                &lb_header_lookup,
            )
        },
    );
    input
        .metrics
        .set_brownout_active(input.resilience.brownout.is_active());
    let rejection_response = admission_rejection_response(&admission);

    match admission {
        AdmissionPolicyDecision::AdmitReady => {}
        AdmissionPolicyDecision::Unauthorized(_) => {
            input.metrics.inc_policy_denied();
            let _ = observe_admission_outcome(
                input.metrics,
                bootstrap_route_target(&resolved.upstream_name),
                Some(bootstrap_backend_target(
                    &resolved.upstream_name,
                    &resolved.backend_addr,
                    resolved.backend_index,
                )),
                input.request_start.elapsed(),
                StatusCode::UNAUTHORIZED,
                AdmissionOutcomeClass::AuthDenied,
            );
            warn!(
                "Bootstrap request route={} denied by auth policy",
                resolved.upstream_name
            );
            let Some(response) = rejection_response.as_ref() else {
                warn!(
                    "Bootstrap request route={} missing admission rejection response for unauthorized decision",
                    resolved.upstream_name
                );
                return Err(internal_proxy_error_response(input.alt_svc));
            };
            let Some(challenge) = response.www_authenticate else {
                warn!(
                    "Bootstrap request route={} missing auth challenge in admission rejection response",
                    resolved.upstream_name
                );
                return Err(internal_proxy_error_response(input.alt_svc));
            };
            return Err(Response::builder()
                .status(response.status)
                .header("alt-svc", input.alt_svc)
                .header("www-authenticate", challenge)
                .body(boxed_full(Bytes::from_static(response.body)))
                .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from_static(b"error\n")))));
        }
        AdmissionPolicyDecision::RateLimited(decision) => {
            input.metrics.inc_request_rate_limited();
            let _ = observe_admission_outcome(
                input.metrics,
                bootstrap_route_target(&resolved.upstream_name),
                Some(bootstrap_backend_target(
                    &resolved.upstream_name,
                    &resolved.backend_addr,
                    resolved.backend_index,
                )),
                input.request_start.elapsed(),
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
                    resolved.upstream_name
                );
                return Err(internal_proxy_error_response(input.alt_svc));
            };
            let Some(retry_after_seconds) = response.retry_after_seconds else {
                warn!(
                    "Bootstrap request route={} missing retry-after in rate-limited admission rejection response",
                    resolved.upstream_name
                );
                return Err(internal_proxy_error_response(input.alt_svc));
            };
            return Err(Response::builder()
                .status(response.status)
                .header("alt-svc", input.alt_svc)
                .header("retry-after", retry_after_seconds.to_string())
                .body(boxed_full(Bytes::from_static(response.body)))
                .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from_static(b"error\n")))));
        }
        AdmissionPolicyDecision::Overloaded(decision) => {
            let _ = observe_admission_outcome(
                input.metrics,
                bootstrap_route_target(&resolved.upstream_name),
                Some(bootstrap_backend_target(
                    &resolved.upstream_name,
                    &resolved.backend_addr,
                    resolved.backend_index,
                )),
                input.request_start.elapsed(),
                StatusCode::SERVICE_UNAVAILABLE,
                AdmissionOutcomeClass::OverloadShed {
                    reason: Some(decision.reason.metrics_reason()),
                },
            );
            input
                .resilience
                .adaptive_admission
                .observe(input.request_start.elapsed(), true);
            let Some(response) = rejection_response.as_ref() else {
                warn!(
                    "Bootstrap request route={} missing admission rejection response for overload decision",
                    resolved.upstream_name
                );
                return Err(internal_proxy_error_response(input.alt_svc));
            };
            let Some(retry_after_seconds) = response.retry_after_seconds else {
                warn!(
                    "Bootstrap request route={} missing retry-after in overload admission rejection response",
                    resolved.upstream_name
                );
                return Err(internal_proxy_error_response(input.alt_svc));
            };
            return Err(Response::builder()
                .status(response.status)
                .header("alt-svc", input.alt_svc)
                .header("retry-after", retry_after_seconds.to_string())
                .body(boxed_full(Bytes::from_static(response.body)))
                .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from_static(b"error\n")))));
        }
    }

    let endpoint = match input.backend_endpoints.get(&resolved.backend_addr) {
        Some(endpoint) => endpoint.clone(),
        None => {
            let _ = observe_proxy_error_outcome(
                input.metrics,
                bootstrap_route_target(&resolved.upstream_name),
                Some(bootstrap_backend_target(
                    &resolved.upstream_name,
                    &resolved.backend_addr,
                    resolved.backend_index,
                )),
                input.request_start.elapsed(),
                Some(StatusCode::BAD_GATEWAY),
                &ProxyError::Transport("no endpoint".into()),
                None,
            );
            return Err(bootstrap_error_response(
                input.alt_svc,
                StatusCode::BAD_GATEWAY,
                b"no endpoint\n",
            ));
        }
    };

    Ok(BootstrapPreparedRoute {
        endpoint,
        backend_addr: resolved.backend_addr,
        backend_index: resolved.backend_index,
        upstream_name: resolved.upstream_name,
        upstream_policy: resolved.upstream_policy,
        upstream_pool: resolved.upstream_pool,
    })
}

pub(in crate::quic_listener) fn build_bootstrap_upstream_request(
    input: BootstrapBuildRequestInput<'_>,
) -> Result<Request<BoxBody<Bytes, Infallible>>, BridgeError> {
    let bridge_headers = bootstrap_bridge_headers(input.request.headers());
    let request_target = bootstrap_request_build_target(
        &input.prepared_route.endpoint,
        &input.prepared_route.upstream_policy,
    );

    if input.intake.is_websocket_upgrade {
        return build_h1_request(
            request_target,
            bootstrap_request_build_input(
                input.intake,
                &bridge_headers,
                boxed_full(Bytes::new()),
                None,
                input.request_id,
                input.traceparent,
                input.peer,
            ),
        );
    }

    let bridge_body = BootstrapStreamingBody::new(input.request.into_body())
        .map_err(|never| match never {})
        .boxed();
    if input.prepared_route.endpoint.scheme() == BackendScheme::Http {
        build_h1_request(
            request_target,
            bootstrap_request_build_input(
                input.intake,
                &bridge_headers,
                bridge_body,
                None,
                input.request_id,
                input.traceparent,
                input.peer,
            ),
        )
    } else {
        build_h2_request_for_target(
            request_target,
            bootstrap_request_build_input(
                input.intake,
                &bridge_headers,
                bridge_body,
                None,
                input.request_id,
                input.traceparent,
                input.peer,
            ),
        )
    }
}
