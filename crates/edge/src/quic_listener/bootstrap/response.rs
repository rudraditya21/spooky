use std::{
    convert::Infallible,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::{Body, Frame, Incoming};
use spooky_bridge::response::{
    ResponseBodyMode, ResponseBodyPolicy, ResponseNormalizationInput,
    ResponseNormalizationProtocol, ResponseProtocolConstraints, normalize_upstream_response,
};
use spooky_errors::ProxyError;
use spooky_lb::upstream_pool::UpstreamPool;

use crate::{
    Metrics, OverloadShedReason,
    quic_listener::bootstrap::{
        BootstrapPreparedRoute,
        request::{bootstrap_backend_target_for_prepared, bootstrap_route_target_for_prepared},
        write_bootstrap_websocket_upgrade,
    },
    runtime::connection::{
        guardrails::{
            BodyLimitKind, RESPONSE_BODY_TOO_LARGE_BODY, ResponseBodyGuardrailConfig,
            ResponseBodyGuardrailDecision, ResponseBodyGuardrailInput,
            checked_response_body_guardrails,
        },
        outcome::{
            observe_backend_response_status, observe_proxy_error_outcome, observe_status_outcome,
        },
    },
};

pub(in crate::quic_listener) struct BootstrapStreamingBody {
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
    pub(in crate::quic_listener) fn new(inner: Incoming) -> Self {
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

pub(in crate::quic_listener) fn boxed_full(body: Bytes) -> BoxBody<Bytes, Infallible> {
    Full::new(body).map_err(|never| match never {}).boxed()
}

pub(in crate::quic_listener) struct BootstrapWritebackInput<'a> {
    pub(in crate::quic_listener) upstream_resp: Response<Incoming>,
    pub(in crate::quic_listener) prepared_route: &'a BootstrapPreparedRoute,
    pub(in crate::quic_listener) metrics: &'a Metrics,
    pub(in crate::quic_listener) request_start: Instant,
    pub(in crate::quic_listener) alt_svc: &'a str,
    pub(in crate::quic_listener) suppress_downstream_body: bool,
    pub(in crate::quic_listener) is_websocket_upgrade: bool,
    pub(in crate::quic_listener) client_upgrade: Option<hyper::upgrade::OnUpgrade>,
    pub(in crate::quic_listener) max_response_body_bytes: usize,
}

pub(in crate::quic_listener) fn write_bootstrap_response(
    mut input: BootstrapWritebackInput<'_>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
    let status = input.upstream_resp.status();
    let normalized_response = normalize_upstream_response(ResponseNormalizationInput {
        upstream: spooky_bridge::response::UpstreamResponseView {
            status,
            headers: input.upstream_resp.headers(),
            trailers: None,
        },
        body_mode: if input.suppress_downstream_body {
            ResponseBodyMode::HeadRequest
        } else {
            ResponseBodyMode::Normal
        },
        constraints: ResponseProtocolConstraints {
            protocol: ResponseNormalizationProtocol::Http1,
            strip_connection_headers: true,
            allow_trailers: false,
            preserve_upgrade: input.is_websocket_upgrade
                && status == StatusCode::SWITCHING_PROTOCOLS,
        },
    });
    let upstream_content_length = input
        .upstream_resp
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());
    let response_size_decision = checked_response_body_guardrails(
        ResponseBodyGuardrailConfig {
            idle_timeout: Duration::ZERO,
            total_timeout: Duration::MAX,
            max_body_bytes: input.max_response_body_bytes,
            unknown_length_prebuffer_bytes: input.max_response_body_bytes,
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
            progressive_emission_allowed: !normalized_response.emission.emit_end_stream_on_headers,
            body_forwarding_enabled: matches!(
                normalized_response.emission.body,
                ResponseBodyPolicy::Forward
            ),
            exempt_from_body_size_cap: input.is_websocket_upgrade
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
            input.metrics,
            bootstrap_route_target_for_prepared(input.prepared_route),
            Some(bootstrap_backend_target_for_prepared(input.prepared_route)),
            input.request_start.elapsed(),
            Some(StatusCode::SERVICE_UNAVAILABLE),
            &ProxyError::Pool(spooky_errors::PoolError::BackendOverloaded(
                "response prebuffer cap".into(),
            )),
            Some(OverloadShedReason::ResponsePrebufferCap),
        );
        return Ok(Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("alt-svc", input.alt_svc)
            .body(boxed_full(Bytes::from_static(RESPONSE_BODY_TOO_LARGE_BODY)))
            .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from_static(b"error\n")))));
    }
    let _ = observe_status_outcome(
        input.metrics,
        bootstrap_route_target_for_prepared(input.prepared_route),
        Some(bootstrap_backend_target_for_prepared(input.prepared_route)),
        input.request_start.elapsed(),
        status,
    );
    if let Some(transition) = observe_backend_response_status(
        crate::runtime::connection::outcome::BackendHealthObservationInput {
            backend_addr: &input.prepared_route.backend_addr,
            backend_index: input.prepared_route.backend_index,
            upstream_pool: Some(&input.prepared_route.upstream_pool),
            status,
        },
    ) {
        crate::runtime::connection::outcome::log_backend_health_transition(
            &input.prepared_route.backend_addr,
            transition,
        );
    }

    let mut resp_builder = Response::builder().status(normalized_response.head.status);
    for header in &normalized_response.head.headers {
        resp_builder = resp_builder.header(&header.name, &header.value);
    }
    resp_builder = resp_builder.header("alt-svc", input.alt_svc);

    if input.is_websocket_upgrade && input.upstream_resp.status() == StatusCode::SWITCHING_PROTOCOLS
    {
        return write_bootstrap_websocket_upgrade(
            resp_builder,
            &mut input.upstream_resp,
            input.prepared_route,
            input.request_start,
            input.alt_svc,
            input.client_upgrade,
            status,
        );
    }

    let resp_body = if matches!(
        normalized_response.emission.body,
        ResponseBodyPolicy::Suppress
    ) {
        crate::runtime::connection::outcome::finish_backend_request_accounting(
            crate::runtime::connection::outcome::BackendRequestFinishInput {
                upstream_pool: Some(&input.prepared_route.upstream_pool),
                backend_index: Some(input.prepared_route.backend_index),
                elapsed: input.request_start.elapsed(),
                status: Some(status.as_u16()),
            },
        );
        boxed_full(Bytes::new())
    } else {
        BootstrapStreamingBody::with_response_guardrails(
            input.upstream_resp.into_body(),
            input.max_response_body_bytes,
            upstream_content_length,
            Arc::clone(&input.prepared_route.upstream_pool),
            input.prepared_route.backend_index,
            input.request_start,
            Some(status.as_u16()),
        )
        .map_err(|never| match never {})
        .boxed()
    };

    Ok(resp_builder
        .body(resp_body)
        .unwrap_or_else(|_| Response::new(boxed_full(Bytes::new()))))
}
