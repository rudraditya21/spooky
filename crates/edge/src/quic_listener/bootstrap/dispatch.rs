use std::{
    convert::Infallible,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use hyper::{body::Incoming, client::conn::http1 as client_http1};
use hyper_util::rt::TokioIo;
use log::warn;
use spooky_config::backend_endpoint::BackendScheme;
use spooky_errors::{ProxyError, classify_upstream_proxy_error};
use spooky_transport::transport_pool::UpstreamTransportPool;

use crate::{
    Metrics,
    quic_listener::{
        QUICListener,
        bootstrap::{
            BootstrapPreparedRoute, bootstrap_error_response,
            request::bootstrap_backend_target_for_prepared,
            request::bootstrap_route_target_for_prepared,
        },
    },
};

pub(in crate::quic_listener) struct BootstrapDispatchInput<'a> {
    pub(in crate::quic_listener) upstream_req: Request<BoxBody<Bytes, Infallible>>,
    pub(in crate::quic_listener) prepared_route: &'a BootstrapPreparedRoute,
    pub(in crate::quic_listener) transport_pool: &'a UpstreamTransportPool,
    pub(in crate::quic_listener) metrics: &'a Metrics,
    pub(in crate::quic_listener) request_start: Instant,
    pub(in crate::quic_listener) request_id: u64,
    pub(in crate::quic_listener) backend_timeout: Duration,
    pub(in crate::quic_listener) request_path: &'a str,
    pub(in crate::quic_listener) is_websocket_upgrade: bool,
    pub(in crate::quic_listener) alt_svc: &'a str,
}

fn observe_bootstrap_dispatch_failure(
    prepared_route: &BootstrapPreparedRoute,
    metrics: &Metrics,
    request_start: Instant,
    request_id: u64,
    status: StatusCode,
    proxy_err: &ProxyError,
) {
    let _ = crate::runtime::connection::outcome::observe_proxy_error_outcome(
        metrics,
        bootstrap_route_target_for_prepared(prepared_route),
        Some(bootstrap_backend_target_for_prepared(prepared_route)),
        request_start.elapsed(),
        Some(status),
        proxy_err,
        None,
    );
    if let Some(classified) = classify_upstream_proxy_error(proxy_err) {
        QUICListener::log_classified_upstream_failure(
            "bootstrap",
            Some(request_id),
            Some(&prepared_route.upstream_name),
            &prepared_route.backend_addr,
            &classified,
        );
        if let Some(transition) =
            crate::runtime::connection::outcome::observe_classified_backend_failure(
                crate::runtime::connection::outcome::ClassifiedBackendFailureInput {
                    metrics_phase: "bootstrap",
                    backend_addr: &prepared_route.backend_addr,
                    backend_index: prepared_route.backend_index,
                    upstream_pool: Some(&prepared_route.upstream_pool),
                    metrics,
                    classified: &classified,
                },
            )
        {
            crate::runtime::connection::outcome::log_backend_health_transition(
                &prepared_route.backend_addr,
                transition,
            );
        }
    } else {
        warn!(
            "Bootstrap upstream error route={} backend={}: {}",
            prepared_route.upstream_name, prepared_route.backend_addr, proxy_err
        );
    }
}

async fn dispatch_bootstrap_websocket(
    input: BootstrapDispatchInput<'_>,
) -> Result<Response<Incoming>, Response<BoxBody<Bytes, Infallible>>> {
    if input.prepared_route.endpoint.scheme() != BackendScheme::Http {
        return Err(bootstrap_error_response(
            input.alt_svc,
            StatusCode::BAD_GATEWAY,
            b"websocket bootstrap requires http upstream\n",
        ));
    }

    let backend_target = input.prepared_route.endpoint.authority().to_string();
    let upstream_path_uri = match Uri::try_from(input.request_path) {
        Ok(uri) => uri,
        Err(_) => {
            return Err(bootstrap_error_response(
                input.alt_svc,
                StatusCode::BAD_GATEWAY,
                b"bad uri\n",
            ));
        }
    };
    let (mut parts, body) = input.upstream_req.into_parts();
    parts.uri = upstream_path_uri;
    let upstream_req = Request::from_parts(parts, body);

    let stream = match tokio::time::timeout(
        input.backend_timeout,
        tokio::net::TcpStream::connect(&backend_target),
    )
    .await
    {
        Ok(Ok(stream)) => {
            if let Ok(resolved_addr) = stream.peer_addr() {
                input.metrics.record_backend_connect(
                    &backend_target,
                    input.prepared_route.endpoint.authority_host(),
                    resolved_addr,
                );
            }
            stream
        }
        Ok(Err(err)) => {
            warn!("Bootstrap WebSocket connect error: {}", err);
            return Err(bootstrap_error_response(
                input.alt_svc,
                StatusCode::BAD_GATEWAY,
                b"upstream error\n",
            ));
        }
        Err(_) => {
            return Err(bootstrap_error_response(
                input.alt_svc,
                StatusCode::GATEWAY_TIMEOUT,
                b"upstream timeout\n",
            ));
        }
    };

    let io = TokioIo::new(stream);
    let (mut sender, conn) = match client_http1::handshake(io).await {
        Ok(v) => v,
        Err(err) => {
            warn!("Bootstrap WebSocket handshake setup failed: {}", err);
            return Err(bootstrap_error_response(
                input.alt_svc,
                StatusCode::BAD_GATEWAY,
                b"upstream error\n",
            ));
        }
    };
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    match tokio::time::timeout(input.backend_timeout, sender.send_request(upstream_req)).await {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(err)) => {
            let proxy_err = ProxyError::Transport(err.to_string());
            observe_bootstrap_dispatch_failure(
                input.prepared_route,
                input.metrics,
                input.request_start,
                input.request_id,
                StatusCode::BAD_GATEWAY,
                &proxy_err,
            );
            Err(bootstrap_error_response(
                input.alt_svc,
                StatusCode::BAD_GATEWAY,
                b"upstream error\n",
            ))
        }
        Err(_) => {
            observe_bootstrap_dispatch_failure(
                input.prepared_route,
                input.metrics,
                input.request_start,
                input.request_id,
                StatusCode::GATEWAY_TIMEOUT,
                &ProxyError::Timeout,
            );
            Err(bootstrap_error_response(
                input.alt_svc,
                StatusCode::GATEWAY_TIMEOUT,
                b"upstream timeout\n",
            ))
        }
    }
}

async fn dispatch_bootstrap_http(
    input: BootstrapDispatchInput<'_>,
) -> Result<Response<Incoming>, Response<BoxBody<Bytes, Infallible>>> {
    match tokio::time::timeout(
        input.backend_timeout,
        input
            .transport_pool
            .send(&input.prepared_route.backend_addr, input.upstream_req),
    )
    .await
    {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(err)) => {
            let proxy_err = ProxyError::Pool(err);
            observe_bootstrap_dispatch_failure(
                input.prepared_route,
                input.metrics,
                input.request_start,
                input.request_id,
                StatusCode::BAD_GATEWAY,
                &proxy_err,
            );
            Err(bootstrap_error_response(
                input.alt_svc,
                StatusCode::BAD_GATEWAY,
                b"upstream error\n",
            ))
        }
        Err(_) => {
            observe_bootstrap_dispatch_failure(
                input.prepared_route,
                input.metrics,
                input.request_start,
                input.request_id,
                StatusCode::GATEWAY_TIMEOUT,
                &ProxyError::Timeout,
            );
            Err(bootstrap_error_response(
                input.alt_svc,
                StatusCode::GATEWAY_TIMEOUT,
                b"upstream timeout\n",
            ))
        }
    }
}

pub(in crate::quic_listener) async fn dispatch_bootstrap_upstream(
    input: BootstrapDispatchInput<'_>,
) -> Result<Response<Incoming>, Response<BoxBody<Bytes, Infallible>>> {
    if input.is_websocket_upgrade {
        dispatch_bootstrap_websocket(input).await
    } else {
        dispatch_bootstrap_http(input).await
    }
}
