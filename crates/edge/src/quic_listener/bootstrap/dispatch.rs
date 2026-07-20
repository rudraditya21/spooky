use std::convert::Infallible;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use spooky_errors::ProxyError;

use super::outcome::observe_bootstrap_dispatch_failure;
use super::{
    context::BootstrapDispatchCtx, intake::bootstrap_error_response,
    request::BootstrapPreparedRoute, websocket::dispatch_bootstrap_websocket,
};

pub(in crate::quic_listener) struct BootstrapDispatchInput<'a> {
    pub(in crate::quic_listener) upstream_req: Request<BoxBody<Bytes, Infallible>>,
    pub(in crate::quic_listener) prepared_route: &'a BootstrapPreparedRoute,
    pub(in crate::quic_listener) dispatch_ctx: BootstrapDispatchCtx<'a>,
}

async fn dispatch_bootstrap_http(
    input: BootstrapDispatchInput<'_>,
) -> Result<Response<Incoming>, Response<BoxBody<Bytes, Infallible>>> {
    match tokio::time::timeout(
        input.dispatch_ctx.request.runtime.backend_timeout,
        input
            .dispatch_ctx
            .request
            .runtime
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
                input.dispatch_ctx.request.runtime.metrics.as_ref(),
                input.dispatch_ctx.request.request_start,
                input.dispatch_ctx.request_id,
                StatusCode::BAD_GATEWAY,
                &proxy_err,
            );
            Err(bootstrap_error_response(
                &input.dispatch_ctx.request.runtime.alt_svc,
                StatusCode::BAD_GATEWAY,
                b"upstream error\n",
            ))
        }
        Err(_) => {
            observe_bootstrap_dispatch_failure(
                input.prepared_route,
                input.dispatch_ctx.request.runtime.metrics.as_ref(),
                input.dispatch_ctx.request.request_start,
                input.dispatch_ctx.request_id,
                StatusCode::GATEWAY_TIMEOUT,
                &ProxyError::Timeout,
            );
            Err(bootstrap_error_response(
                &input.dispatch_ctx.request.runtime.alt_svc,
                StatusCode::GATEWAY_TIMEOUT,
                b"upstream timeout\n",
            ))
        }
    }
}

pub(in crate::quic_listener) async fn dispatch_bootstrap_upstream(
    input: BootstrapDispatchInput<'_>,
) -> Result<Response<Incoming>, Response<BoxBody<Bytes, Infallible>>> {
    if input.dispatch_ctx.is_websocket_upgrade {
        dispatch_bootstrap_websocket(input).await
    } else {
        dispatch_bootstrap_http(input).await
    }
}
