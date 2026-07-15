use std::convert::Infallible;

use bytes::Bytes;
use http::{Method, Request, Uri};
use http_body_util::combinators::BoxBody;
use spooky_config::{
    backend_endpoint::BackendEndpoint,
    config::{ForwardedHeaderPolicy, UpstreamHostPolicy},
};

use crate::{
    BridgeError,
    context::ForwardedContext,
    request::{
        RequestBuildInput, RequestBuildPolicies, RequestBuildTarget, RequestHeaderAssembly,
        RequestHeaderPolicyInput, RequestTraceContext, apply_request_header_assembly,
        apply_request_header_policies,
    },
    websocket::{H3WebsocketRequestKind, h3_websocket_request_kind},
};

/// Build an HTTP/1.1 request forwarded to an `http://` upstream.
///
/// For plain requests: strips hop-by-hop headers and adds `TE: trailers`.
/// For WebSocket legacy upgrades (`GET` + `Upgrade: websocket`): preserves
/// `Connection` and `Upgrade` so the H1 upstream can complete the handshake.
pub fn build_h1_request(
    target: RequestBuildTarget<'_>,
    input: RequestBuildInput<'_, BoxBody<Bytes, Infallible>>,
) -> Result<Request<BoxBody<Bytes, Infallible>>, BridgeError> {
    let RequestBuildTarget { endpoint, policies } = target;
    let RequestBuildInput {
        method,
        path,
        authority,
        headers,
        body,
        content_length,
        body_mode: _body_mode,
        trace,
        forwarded,
    } = input;

    let method = Method::from_bytes(method.as_bytes()).map_err(|_| BridgeError::InvalidMethod)?;
    let websocket_kind = h3_websocket_request_kind(method.as_str(), headers);
    let preserve_upgrade = websocket_kind == H3WebsocketRequestKind::LegacyUpgrade;

    let mut builder = Request::builder().method(method.clone());
    let resolved_headers = apply_request_header_policies(RequestHeaderPolicyInput {
        target: RequestBuildTarget { endpoint, policies },
        authority,
        headers,
        preserve_upgrade,
        forwarded,
    })?;
    for (header_name, header_value) in &resolved_headers.passthrough_headers {
        builder = builder.header(header_name, header_value);
    }

    let request_path = if path.is_empty() { "/" } else { path };
    let uri =
        Uri::try_from(endpoint.uri_for_path(request_path)).map_err(|_| BridgeError::InvalidUri)?;
    builder = builder.uri(uri);
    builder = apply_request_header_assembly(
        builder,
        RequestHeaderAssembly {
            resolved_headers,
            trace,
            content_length,
            include_content_length: true,
            include_host_header: true,
            add_te_trailers: !preserve_upgrade,
        },
    )?;

    builder.body(body).map_err(BridgeError::Build)
}

#[allow(clippy::too_many_arguments)]
pub fn build_h1_request_for_endpoint_with_host_policy(
    endpoint: &BackendEndpoint,
    host_policy: &UpstreamHostPolicy,
    forwarded_policy: &ForwardedHeaderPolicy,
    method: &str,
    path: &str,
    headers: &[quiche::h3::Header],
    body: BoxBody<Bytes, Infallible>,
    content_length: Option<usize>,
    forwarded_ctx: ForwardedContext<'_>,
) -> Result<Request<BoxBody<Bytes, Infallible>>, BridgeError> {
    build_h1_request(
        RequestBuildTarget {
            endpoint,
            policies: RequestBuildPolicies {
                host_policy,
                forwarded_header_policy: forwarded_policy,
            },
        },
        RequestBuildInput {
            method,
            path,
            authority: forwarded_ctx.request_authority,
            headers,
            body,
            content_length,
            body_mode: RequestBuildInput::<BoxBody<Bytes, Infallible>>::body_mode_for_length(
                content_length,
            ),
            trace: RequestTraceContext {
                request_id: forwarded_ctx.request_id,
                traceparent: forwarded_ctx.traceparent,
            },
            forwarded: crate::request::RequestForwardedContext {
                client_addr: forwarded_ctx.client_addr,
            },
        },
    )
}
