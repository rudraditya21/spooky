use std::convert::Infallible;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, Uri};
use http_body_util::combinators::BoxBody;
use quiche::h3::NameValue;
use spooky_config::{
    backend_endpoint::BackendEndpoint,
    config::{ForwardedHeaderPolicy, UpstreamHostPolicy},
};

use crate::{
    BridgeError, ForwardedContext, ForwardedHeaderChains, H3WebsocketRequestKind,
    build_forwarded_header_values, connection_header_tokens, h3_websocket_request_kind,
    resolve_upstream_host_value, should_strip_request_header,
};

/// Build an HTTP/1.1 request forwarded to an `http://` upstream.
///
/// For plain requests: strips hop-by-hop headers and adds `TE: trailers`.
/// For WebSocket legacy upgrades (`GET` + `Upgrade: websocket`): preserves
/// `Connection` and `Upgrade` so the H1 upstream can complete the handshake.
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
    let method = Method::from_bytes(method.as_bytes()).map_err(|_| BridgeError::InvalidMethod)?;
    let websocket_kind = h3_websocket_request_kind(method.as_str(), headers);
    let preserve_upgrade = websocket_kind == H3WebsocketRequestKind::LegacyUpgrade;

    let mut builder = Request::builder().method(method.clone());
    let connection_tokens = connection_header_tokens(headers);
    let mut host_from_headers: Option<String> = None;
    let mut forwarded_from_headers: Vec<Vec<u8>> = Vec::new();
    let mut x_forwarded_for_from_headers: Vec<Vec<u8>> = Vec::new();
    let mut x_forwarded_proto_from_headers: Vec<Vec<u8>> = Vec::new();
    let mut x_forwarded_host_from_headers: Vec<Vec<u8>> = Vec::new();

    for header in headers {
        let name = header.name();
        if name.starts_with(b":") {
            continue;
        }
        if name.eq_ignore_ascii_case(b"forwarded") {
            forwarded_from_headers.push(header.value().to_vec());
            continue;
        }
        if name.eq_ignore_ascii_case(b"x-forwarded-for") {
            x_forwarded_for_from_headers.push(header.value().to_vec());
            continue;
        }
        if name.eq_ignore_ascii_case(b"x-forwarded-proto") {
            x_forwarded_proto_from_headers.push(header.value().to_vec());
            continue;
        }
        if name.eq_ignore_ascii_case(b"x-forwarded-host") {
            x_forwarded_host_from_headers.push(header.value().to_vec());
            continue;
        }

        let header_name = HeaderName::from_bytes(name).map_err(|_| BridgeError::InvalidHeader)?;
        if should_strip_request_header(&header_name, &connection_tokens, preserve_upgrade) {
            continue;
        }

        let header_value =
            HeaderValue::from_bytes(header.value()).map_err(|_| BridgeError::InvalidHeader)?;
        if header_name == http::header::HOST {
            host_from_headers = header_value.to_str().ok().map(str::to_string);
            continue;
        }
        builder = builder.header(header_name, header_value);
    }

    let host_value = resolve_upstream_host_value(
        endpoint,
        host_policy,
        forwarded_ctx.request_authority,
        host_from_headers.as_deref(),
    )?;

    let request_path = if path.is_empty() { "/" } else { path };
    let uri = Uri::try_from(endpoint.uri_for_path(request_path))
        .map_err(|_| BridgeError::InvalidUri)?;
    builder = builder.uri(uri).header(http::header::HOST, host_value);

    if let Some(len) = content_length
        && len > 0
    {
        builder = builder.header(http::header::CONTENT_LENGTH, len);
    }

    let has_request_id = builder
        .headers_ref()
        .is_some_and(|h| h.contains_key("x-request-id"));
    if !has_request_id {
        builder = builder.header(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_str(&forwarded_ctx.request_id.to_string())
                .map_err(|_| BridgeError::InvalidHeader)?,
        );
    }

    let has_traceparent = builder
        .headers_ref()
        .is_some_and(|h| h.contains_key("traceparent"));
    if !has_traceparent && let Some(traceparent) = forwarded_ctx.traceparent {
        builder = builder.header(
            HeaderName::from_static("traceparent"),
            HeaderValue::from_str(traceparent).map_err(|_| BridgeError::InvalidHeader)?,
        );
    }

    let forwarded_values = build_forwarded_header_values(
        forwarded_policy,
        ForwardedHeaderChains {
            forwarded: &forwarded_from_headers,
            x_forwarded_for: &x_forwarded_for_from_headers,
            x_forwarded_proto: &x_forwarded_proto_from_headers,
            x_forwarded_host: &x_forwarded_host_from_headers,
        },
        forwarded_ctx.client_addr.ip(),
        host_value,
    )?;
    if let Some(value) = forwarded_values.forwarded {
        builder = builder.header(HeaderName::from_static("forwarded"), value);
    }
    if let Some(value) = forwarded_values.x_forwarded_for {
        builder = builder.header(HeaderName::from_static("x-forwarded-for"), value);
    }
    if let Some(value) = forwarded_values.x_forwarded_proto {
        builder = builder.header(HeaderName::from_static("x-forwarded-proto"), value);
    }
    if let Some(value) = forwarded_values.x_forwarded_host {
        builder = builder.header(HeaderName::from_static("x-forwarded-host"), value);
    }

    // Plain H1 requests advertise trailer support; upgrade tunnels must not add this.
    if !preserve_upgrade {
        builder = builder.header(http::header::TE, "trailers");
    }

    builder.body(body).map_err(BridgeError::Build)
}
