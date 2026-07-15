use std::convert::Infallible;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, Uri, Version};
use http_body_util::combinators::BoxBody;
use hyper::ext::Protocol;
use spooky_config::{
    backend_endpoint::BackendEndpoint,
    config::{ForwardedHeaderPolicy, UpstreamHostPolicy},
};

use crate::{
    BridgeError,
    context::ForwardedContext,
    request::{
        RequestBuildInput, RequestBuildPolicies, RequestBuildTarget, RequestHeaderPolicyInput,
        RequestTraceContext, apply_request_header_policies,
    },
    websocket::{H3WebsocketRequestKind, h3_websocket_request_kind},
};

/// Build an HTTP/2 request with a pre-boxed streaming body.
/// `content_length` is `Some(n)` only when the full length is known upfront
/// (i.e. the body was fully buffered); pass `None` for streaming bodies.
pub fn build_h2_request(
    backend: &str,
    method: &str,
    path: &str,
    headers: &[quiche::h3::Header],
    body: BoxBody<Bytes, Infallible>,
    content_length: Option<usize>,
    forwarded_ctx: ForwardedContext<'_>,
) -> Result<Request<BoxBody<Bytes, Infallible>>, BridgeError> {
    let endpoint = BackendEndpoint::parse(backend).map_err(|_| BridgeError::InvalidUri)?;
    build_h2_request_for_endpoint(
        &endpoint,
        method,
        path,
        headers,
        body,
        content_length,
        forwarded_ctx,
    )
}

pub fn build_h2_request_for_endpoint(
    endpoint: &BackendEndpoint,
    method: &str,
    path: &str,
    headers: &[quiche::h3::Header],
    body: BoxBody<Bytes, Infallible>,
    content_length: Option<usize>,
    forwarded_ctx: ForwardedContext<'_>,
) -> Result<Request<BoxBody<Bytes, Infallible>>, BridgeError> {
    build_h2_request_for_endpoint_with_host_policy(
        endpoint,
        &UpstreamHostPolicy::default(),
        &ForwardedHeaderPolicy::default(),
        method,
        path,
        headers,
        body,
        content_length,
        forwarded_ctx,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_h2_request_for_target(
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
    // Extended CONNECT is the H2 websocket path (RFC 8441).
    let websocket_extended_connect = websocket_kind == H3WebsocketRequestKind::ExtendedConnect
        || websocket_kind == H3WebsocketRequestKind::LegacyUpgrade;
    let upstream_method = if websocket_extended_connect {
        Method::CONNECT
    } else {
        method.clone()
    };
    let is_connect = upstream_method == Method::CONNECT;
    let mut builder = Request::builder().method(upstream_method.clone());
    let resolved_headers = apply_request_header_policies(RequestHeaderPolicyInput {
        target: RequestBuildTarget { endpoint, policies },
        authority,
        headers,
        preserve_upgrade: false,
        forwarded,
    })?;
    for (header_name, header_value) in &resolved_headers.passthrough_headers {
        builder = builder.header(header_name, header_value);
    }
    let host_value = resolved_headers.host_value.as_str();

    let uri = if websocket_extended_connect {
        let request_path = if path.is_empty() { "/" } else { path };
        let uri = endpoint.uri_for_path(request_path);
        Uri::try_from(uri).map_err(|_| BridgeError::InvalidUri)?
    } else if is_connect {
        Uri::try_from(host_value).map_err(|_| BridgeError::InvalidUri)?
    } else {
        let request_path = if path.is_empty() { "/" } else { path };
        let uri = endpoint.uri_for_path(request_path);
        Uri::try_from(uri).map_err(|_| BridgeError::InvalidUri)?
    };
    builder = builder.uri(uri);
    if websocket_extended_connect {
        builder = builder
            .version(Version::HTTP_2)
            .extension(Protocol::from_static("websocket"));
    } else {
        builder = builder.header(http::header::HOST, host_value);
    }

    if let Some(len) = content_length
        && len > 0
        && !websocket_extended_connect
    {
        builder = builder.header(http::header::CONTENT_LENGTH, len);
    }

    let has_request_id = builder
        .headers_ref()
        .is_some_and(|h| h.contains_key("x-request-id"));
    if !has_request_id {
        builder = builder.header(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_str(&trace.request_id.to_string())
                .map_err(|_| BridgeError::InvalidHeader)?,
        );
    }

    let has_traceparent = builder
        .headers_ref()
        .is_some_and(|h| h.contains_key("traceparent"));
    if !has_traceparent && let Some(traceparent) = trace.traceparent {
        builder = builder.header(
            HeaderName::from_static("traceparent"),
            HeaderValue::from_str(traceparent).map_err(|_| BridgeError::InvalidHeader)?,
        );
    }

    if let Some(value) = resolved_headers.forwarded_values.forwarded {
        builder = builder.header(HeaderName::from_static("forwarded"), value);
    }
    if let Some(value) = resolved_headers.forwarded_values.x_forwarded_for {
        builder = builder.header(HeaderName::from_static("x-forwarded-for"), value);
    }
    if let Some(value) = resolved_headers.forwarded_values.x_forwarded_proto {
        builder = builder.header(HeaderName::from_static("x-forwarded-proto"), value);
    }
    if let Some(value) = resolved_headers.forwarded_values.x_forwarded_host {
        builder = builder.header(HeaderName::from_static("x-forwarded-host"), value);
    }

    builder.body(body).map_err(BridgeError::Build)
}

#[allow(clippy::too_many_arguments)]
pub fn build_h2_request_for_endpoint_with_host_policy(
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
    build_h2_request_for_target(
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

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::header::HOST;
    use http_body_util::{BodyExt, Empty};
    use quiche::h3::Header;
    use spooky_config::{
        backend_endpoint::BackendEndpoint,
        config::{
            ForwardedHeaderPolicy, ForwardedHeaderPolicyMode, UpstreamHostPolicy,
            UpstreamHostPolicyMode,
        },
    };

    use super::{
        BridgeError, ForwardedContext, build_h2_request,
        build_h2_request_for_endpoint_with_host_policy,
    };

    #[test]
    fn defaults_to_https_origin_for_host_port_backend() {
        let req = build_h2_request(
            "backend.internal:443",
            "GET",
            "/health",
            &[],
            Empty::<Bytes>::new().boxed(),
            None,
            ForwardedContext {
                client_addr: "203.0.113.10:44321".parse().expect("client"),
                request_authority: Some("api.example.com"),
                request_id: 0,
                traceparent: None,
            },
        )
        .expect("request");

        assert_eq!(req.uri().to_string(), "https://backend.internal:443/health");
        assert_eq!(
            req.headers().get(HOST).and_then(|h| h.to_str().ok()),
            Some("api.example.com")
        );
        assert_eq!(
            req.headers()
                .get("x-forwarded-proto")
                .and_then(|h| h.to_str().ok()),
            Some("https")
        );
    }

    #[test]
    fn keeps_explicit_http_scheme() {
        let req = build_h2_request(
            "http://127.0.0.1:8080",
            "GET",
            "/",
            &[],
            Empty::<Bytes>::new().boxed(),
            None,
            ForwardedContext {
                client_addr: "198.51.100.3:5555".parse().expect("client"),
                request_authority: None,
                request_id: 0,
                traceparent: None,
            },
        )
        .expect("request");

        assert_eq!(req.uri().to_string(), "http://127.0.0.1:8080/");
        assert_eq!(
            req.headers().get(HOST).and_then(|h| h.to_str().ok()),
            Some("127.0.0.1:8080")
        );
    }

    #[test]
    fn rejects_invalid_backend_endpoint() {
        let err = build_h2_request(
            "https://backend.internal:443/path",
            "GET",
            "/",
            &[],
            Empty::<Bytes>::new().boxed(),
            None,
            ForwardedContext {
                client_addr: "127.0.0.1:12345".parse().expect("client"),
                request_authority: None,
                request_id: 0,
                traceparent: None,
            },
        )
        .expect_err("invalid backend endpoint should fail");

        assert!(matches!(err, BridgeError::InvalidUri));
    }

    #[test]
    fn strips_spoofed_forwarded_headers_and_normalizes() {
        let headers = vec![
            Header::new(b"x-forwarded-for", b"1.2.3.4"),
            Header::new(b"forwarded", b"for=1.2.3.4"),
            Header::new(b"x-forwarded-host", b"evil.example"),
            Header::new(b"x-forwarded-proto", b"http"),
            Header::new(b"host", b"api.example.com"),
            Header::new(b"connection", b"keep-alive, x-secret"),
            Header::new(b"x-secret", b"drop-me"),
            Header::new(b"x-keep", b"ok"),
        ];

        let req = build_h2_request(
            "backend.internal:443",
            "GET",
            "/",
            &headers,
            Empty::<Bytes>::new().boxed(),
            None,
            ForwardedContext {
                client_addr: "203.0.113.55:43210".parse().expect("client"),
                request_authority: Some("api.example.com"),
                request_id: 0,
                traceparent: None,
            },
        )
        .expect("request");

        assert_eq!(
            req.headers()
                .get("x-forwarded-for")
                .and_then(|h| h.to_str().ok()),
            Some("203.0.113.55")
        );
        assert_eq!(
            req.headers()
                .get("x-forwarded-host")
                .and_then(|h| h.to_str().ok()),
            Some("api.example.com")
        );
        assert_eq!(
            req.headers().get("forwarded").and_then(|h| h.to_str().ok()),
            Some("for=203.0.113.55;proto=https;host=\"api.example.com\"")
        );
        assert!(req.headers().get("x-secret").is_none());
        assert_eq!(
            req.headers().get("x-keep").and_then(|h| h.to_str().ok()),
            Some("ok")
        );
    }

    #[test]
    fn forwarded_header_policy_append_and_preserve_behave_as_expected() {
        let endpoint = BackendEndpoint::parse("backend.internal:443").expect("endpoint");
        let headers = vec![
            Header::new(b"forwarded", b"for=1.2.3.4;proto=http;host=\"old.example\""),
            Header::new(b"x-forwarded-for", b"1.2.3.4"),
            Header::new(b"x-forwarded-proto", b"http"),
            Header::new(b"x-forwarded-host", b"old.example"),
        ];

        let host_policy = UpstreamHostPolicy::default();
        let append_policy = ForwardedHeaderPolicy {
            mode: ForwardedHeaderPolicyMode::Append,
        };
        let req = build_h2_request_for_endpoint_with_host_policy(
            &endpoint,
            &host_policy,
            &append_policy,
            "GET",
            "/",
            &headers,
            Empty::<Bytes>::new().boxed(),
            None,
            ForwardedContext {
                client_addr: "203.0.113.55:43210".parse().expect("client"),
                request_authority: Some("api.example.com"),
                request_id: 0,
                traceparent: None,
            },
        )
        .expect("append request");

        assert_eq!(
            req.headers().get("forwarded").and_then(|h| h.to_str().ok()),
            Some(
                "for=1.2.3.4;proto=http;host=\"old.example\", for=203.0.113.55;proto=https;host=\"api.example.com\""
            )
        );
        assert_eq!(
            req.headers()
                .get("x-forwarded-for")
                .and_then(|h| h.to_str().ok()),
            Some("1.2.3.4, 203.0.113.55")
        );
        assert_eq!(
            req.headers()
                .get("x-forwarded-proto")
                .and_then(|h| h.to_str().ok()),
            Some("http, https")
        );
        assert_eq!(
            req.headers()
                .get("x-forwarded-host")
                .and_then(|h| h.to_str().ok()),
            Some("old.example, api.example.com")
        );

        let preserve_policy = ForwardedHeaderPolicy {
            mode: ForwardedHeaderPolicyMode::Preserve,
        };
        let req = build_h2_request_for_endpoint_with_host_policy(
            &endpoint,
            &host_policy,
            &preserve_policy,
            "GET",
            "/",
            &headers,
            Empty::<Bytes>::new().boxed(),
            None,
            ForwardedContext {
                client_addr: "203.0.113.55:43210".parse().expect("client"),
                request_authority: Some("api.example.com"),
                request_id: 0,
                traceparent: None,
            },
        )
        .expect("preserve request");

        assert_eq!(
            req.headers().get("forwarded").and_then(|h| h.to_str().ok()),
            Some("for=1.2.3.4;proto=http;host=\"old.example\"")
        );
        assert_eq!(
            req.headers()
                .get("x-forwarded-for")
                .and_then(|h| h.to_str().ok()),
            Some("1.2.3.4")
        );
        assert_eq!(
            req.headers()
                .get("x-forwarded-proto")
                .and_then(|h| h.to_str().ok()),
            Some("http")
        );
        assert_eq!(
            req.headers()
                .get("x-forwarded-host")
                .and_then(|h| h.to_str().ok()),
            Some("old.example")
        );
    }

    #[test]
    fn forwarded_header_formats_ipv6_clients() {
        let req = build_h2_request(
            "backend.internal:443",
            "GET",
            "/",
            &[],
            Empty::<Bytes>::new().boxed(),
            None,
            ForwardedContext {
                client_addr: "[2001:db8::1]:4444".parse().expect("client"),
                request_authority: Some("api.example.com"),
                request_id: 0,
                traceparent: None,
            },
        )
        .expect("request");

        assert_eq!(
            req.headers().get("forwarded").and_then(|h| h.to_str().ok()),
            Some("for=\"[2001:db8::1]\";proto=https;host=\"api.example.com\"")
        );
    }

    #[test]
    fn host_policy_rewrite_uses_configured_host() {
        let endpoint = BackendEndpoint::parse("backend.internal:443").expect("endpoint");
        let policy = UpstreamHostPolicy {
            mode: UpstreamHostPolicyMode::Rewrite,
            host: Some("origin.example.com".to_string()),
        };
        let req = build_h2_request_for_endpoint_with_host_policy(
            &endpoint,
            &policy,
            &ForwardedHeaderPolicy::default(),
            "GET",
            "/",
            &[],
            Empty::<Bytes>::new().boxed(),
            None,
            ForwardedContext {
                client_addr: "203.0.113.10:44321".parse().expect("client"),
                request_authority: Some("api.example.com"),
                request_id: 0,
                traceparent: None,
            },
        )
        .expect("request");

        assert_eq!(
            req.headers().get(HOST).and_then(|h| h.to_str().ok()),
            Some("origin.example.com")
        );
        assert_eq!(
            req.headers()
                .get("x-forwarded-host")
                .and_then(|h| h.to_str().ok()),
            Some("origin.example.com")
        );
    }

    #[test]
    fn host_policy_upstream_uses_backend_authority() {
        let endpoint = BackendEndpoint::parse("backend.internal:8443").expect("endpoint");
        let policy = UpstreamHostPolicy {
            mode: UpstreamHostPolicyMode::Upstream,
            host: None,
        };
        let req = build_h2_request_for_endpoint_with_host_policy(
            &endpoint,
            &policy,
            &ForwardedHeaderPolicy::default(),
            "GET",
            "/",
            &[],
            Empty::<Bytes>::new().boxed(),
            None,
            ForwardedContext {
                client_addr: "203.0.113.10:44321".parse().expect("client"),
                request_authority: Some("api.example.com"),
                request_id: 0,
                traceparent: None,
            },
        )
        .expect("request");

        assert_eq!(
            req.headers().get(HOST).and_then(|h| h.to_str().ok()),
            Some("backend.internal:8443")
        );
    }

    #[test]
    fn connect_uses_authority_form_request_target() {
        let req = build_h2_request(
            "proxy.internal:8443",
            "CONNECT",
            "/",
            &[],
            Empty::<Bytes>::new().boxed(),
            None,
            ForwardedContext {
                client_addr: "203.0.113.8:44321".parse().expect("client"),
                request_authority: Some("target.example.com:443"),
                request_id: 0,
                traceparent: None,
            },
        )
        .expect("request");

        assert_eq!(req.method(), http::Method::CONNECT);
        assert_eq!(req.uri().to_string(), "target.example.com:443");
        assert_eq!(
            req.headers().get(HOST).and_then(|h| h.to_str().ok()),
            Some("target.example.com:443")
        );
    }
}
