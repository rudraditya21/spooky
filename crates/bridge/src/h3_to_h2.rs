use std::convert::Infallible;

use bytes::Bytes;
use http::{Method, Request, Uri, Version};
use http_body_util::combinators::BoxBody;
use hyper::ext::Protocol;

use crate::{
    BridgeError,
    request::{
        RequestBuildInput, RequestBuildTarget, RequestHeaderAssembly, RequestHeaderPolicyInput,
        apply_request_header_assembly, apply_request_header_policies,
    },
    websocket::{H3WebsocketRequestKind, h3_websocket_request_kind},
};

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
    }
    builder = apply_request_header_assembly(
        builder,
        RequestHeaderAssembly {
            resolved_headers,
            trace,
            content_length,
            include_content_length: !websocket_extended_connect,
            include_host_header: !websocket_extended_connect,
            add_te_trailers: false,
        },
    )?;

    builder.body(body).map_err(BridgeError::Build)
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, net::SocketAddr};

    use bytes::Bytes;
    use http::header::HOST;
    use http_body_util::{BodyExt, Empty, combinators::BoxBody};
    use hyper::ext::Protocol;
    use quiche::h3::Header;
    use spooky_config::{
        backend_endpoint::BackendEndpoint,
        config::{
            ForwardedHeaderPolicy, ForwardedHeaderPolicyMode, UpstreamHostPolicy,
            UpstreamHostPolicyMode,
        },
    };

    use super::{BridgeError, build_h2_request_for_target};
    use crate::{
        h3_to_h1::build_h1_request,
        request::{
            RequestBuildInput, RequestBuildPolicies, RequestBuildTarget, RequestForwardedContext,
            RequestTraceContext,
        },
    };

    #[derive(Clone, Copy)]
    struct RequestInputMeta<'a> {
        authority: Option<&'a str>,
        content_length: Option<usize>,
        request_id: u64,
        traceparent: Option<&'a str>,
        client_addr: SocketAddr,
    }

    fn request_target<'a>(
        endpoint: &'a BackendEndpoint,
        host_policy: &'a UpstreamHostPolicy,
        forwarded_header_policy: &'a ForwardedHeaderPolicy,
    ) -> RequestBuildTarget<'a> {
        RequestBuildTarget {
            endpoint,
            policies: RequestBuildPolicies {
                host_policy,
                forwarded_header_policy,
            },
        }
    }

    fn request_input<'a>(
        method: &'a str,
        path: &'a str,
        headers: &'a [Header],
        meta: RequestInputMeta<'a>,
    ) -> RequestBuildInput<'a, BoxBody<Bytes, Infallible>> {
        RequestBuildInput {
            method,
            path,
            authority: meta.authority,
            headers,
            body: Empty::<Bytes>::new().boxed(),
            content_length: meta.content_length,
            body_mode: RequestBuildInput::<BoxBody<Bytes, Infallible>>::body_mode_for_length(
                meta.content_length,
            ),
            trace: RequestTraceContext {
                request_id: meta.request_id,
                traceparent: meta.traceparent,
            },
            forwarded: RequestForwardedContext {
                client_addr: meta.client_addr,
            },
        }
    }

    fn canonical_h2_request(
        backend: &str,
        method: &str,
        path: &str,
        headers: &[Header],
        meta: RequestInputMeta<'_>,
    ) -> Result<http::Request<BoxBody<Bytes, Infallible>>, BridgeError> {
        let endpoint = BackendEndpoint::parse(backend).map_err(|_| BridgeError::InvalidUri)?;
        build_h2_request_for_target(
            request_target(
                &endpoint,
                &UpstreamHostPolicy::default(),
                &ForwardedHeaderPolicy::default(),
            ),
            request_input(method, path, headers, meta),
        )
    }

    fn canonical_h2_request_with_policy(
        endpoint: &BackendEndpoint,
        host_policy: &UpstreamHostPolicy,
        forwarded_policy: &ForwardedHeaderPolicy,
        method: &str,
        path: &str,
        headers: &[Header],
        meta: RequestInputMeta<'_>,
    ) -> Result<http::Request<BoxBody<Bytes, Infallible>>, BridgeError> {
        build_h2_request_for_target(
            request_target(endpoint, host_policy, forwarded_policy),
            request_input(method, path, headers, meta),
        )
    }

    #[test]
    fn defaults_to_https_origin_for_host_port_backend() {
        let req = canonical_h2_request(
            "backend.internal:443",
            "GET",
            "/health",
            &[],
            RequestInputMeta {
                authority: Some("api.example.com"),
                content_length: None,
                request_id: 0,
                traceparent: None,
                client_addr: "203.0.113.10:44321".parse().expect("client"),
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
        let req = canonical_h2_request(
            "http://127.0.0.1:8080",
            "GET",
            "/",
            &[],
            RequestInputMeta {
                authority: None,
                content_length: None,
                request_id: 0,
                traceparent: None,
                client_addr: "198.51.100.3:5555".parse().expect("client"),
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
        let err = canonical_h2_request(
            "https://backend.internal:443/path",
            "GET",
            "/",
            &[],
            RequestInputMeta {
                authority: None,
                content_length: None,
                request_id: 0,
                traceparent: None,
                client_addr: "127.0.0.1:12345".parse().expect("client"),
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

        let req = canonical_h2_request(
            "backend.internal:443",
            "GET",
            "/",
            &headers,
            RequestInputMeta {
                authority: Some("api.example.com"),
                content_length: None,
                request_id: 0,
                traceparent: None,
                client_addr: "203.0.113.55:43210".parse().expect("client"),
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
        let req = canonical_h2_request_with_policy(
            &endpoint,
            &host_policy,
            &append_policy,
            "GET",
            "/",
            &headers,
            RequestInputMeta {
                authority: Some("api.example.com"),
                content_length: None,
                request_id: 0,
                traceparent: None,
                client_addr: "203.0.113.55:43210".parse().expect("client"),
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
        let req = canonical_h2_request_with_policy(
            &endpoint,
            &host_policy,
            &preserve_policy,
            "GET",
            "/",
            &headers,
            RequestInputMeta {
                authority: Some("api.example.com"),
                content_length: None,
                request_id: 0,
                traceparent: None,
                client_addr: "203.0.113.55:43210".parse().expect("client"),
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
        let req = canonical_h2_request(
            "backend.internal:443",
            "GET",
            "/",
            &[],
            RequestInputMeta {
                authority: Some("api.example.com"),
                content_length: None,
                request_id: 0,
                traceparent: None,
                client_addr: "[2001:db8::1]:4444".parse().expect("client"),
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
        let req = canonical_h2_request_with_policy(
            &endpoint,
            &policy,
            &ForwardedHeaderPolicy::default(),
            "GET",
            "/",
            &[],
            RequestInputMeta {
                authority: Some("api.example.com"),
                content_length: None,
                request_id: 0,
                traceparent: None,
                client_addr: "203.0.113.10:44321".parse().expect("client"),
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
        let req = canonical_h2_request_with_policy(
            &endpoint,
            &policy,
            &ForwardedHeaderPolicy::default(),
            "GET",
            "/",
            &[],
            RequestInputMeta {
                authority: Some("api.example.com"),
                content_length: None,
                request_id: 0,
                traceparent: None,
                client_addr: "203.0.113.10:44321".parse().expect("client"),
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
        let req = canonical_h2_request(
            "proxy.internal:8443",
            "CONNECT",
            "/",
            &[],
            RequestInputMeta {
                authority: Some("target.example.com:443"),
                content_length: None,
                request_id: 0,
                traceparent: None,
                client_addr: "203.0.113.8:44321".parse().expect("client"),
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

    #[test]
    fn websocket_requests_are_shaped_as_extended_connect() {
        let endpoint = BackendEndpoint::parse("backend.internal:443").expect("endpoint");
        let headers = vec![
            Header::new(b"connection", b"upgrade"),
            Header::new(b"upgrade", b"websocket"),
            Header::new(b"sec-websocket-key", b"dGhlIHNhbXBsZSBub25jZQ=="),
        ];

        let req = build_h2_request_for_target(
            request_target(
                &endpoint,
                &UpstreamHostPolicy::default(),
                &ForwardedHeaderPolicy::default(),
            ),
            request_input(
                "GET",
                "/ws",
                &headers,
                RequestInputMeta {
                    authority: Some("socket.example.com"),
                    content_length: None,
                    request_id: 11,
                    traceparent: None,
                    client_addr: "203.0.113.33:6000".parse().expect("client"),
                },
            ),
        )
        .expect("request");

        assert_eq!(req.method(), http::Method::CONNECT);
        assert_eq!(req.version(), http::Version::HTTP_2);
        assert_eq!(req.uri().to_string(), "https://backend.internal:443/ws");
        assert!(req.extensions().get::<Protocol>().is_some());
        assert!(req.headers().get(HOST).is_none());
        assert!(req.headers().get(http::header::CONTENT_LENGTH).is_none());
        assert!(req.headers().get("connection").is_none());
        assert!(req.headers().get("upgrade").is_none());
        assert_eq!(
            req.headers()
                .get("sec-websocket-key")
                .and_then(|value| value.to_str().ok()),
            Some("dGhlIHNhbXBsZSBub25jZQ==")
        );
        assert_eq!(
            req.headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("11")
        );
    }

    #[test]
    fn h1_and_h2_share_canonical_policy_outputs() {
        let endpoint = BackendEndpoint::parse("backend.internal:443").expect("endpoint");
        let headers = vec![
            Header::new(b"host", b"spoofed.example.com"),
            Header::new(b"x-forwarded-for", b"1.2.3.4"),
            Header::new(b"forwarded", b"for=1.2.3.4"),
            Header::new(b"connection", b"keep-alive, x-secret"),
            Header::new(b"x-secret", b"drop-me"),
            Header::new(b"x-keep", b"ok"),
        ];
        let host_policy = UpstreamHostPolicy::default();
        let forwarded_policy = ForwardedHeaderPolicy::default();

        let h1 = build_h1_request(
            request_target(&endpoint, &host_policy, &forwarded_policy),
            request_input(
                "GET",
                "/shared",
                &headers,
                RequestInputMeta {
                    authority: Some("api.example.com"),
                    content_length: None,
                    request_id: 55,
                    traceparent: Some("00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"),
                    client_addr: "198.51.100.44:7000".parse().expect("client"),
                },
            ),
        )
        .expect("h1 request");
        let h2 = build_h2_request_for_target(
            request_target(&endpoint, &host_policy, &forwarded_policy),
            request_input(
                "GET",
                "/shared",
                &headers,
                RequestInputMeta {
                    authority: Some("api.example.com"),
                    content_length: None,
                    request_id: 55,
                    traceparent: Some("00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"),
                    client_addr: "198.51.100.44:7000".parse().expect("client"),
                },
            ),
        )
        .expect("h2 request");

        assert_eq!(h1.uri(), h2.uri());
        for name in [
            HOST.as_str(),
            "x-keep",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-host",
            "forwarded",
            "x-request-id",
            "traceparent",
        ] {
            assert_eq!(
                h1.headers().get(name).and_then(|value| value.to_str().ok()),
                h2.headers().get(name).and_then(|value| value.to_str().ok()),
                "header mismatch for {name}"
            );
        }
        assert!(h1.headers().get("x-secret").is_none());
        assert!(h2.headers().get("x-secret").is_none());
        assert_eq!(
            h1.headers().get("te").and_then(|value| value.to_str().ok()),
            Some("trailers")
        );
        assert!(h2.headers().get("te").is_none());
    }
}
