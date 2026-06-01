use std::{
    collections::HashSet,
    convert::Infallible,
    net::{IpAddr, SocketAddr},
};

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, Uri};
use http_body_util::combinators::BoxBody;
use quiche::h3::NameValue;
use spooky_config::{
    backend_endpoint::BackendEndpoint,
    config::{ForwardedHeaderPolicy, ForwardedHeaderPolicyMode, UpstreamHostPolicy, UpstreamHostPolicyMode},
};

pub use spooky_errors::BridgeError;

pub struct ForwardedContext<'a> {
    pub client_addr: SocketAddr,
    pub request_authority: Option<&'a str>,
    pub request_id: u64,
    pub traceparent: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ForwardedHeaderChains<'a> {
    pub forwarded: &'a [Vec<u8>],
    pub x_forwarded_for: &'a [Vec<u8>],
    pub x_forwarded_proto: &'a [Vec<u8>],
    pub x_forwarded_host: &'a [Vec<u8>],
}

#[derive(Debug, Default)]
pub struct ForwardedHeaderValues {
    pub forwarded: Option<HeaderValue>,
    pub x_forwarded_for: Option<HeaderValue>,
    pub x_forwarded_proto: Option<HeaderValue>,
    pub x_forwarded_host: Option<HeaderValue>,
}


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
    let method = Method::from_bytes(method.as_bytes()).map_err(|_| BridgeError::InvalidMethod)?;
    let is_connect = method == Method::CONNECT;
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
        if should_strip_request_header(&header_name, &connection_tokens) {
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

    let uri = if is_connect {
        Uri::try_from(host_value).map_err(|_| BridgeError::InvalidUri)?
    } else {
        let request_path = if path.is_empty() { "/" } else { path };
        let uri = endpoint.uri_for_path(request_path);
        Uri::try_from(uri).map_err(|_| BridgeError::InvalidUri)?
    };
    builder = builder.uri(uri);
    builder = builder.header(http::header::HOST, host_value);

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

    builder.body(body).map_err(BridgeError::Build)
}

pub fn resolve_upstream_host_value<'a>(
    endpoint: &'a BackendEndpoint,
    host_policy: &'a UpstreamHostPolicy,
    request_authority: Option<&'a str>,
    host_header: Option<&'a str>,
) -> Result<&'a str, BridgeError> {
    match host_policy.mode {
        UpstreamHostPolicyMode::PassThrough => Ok(request_authority
            .or(host_header)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(endpoint.authority())),
        UpstreamHostPolicyMode::Rewrite => host_policy
            .host
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or(BridgeError::InvalidHeader),
        UpstreamHostPolicyMode::Upstream => Ok(endpoint.authority()),
    }
}

pub fn build_forwarded_header_values(
    policy: &ForwardedHeaderPolicy,
    inbound: ForwardedHeaderChains<'_>,
    client_ip: IpAddr,
    host_value: &str,
) -> Result<ForwardedHeaderValues, BridgeError> {
    let forwarded_current = format!(
        "for={};proto=https;host=\"{}\"",
        forwarded_for_value(client_ip),
        escape_forwarded_host(host_value),
    );
    let x_forwarded_for_current = client_ip.to_string();
    let x_forwarded_proto_current = "https";
    let x_forwarded_host_current = host_value;

    Ok(ForwardedHeaderValues {
        forwarded: merge_forwarded_chain(
            policy.mode,
            inbound.forwarded,
            Some(forwarded_current.as_bytes()),
        )?,
        x_forwarded_for: merge_forwarded_chain(
            policy.mode,
            inbound.x_forwarded_for,
            Some(x_forwarded_for_current.as_bytes()),
        )?,
        x_forwarded_proto: merge_forwarded_chain(
            policy.mode,
            inbound.x_forwarded_proto,
            Some(x_forwarded_proto_current.as_bytes()),
        )?,
        x_forwarded_host: merge_forwarded_chain(
            policy.mode,
            inbound.x_forwarded_host,
            Some(x_forwarded_host_current.as_bytes()),
        )?,
    })
}

fn merge_forwarded_chain(
    mode: ForwardedHeaderPolicyMode,
    inbound: &[Vec<u8>],
    current: Option<&[u8]>,
) -> Result<Option<HeaderValue>, BridgeError> {
    match mode {
        ForwardedHeaderPolicyMode::Preserve => join_header_chain(inbound),
        ForwardedHeaderPolicyMode::Append => {
            let mut values = inbound.to_vec();
            if let Some(current) = current {
                values.push(current.to_vec());
            }
            join_header_chain(&values)
        }
        ForwardedHeaderPolicyMode::Overwrite => current
            .map(HeaderValue::from_bytes)
            .transpose()
            .map_err(|_| BridgeError::InvalidHeader),
    }
}

fn join_header_chain(values: &[Vec<u8>]) -> Result<Option<HeaderValue>, BridgeError> {
    if values.is_empty() {
        return Ok(None);
    }

    let mut joined = Vec::new();
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            joined.extend_from_slice(b", ");
        }
        joined.extend_from_slice(value);
    }

    HeaderValue::from_bytes(&joined)
        .map(Some)
        .map_err(|_| BridgeError::InvalidHeader)
}

fn connection_header_tokens(headers: &[quiche::h3::Header]) -> HashSet<String> {
    let mut tokens = HashSet::new();
    for header in headers {
        if !header.name().eq_ignore_ascii_case(b"connection") {
            continue;
        }
        let Ok(value) = std::str::from_utf8(header.value()) else {
            continue;
        };
        for token in value.split(',') {
            let normalized = token.trim().to_ascii_lowercase();
            if !normalized.is_empty() {
                tokens.insert(normalized);
            }
        }
    }
    tokens
}

fn should_strip_request_header(name: &HeaderName, connection_tokens: &HashSet<String>) -> bool {
    if connection_tokens.contains(name.as_str()) {
        return true;
    }

    if name == http::header::CONTENT_LENGTH {
        return true;
    }

    if name == http::header::CONNECTION
        || name == http::header::PROXY_AUTHENTICATE
        || name == http::header::PROXY_AUTHORIZATION
        || name == http::header::TE
        || name == http::header::TRAILER
        || name == http::header::TRANSFER_ENCODING
        || name == http::header::UPGRADE
        || name.as_str().eq_ignore_ascii_case("keep-alive")
        || name.as_str().eq_ignore_ascii_case("proxy-connection")
        || name.as_str().eq_ignore_ascii_case("forwarded")
        || name.as_str().eq_ignore_ascii_case("x-forwarded-for")
        || name.as_str().eq_ignore_ascii_case("x-forwarded-proto")
        || name.as_str().eq_ignore_ascii_case("x-forwarded-host")
    {
        return true;
    }

    false
}

fn forwarded_for_value(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("\"[{}]\"", v6),
    }
}

fn escape_forwarded_host(host: &str) -> String {
    host.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::header::HOST;
    use http_body_util::{BodyExt, Empty};
    use quiche::h3::Header;
    use spooky_config::{
        backend_endpoint::BackendEndpoint,
        config::{ForwardedHeaderPolicy, ForwardedHeaderPolicyMode, UpstreamHostPolicy, UpstreamHostPolicyMode},
    };

    use super::{
        ForwardedContext, build_h2_request, build_h2_request_for_endpoint_with_host_policy,
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

        assert!(matches!(err, crate::h3_to_h2::BridgeError::InvalidUri));
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
            Some("for=1.2.3.4;proto=http;host=\"old.example\", for=203.0.113.55;proto=https;host=\"api.example.com\"")
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
