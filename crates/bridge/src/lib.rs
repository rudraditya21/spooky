pub mod h3_to_h1;
pub mod h3_to_h2;

use std::{
    collections::HashSet,
    net::IpAddr,
};

use http::{HeaderName, HeaderValue};
use spooky_config::{
    backend_endpoint::BackendEndpoint,
    config::{ForwardedHeaderPolicy, ForwardedHeaderPolicyMode, UpstreamHostPolicy, UpstreamHostPolicyMode},
};
use std::net::SocketAddr;

pub use spooky_errors::BridgeError;

// --- Shared context and header value types ---

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

// --- Shared websocket detection ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3WebsocketRequestKind {
    None,
    LegacyUpgrade,
    ExtendedConnect,
}

pub fn h3_websocket_request_kind(
    method: &str,
    headers: &[quiche::h3::Header],
) -> H3WebsocketRequestKind {
    use quiche::h3::NameValue;

    let upgrade_is_websocket = headers.iter().any(|header| {
        header.name().eq_ignore_ascii_case(b"upgrade")
            && std::str::from_utf8(header.value())
                .map(|value| value.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false)
    });
    let connection_mentions_upgrade = headers.iter().any(|header| {
        header.name().eq_ignore_ascii_case(b"connection")
            && std::str::from_utf8(header.value())
                .map(|value| {
                    value
                        .split(',')
                        .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
                })
                .unwrap_or(false)
    });
    let protocol_is_websocket = headers.iter().any(|header| {
        header.name().eq_ignore_ascii_case(b":protocol")
            && std::str::from_utf8(header.value())
                .map(|value| value.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false)
    });

    if method.eq_ignore_ascii_case("CONNECT") && protocol_is_websocket {
        H3WebsocketRequestKind::ExtendedConnect
    } else if method.eq_ignore_ascii_case("GET")
        && upgrade_is_websocket
        && connection_mentions_upgrade
    {
        H3WebsocketRequestKind::LegacyUpgrade
    } else {
        H3WebsocketRequestKind::None
    }
}

pub fn h3_websocket_tunnel_requested(method: &str, headers: &[quiche::h3::Header]) -> bool {
    h3_websocket_request_kind(method, headers) != H3WebsocketRequestKind::None
}

// --- Shared header utilities ---

pub(crate) fn connection_header_tokens(headers: &[quiche::h3::Header]) -> HashSet<String> {
    use quiche::h3::NameValue;

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

/// Strip hop-by-hop and proxy-injected headers from an inbound H3 request.
/// `preserve_upgrade` keeps `Connection` and `Upgrade` for H1 WebSocket tunnels.
pub(crate) fn should_strip_request_header(
    name: &HeaderName,
    connection_tokens: &HashSet<String>,
    preserve_upgrade: bool,
) -> bool {
    if preserve_upgrade
        && (name == http::header::CONNECTION || name == http::header::UPGRADE)
    {
        return false;
    }

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

// --- Shared upstream host resolution ---

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

// --- Shared forwarded header helpers ---

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

pub(crate) fn forwarded_for_value(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("\"[{}]\"", v6),
    }
}

pub(crate) fn escape_forwarded_host(host: &str) -> String {
    host.replace('\\', "\\\\").replace('"', "\\\"")
}
