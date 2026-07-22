//! Canonical websocket and upgrade detection helpers for bridge callers.
//!
//! This module owns request-shape inspection for websocket tunneling semantics.
//! Transport execution and tunnel I/O stay outside this crate; callers should
//! use these helpers only to decide whether websocket-specific bridging rules apply.

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
