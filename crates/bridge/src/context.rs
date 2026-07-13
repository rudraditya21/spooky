use std::net::SocketAddr;

use http::HeaderValue;

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
