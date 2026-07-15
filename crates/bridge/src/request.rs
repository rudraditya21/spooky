use std::{convert::Infallible, net::SocketAddr};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use spooky_config::{
    backend_endpoint::BackendEndpoint,
    config::{ForwardedHeaderPolicy, UpstreamHostPolicy},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestBodyMode {
    Empty,
    KnownLength,
    Streaming,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestTraceContext<'a> {
    pub request_id: u64,
    pub traceparent: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestForwardedContext {
    pub client_addr: SocketAddr,
}

#[derive(Clone, Copy, Debug)]
pub struct RequestBuildPolicies<'a> {
    pub host_policy: &'a UpstreamHostPolicy,
    pub forwarded_header_policy: &'a ForwardedHeaderPolicy,
}

#[derive(Debug)]
pub struct RequestBuildTarget<'a> {
    pub endpoint: &'a BackendEndpoint,
    pub policies: RequestBuildPolicies<'a>,
}

pub struct RequestBuildInput<'a, B = BoxBody<Bytes, Infallible>> {
    pub method: &'a str,
    pub path: &'a str,
    pub authority: Option<&'a str>,
    pub headers: &'a [quiche::h3::Header],
    pub body: B,
    pub content_length: Option<usize>,
    pub body_mode: RequestBodyMode,
    pub trace: RequestTraceContext<'a>,
    pub forwarded: RequestForwardedContext,
}

impl<'a, B> RequestBuildInput<'a, B> {
    pub fn body_mode_for_length(content_length: Option<usize>) -> RequestBodyMode {
        match content_length {
            Some(0) => RequestBodyMode::Empty,
            Some(_) => RequestBodyMode::KnownLength,
            None => RequestBodyMode::Streaming,
        }
    }
}
