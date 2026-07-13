use bytes::Bytes;
use spooky_errors::ProxyError;
use tokio::sync::mpsc;

use crate::RetryReason;

pub enum ForwardSuccess {
    Response {
        status: http::StatusCode,
        headers: http::HeaderMap,
        body: hyper::body::Incoming,
    },
    Tunnel {
        status: http::StatusCode,
        headers: http::HeaderMap,
        response_chunk_rx: mpsc::Receiver<ResponseChunk>,
    },
}

pub type ForwardResult = Result<ForwardSuccess, ProxyError>;

pub struct UpstreamResult {
    pub forward: ForwardResult,
    pub hedge: HedgeTelemetry,
    pub retry_count: u8,
    /// Set when a retry was attempted; the error reason that triggered it.
    pub retry_attempt_reason: Option<RetryReason>,
    /// Set when a retry was denied; the first denial reason encountered.
    pub retry_denial_reason: Option<RetryReason>,
}

/// A chunk of the upstream response being streamed back to the client.
#[derive(Debug)]
pub enum ResponseChunk {
    /// Emit downstream response headers (used when headers are deferred until
    /// body-size validation completes).
    Start {
        status: http::StatusCode,
        headers: Vec<(Vec<u8>, Vec<u8>)>,
    },
    Data(Bytes),
    Trailers {
        headers: Vec<(Vec<u8>, Vec<u8>)>,
    },
    End,
    Error(ProxyError),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HedgeTelemetry {
    pub launched: bool,
    pub hedge_won: bool,
    pub hedge_wasted: bool,
    pub primary_won_after_trigger: bool,
    pub primary_late_ms: u64,
}
