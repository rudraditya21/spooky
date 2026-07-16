use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Instant,
};

use bytes::Bytes;
use spooky_config::config::{ForwardedHeaderPolicy, UpstreamHostPolicy};
use spooky_lb::upstream_pool::UpstreamPool;
use tokio::{
    sync::{OwnedSemaphorePermit, mpsc, oneshot},
    task::AbortHandle,
};
use tracing::Span;

use crate::{
    resilience::{adaptive_admission::AdaptivePermit, route_queue::RouteQueuePermit},
    runtime::connection::{
        auth::{ExternalAuthResult, PendingHeaderMutation},
        response::{ResponseChunk, UpstreamResult},
        stream::{StreamAdmissionState, StreamPhase, TunnelMode},
    },
};

pub struct RequestEnvelope {
    pub request_id: u64,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub traceparent: Option<String>,
    pub trace_span: Option<Span>,

    pub method: String,
    pub path: String,
    pub authority: Option<String>,
    /// Sender half of the body channel.  Dropping it signals end-of-body to hyper.
    pub body_tx: Option<mpsc::Sender<Bytes>>,
    /// Body chunks that arrived before the channel had capacity.
    pub body_buf: VecDeque<Bytes>,
    /// Current bytes held in `body_buf`.
    pub body_buf_bytes: usize,
    /// Total body bytes received on this stream (buffered + already forwarded).
    pub body_bytes_received: usize,
    /// Last observed request-body byte arrival time.
    pub last_body_activity: Instant,
    /// Resolved backend address and index (for health marking on response).
    pub backend_addr: Option<String>,
    pub backend_index: Option<usize>,
    pub upstream_name: Option<String>,
    pub route_reason: Option<String>,
    pub route_path_len: Option<usize>,
    pub route_host_specific: Option<bool>,
    pub backend_lb: Option<String>,
    pub upstream_pool: Option<Arc<RwLock<UpstreamPool>>>,
    pub routing_transparency_enabled: bool,
    pub routing_transparency_include_reason: bool,
    pub response_status: Option<u16>,
    pub backend_request_started: bool,
    pub backend_request_finished: bool,
    pub global_inflight_permit: Option<OwnedSemaphorePermit>,
    pub upstream_inflight_permit: Option<OwnedSemaphorePermit>,
    pub adaptive_admission_permit: Option<AdaptivePermit>,
    pub route_queue_permit: Option<RouteQueuePermit>,
    pub start: Instant,
    pub total_request_deadline: Instant,
    pub bodyless_mode: bool,
    pub tunnel_mode: TunnelMode,

    pub retry_count: u8,
    pub error_kind: Option<&'static str>,
    /// Deferred request-building snapshot for async auth/admission handoff.
    pub pending_forward: Option<Arc<PendingForward>>,
    /// Receives the external auth decision once async auth completes.
    pub(crate) auth_result_rx: Option<oneshot::Receiver<ExternalAuthResult>>,
    /// Aborts the detached external auth task when the stream is cancelled.
    pub auth_abort: Option<AbortHandle>,
    /// Whether auth transport errors and timeouts should allow the request.
    pub auth_fail_open: bool,
    /// Deadline for the external auth decision, when auth is running asynchronously.
    pub auth_deadline: Option<Instant>,

    /// Current lifecycle phase of this stream.
    pub phase: StreamPhase,
    /// Current auth/admission state of this stream.
    pub admission_state: StreamAdmissionState,
    /// True once the client has sent FIN on the request stream.
    pub request_fin_received: bool,
    /// Receives the upstream H2 response (status, headers, body stream).
    pub upstream_result_rx: Option<oneshot::Receiver<UpstreamResult>>,
    /// Receives response body chunks to write back over QUIC.
    pub response_chunk_rx: Option<mpsc::Receiver<ResponseChunk>>,
    /// True once downstream response headers are emitted on this stream.
    pub response_headers_sent: bool,
    /// A chunk that could not be written due to QUIC send backpressure; retried next poll.
    pub pending_chunk: Option<ResponseChunk>,
}

impl RequestEnvelope {
    pub fn request_id(&self) -> u64 {
        self.request_id
    }
}

#[derive(Debug, Clone)]
pub struct PendingForward {
    pub method: Arc<str>,
    pub path: Arc<str>,
    pub authority: Option<Arc<str>>,
    pub headers: Arc<Vec<quiche::h3::Header>>,
    pub upstream_name: Arc<str>,
    pub route_reason: Arc<str>,
    pub route_path_len: usize,
    pub route_host_specific: bool,
    pub backend_addr: Arc<str>,
    pub backend_index: usize,
    pub backend_lb: Option<Arc<str>>,
    pub client_addr: SocketAddr,
    pub request_id: u64,
    pub trace_id: Option<Arc<str>>,
    pub span_id: Option<Arc<str>>,
    pub traceparent: Option<Arc<str>>,
    pub host_policy: UpstreamHostPolicy,
    pub forwarded_header_policy: ForwardedHeaderPolicy,
    pub(crate) auth_header_mutations: Vec<PendingHeaderMutation>,
}
