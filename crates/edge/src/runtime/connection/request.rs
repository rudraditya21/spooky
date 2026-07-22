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
        auth::{ExternalAuthFailureDisposition, ExternalAuthResult, PendingHeaderMutation},
        response::{ResponseChunk, UpstreamResult},
        stream::{
            LegacyRequestLifecycle, RequestBodyRuntime, RequestBodyState, RequestContext,
            RequestExecutionState, RequestMode, RoutingSnapshot, StreamAdmissionState, StreamPhase,
            TunnelMode,
        },
    },
};

pub(crate) enum IntakeExecutionSeed {
    AwaitingAuth {
        pending_forward: Arc<PendingForward>,
        auth_result_rx: oneshot::Receiver<ExternalAuthResult>,
        auth_abort: AbortHandle,
        auth_disposition: ExternalAuthFailureDisposition,
        auth_deadline: Instant,
    },
    ReadyForForwarding {
        pending_forward: Arc<PendingForward>,
    },
}

pub struct RequestEnvelope {
    pub request_id: u64,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub traceparent: Option<String>,
    pub trace_span: Option<Span>,

    pub method: String,
    pub path: String,
    pub authority: Option<String>,
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
    pub start: Instant,
    pub total_request_deadline: Instant,
    pub bodyless_mode: bool,
    pub tunnel_mode: TunnelMode,

    pub retry_count: u8,
    pub error_kind: Option<&'static str>,
    pub execution: RequestExecutionState,
}

impl RequestEnvelope {
    pub fn request_id(&self) -> u64 {
        self.request_id
    }

    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn new_legacy(
        request_id: u64,
        trace_id: Option<String>,
        span_id: Option<String>,
        traceparent: Option<String>,
        trace_span: Option<Span>,
        method: String,
        path: String,
        authority: Option<String>,
        backend_addr: Option<String>,
        backend_index: Option<usize>,
        upstream_name: Option<String>,
        route_reason: Option<String>,
        route_path_len: Option<usize>,
        route_host_specific: Option<bool>,
        backend_lb: Option<String>,
        upstream_pool: Option<Arc<RwLock<UpstreamPool>>>,
        routing_transparency_enabled: bool,
        routing_transparency_include_reason: bool,
        start: Instant,
        total_request_deadline: Instant,
        bodyless_mode: bool,
        tunnel_mode: TunnelMode,
        retry_count: u8,
        error_kind: Option<&'static str>,
        phase: StreamPhase,
        admission_state: StreamAdmissionState,
        request_fin_received: bool,
        pending_forward: Option<Arc<PendingForward>>,
        auth_result_rx: Option<oneshot::Receiver<ExternalAuthResult>>,
        auth_abort: Option<AbortHandle>,
        auth_disposition: Option<ExternalAuthFailureDisposition>,
        auth_deadline: Option<Instant>,
    ) -> Self {
        Self {
            request_id,
            trace_id,
            span_id,
            traceparent,
            trace_span,
            method,
            path,
            authority,
            backend_addr,
            backend_index,
            upstream_name,
            route_reason,
            route_path_len,
            route_host_specific,
            backend_lb,
            upstream_pool,
            routing_transparency_enabled,
            routing_transparency_include_reason,
            response_status: None,
            start,
            total_request_deadline,
            bodyless_mode,
            tunnel_mode,
            retry_count,
            error_kind,
            execution: RequestExecutionState::Legacy(LegacyRequestLifecycle {
                phase,
                admission_state,
                request_body_runtime: RequestBodyRuntime {
                    body_tx: None,
                    body_buf: VecDeque::new(),
                    body_buf_bytes: 0,
                    body_bytes_received: 0,
                    last_body_activity: start,
                    request_fin_received,
                },
                pending_forward,
                auth_result_rx,
                auth_abort,
                auth_disposition,
                auth_deadline,
                backend_request_started: false,
                backend_request_finished: false,
                global_inflight_permit: None,
                upstream_inflight_permit: None,
                adaptive_admission_permit: None,
                route_queue_permit: None,
                upstream_result_rx: None,
                response_chunk_rx: None,
                response_headers_sent: false,
                pending_chunk: None,
            }),
        }
    }

    pub(crate) fn from_intake_legacy(
        context: RequestContext,
        routing: RoutingSnapshot,
        upstream_pool: Arc<RwLock<UpstreamPool>>,
        request_mode: RequestMode,
        request_body: RequestBodyState,
        routing_transparency_enabled: bool,
        routing_transparency_include_reason: bool,
        retry_count: u8,
        error_kind: Option<&'static str>,
        execution: IntakeExecutionSeed,
    ) -> Self {
        let (
            admission_state,
            pending_forward,
            auth_result_rx,
            auth_abort,
            auth_disposition,
            auth_deadline,
        ) = match execution {
            IntakeExecutionSeed::AwaitingAuth {
                pending_forward,
                auth_result_rx,
                auth_abort,
                auth_disposition,
                auth_deadline,
            } => (
                StreamAdmissionState::WaitingForAuth,
                Some(pending_forward),
                Some(auth_result_rx),
                Some(auth_abort),
                Some(auth_disposition),
                Some(auth_deadline),
            ),
            IntakeExecutionSeed::ReadyForForwarding { pending_forward } => (
                StreamAdmissionState::ReadyToForward,
                Some(pending_forward),
                None,
                None,
                None,
                None,
            ),
        };

        Self {
            request_id: context.request_id,
            trace_id: context.trace_id,
            span_id: context.span_id,
            traceparent: context.traceparent,
            trace_span: context.trace_span,
            method: context.method,
            path: context.path,
            authority: context.authority,
            backend_addr: Some(routing.backend_addr),
            backend_index: Some(routing.backend_index),
            upstream_name: Some(routing.upstream_name),
            route_reason: Some(routing.route_reason),
            route_path_len: Some(routing.route_path_len),
            route_host_specific: Some(routing.route_host_specific),
            backend_lb: routing.backend_lb,
            upstream_pool: Some(upstream_pool),
            routing_transparency_enabled,
            routing_transparency_include_reason,
            response_status: None,
            start: context.start,
            total_request_deadline: context.total_request_deadline,
            bodyless_mode: request_mode.bodyless_mode(),
            tunnel_mode: request_mode.tunnel_mode(),
            retry_count,
            error_kind,
            execution: RequestExecutionState::Legacy(LegacyRequestLifecycle {
                phase: StreamPhase::ReceivingRequest,
                admission_state,
                request_body_runtime: RequestBodyRuntime {
                    body_tx: None,
                    body_buf: VecDeque::new(),
                    body_buf_bytes: 0,
                    body_bytes_received: 0,
                    last_body_activity: context.start,
                    request_fin_received: request_body.request_fin_received(),
                },
                pending_forward,
                auth_result_rx,
                auth_abort,
                auth_disposition,
                auth_deadline,
                backend_request_started: false,
                backend_request_finished: false,
                global_inflight_permit: None,
                upstream_inflight_permit: None,
                adaptive_admission_permit: None,
                route_queue_permit: None,
                upstream_result_rx: None,
                response_chunk_rx: None,
                response_headers_sent: false,
                pending_chunk: None,
            }),
        }
    }

    pub fn phase(&self) -> StreamPhase {
        self.execution.phase()
    }

    pub fn admission_state(&self) -> StreamAdmissionState {
        self.execution.admission_state()
    }

    pub fn request_fin_received(&self) -> bool {
        self.legacy().request_body_runtime.request_fin_received
    }

    pub fn set_request_fin_received(&mut self, value: bool) {
        self.legacy_mut().request_body_runtime.request_fin_received = value;
    }

    pub fn body_tx(&self) -> Option<&mpsc::Sender<Bytes>> {
        self.legacy().request_body_runtime.body_tx.as_ref()
    }

    pub fn body_tx_mut(&mut self) -> &mut Option<mpsc::Sender<Bytes>> {
        &mut self.legacy_mut().request_body_runtime.body_tx
    }

    pub fn clear_body_tx(&mut self) {
        self.legacy_mut().request_body_runtime.body_tx = None;
    }

    pub fn body_buf(&self) -> &VecDeque<Bytes> {
        &self.legacy().request_body_runtime.body_buf
    }

    pub fn body_buf_mut(&mut self) -> &mut VecDeque<Bytes> {
        &mut self.legacy_mut().request_body_runtime.body_buf
    }

    pub fn body_buf_bytes(&self) -> usize {
        self.legacy().request_body_runtime.body_buf_bytes
    }

    pub fn set_body_buf_bytes(&mut self, value: usize) {
        self.legacy_mut().request_body_runtime.body_buf_bytes = value;
    }

    pub fn body_bytes_received(&self) -> usize {
        self.legacy().request_body_runtime.body_bytes_received
    }

    pub fn set_body_bytes_received(&mut self, value: usize) {
        self.legacy_mut().request_body_runtime.body_bytes_received = value;
    }

    pub fn last_body_activity(&self) -> Instant {
        self.legacy().request_body_runtime.last_body_activity
    }

    pub fn set_last_body_activity(&mut self, value: Instant) {
        self.legacy_mut().request_body_runtime.last_body_activity = value;
    }

    pub fn pending_forward(&self) -> Option<&Arc<PendingForward>> {
        self.legacy().pending_forward.as_ref()
    }

    pub fn pending_forward_mut(&mut self) -> Option<&mut Arc<PendingForward>> {
        self.legacy_mut().pending_forward.as_mut()
    }

    pub fn clear_pending_forward(&mut self) {
        self.legacy_mut().pending_forward = None;
    }

    pub(crate) fn auth_result_rx_mut(
        &mut self,
    ) -> Option<&mut oneshot::Receiver<ExternalAuthResult>> {
        self.legacy_mut().auth_result_rx.as_mut()
    }

    pub fn clear_auth_result_rx(&mut self) {
        self.legacy_mut().auth_result_rx = None;
    }

    #[allow(dead_code)]
    pub(crate) fn set_auth_result_rx(&mut self, rx: Option<oneshot::Receiver<ExternalAuthResult>>) {
        self.legacy_mut().auth_result_rx = rx;
    }

    pub fn has_auth_result_rx(&self) -> bool {
        self.legacy().auth_result_rx.is_some()
    }

    pub fn take_auth_abort(&mut self) -> Option<AbortHandle> {
        self.legacy_mut().auth_abort.take()
    }

    pub fn clear_auth_abort(&mut self) {
        self.legacy_mut().auth_abort = None;
    }

    pub fn set_auth_abort(&mut self, abort: Option<AbortHandle>) {
        self.legacy_mut().auth_abort = abort;
    }

    pub fn has_auth_abort(&self) -> bool {
        self.legacy().auth_abort.is_some()
    }

    pub fn auth_fail_open(&self) -> bool {
        self.legacy()
            .auth_disposition
            .is_some_and(ExternalAuthFailureDisposition::fail_open)
    }

    #[allow(dead_code)]
    pub(crate) fn set_auth_disposition(
        &mut self,
        disposition: Option<ExternalAuthFailureDisposition>,
    ) {
        self.legacy_mut().auth_disposition = disposition;
    }

    pub fn auth_deadline(&self) -> Option<Instant> {
        self.legacy().auth_deadline
    }

    pub fn set_auth_deadline(&mut self, deadline: Option<Instant>) {
        self.legacy_mut().auth_deadline = deadline;
    }

    pub(crate) fn upstream_result_rx_mut(
        &mut self,
    ) -> Option<&mut oneshot::Receiver<UpstreamResult>> {
        self.legacy_mut().upstream_result_rx.as_mut()
    }

    #[allow(dead_code)]
    pub(crate) fn set_upstream_result_rx(&mut self, rx: Option<oneshot::Receiver<UpstreamResult>>) {
        self.legacy_mut().upstream_result_rx = rx;
    }

    pub fn clear_upstream_result_rx(&mut self) {
        self.legacy_mut().upstream_result_rx = None;
    }

    pub(crate) fn response_chunk_rx_mut(&mut self) -> Option<&mut mpsc::Receiver<ResponseChunk>> {
        self.legacy_mut().response_chunk_rx.as_mut()
    }

    #[allow(dead_code)]
    pub(crate) fn set_response_chunk_rx(&mut self, rx: Option<mpsc::Receiver<ResponseChunk>>) {
        self.legacy_mut().response_chunk_rx = rx;
    }

    pub fn clear_response_chunk_rx(&mut self) {
        self.legacy_mut().response_chunk_rx = None;
    }

    pub fn has_upstream_result_rx(&self) -> bool {
        self.legacy().upstream_result_rx.is_some()
    }

    pub fn has_response_chunk_rx(&self) -> bool {
        self.legacy().response_chunk_rx.is_some()
    }

    pub fn response_headers_sent(&self) -> bool {
        self.legacy().response_headers_sent
    }

    pub fn set_response_headers_sent(&mut self, sent: bool) {
        self.legacy_mut().response_headers_sent = sent;
    }

    pub(crate) fn take_pending_chunk(&mut self) -> Option<ResponseChunk> {
        self.legacy_mut().pending_chunk.take()
    }

    pub(crate) fn set_pending_chunk(&mut self, chunk: Option<ResponseChunk>) {
        self.legacy_mut().pending_chunk = chunk;
    }

    pub fn has_pending_chunk(&self) -> bool {
        self.legacy().pending_chunk.is_some()
    }

    pub fn backend_request_started(&self) -> bool {
        self.legacy().backend_request_started
    }

    pub fn backend_request_finished(&self) -> bool {
        self.legacy().backend_request_finished
    }

    pub fn set_backend_request_state(&mut self, started: bool, finished: bool) {
        let legacy = self.legacy_mut();
        legacy.backend_request_started = started;
        legacy.backend_request_finished = finished;
    }

    pub fn set_dispatch_permits(
        &mut self,
        global: Option<OwnedSemaphorePermit>,
        upstream: Option<OwnedSemaphorePermit>,
        adaptive: Option<AdaptivePermit>,
        route_queue: Option<RouteQueuePermit>,
    ) {
        let legacy = self.legacy_mut();
        legacy.global_inflight_permit = global;
        legacy.upstream_inflight_permit = upstream;
        legacy.adaptive_admission_permit = adaptive;
        legacy.route_queue_permit = route_queue;
    }

    pub fn clear_dispatch_permits(&mut self) {
        let legacy = self.legacy_mut();
        legacy.global_inflight_permit = None;
        legacy.upstream_inflight_permit = None;
        legacy.adaptive_admission_permit = None;
        legacy.route_queue_permit = None;
    }

    pub fn has_global_inflight_permit(&self) -> bool {
        self.legacy().global_inflight_permit.is_some()
    }

    pub fn has_upstream_inflight_permit(&self) -> bool {
        self.legacy().upstream_inflight_permit.is_some()
    }

    pub fn has_adaptive_admission_permit(&self) -> bool {
        self.legacy().adaptive_admission_permit.is_some()
    }

    pub fn has_route_queue_permit(&self) -> bool {
        self.legacy().route_queue_permit.is_some()
    }

    #[allow(dead_code)]
    pub(crate) fn transition_to_awaiting_auth(
        &mut self,
        pending_forward: Arc<PendingForward>,
        auth_result_rx: oneshot::Receiver<ExternalAuthResult>,
        auth_abort: AbortHandle,
        auth_disposition: ExternalAuthFailureDisposition,
        auth_deadline: Instant,
    ) {
        let legacy = self.legacy_mut();
        legacy.phase = StreamPhase::ReceivingRequest;
        legacy.admission_state = StreamAdmissionState::WaitingForAuth;
        legacy.pending_forward = Some(pending_forward);
        legacy.auth_result_rx = Some(auth_result_rx);
        legacy.auth_abort = Some(auth_abort);
        legacy.auth_disposition = Some(auth_disposition);
        legacy.auth_deadline = Some(auth_deadline);
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn transition_to_dispatching(
        &mut self,
        body_tx: Option<mpsc::Sender<Bytes>>,
        upstream_result_rx: oneshot::Receiver<UpstreamResult>,
        global: OwnedSemaphorePermit,
        upstream: OwnedSemaphorePermit,
        adaptive: AdaptivePermit,
        route_queue: RouteQueuePermit,
    ) {
        let should_await_upstream = self.request_fin_received() && self.body_buf().is_empty();
        let legacy = self.legacy_mut();
        legacy.backend_request_started = true;
        legacy.backend_request_finished = false;
        legacy.request_body_runtime.body_tx = body_tx;
        legacy.upstream_result_rx = Some(upstream_result_rx);
        legacy.global_inflight_permit = Some(global);
        legacy.upstream_inflight_permit = Some(upstream);
        legacy.adaptive_admission_permit = Some(adaptive);
        legacy.route_queue_permit = Some(route_queue);
        legacy.admission_state = StreamAdmissionState::ReadyToForward;
        legacy.phase = if should_await_upstream {
            StreamPhase::AwaitingUpstream
        } else {
            StreamPhase::ReceivingRequest
        };
        legacy.auth_abort = None;
        legacy.auth_result_rx = None;
        legacy.auth_disposition = None;
        legacy.auth_deadline = None;
        if should_await_upstream {
            legacy.request_body_runtime.body_tx = None;
        }
    }

    pub(crate) fn transition_to_streaming_response(
        &mut self,
        response_chunk_rx: Option<mpsc::Receiver<ResponseChunk>>,
        response_headers_sent: bool,
        phase: StreamPhase,
    ) {
        let legacy = self.legacy_mut();
        legacy.response_chunk_rx = response_chunk_rx;
        legacy.response_headers_sent = response_headers_sent;
        legacy.phase = phase;
    }

    pub fn transition_to_terminal(
        &mut self,
        terminal: crate::runtime::connection::stream::TerminalState,
    ) {
        self.execution = RequestExecutionState::Terminal(terminal);
    }

    pub fn set_phase_legacy(&mut self, phase: StreamPhase) {
        self.legacy_mut().phase = phase;
    }

    pub fn set_admission_state_legacy(&mut self, state: StreamAdmissionState) {
        self.legacy_mut().admission_state = state;
    }

    pub fn set_pending_forward(&mut self, pending_forward: Option<Arc<PendingForward>>) {
        self.legacy_mut().pending_forward = pending_forward;
    }

    fn legacy(&self) -> &LegacyRequestLifecycle {
        match &self.execution {
            RequestExecutionState::Legacy(state) => state,
            other => panic!(
                "legacy lifecycle access attempted after migration to {:?}",
                std::mem::discriminant(other)
            ),
        }
    }

    fn legacy_mut(&mut self) -> &mut LegacyRequestLifecycle {
        match &mut self.execution {
            RequestExecutionState::Legacy(state) => state,
            other => panic!(
                "legacy lifecycle mutation attempted after migration to {:?}",
                std::mem::discriminant(other)
            ),
        }
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
