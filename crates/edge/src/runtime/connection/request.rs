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
            AwaitingAuthState, CancellationReason, CancelledState, DispatchReadyState,
            LegacyRequestLifecycle, RequestBodyRuntime, RequestContext, RequestExecutionState,
            RequestMode, StreamAdmissionState, StreamPhase, TerminalSnapshot, TerminalState,
            TunnelMode,
        },
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
        _auth_result_rx: Option<oneshot::Receiver<ExternalAuthResult>>,
        _auth_abort: Option<AbortHandle>,
        _auth_disposition: Option<ExternalAuthFailureDisposition>,
        _auth_deadline: Option<Instant>,
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

    pub(crate) fn from_dispatch_ready_state(
        state: DispatchReadyState,
        upstream_pool: Arc<RwLock<UpstreamPool>>,
        routing_transparency_enabled: bool,
        routing_transparency_include_reason: bool,
        retry_count: u8,
        error_kind: Option<&'static str>,
    ) -> Self {
        let DispatchReadyState {
            context,
            routing,
            request_mode,
            request_body: _,
            request_body_runtime: _,
            pending_forward: _,
        } = &state;

        Self {
            request_id: context.request_id,
            trace_id: context.trace_id.clone(),
            span_id: context.span_id.clone(),
            traceparent: context.traceparent.clone(),
            trace_span: context.trace_span.clone(),
            method: context.method.clone(),
            path: context.path.clone(),
            authority: context.authority.clone(),
            backend_addr: Some(routing.backend_addr.clone()),
            backend_index: Some(routing.backend_index),
            upstream_name: Some(routing.upstream_name.clone()),
            route_reason: Some(routing.route_reason.clone()),
            route_path_len: Some(routing.route_path_len),
            route_host_specific: Some(routing.route_host_specific),
            backend_lb: routing.backend_lb.clone(),
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
            execution: RequestExecutionState::DispatchReady(state),
        }
    }

    pub(crate) fn from_awaiting_auth_state(
        state: AwaitingAuthState,
        upstream_pool: Arc<RwLock<UpstreamPool>>,
        routing_transparency_enabled: bool,
        routing_transparency_include_reason: bool,
        retry_count: u8,
        error_kind: Option<&'static str>,
    ) -> Self {
        let AwaitingAuthState {
            context,
            routing,
            request_mode,
            request_body: _,
            request_body_runtime: _,
            pending_forward: _,
            auth_result_rx: _,
            auth_abort: _,
            auth_deadline: _,
            auth_disposition: _,
        } = &state;

        Self {
            request_id: context.request_id,
            trace_id: context.trace_id.clone(),
            span_id: context.span_id.clone(),
            traceparent: context.traceparent.clone(),
            trace_span: context.trace_span.clone(),
            method: context.method.clone(),
            path: context.path.clone(),
            authority: context.authority.clone(),
            backend_addr: Some(routing.backend_addr.clone()),
            backend_index: Some(routing.backend_index),
            upstream_name: Some(routing.upstream_name.clone()),
            route_reason: Some(routing.route_reason.clone()),
            route_path_len: Some(routing.route_path_len),
            route_host_specific: Some(routing.route_host_specific),
            backend_lb: routing.backend_lb.clone(),
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
            execution: RequestExecutionState::AwaitingAuth(state),
        }
    }

    pub fn phase(&self) -> StreamPhase {
        self.execution.phase()
    }

    pub fn admission_state(&self) -> StreamAdmissionState {
        self.execution.admission_state()
    }

    pub fn request_fin_received(&self) -> bool {
        self.request_body_runtime().request_fin_received
    }

    pub fn set_request_fin_received(&mut self, value: bool) {
        self.request_body_runtime_mut().request_fin_received = value;
    }

    pub fn body_tx(&self) -> Option<&mpsc::Sender<Bytes>> {
        self.request_body_runtime().body_tx.as_ref()
    }

    pub fn body_tx_mut(&mut self) -> &mut Option<mpsc::Sender<Bytes>> {
        &mut self.request_body_runtime_mut().body_tx
    }

    pub fn clear_body_tx(&mut self) {
        self.request_body_runtime_mut().body_tx = None;
    }

    pub fn body_buf(&self) -> &VecDeque<Bytes> {
        &self.request_body_runtime().body_buf
    }

    pub fn body_buf_mut(&mut self) -> &mut VecDeque<Bytes> {
        &mut self.request_body_runtime_mut().body_buf
    }

    pub fn body_buf_bytes(&self) -> usize {
        self.request_body_runtime().body_buf_bytes
    }

    pub fn set_body_buf_bytes(&mut self, value: usize) {
        self.request_body_runtime_mut().body_buf_bytes = value;
    }

    pub fn body_bytes_received(&self) -> usize {
        self.request_body_runtime().body_bytes_received
    }

    pub fn set_body_bytes_received(&mut self, value: usize) {
        self.request_body_runtime_mut().body_bytes_received = value;
    }

    pub fn last_body_activity(&self) -> Instant {
        self.request_body_runtime().last_body_activity
    }

    pub fn set_last_body_activity(&mut self, value: Instant) {
        self.request_body_runtime_mut().last_body_activity = value;
    }

    pub fn pending_forward(&self) -> Option<&Arc<PendingForward>> {
        match &self.execution {
            RequestExecutionState::AwaitingAuth(state) => Some(&state.pending_forward),
            RequestExecutionState::DispatchReady(state) => Some(&state.pending_forward),
            RequestExecutionState::AwaitingUpstream(state) => Some(&state.pending_forward),
            RequestExecutionState::Legacy(state) => state.pending_forward.as_ref(),
            RequestExecutionState::Intake(_)
            | RequestExecutionState::StreamingResponse(_)
            | RequestExecutionState::Terminal(_) => None,
        }
    }

    pub fn pending_forward_mut(&mut self) -> Option<&mut Arc<PendingForward>> {
        match &mut self.execution {
            RequestExecutionState::AwaitingAuth(state) => Some(&mut state.pending_forward),
            RequestExecutionState::DispatchReady(state) => Some(&mut state.pending_forward),
            RequestExecutionState::AwaitingUpstream(state) => Some(&mut state.pending_forward),
            RequestExecutionState::Legacy(state) => state.pending_forward.as_mut(),
            RequestExecutionState::Intake(_)
            | RequestExecutionState::StreamingResponse(_)
            | RequestExecutionState::Terminal(_) => None,
        }
    }

    pub fn clear_pending_forward(&mut self) {
        match &mut self.execution {
            RequestExecutionState::AwaitingAuth(_)
            | RequestExecutionState::DispatchReady(_)
            | RequestExecutionState::AwaitingUpstream(_)
            | RequestExecutionState::Legacy(_) => {
                self.set_pending_forward(None);
            }
            RequestExecutionState::Intake(_)
            | RequestExecutionState::StreamingResponse(_)
            | RequestExecutionState::Terminal(_) => {}
        }
    }

    pub(crate) fn poll_awaiting_auth_non_blocking(
        &mut self,
        now: Instant,
    ) -> Option<ExternalAuthResult> {
        match &mut self.execution {
            RequestExecutionState::AwaitingAuth(state) => state.poll_non_blocking(now),
            _ => None,
        }
    }

    pub(crate) fn upstream_result_rx_mut(
        &mut self,
    ) -> Option<&mut oneshot::Receiver<UpstreamResult>> {
        match &mut self.execution {
            RequestExecutionState::Legacy(state) => state.upstream_result_rx.as_mut(),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn set_upstream_result_rx(&mut self, rx: Option<oneshot::Receiver<UpstreamResult>>) {
        self.legacy_mut().upstream_result_rx = rx;
    }

    pub fn clear_upstream_result_rx(&mut self) {
        if let RequestExecutionState::Legacy(state) = &mut self.execution {
            state.upstream_result_rx = None;
        }
    }

    pub(crate) fn response_chunk_rx_mut(&mut self) -> Option<&mut mpsc::Receiver<ResponseChunk>> {
        match &mut self.execution {
            RequestExecutionState::Legacy(state) => state.response_chunk_rx.as_mut(),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn set_response_chunk_rx(&mut self, rx: Option<mpsc::Receiver<ResponseChunk>>) {
        self.legacy_mut().response_chunk_rx = rx;
    }

    pub fn clear_response_chunk_rx(&mut self) {
        if let RequestExecutionState::Legacy(state) = &mut self.execution {
            state.response_chunk_rx = None;
        }
    }

    pub fn has_upstream_result_rx(&self) -> bool {
        match &self.execution {
            RequestExecutionState::Legacy(state) => state.upstream_result_rx.is_some(),
            _ => false,
        }
    }

    pub fn has_response_chunk_rx(&self) -> bool {
        match &self.execution {
            RequestExecutionState::Legacy(state) => state.response_chunk_rx.is_some(),
            _ => false,
        }
    }

    pub fn response_headers_sent(&self) -> bool {
        match &self.execution {
            RequestExecutionState::Legacy(state) => state.response_headers_sent,
            _ => false,
        }
    }

    pub fn set_response_headers_sent(&mut self, sent: bool) {
        if let RequestExecutionState::Legacy(state) = &mut self.execution {
            state.response_headers_sent = sent;
        }
    }

    pub(crate) fn take_pending_chunk(&mut self) -> Option<ResponseChunk> {
        match &mut self.execution {
            RequestExecutionState::Legacy(state) => state.pending_chunk.take(),
            RequestExecutionState::StreamingResponse(state) => state.pending_chunk.take(),
            _ => None,
        }
    }

    pub(crate) fn set_pending_chunk(&mut self, chunk: Option<ResponseChunk>) {
        match &mut self.execution {
            RequestExecutionState::Legacy(state) => state.pending_chunk = chunk,
            RequestExecutionState::StreamingResponse(state) => state.pending_chunk = chunk,
            _ => {}
        }
    }

    pub fn has_pending_chunk(&self) -> bool {
        match &self.execution {
            RequestExecutionState::Legacy(state) => state.pending_chunk.is_some(),
            RequestExecutionState::StreamingResponse(state) => state.pending_chunk.is_some(),
            _ => false,
        }
    }

    pub fn backend_request_started(&self) -> bool {
        match &self.execution {
            RequestExecutionState::Legacy(state) => state.backend_request_started,
            RequestExecutionState::AwaitingUpstream(_)
            | RequestExecutionState::StreamingResponse(_) => true,
            _ => false,
        }
    }

    pub fn backend_request_finished(&self) -> bool {
        match &self.execution {
            RequestExecutionState::Legacy(state) => state.backend_request_finished,
            RequestExecutionState::AwaitingUpstream(state) => state.backend_accounting.finalized,
            RequestExecutionState::StreamingResponse(state) => state.backend_accounting.finalized,
            _ => false,
        }
    }

    pub fn set_backend_request_state(&mut self, started: bool, finished: bool) {
        match &mut self.execution {
            RequestExecutionState::Legacy(state) => {
                state.backend_request_started = started;
                state.backend_request_finished = finished;
            }
            RequestExecutionState::AwaitingUpstream(state) => {
                state.backend_accounting.finalized = started && finished;
            }
            RequestExecutionState::StreamingResponse(state) => {
                state.backend_accounting.finalized = started && finished;
            }
            _ => {}
        }
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
        if let RequestExecutionState::Legacy(state) = &mut self.execution {
            state.global_inflight_permit = None;
            state.upstream_inflight_permit = None;
            state.adaptive_admission_permit = None;
            state.route_queue_permit = None;
        }
    }

    pub fn has_global_inflight_permit(&self) -> bool {
        match &self.execution {
            RequestExecutionState::Legacy(state) => state.global_inflight_permit.is_some(),
            RequestExecutionState::AwaitingUpstream(_)
            | RequestExecutionState::StreamingResponse(_) => true,
            _ => false,
        }
    }

    pub fn has_upstream_inflight_permit(&self) -> bool {
        match &self.execution {
            RequestExecutionState::Legacy(state) => state.upstream_inflight_permit.is_some(),
            RequestExecutionState::AwaitingUpstream(_)
            | RequestExecutionState::StreamingResponse(_) => true,
            _ => false,
        }
    }

    pub fn has_adaptive_admission_permit(&self) -> bool {
        match &self.execution {
            RequestExecutionState::Legacy(state) => state.adaptive_admission_permit.is_some(),
            RequestExecutionState::AwaitingUpstream(_)
            | RequestExecutionState::StreamingResponse(_) => true,
            _ => false,
        }
    }

    pub fn has_route_queue_permit(&self) -> bool {
        match &self.execution {
            RequestExecutionState::Legacy(state) => state.route_queue_permit.is_some(),
            RequestExecutionState::AwaitingUpstream(_)
            | RequestExecutionState::StreamingResponse(_) => true,
            _ => false,
        }
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
        match &mut self.execution {
            RequestExecutionState::Legacy(legacy) => {
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
                if should_await_upstream {
                    legacy.request_body_runtime.body_tx = None;
                }
            }
            RequestExecutionState::DispatchReady(state) => {
                let mut request_body_runtime = std::mem::replace(
                    &mut state.request_body_runtime,
                    RequestBodyRuntime {
                        body_tx: None,
                        body_buf: VecDeque::new(),
                        body_buf_bytes: 0,
                        body_bytes_received: 0,
                        last_body_activity: self.start,
                        request_fin_received: true,
                    },
                );
                request_body_runtime.body_tx = body_tx;
                if should_await_upstream {
                    request_body_runtime.body_tx = None;
                }
                let pending_forward = Some(Arc::clone(&state.pending_forward));
                self.execution = RequestExecutionState::Legacy(LegacyRequestLifecycle {
                    phase: if should_await_upstream {
                        StreamPhase::AwaitingUpstream
                    } else {
                        StreamPhase::ReceivingRequest
                    },
                    admission_state: StreamAdmissionState::ReadyToForward,
                    request_body_runtime,
                    pending_forward,
                    backend_request_started: true,
                    backend_request_finished: false,
                    global_inflight_permit: Some(global),
                    upstream_inflight_permit: Some(upstream),
                    adaptive_admission_permit: Some(adaptive),
                    route_queue_permit: Some(route_queue),
                    upstream_result_rx: Some(upstream_result_rx),
                    response_chunk_rx: None,
                    response_headers_sent: false,
                    pending_chunk: None,
                });
            }
            other => panic!(
                "dispatch transition attempted from unsupported state {:?}",
                std::mem::discriminant(other)
            ),
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
        match &mut self.execution {
            RequestExecutionState::AwaitingAuth(state) => {
                if let Some(pending_forward) = pending_forward {
                    state.pending_forward = pending_forward;
                }
            }
            RequestExecutionState::DispatchReady(state) => {
                if let Some(pending_forward) = pending_forward {
                    state.pending_forward = pending_forward;
                }
            }
            RequestExecutionState::AwaitingUpstream(state) => {
                if let Some(pending_forward) = pending_forward {
                    state.pending_forward = pending_forward;
                }
            }
            RequestExecutionState::Legacy(state) => {
                state.pending_forward = pending_forward;
            }
            RequestExecutionState::Intake(_)
            | RequestExecutionState::StreamingResponse(_)
            | RequestExecutionState::Terminal(_) => {}
        }
    }

    pub(crate) fn transition_awaiting_auth_to_dispatch_ready<I>(&mut self, mutations: I)
    where
        I: IntoIterator<Item = PendingHeaderMutation>,
    {
        let state = match self.take_awaiting_auth_state() {
            Some(state) => {
                let mut state = state;
                crate::runtime::connection::auth::merge_auth_request_mutations(
                    &mut Arc::make_mut(&mut state.pending_forward).auth_header_mutations,
                    mutations,
                );
                state
            }
            None => panic!("awaiting-auth transition attempted outside AwaitingAuth state"),
        };
        self.execution = RequestExecutionState::DispatchReady(DispatchReadyState {
            context: state.context,
            routing: state.routing,
            request_mode: state.request_mode,
            request_body: state.request_body,
            request_body_runtime: state.request_body_runtime,
            pending_forward: state.pending_forward,
        });
    }

    pub(crate) fn take_awaiting_auth_state(&mut self) -> Option<AwaitingAuthState> {
        let placeholder =
            RequestExecutionState::Terminal(TerminalState::Cancelled(CancelledState {
                reason: CancellationReason::OperatorAbort,
                snapshot: self.terminal_snapshot(),
            }));
        match std::mem::replace(&mut self.execution, placeholder) {
            RequestExecutionState::AwaitingAuth(state) => {
                state.auth_abort.abort();
                Some(state)
            }
            other => {
                self.execution = other;
                None
            }
        }
    }

    pub(crate) fn discard_awaiting_auth_resources(&mut self) {
        let Some(state) = self.take_awaiting_auth_state() else {
            return;
        };
        self.execution = RequestExecutionState::DispatchReady(DispatchReadyState {
            context: state.context,
            routing: state.routing,
            request_mode: state.request_mode,
            request_body: state.request_body,
            request_body_runtime: state.request_body_runtime,
            pending_forward: state.pending_forward,
        });
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

    fn request_body_runtime(&self) -> &RequestBodyRuntime {
        match &self.execution {
            RequestExecutionState::AwaitingAuth(state) => &state.request_body_runtime,
            RequestExecutionState::DispatchReady(state) => &state.request_body_runtime,
            RequestExecutionState::AwaitingUpstream(state) => &state.request_body_runtime,
            RequestExecutionState::StreamingResponse(state) => &state.request_body_runtime,
            RequestExecutionState::Legacy(state) => &state.request_body_runtime,
            RequestExecutionState::Intake(_) | RequestExecutionState::Terminal(_) => {
                panic!("request body runtime unavailable in current execution state")
            }
        }
    }

    fn request_body_runtime_mut(&mut self) -> &mut RequestBodyRuntime {
        match &mut self.execution {
            RequestExecutionState::AwaitingAuth(state) => &mut state.request_body_runtime,
            RequestExecutionState::DispatchReady(state) => &mut state.request_body_runtime,
            RequestExecutionState::AwaitingUpstream(state) => &mut state.request_body_runtime,
            RequestExecutionState::StreamingResponse(state) => &mut state.request_body_runtime,
            RequestExecutionState::Legacy(state) => &mut state.request_body_runtime,
            RequestExecutionState::Intake(_) | RequestExecutionState::Terminal(_) => {
                panic!("request body runtime mutation unavailable in current execution state")
            }
        }
    }

    fn terminal_snapshot(&self) -> TerminalSnapshot {
        let routing = match &self.execution {
            RequestExecutionState::AwaitingAuth(state) => Some(state.routing.clone()),
            RequestExecutionState::DispatchReady(state) => Some(state.routing.clone()),
            RequestExecutionState::AwaitingUpstream(state) => Some(state.routing.clone()),
            RequestExecutionState::StreamingResponse(state) => Some(state.routing.clone()),
            RequestExecutionState::Legacy(_) | RequestExecutionState::Intake(_) => None,
            RequestExecutionState::Terminal(state) => match state {
                TerminalState::Completed(state) => state.snapshot.routing.clone(),
                TerminalState::Cancelled(state) => state.snapshot.routing.clone(),
                TerminalState::TimedOut(state) => state.snapshot.routing.clone(),
                TerminalState::Rejected(state) => state.snapshot.routing.clone(),
                TerminalState::BackendFailed(state) => state.snapshot.routing.clone(),
            },
        };

        TerminalSnapshot {
            context: RequestContext {
                request_id: self.request_id,
                trace_id: self.trace_id.clone(),
                span_id: self.span_id.clone(),
                traceparent: self.traceparent.clone(),
                trace_span: self.trace_span.clone(),
                method: self.method.clone(),
                path: self.path.clone(),
                authority: self.authority.clone(),
                start: self.start,
                total_request_deadline: self.total_request_deadline,
            },
            routing,
            request_mode: RequestMode::from_intake(self.tunnel_mode, &self.method, None),
            response_status: self
                .response_status
                .and_then(|status| http::StatusCode::from_u16(status).ok()),
            backend_accounting: None,
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
