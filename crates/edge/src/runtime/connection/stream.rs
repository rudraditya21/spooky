use std::{sync::Arc, time::Instant};

use http::StatusCode;
use tokio::{
    sync::{OwnedSemaphorePermit, mpsc, oneshot},
    task::AbortHandle,
};

use crate::{
    resilience::{adaptive_admission::AdaptivePermit, route_queue::RouteQueuePermit},
    runtime::connection::{
        auth::{ExternalAuthFailureDisposition, ExternalAuthResult},
        request::PendingForward,
        response::{ResponseChunk, UpstreamResult},
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamPhase {
    /// Still receiving request headers/body from the QUIC client.
    ReceivingRequest,
    /// Request fully received; waiting for the upstream response.
    AwaitingUpstream,
    /// Upstream responded; streaming response back to the QUIC client.
    SendingResponse,
    /// Stream finished cleanly.
    Completed,
    /// Stream terminated with an error.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamAdmissionState {
    /// Request admission is still pending an external auth/authz decision.
    WaitingForAuth,
    /// Request cleared admission checks and may proceed to upstream forwarding.
    ReadyToForward,
    /// Request was denied by admission/auth checks and should not be forwarded.
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelMode {
    None,
    Connect,
    Websocket,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestMode {
    Normal,
    HeadLike,
    ConnectTunnel,
    WebsocketTunnel,
}

#[allow(dead_code)]
impl RequestMode {
    pub fn is_tunnel(self) -> bool {
        matches!(self, Self::ConnectTunnel | Self::WebsocketTunnel)
    }

    pub fn suppresses_response_body(self) -> bool {
        matches!(self, Self::HeadLike)
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBodyState {
    Open,
    Buffered,
    FinReceived,
    ClosedToUpstream,
}

#[allow(dead_code)]
impl RequestBodyState {
    pub fn can_accept_downstream_body(self) -> bool {
        matches!(self, Self::Open | Self::Buffered)
    }

    pub fn forwarding_complete(self) -> bool {
        matches!(self, Self::ClosedToUpstream)
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseEmissionState {
    DeferredHeaders,
    HeadersSent,
    StreamingBody,
    TrailersPending,
    EndPending,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionReason {
    ResponseStreamFinished,
    ImmediateResponse,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationReason {
    ClientReset,
    ConnectionClosed,
    OperatorAbort,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutReason {
    RequestBodyIdle,
    RequestBodyTotal,
    ExternalAuth,
    TotalRequest,
    AwaitingUpstream,
    ResponseBodyIdle,
    ResponseBodyTotal,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    AuthDenied,
    AuthUnavailable,
    ValidationFailed,
    RateLimited,
    Overloaded,
    RequestBodyNotAllowed,
    RequestBodyTooLarge,
    ResponsePrebufferCap,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendFailureReason {
    DispatchSpawnFailed,
    UpstreamResultChannelDropped,
    UpstreamTimeout,
    UpstreamTransport,
    UpstreamProtocol,
    UpstreamTls,
    UpstreamBridge,
    ResponseWriteFailed,
    ResponseStreamAborted,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: u64,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub traceparent: Option<String>,
    pub method: String,
    pub path: String,
    pub authority: Option<String>,
    pub start: Instant,
    pub total_request_deadline: Instant,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RoutingSnapshot {
    pub backend_addr: String,
    pub backend_index: usize,
    pub upstream_name: String,
    pub route_reason: String,
    pub route_path_len: usize,
    pub route_host_specific: bool,
    pub backend_lb: Option<String>,
}

#[allow(dead_code)]
pub struct RequestIntakeState {
    pub context: RequestContext,
    pub request_mode: RequestMode,
    pub request_body: RequestBodyState,
}

#[allow(dead_code)]
pub struct AuthWaitState {
    pub context: RequestContext,
    pub routing: RoutingSnapshot,
    pub request_mode: RequestMode,
    pub request_body: RequestBodyState,
    pub pending_forward: Arc<PendingForward>,
    pub auth_result_rx: oneshot::Receiver<ExternalAuthResult>,
    pub auth_abort: AbortHandle,
    pub auth_deadline: Instant,
    pub auth_disposition: ExternalAuthFailureDisposition,
}

#[allow(dead_code)]
pub struct DispatchReadyState {
    pub context: RequestContext,
    pub routing: RoutingSnapshot,
    pub request_mode: RequestMode,
    pub request_body: RequestBodyState,
    pub pending_forward: Arc<PendingForward>,
}

#[allow(dead_code)]
pub struct AdmissionPermits {
    pub global: OwnedSemaphorePermit,
    pub upstream: OwnedSemaphorePermit,
    pub adaptive: AdaptivePermit,
    pub route_queue: RouteQueuePermit,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendAccountingState {
    pub response_status: Option<StatusCode>,
    pub finalized: bool,
}

#[allow(dead_code)]
impl BackendAccountingState {
    pub fn should_finalize(self) -> bool {
        !self.finalized
    }
}

#[allow(dead_code)]
pub struct AwaitingUpstreamState {
    pub context: RequestContext,
    pub routing: RoutingSnapshot,
    pub request_mode: RequestMode,
    pub request_body: RequestBodyState,
    pub pending_forward: Arc<PendingForward>,
    pub permits: AdmissionPermits,
    pub upstream_result_rx: oneshot::Receiver<UpstreamResult>,
    pub backend_accounting: BackendAccountingState,
}

#[allow(dead_code)]
pub struct ResponseStreamingState {
    pub context: RequestContext,
    pub routing: RoutingSnapshot,
    pub request_mode: RequestMode,
    pub response_status: StatusCode,
    pub emission: ResponseEmissionState,
    pub response_chunk_rx: mpsc::Receiver<ResponseChunk>,
    pub pending_chunk: Option<ResponseChunk>,
    pub backend_accounting: BackendAccountingState,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TerminalSnapshot {
    pub context: RequestContext,
    pub routing: Option<RoutingSnapshot>,
    pub request_mode: RequestMode,
    pub response_status: Option<StatusCode>,
    pub backend_accounting: Option<BackendAccountingState>,
}

#[allow(dead_code)]
pub struct CompletedState {
    pub reason: CompletionReason,
    pub snapshot: TerminalSnapshot,
}

#[allow(dead_code)]
pub struct CancelledState {
    pub reason: CancellationReason,
    pub snapshot: TerminalSnapshot,
}

#[allow(dead_code)]
pub struct TimedOutState {
    pub reason: TimeoutReason,
    pub snapshot: TerminalSnapshot,
}

#[allow(dead_code)]
pub struct RejectedState {
    pub reason: RejectionReason,
    pub snapshot: TerminalSnapshot,
}

#[allow(dead_code)]
pub struct BackendFailedState {
    pub reason: BackendFailureReason,
    pub snapshot: TerminalSnapshot,
}

#[allow(dead_code)]
pub enum TerminalState {
    Completed(CompletedState),
    Cancelled(CancelledState),
    TimedOut(TimedOutState),
    Rejected(RejectedState),
    BackendFailed(BackendFailedState),
}

#[allow(dead_code)]
impl TerminalState {
    pub fn terminal_status(&self) -> Option<StatusCode> {
        match self {
            Self::Completed(state) => state.snapshot.response_status,
            Self::Cancelled(state) => state.snapshot.response_status,
            Self::TimedOut(state) => state.snapshot.response_status,
            Self::Rejected(state) => state.snapshot.response_status,
            Self::BackendFailed(state) => state.snapshot.response_status,
        }
    }

    pub fn should_finalize_backend_accounting(&self) -> bool {
        match self {
            Self::Completed(state) => state
                .snapshot
                .backend_accounting
                .is_some_and(BackendAccountingState::should_finalize),
            Self::Cancelled(state) => state
                .snapshot
                .backend_accounting
                .is_some_and(BackendAccountingState::should_finalize),
            Self::TimedOut(state) => state
                .snapshot
                .backend_accounting
                .is_some_and(BackendAccountingState::should_finalize),
            Self::Rejected(state) => state
                .snapshot
                .backend_accounting
                .is_some_and(BackendAccountingState::should_finalize),
            Self::BackendFailed(state) => state
                .snapshot
                .backend_accounting
                .is_some_and(BackendAccountingState::should_finalize),
        }
    }
}

#[allow(dead_code)]
pub enum RequestExecutionState {
    Intake(RequestIntakeState),
    AwaitingAuth(AuthWaitState),
    DispatchReady(DispatchReadyState),
    AwaitingUpstream(AwaitingUpstreamState),
    StreamingResponse(ResponseStreamingState),
    Terminal(TerminalState),
}

#[allow(dead_code)]
impl RequestExecutionState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminal(_))
    }

    pub fn terminal_status(&self) -> Option<StatusCode> {
        match self {
            Self::Terminal(state) => state.terminal_status(),
            _ => None,
        }
    }

    pub fn should_finalize_backend_accounting(&self) -> bool {
        match self {
            Self::AwaitingUpstream(state) => state.backend_accounting.should_finalize(),
            Self::StreamingResponse(state) => state.backend_accounting.should_finalize(),
            Self::Terminal(state) => state.should_finalize_backend_accounting(),
            Self::Intake(_) | Self::AwaitingAuth(_) | Self::DispatchReady(_) => false,
        }
    }

    pub fn can_accept_request_body(&self) -> bool {
        match self {
            Self::Intake(state) => state.request_body.can_accept_downstream_body(),
            Self::AwaitingAuth(state) => state.request_body.can_accept_downstream_body(),
            Self::DispatchReady(state) => state.request_body.can_accept_downstream_body(),
            Self::AwaitingUpstream(state) => {
                state.request_mode.is_tunnel() && state.request_body.can_accept_downstream_body()
            }
            Self::StreamingResponse(_) | Self::Terminal(_) => false,
        }
    }

    pub fn can_poll_upstream(&self) -> bool {
        match self {
            Self::AwaitingUpstream(state) => {
                state.request_mode.is_tunnel() || state.request_body.forwarding_complete()
            }
            _ => false,
        }
    }

    pub fn can_emit_response(&self) -> bool {
        matches!(self, Self::StreamingResponse(_))
    }
}
