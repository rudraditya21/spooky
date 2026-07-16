pub mod bridge;
pub mod pool;
pub mod proxy;
pub mod retry;
pub mod upstream;

pub use bridge::BridgeError;
pub use pool::PoolError;
pub use proxy::{
    ClassifiedUpstreamProxyError, ProxyError, UpstreamProxyErrorKind,
    classify_upstream_proxy_error, classify_upstream_send_error,
};
pub use retry::{
    AlternateBackendChoice, AlternateBackendDecision, AlternateBackendDenialReason,
    AlternateBackendPolicyFacts, HedgePolicyDecision, HedgePolicyDenialReason,
    HedgePolicyFacts, HedgePrimaryState, HedgeTelemetryReason, RetryPolicyDecision, RetryPolicyDenial,
    RetryPolicyDenialReason, RetryPolicyFacts, RetryPolicyInput, RetryTelemetryReason,
    UpstreamRetryReason, UpstreamRetryability, UpstreamTerminalErrorKind,
    is_idempotent_method,
    classify_retryability, evaluate_hedge_policy, evaluate_retry_policy, is_retryable,
};
pub use upstream::{
    UpstreamErrorCategory, UpstreamErrorClassification, UpstreamHealthFailureMapping,
    UpstreamTlsReason, classify_upstream_error_detail,
};
