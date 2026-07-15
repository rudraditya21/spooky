pub mod bridge;
pub mod pool;
pub mod proxy;
pub mod retry;
pub mod upstream;

pub use bridge::BridgeError;
pub use pool::PoolError;
pub use proxy::ProxyError;
pub use retry::{
    RetryPolicyDecision, RetryPolicyDenial, RetryPolicyInput, UpstreamRetryReason,
    UpstreamRetryability, UpstreamTerminalErrorKind, classify_retryability, evaluate_retry_policy,
    is_retryable,
};
pub use upstream::{
    UpstreamErrorCategory, UpstreamErrorClassification, UpstreamErrorDetails,
    UpstreamHealthFailureMapping, UpstreamTlsReason, format_error_chain,
};
