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
    RetryPolicyDecision, RetryPolicyDenial, RetryPolicyInput, UpstreamRetryReason,
    UpstreamRetryability, UpstreamTerminalErrorKind, classify_retryability, evaluate_retry_policy,
    is_retryable,
};
pub use upstream::{
    UpstreamErrorCategory, UpstreamErrorClassification, UpstreamHealthFailureMapping,
    UpstreamTlsReason, classify_upstream_error_detail,
};
