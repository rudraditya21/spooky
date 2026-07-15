use crate::{PoolError, ProxyError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamRetryReason {
    Timeout,
    Transport,
    Pool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamTerminalErrorKind {
    PoolSend,
    Tls,
    Protocol,
    Bridge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamRetryability {
    Retryable(UpstreamRetryReason),
    Terminal(UpstreamTerminalErrorKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryPolicyDenial {
    NotBodylessMode,
    BudgetDenied,
    NoAlternateBackend,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicyInput {
    pub retryability: UpstreamRetryability,
    pub bodyless_mode: bool,
    pub budget_available: bool,
    pub alternate_backend_available: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryPolicyDecision {
    Retry { reason: UpstreamRetryReason },
    DoNotRetry { denial: Option<RetryPolicyDenial> },
}

pub fn classify_retryability(err: &ProxyError) -> UpstreamRetryability {
    match err {
        ProxyError::Transport(_) => UpstreamRetryability::Retryable(UpstreamRetryReason::Transport),
        ProxyError::Timeout => UpstreamRetryability::Retryable(UpstreamRetryReason::Timeout),
        ProxyError::Pool(PoolError::Send(_)) => {
            UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::PoolSend)
        }
        ProxyError::Pool(_) => UpstreamRetryability::Retryable(UpstreamRetryReason::Pool),
        ProxyError::Tls(_) => UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Tls),
        ProxyError::Protocol(_) => {
            UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Protocol)
        }
        ProxyError::Bridge(_) => UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Bridge),
    }
}

pub fn evaluate_retry_policy(input: RetryPolicyInput) -> RetryPolicyDecision {
    match input.retryability {
        UpstreamRetryability::Terminal(_) => RetryPolicyDecision::DoNotRetry { denial: None },
        UpstreamRetryability::Retryable(reason) => {
            if !input.bodyless_mode {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenial::NotBodylessMode),
                }
            } else if !input.budget_available {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenial::BudgetDenied),
                }
            } else if !input.alternate_backend_available {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenial::NoAlternateBackend),
                }
            } else {
                RetryPolicyDecision::Retry { reason }
            }
        }
    }
}

pub fn is_retryable(err: &ProxyError) -> bool {
    matches!(
        classify_retryability(err),
        UpstreamRetryability::Retryable(_)
    )
}
