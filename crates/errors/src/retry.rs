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
pub enum RetryPolicyDenialReason {
    TerminalError(UpstreamTerminalErrorKind),
    MethodNotIdempotent,
    RequestBodyNotReplayable,
    AttemptLimitReached,
    BudgetDenied,
    NoAlternateBackend,
    AlternateBackendUnhealthy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicyFacts {
    pub retryability: UpstreamRetryability,
    pub method_idempotent: bool,
    pub request_body_replayable: bool,
    pub attempt_count: u8,
    pub max_attempts: u8,
    pub budget_available: bool,
    pub alternate_backend_available: bool,
    pub alternate_backend_healthy: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryPolicyDecision {
    Retry { reason: UpstreamRetryReason },
    DoNotRetry {
        denial: Option<RetryPolicyDenialReason>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryTelemetryReason {
    Timeout,
    Transport,
    Pool,
}

impl From<UpstreamRetryReason> for RetryTelemetryReason {
    fn from(value: UpstreamRetryReason) -> Self {
        match value {
            UpstreamRetryReason::Timeout => Self::Timeout,
            UpstreamRetryReason::Transport => Self::Transport,
            UpstreamRetryReason::Pool => Self::Pool,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HedgePolicyFacts {
    pub hedging_configured: bool,
    pub method_allowed: bool,
    pub request_body_replayable: bool,
    pub tunnel_request: bool,
    pub alternate_backend_available: bool,
    pub alternate_backend_healthy: bool,
    pub budget_available: bool,
    pub primary_state: HedgePrimaryState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgePrimaryState {
    InFlightBeforeDelay,
    InFlightAfterDelay,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgePolicyDenialReason {
    HedgingDisabled,
    PrimaryRequestCompleted,
    DelayNotElapsed,
    RequestBodyNotReplayable,
    TunnelRequest,
    MethodNotAllowed,
    NoAlternateBackend,
    AlternateBackendUnhealthy,
    BudgetDenied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgePolicyDecision {
    WaitForPrimary,
    Hedge { reason: HedgeTelemetryReason },
    DoNotHedge { denial: HedgePolicyDenialReason },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgeTelemetryReason {
    DelayElapsed,
    PrimaryWonAfterTrigger,
    HedgeWon,
    HedgeWasted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlternateBackendChoice<Backend> {
    pub backend: Backend,
    pub index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlternateBackendPolicyFacts {
    pub candidate_available: bool,
    pub excluded_primary_backend: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlternateBackendDenialReason {
    NoCandidateAvailable,
    PrimaryBackendNotExcluded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AlternateBackendDecision<Backend> {
    Select(AlternateBackendChoice<Backend>),
    DoNotSelect { denial: AlternateBackendDenialReason },
}

pub type RetryPolicyInput = RetryPolicyFacts;
pub type RetryPolicyDenial = RetryPolicyDenialReason;

pub fn is_idempotent_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "TRACE"
    )
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

pub fn evaluate_retry_policy(input: RetryPolicyFacts) -> RetryPolicyDecision {
    match input.retryability {
        UpstreamRetryability::Terminal(kind) => RetryPolicyDecision::DoNotRetry {
            denial: Some(RetryPolicyDenialReason::TerminalError(kind)),
        },
        UpstreamRetryability::Retryable(reason) => {
            if !input.method_idempotent {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::MethodNotIdempotent),
                }
            } else if !input.request_body_replayable {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::RequestBodyNotReplayable),
                }
            } else if input.attempt_count >= input.max_attempts {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::AttemptLimitReached),
                }
            } else if !input.budget_available {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::BudgetDenied),
                }
            } else if !input.alternate_backend_available {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::NoAlternateBackend),
                }
            } else if !input.alternate_backend_healthy {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::AlternateBackendUnhealthy),
                }
            } else {
                RetryPolicyDecision::Retry { reason }
            }
        }
    }
}

pub fn evaluate_hedge_policy(input: HedgePolicyFacts) -> HedgePolicyDecision {
    if !input.hedging_configured {
        return HedgePolicyDecision::DoNotHedge {
            denial: HedgePolicyDenialReason::HedgingDisabled,
        };
    }

    if !input.method_allowed {
        return HedgePolicyDecision::DoNotHedge {
            denial: HedgePolicyDenialReason::MethodNotAllowed,
        };
    }

    if !input.request_body_replayable {
        return HedgePolicyDecision::DoNotHedge {
            denial: HedgePolicyDenialReason::RequestBodyNotReplayable,
        };
    }

    if input.tunnel_request {
        return HedgePolicyDecision::DoNotHedge {
            denial: HedgePolicyDenialReason::TunnelRequest,
        };
    }

    if !input.alternate_backend_available {
        return HedgePolicyDecision::DoNotHedge {
            denial: HedgePolicyDenialReason::NoAlternateBackend,
        };
    }

    if !input.alternate_backend_healthy {
        return HedgePolicyDecision::DoNotHedge {
            denial: HedgePolicyDenialReason::AlternateBackendUnhealthy,
        };
    }

    match input.primary_state {
        HedgePrimaryState::Completed => HedgePolicyDecision::DoNotHedge {
            denial: HedgePolicyDenialReason::PrimaryRequestCompleted,
        },
        HedgePrimaryState::InFlightBeforeDelay => HedgePolicyDecision::WaitForPrimary,
        HedgePrimaryState::InFlightAfterDelay => {
            if !input.budget_available {
                HedgePolicyDecision::DoNotHedge {
                    denial: HedgePolicyDenialReason::BudgetDenied,
                }
            } else {
                HedgePolicyDecision::Hedge {
                    reason: HedgeTelemetryReason::DelayElapsed,
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn retry_facts() -> RetryPolicyFacts {
        RetryPolicyFacts {
            retryability: UpstreamRetryability::Retryable(UpstreamRetryReason::Timeout),
            method_idempotent: true,
            request_body_replayable: true,
            attempt_count: 0,
            max_attempts: 1,
            budget_available: true,
            alternate_backend_available: true,
            alternate_backend_healthy: true,
        }
    }

    #[test]
    fn idempotent_method_helper_matches_expected_methods() {
        assert!(is_idempotent_method("GET"));
        assert!(is_idempotent_method("delete"));
        assert!(!is_idempotent_method("POST"));
        assert!(!is_idempotent_method("PATCH"));
    }

    #[test]
    fn terminal_errors_return_explicit_denial() {
        let mut facts = retry_facts();
        facts.retryability = UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Tls);

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::TerminalError(
                    UpstreamTerminalErrorKind::Tls
                )),
            }
        );
    }

    #[test]
    fn method_idempotency_blocks_retry() {
        let mut facts = retry_facts();
        facts.method_idempotent = false;

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::MethodNotIdempotent),
            }
        );
    }

    #[test]
    fn request_body_replayability_blocks_retry() {
        let mut facts = retry_facts();
        facts.request_body_replayable = false;

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::RequestBodyNotReplayable),
            }
        );
    }

    #[test]
    fn attempt_limit_blocks_retry() {
        let mut facts = retry_facts();
        facts.attempt_count = 1;

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::AttemptLimitReached),
            }
        );
    }

    #[test]
    fn unhealthy_alternate_backend_blocks_retry() {
        let mut facts = retry_facts();
        facts.alternate_backend_healthy = false;

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::AlternateBackendUnhealthy),
            }
        );
    }

    #[test]
    fn retryable_timeout_allows_retry() {
        assert_eq!(
            evaluate_retry_policy(retry_facts()),
            RetryPolicyDecision::Retry {
                reason: UpstreamRetryReason::Timeout,
            }
        );
    }

    fn hedge_facts() -> HedgePolicyFacts {
        HedgePolicyFacts {
            hedging_configured: true,
            method_allowed: true,
            request_body_replayable: true,
            tunnel_request: false,
            alternate_backend_available: true,
            alternate_backend_healthy: true,
            budget_available: true,
            primary_state: HedgePrimaryState::InFlightAfterDelay,
        }
    }

    #[test]
    fn hedge_policy_waits_for_primary_before_delay() {
        let mut facts = hedge_facts();
        facts.primary_state = HedgePrimaryState::InFlightBeforeDelay;

        assert_eq!(evaluate_hedge_policy(facts), HedgePolicyDecision::WaitForPrimary);
    }

    #[test]
    fn hedge_policy_triggers_after_delay_when_eligible() {
        assert_eq!(
            evaluate_hedge_policy(hedge_facts()),
            HedgePolicyDecision::Hedge {
                reason: HedgeTelemetryReason::DelayElapsed,
            }
        );
    }

    #[test]
    fn hedge_policy_rejects_non_replayable_requests() {
        let mut facts = hedge_facts();
        facts.request_body_replayable = false;

        assert_eq!(
            evaluate_hedge_policy(facts),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::RequestBodyNotReplayable,
            }
        );
    }

    #[test]
    fn hedge_policy_rejects_completed_primary() {
        let mut facts = hedge_facts();
        facts.primary_state = HedgePrimaryState::Completed;

        assert_eq!(
            evaluate_hedge_policy(facts),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::PrimaryRequestCompleted,
            }
        );
    }

    #[test]
    fn hedge_policy_rejects_when_budget_denied_after_delay() {
        let mut facts = hedge_facts();
        facts.budget_available = false;

        assert_eq!(
            evaluate_hedge_policy(facts),
            HedgePolicyDecision::DoNotHedge {
                denial: HedgePolicyDenialReason::BudgetDenied,
            }
        );
    }
}
