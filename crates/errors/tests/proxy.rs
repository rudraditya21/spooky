use spooky_errors::{
    PoolError, ProxyError, RetryPolicyDecision, RetryPolicyDenial, RetryPolicyInput,
    UpstreamRetryReason, UpstreamRetryability, UpstreamTerminalErrorKind, classify_retryability,
    evaluate_retry_policy,
};

#[test]
fn pool_and_transport_errors_have_distinct_display_text() {
    let pool = ProxyError::Pool(PoolError::UnknownBackend("api-a".to_string()));
    let transport = ProxyError::Transport("api-a".to_string());

    assert_eq!(pool.to_string(), "pool error: unknown backend: api-a");
    assert_eq!(transport.to_string(), "transport error: api-a");
}

#[test]
fn overloaded_pool_error_keeps_pool_specific_prefix() {
    let err = ProxyError::Pool(PoolError::BackendOverloaded("api-b".to_string()));

    assert_eq!(err.to_string(), "pool error: backend overloaded: api-b");
}

#[test]
fn retryability_classification_distinguishes_retryable_and_terminal_errors() {
    assert_eq!(
        classify_retryability(&ProxyError::Timeout),
        UpstreamRetryability::Retryable(UpstreamRetryReason::Timeout)
    );
    assert_eq!(
        classify_retryability(&ProxyError::Transport("reset".to_string())),
        UpstreamRetryability::Retryable(UpstreamRetryReason::Transport)
    );
    assert_eq!(
        classify_retryability(&ProxyError::Pool(PoolError::UnknownBackend(
            "api-a".to_string()
        ))),
        UpstreamRetryability::Retryable(UpstreamRetryReason::Pool)
    );
    assert_eq!(
        classify_retryability(&ProxyError::Tls("bad cert".to_string())),
        UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Tls)
    );
}

#[test]
fn retry_policy_evaluation_preserves_existing_denial_behavior() {
    assert_eq!(
        evaluate_retry_policy(RetryPolicyInput {
            retryability: UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Protocol),
            bodyless_mode: true,
            budget_available: true,
            alternate_backend_available: true,
        }),
        RetryPolicyDecision::DoNotRetry { denial: None }
    );
    assert_eq!(
        evaluate_retry_policy(RetryPolicyInput {
            retryability: UpstreamRetryability::Retryable(UpstreamRetryReason::Transport),
            bodyless_mode: false,
            budget_available: true,
            alternate_backend_available: true,
        }),
        RetryPolicyDecision::DoNotRetry {
            denial: Some(RetryPolicyDenial::NotBodylessMode),
        }
    );
    assert_eq!(
        evaluate_retry_policy(RetryPolicyInput {
            retryability: UpstreamRetryability::Retryable(UpstreamRetryReason::Pool),
            bodyless_mode: true,
            budget_available: false,
            alternate_backend_available: true,
        }),
        RetryPolicyDecision::DoNotRetry {
            denial: Some(RetryPolicyDenial::BudgetDenied),
        }
    );
    assert_eq!(
        evaluate_retry_policy(RetryPolicyInput {
            retryability: UpstreamRetryability::Retryable(UpstreamRetryReason::Timeout),
            bodyless_mode: true,
            budget_available: true,
            alternate_backend_available: true,
        }),
        RetryPolicyDecision::Retry {
            reason: UpstreamRetryReason::Timeout,
        }
    );
}
