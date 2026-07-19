use thiserror::Error;

#[derive(Debug, Error)]
pub enum PoolError {
    #[error("unknown backend: {0}")]
    UnknownBackend(String),

    #[error("backend overloaded: {0}")]
    BackendOverloaded(String),

    #[error("backend circuit open: {0}")]
    CircuitOpen(String),

    #[error("send failed: {0}")]
    Send(#[source] hyper_util::client::legacy::Error),

    #[error("backend inflight limiter closed")]
    InflightLimiterClosed,
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http_body_util::Empty;
    use hyper::Uri;
    use hyper_util::{client::legacy::Client, rt::TokioExecutor};

    use super::PoolError;
    use crate::{
        ProxyError, UpstreamRetryReason, UpstreamRetryability, UpstreamTerminalErrorKind,
        classify_retryability,
    };

    async fn connect_send_error() -> hyper_util::client::legacy::Error {
        let client: Client<hyper_util::client::legacy::connect::HttpConnector, Empty<Bytes>> =
            Client::builder(TokioExecutor::new()).build_http();
        let uri: Uri = "http://127.0.0.1:1/".parse().expect("valid local uri");

        client
            .get(uri)
            .await
            .expect_err("connect to unused port should fail")
    }

    #[test]
    fn display_covers_named_pool_variants() {
        assert_eq!(
            PoolError::UnknownBackend("api-a".to_string()).to_string(),
            "unknown backend: api-a"
        );
        assert_eq!(
            PoolError::BackendOverloaded("api-b".to_string()).to_string(),
            "backend overloaded: api-b"
        );
        assert_eq!(
            PoolError::CircuitOpen("api-c".to_string()).to_string(),
            "backend circuit open: api-c"
        );
        assert_eq!(
            PoolError::InflightLimiterClosed.to_string(),
            "backend inflight limiter closed"
        );
    }

    #[test]
    fn retryability_classifies_non_send_pool_errors_as_pool_retryable() {
        assert_eq!(
            classify_retryability(&ProxyError::Pool(PoolError::UnknownBackend(
                "api-a".to_string(),
            ))),
            UpstreamRetryability::Retryable(UpstreamRetryReason::Pool)
        );
        assert_eq!(
            classify_retryability(&ProxyError::Pool(PoolError::BackendOverloaded(
                "api-b".to_string(),
            ))),
            UpstreamRetryability::Retryable(UpstreamRetryReason::Pool)
        );
        assert_eq!(
            classify_retryability(&ProxyError::Pool(PoolError::CircuitOpen(
                "api-c".to_string()
            ))),
            UpstreamRetryability::Retryable(UpstreamRetryReason::Pool)
        );
        assert_eq!(
            classify_retryability(&ProxyError::Pool(PoolError::InflightLimiterClosed)),
            UpstreamRetryability::Retryable(UpstreamRetryReason::Pool)
        );
    }

    #[tokio::test]
    async fn send_variant_display_and_retryability_match_contract() {
        let send_error = connect_send_error().await;
        let display = PoolError::Send(send_error).to_string();

        assert!(display.starts_with("send failed: client error"));

        let send_error = connect_send_error().await;
        assert_eq!(
            classify_retryability(&ProxyError::Pool(PoolError::Send(send_error))),
            UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::PoolSend)
        );
    }
}
