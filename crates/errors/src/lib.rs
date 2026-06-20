use thiserror::Error;

/// HTTP/3 to HTTP/2 bridge error types
#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("invalid HTTP method")]
    InvalidMethod,

    #[error("invalid URI")]
    InvalidUri,

    #[error("invalid header")]
    InvalidHeader,

    #[error("failed to build request: {0}")]
    Build(#[from] http::Error),
}

/// HTTP/2 pool and transport error types
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

/// Top-level proxy error type unifying bridge and transport errors
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("bridge error: {0}")]
    Bridge(#[from] BridgeError),

    #[error("pool error: {0}")]
    Pool(#[from] PoolError),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("backend timeout")]
    Timeout,

    #[error("TLS error: {0}")]
    Tls(String),
}

pub fn is_retryable(err: &ProxyError) -> bool {
    match err {
        ProxyError::Transport(_) | ProxyError::Timeout => true,
        // Pool send failures are connection-level (TLS/cert/SNI) — not transient
        ProxyError::Pool(PoolError::Send(_)) => false,
        ProxyError::Pool(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{PoolError, ProxyError};

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
}
