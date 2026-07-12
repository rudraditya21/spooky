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
