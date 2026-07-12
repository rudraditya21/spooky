use thiserror::Error;
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
