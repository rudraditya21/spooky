use thiserror::Error;

use crate::{BridgeError, PoolError};

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
