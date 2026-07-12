use crate::{PoolError, ProxyError};

pub fn is_retryable(err: &ProxyError) -> bool {
    match err {
        ProxyError::Transport(_) | ProxyError::Timeout => true,
        // Pool send failures are connection-level (TLS/cert/SNI) — not transient
        ProxyError::Pool(PoolError::Send(_)) => false,
        ProxyError::Pool(_) => true,
        _ => false,
    }
}
