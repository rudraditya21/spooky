use thiserror::Error;

use crate::{
    BridgeError, PoolError, UpstreamErrorCategory, UpstreamErrorClassification,
    UpstreamErrorDetails, UpstreamHealthFailureMapping, UpstreamRetryability, UpstreamTlsReason,
    classify_retryability,
};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamProxyErrorKind {
    Send,
    Transport,
    Timeout,
    Protocol,
    Tls,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassifiedUpstreamProxyError {
    pub kind: UpstreamProxyErrorKind,
    pub detail: String,
    pub classification: UpstreamErrorClassification,
    pub health_failure: Option<UpstreamHealthFailureMapping>,
    pub retryability: UpstreamRetryability,
}

fn classify_tls_detail(detail: &str) -> UpstreamErrorClassification {
    let classification = UpstreamErrorDetails::new(detail.to_string(), true).classify();
    if matches!(classification.category, UpstreamErrorCategory::Transport) {
        UpstreamErrorClassification::tls(UpstreamTlsReason::Handshake)
    } else {
        classification
    }
}

pub fn classify_upstream_proxy_error(err: &ProxyError) -> Option<ClassifiedUpstreamProxyError> {
    match err {
        ProxyError::Pool(PoolError::Send(send_err)) => {
            let details = UpstreamErrorDetails::from_error_chain(send_err, send_err.is_connect());
            let classification = details.classify();
            Some(ClassifiedUpstreamProxyError {
                kind: UpstreamProxyErrorKind::Send,
                detail: details.detail,
                classification,
                health_failure: Some(classification.health_failure_mapping()),
                retryability: classify_retryability(err),
            })
        }
        ProxyError::Transport(detail) => {
            let classification = UpstreamErrorClassification::transport();
            Some(ClassifiedUpstreamProxyError {
                kind: UpstreamProxyErrorKind::Transport,
                detail: detail.clone(),
                classification,
                health_failure: Some(classification.health_failure_mapping()),
                retryability: classify_retryability(err),
            })
        }
        ProxyError::Timeout => {
            let classification = UpstreamErrorClassification::timeout();
            Some(ClassifiedUpstreamProxyError {
                kind: UpstreamProxyErrorKind::Timeout,
                detail: err.to_string(),
                classification,
                health_failure: Some(classification.health_failure_mapping()),
                retryability: classify_retryability(err),
            })
        }
        ProxyError::Protocol(detail) => Some(ClassifiedUpstreamProxyError {
            kind: UpstreamProxyErrorKind::Protocol,
            detail: detail.clone(),
            classification: UpstreamErrorClassification::protocol(),
            health_failure: None,
            retryability: classify_retryability(err),
        }),
        ProxyError::Tls(detail) => Some(ClassifiedUpstreamProxyError {
            kind: UpstreamProxyErrorKind::Tls,
            detail: detail.clone(),
            classification: classify_tls_detail(detail),
            health_failure: None,
            retryability: classify_retryability(err),
        }),
        ProxyError::Bridge(_)
        | ProxyError::Pool(PoolError::UnknownBackend(_))
        | ProxyError::Pool(PoolError::BackendOverloaded(_))
        | ProxyError::Pool(PoolError::CircuitOpen(_))
        | ProxyError::Pool(PoolError::InflightLimiterClosed) => None,
    }
}
