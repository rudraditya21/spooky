use std::error::Error as StdError;

use spooky_lb::health::HealthFailureReason;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamErrorDetails {
    pub detail: String,
    pub is_connect: bool,
}

impl UpstreamErrorDetails {
    pub fn new(detail: String, is_connect: bool) -> Self {
        Self { detail, is_connect }
    }

    pub fn from_error_chain(err: &(dyn StdError + 'static), is_connect: bool) -> Self {
        Self::new(format_error_chain(err), is_connect)
    }

    pub fn classify(&self) -> UpstreamErrorClassification {
        classify_upstream_error_detail(&self.detail, self.is_connect)
    }
}

pub fn classify_upstream_error_detail(
    detail: &str,
    is_connect: bool,
) -> UpstreamErrorClassification {
    let normalized = detail.to_ascii_lowercase();
    if normalized.contains("timeout") || normalized.contains("timed out") {
        return UpstreamErrorClassification::timeout();
    }

    if is_connect {
        if normalized.contains("unknownissuer") || normalized.contains("unknown issuer") {
            return UpstreamErrorClassification::tls(UpstreamTlsReason::UnknownIssuer);
        }
        if normalized.contains("expired")
            || normalized.contains("not yet valid")
            || normalized.contains("validity")
        {
            return UpstreamErrorClassification::tls(UpstreamTlsReason::ExpiredCertificate);
        }
        if normalized.contains("hostname")
            || normalized.contains("dns name")
            || normalized.contains("subjectaltname")
            || normalized.contains("not valid for")
        {
            return UpstreamErrorClassification::tls(UpstreamTlsReason::HostnameMismatch);
        }
        if normalized.contains("alpn") {
            return UpstreamErrorClassification::tls(UpstreamTlsReason::Alpn);
        }
        if normalized.contains("invalidcertificate")
            || normalized.contains("certificate")
            || normalized.contains("x509")
            || normalized.contains("rustls")
            || normalized.contains("webpki")
            || normalized.contains("tls")
        {
            return UpstreamErrorClassification::tls(UpstreamTlsReason::Handshake);
        }
    }

    UpstreamErrorClassification::transport()
}

pub fn format_error_chain(err: &(dyn StdError + 'static)) -> String {
    let mut detail = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        detail.push_str(": ");
        detail.push_str(&cause.to_string());
        source = cause.source();
    }
    detail
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamErrorCategory {
    Timeout,
    Transport,
    Tls,
    Protocol,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamTlsReason {
    UnknownIssuer,
    ExpiredCertificate,
    HostnameMismatch,
    Alpn,
    Handshake,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamErrorClassification {
    pub category: UpstreamErrorCategory,
    pub tls_reason: Option<UpstreamTlsReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamHealthFailureMapping {
    pub failure_reason: HealthFailureReason,
    pub metrics_reason: &'static str,
}

impl UpstreamErrorClassification {
    pub const fn timeout() -> Self {
        Self {
            category: UpstreamErrorCategory::Timeout,
            tls_reason: None,
        }
    }

    pub const fn transport() -> Self {
        Self {
            category: UpstreamErrorCategory::Transport,
            tls_reason: None,
        }
    }

    pub const fn tls(reason: UpstreamTlsReason) -> Self {
        Self {
            category: UpstreamErrorCategory::Tls,
            tls_reason: Some(reason),
        }
    }

    pub const fn protocol() -> Self {
        Self {
            category: UpstreamErrorCategory::Protocol,
            tls_reason: None,
        }
    }

    pub const fn internal() -> Self {
        Self {
            category: UpstreamErrorCategory::Internal,
            tls_reason: None,
        }
    }

    pub fn health_failure_mapping(self) -> UpstreamHealthFailureMapping {
        match self.category {
            UpstreamErrorCategory::Timeout => UpstreamHealthFailureMapping {
                failure_reason: HealthFailureReason::Timeout,
                metrics_reason: "timeout",
            },
            UpstreamErrorCategory::Transport => UpstreamHealthFailureMapping {
                failure_reason: HealthFailureReason::Transport,
                metrics_reason: "transport",
            },
            UpstreamErrorCategory::Tls => UpstreamHealthFailureMapping {
                failure_reason: HealthFailureReason::Tls,
                metrics_reason: match self.tls_reason.unwrap_or(UpstreamTlsReason::Handshake) {
                    UpstreamTlsReason::UnknownIssuer => "unknown_issuer",
                    UpstreamTlsReason::ExpiredCertificate => "expired_certificate",
                    UpstreamTlsReason::HostnameMismatch => "hostname_mismatch",
                    UpstreamTlsReason::Alpn => "alpn",
                    UpstreamTlsReason::Handshake => "handshake",
                },
            },
            UpstreamErrorCategory::Protocol | UpstreamErrorCategory::Internal => {
                UpstreamHealthFailureMapping {
                    failure_reason: HealthFailureReason::Transport,
                    metrics_reason: "transport",
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use spooky_lb::health::HealthFailureReason;

    use super::{UpstreamErrorClassification, UpstreamHealthFailureMapping, UpstreamTlsReason};

    #[test]
    fn health_failure_mapping_preserves_tls_and_transport_reasoning() {
        assert_eq!(
            UpstreamErrorClassification::timeout().health_failure_mapping(),
            UpstreamHealthFailureMapping {
                failure_reason: HealthFailureReason::Timeout,
                metrics_reason: "timeout",
            }
        );
        assert_eq!(
            UpstreamErrorClassification::tls(UpstreamTlsReason::UnknownIssuer)
                .health_failure_mapping(),
            UpstreamHealthFailureMapping {
                failure_reason: HealthFailureReason::Tls,
                metrics_reason: "unknown_issuer",
            }
        );
        assert_eq!(
            UpstreamErrorClassification::protocol().health_failure_mapping(),
            UpstreamHealthFailureMapping {
                failure_reason: HealthFailureReason::Transport,
                metrics_reason: "transport",
            }
        );
    }
}
