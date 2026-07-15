use std::error::Error as StdError;

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
        let normalized = self.detail.to_ascii_lowercase();
        if normalized.contains("timeout") || normalized.contains("timed out") {
            return UpstreamErrorClassification::timeout();
        }

        if self.is_connect {
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
}
