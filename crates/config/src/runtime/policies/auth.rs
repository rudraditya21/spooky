use std::time::Duration;

use super::{
    config_invalid, normalize_nonempty_string_vec, normalize_optional_string,
};
use crate::runtime::RuntimeConfigError;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimeApiKeyAuth {
    pub header_name: String,
    pub keys: Vec<String>,
}

impl RuntimeApiKeyAuth {
    pub(crate) fn normalize(
        api_key: &crate::config::ApiKeyAuth,
        upstream_name: &str,
    ) -> Result<Self, RuntimeConfigError> {
        let header_name = api_key.header_name.trim();
        if header_name.is_empty() {
            return Err(config_invalid(format!(
                "upstream '{upstream_name}' auth.api_key.header_name must be non-empty"
            )));
        }
        let keys = normalize_nonempty_string_vec(
            &format!("upstream '{upstream_name}' auth.api_key.keys"),
            &api_key.keys,
        )?;
        Ok(Self {
            header_name: header_name.to_string(),
            keys,
        })
    }

    #[cfg(test)]
    pub(crate) fn as_config(&self) -> crate::config::ApiKeyAuth {
        crate::config::ApiKeyAuth {
            header_name: self.header_name.clone(),
            keys: self.keys.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimeJwtAuth {
    pub secret: String,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub clock_skew: Duration,
}

impl RuntimeJwtAuth {
    pub(crate) fn normalize(
        jwt: &crate::config::JwtAuth,
        upstream_name: &str,
    ) -> Result<Self, RuntimeConfigError> {
        let secret = jwt.secret.trim();
        if secret.is_empty() {
            return Err(config_invalid(format!(
                "upstream '{upstream_name}' auth.jwt.secret must be non-empty"
            )));
        }

        Ok(Self {
            secret: secret.to_string(),
            issuer: normalize_optional_string(jwt.issuer.as_deref()),
            audience: normalize_optional_string(jwt.audience.as_deref()),
            clock_skew: Duration::from_secs(jwt.clock_skew_secs),
        })
    }

    #[cfg(test)]
    pub(crate) fn as_config(&self) -> crate::config::JwtAuth {
        crate::config::JwtAuth {
            secret: self.secret.clone(),
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
            clock_skew_secs: self.clock_skew.as_secs(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RuntimeExternalAuthFailureMode {
    FailOpen,
    #[default]
    FailClosed,
}

impl RuntimeExternalAuthFailureMode {
    pub(crate) fn from_config(mode: crate::config::ExternalAuthFailureMode) -> Self {
        match mode {
            crate::config::ExternalAuthFailureMode::FailOpen => Self::FailOpen,
            crate::config::ExternalAuthFailureMode::FailClosed => Self::FailClosed,
        }
    }

    #[cfg(test)]
    pub(crate) fn as_config(self) -> crate::config::ExternalAuthFailureMode {
        match self {
            Self::FailOpen => crate::config::ExternalAuthFailureMode::FailOpen,
            Self::FailClosed => crate::config::ExternalAuthFailureMode::FailClosed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimeExternalAuthRequestHeader {
    pub name: String,
    pub value: String,
}

impl RuntimeExternalAuthRequestHeader {
    fn normalize(
        header: &crate::config::ExternalAuthRequestHeader,
        field_name: &str,
    ) -> Result<Self, RuntimeConfigError> {
        let name = header.name.trim();
        if name.is_empty() {
            return Err(config_invalid(format!(
                "{field_name}.name must be non-empty"
            )));
        }
        http::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            config_invalid(format!(
                "{field_name}.name must be a valid HTTP header name"
            ))
        })?;

        Ok(Self {
            name: name.to_string(),
            value: header.value.clone(),
        })
    }

    fn normalize_many(
        headers: &[crate::config::ExternalAuthRequestHeader],
        field_name: &str,
    ) -> Result<Vec<Self>, RuntimeConfigError> {
        headers
            .iter()
            .enumerate()
            .map(|(index, header)| Self::normalize(header, &format!("{field_name}[{index}]")))
            .collect()
    }

    #[cfg(test)]
    fn as_config(&self) -> crate::config::ExternalAuthRequestHeader {
        crate::config::ExternalAuthRequestHeader {
            name: self.name.clone(),
            value: self.value.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeExternalAuth {
    Http {
        endpoint: String,
        request_headers: Vec<RuntimeExternalAuthRequestHeader>,
        response_header_allowlist: Vec<String>,
        timeout: Duration,
        failure_mode: RuntimeExternalAuthFailureMode,
    },
    Oidc {
        discovery_url: Option<String>,
        issuer_url: Option<String>,
        client_id: String,
        client_secret: Option<String>,
        audience: Option<String>,
        scopes: Vec<String>,
        request_headers: Vec<RuntimeExternalAuthRequestHeader>,
        response_header_allowlist: Vec<String>,
        timeout: Duration,
        failure_mode: RuntimeExternalAuthFailureMode,
    },
}

impl RuntimeExternalAuth {
    fn normalize(
        external_auth: &crate::config::ExternalAuth,
        upstream_name: &str,
    ) -> Result<Self, RuntimeConfigError> {
        match external_auth {
            crate::config::ExternalAuth::Http {
                endpoint,
                request_headers,
                response_header_allowlist,
                timeout_ms,
                failure_mode,
            } => {
                if *timeout_ms == 0 {
                    return Err(config_invalid(format!(
                        "upstream '{upstream_name}' auth.external_auth.http.timeout_ms must be greater than 0"
                    )));
                }
                Ok(Self::Http {
                    endpoint: endpoint.clone(),
                    request_headers: RuntimeExternalAuthRequestHeader::normalize_many(
                        request_headers,
                        &format!(
                            "upstream '{upstream_name}' auth.external_auth.http.request_headers"
                        ),
                    )?,
                    response_header_allowlist: normalize_nonempty_string_vec(
                        &format!(
                            "upstream '{upstream_name}' auth.external_auth.http.response_header_allowlist"
                        ),
                        response_header_allowlist,
                    )?,
                    timeout: Duration::from_millis(*timeout_ms),
                    failure_mode: RuntimeExternalAuthFailureMode::from_config(*failure_mode),
                })
            }
            crate::config::ExternalAuth::Oidc {
                discovery_url,
                issuer_url,
                client_id,
                client_secret,
                audience,
                scopes,
                request_headers,
                response_header_allowlist,
                timeout_ms,
                failure_mode,
            } => {
                if *timeout_ms == 0 {
                    return Err(config_invalid(format!(
                        "upstream '{upstream_name}' auth.external_auth.oidc.timeout_ms must be greater than 0"
                    )));
                }
                let client_id = client_id.trim();
                if client_id.is_empty() {
                    return Err(config_invalid(format!(
                        "upstream '{upstream_name}' auth.external_auth.oidc.client_id must be non-empty"
                    )));
                }
                Ok(Self::Oidc {
                    discovery_url: normalize_optional_string(discovery_url.as_deref()),
                    issuer_url: normalize_optional_string(issuer_url.as_deref()),
                    client_id: client_id.to_string(),
                    client_secret: normalize_optional_string(client_secret.as_deref()),
                    audience: normalize_optional_string(audience.as_deref()),
                    scopes: normalize_nonempty_string_vec(
                        &format!("upstream '{upstream_name}' auth.external_auth.oidc.scopes"),
                        scopes,
                    )?,
                    request_headers: RuntimeExternalAuthRequestHeader::normalize_many(
                        request_headers,
                        &format!(
                            "upstream '{upstream_name}' auth.external_auth.oidc.request_headers"
                        ),
                    )?,
                    response_header_allowlist: normalize_nonempty_string_vec(
                        &format!(
                            "upstream '{upstream_name}' auth.external_auth.oidc.response_header_allowlist"
                        ),
                        response_header_allowlist,
                    )?,
                    timeout: Duration::from_millis(*timeout_ms),
                    failure_mode: RuntimeExternalAuthFailureMode::from_config(*failure_mode),
                })
            }
        }
    }

    #[cfg(test)]
    fn as_config(&self) -> crate::config::ExternalAuth {
        match self {
            Self::Http {
                endpoint,
                request_headers,
                response_header_allowlist,
                timeout,
                failure_mode,
            } => crate::config::ExternalAuth::Http {
                endpoint: endpoint.clone(),
                request_headers: request_headers.iter().map(Self::header_as_config).collect(),
                response_header_allowlist: response_header_allowlist.clone(),
                timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX),
                failure_mode: failure_mode.as_config(),
            },
            Self::Oidc {
                discovery_url,
                issuer_url,
                client_id,
                client_secret,
                audience,
                scopes,
                request_headers,
                response_header_allowlist,
                timeout,
                failure_mode,
            } => crate::config::ExternalAuth::Oidc {
                discovery_url: discovery_url.clone(),
                issuer_url: issuer_url.clone(),
                client_id: client_id.clone(),
                client_secret: client_secret.clone(),
                audience: audience.clone(),
                scopes: scopes.clone(),
                request_headers: request_headers.iter().map(Self::header_as_config).collect(),
                response_header_allowlist: response_header_allowlist.clone(),
                timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX),
                failure_mode: failure_mode.as_config(),
            },
        }
    }

    #[cfg(test)]
    fn header_as_config(
        header: &RuntimeExternalAuthRequestHeader,
    ) -> crate::config::ExternalAuthRequestHeader {
        header.as_config()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimeAuthPolicy {
    pub api_key: Option<RuntimeApiKeyAuth>,
    pub jwt: Option<RuntimeJwtAuth>,
    pub external_auth: Option<RuntimeExternalAuth>,
    pub required_scopes: Vec<String>,
    pub required_roles: Vec<String>,
}

impl RuntimeAuthPolicy {
    pub(crate) fn normalize(
        auth: &crate::config::RouteAuth,
        upstream_name: &str,
    ) -> Result<Self, RuntimeConfigError> {
        Ok(Self {
            api_key: auth
                .api_key
                .as_ref()
                .map(|api_key| RuntimeApiKeyAuth::normalize(api_key, upstream_name))
                .transpose()?,
            jwt: auth
                .jwt
                .as_ref()
                .map(|jwt| RuntimeJwtAuth::normalize(jwt, upstream_name))
                .transpose()?,
            external_auth: auth
                .external_auth
                .as_ref()
                .map(|external_auth| RuntimeExternalAuth::normalize(external_auth, upstream_name))
                .transpose()?,
            required_scopes: normalize_nonempty_string_vec(
                &format!("upstream '{upstream_name}' auth.required_scopes"),
                &auth.required_scopes,
            )?,
            required_roles: normalize_nonempty_string_vec(
                &format!("upstream '{upstream_name}' auth.required_roles"),
                &auth.required_roles,
            )?,
        })
    }

    #[cfg(test)]
    pub(crate) fn as_config(&self) -> crate::config::RouteAuth {
        crate::config::RouteAuth {
            api_key: self.api_key.as_ref().map(RuntimeApiKeyAuth::as_config),
            jwt: self.jwt.as_ref().map(RuntimeJwtAuth::as_config),
            external_auth: self
                .external_auth
                .as_ref()
                .map(RuntimeExternalAuth::as_config),
            required_scopes: self.required_scopes.clone(),
            required_roles: self.required_roles.clone(),
        }
    }
}
