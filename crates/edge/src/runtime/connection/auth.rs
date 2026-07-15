use std::{collections::HashMap, time::Duration};

use quiche::h3::NameValue;
use spooky_config::runtime::{
    RuntimeExternalAuth, RuntimeExternalAuthFailureMode, RuntimeExternalAuthRequestHeader,
};
use spooky_errors::ProxyError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalAuthProviderKind {
    Http,
    Oidc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalAuthFailureDisposition {
    FailOpen,
    FailClosed,
}

impl ExternalAuthFailureDisposition {
    pub fn from_failure_mode(mode: RuntimeExternalAuthFailureMode) -> Self {
        match mode {
            RuntimeExternalAuthFailureMode::FailOpen => Self::FailOpen,
            RuntimeExternalAuthFailureMode::FailClosed => Self::FailClosed,
        }
    }

    pub fn from_fail_open(fail_open: bool) -> Self {
        if fail_open {
            Self::FailOpen
        } else {
            Self::FailClosed
        }
    }

    pub fn fail_open(self) -> bool {
        matches!(self, Self::FailOpen)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalAuthExecutionPolicy {
    pub timeout: Duration,
    pub failure_mode: RuntimeExternalAuthFailureMode,
}

impl ExternalAuthExecutionPolicy {
    pub fn from_external_auth(value: &RuntimeExternalAuth) -> Self {
        match value {
            RuntimeExternalAuth::Http {
                timeout_ms,
                failure_mode,
                ..
            }
            | RuntimeExternalAuth::Oidc {
                timeout_ms,
                failure_mode,
                ..
            } => Self {
                timeout: Duration::from_millis((*timeout_ms).max(1)),
                failure_mode: *failure_mode,
            },
        }
    }

    pub fn disposition(self) -> ExternalAuthFailureDisposition {
        ExternalAuthFailureDisposition::from_failure_mode(self.failure_mode)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalAuthTaskConfig {
    pub timeout: Duration,
    pub disposition: ExternalAuthFailureDisposition,
}

impl ExternalAuthTaskConfig {
    pub fn from_external_auth(value: &RuntimeExternalAuth) -> Self {
        let policy = ExternalAuthExecutionPolicy::from_external_auth(value);
        Self {
            timeout: policy.timeout,
            disposition: policy.disposition(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ExternalAuthProviderInput<'a> {
    Http {
        endpoint: &'a str,
        request_headers: &'a [RuntimeExternalAuthRequestHeader],
        response_header_allowlist: &'a [String],
    },
    Oidc {
        discovery_url: Option<&'a str>,
        issuer_url: Option<&'a str>,
        client_id: &'a str,
        client_secret: Option<&'a str>,
        audience: Option<&'a str>,
        scopes: &'a [String],
        request_headers: &'a [RuntimeExternalAuthRequestHeader],
        response_header_allowlist: &'a [String],
    },
}

impl<'a> ExternalAuthProviderInput<'a> {
    pub fn kind(&self) -> ExternalAuthProviderKind {
        match self {
            Self::Http { .. } => ExternalAuthProviderKind::Http,
            Self::Oidc { .. } => ExternalAuthProviderKind::Oidc,
        }
    }

    pub fn request_headers(&self) -> &'a [RuntimeExternalAuthRequestHeader] {
        match self {
            Self::Http {
                request_headers, ..
            }
            | Self::Oidc {
                request_headers, ..
            } => request_headers,
        }
    }

    pub fn response_header_allowlist(&self) -> &'a [String] {
        match self {
            Self::Http {
                response_header_allowlist,
                ..
            }
            | Self::Oidc {
                response_header_allowlist,
                ..
            } => response_header_allowlist,
        }
    }
}

impl<'a> From<&'a RuntimeExternalAuth> for ExternalAuthProviderInput<'a> {
    fn from(value: &'a RuntimeExternalAuth) -> Self {
        match value {
            RuntimeExternalAuth::Http {
                endpoint,
                request_headers,
                response_header_allowlist,
                ..
            } => Self::Http {
                endpoint,
                request_headers,
                response_header_allowlist,
            },
            RuntimeExternalAuth::Oidc {
                discovery_url,
                issuer_url,
                client_id,
                client_secret,
                audience,
                scopes,
                request_headers,
                response_header_allowlist,
                ..
            } => Self::Oidc {
                discovery_url: discovery_url.as_deref(),
                issuer_url: issuer_url.as_deref(),
                client_id,
                client_secret: client_secret.as_deref(),
                audience: audience.as_deref(),
                scopes,
                request_headers,
                response_header_allowlist,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalAuthRequestContext<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub authority: Option<&'a str>,
    pub upstream_name: &'a str,
    pub backend_addr: &'a str,
}

#[derive(Debug)]
pub struct ExternalAuthResponseMetadata<'a> {
    pub status: http::StatusCode,
    pub headers: &'a http::HeaderMap,
    pub body: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidcAuthorizationCheck {
    Token(String),
    Challenge(ExternalAuthChallengeResponse),
}

#[derive(Debug, Clone)]
pub struct OidcDiscoveryTarget {
    pub url: String,
    pub uri: http::Uri,
}

#[derive(Debug, Clone)]
pub struct OidcProviderMetadata {
    pub introspection_endpoint: String,
    pub introspection_uri: http::Uri,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalAuthMutationIntent {
    Upsert { name: Vec<u8>, value: Vec<u8> },
    Remove { name: Vec<u8> },
}

impl From<ExternalAuthMutationIntent> for PendingHeaderMutation {
    fn from(value: ExternalAuthMutationIntent) -> Self {
        match value {
            ExternalAuthMutationIntent::Upsert { name, value } => Self::Upsert { name, value },
            ExternalAuthMutationIntent::Remove { name } => Self::Remove { name },
        }
    }
}

impl From<PendingHeaderMutation> for ExternalAuthMutationIntent {
    fn from(value: PendingHeaderMutation) -> Self {
        match value {
            PendingHeaderMutation::Upsert { name, value } => Self::Upsert { name, value },
            PendingHeaderMutation::Remove { name } => Self::Remove { name },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalAuthDecision {
    Allow {
        request_header_mutations: Vec<PendingHeaderMutation>,
    },
    Deny(ExternalAuthDenyResponse),
    Redirect(ExternalAuthRedirectResponse),
    Challenge(ExternalAuthChallengeResponse),
}

pub type ExternalAuthResult = Result<ExternalAuthDecision, ProxyError>;

#[derive(Debug)]
pub enum ExternalAuthDecisionOutcome {
    Allow {
        request_header_mutations: Vec<ExternalAuthMutationIntent>,
    },
    Deny(ExternalAuthDenyResponse),
    Redirect(ExternalAuthRedirectResponse),
    Challenge(ExternalAuthChallengeResponse),
    Timeout {
        disposition: ExternalAuthFailureDisposition,
    },
    Error {
        disposition: ExternalAuthFailureDisposition,
        error: ProxyError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalAuthFailureResolution {
    FailOpen,
    Reject {
        status: http::StatusCode,
        body: &'static [u8],
        timed_out: bool,
    },
}

#[derive(Debug)]
pub enum ExternalAuthCompletion {
    Allow {
        request_header_mutations: Vec<PendingHeaderMutation>,
    },
    Respond(ExternalAuthDecision),
    FailOpen {
        timed_out: bool,
        error: Option<ProxyError>,
    },
    Reject {
        status: http::StatusCode,
        body: &'static [u8],
        timed_out: bool,
        error: Option<ProxyError>,
    },
}

impl ExternalAuthDecisionOutcome {
    pub fn from_result(
        result: ExternalAuthResult,
        disposition: ExternalAuthFailureDisposition,
    ) -> Self {
        match result {
            Ok(ExternalAuthDecision::Allow {
                request_header_mutations,
            }) => Self::Allow {
                request_header_mutations: request_header_mutations
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            },
            Ok(ExternalAuthDecision::Deny(response)) => Self::Deny(response),
            Ok(ExternalAuthDecision::Redirect(response)) => Self::Redirect(response),
            Ok(ExternalAuthDecision::Challenge(response)) => Self::Challenge(response),
            Err(ProxyError::Timeout) => Self::Timeout { disposition },
            Err(error) => Self::Error { disposition, error },
        }
    }

    pub fn failure_resolution(&self) -> Option<ExternalAuthFailureResolution> {
        match self {
            Self::Timeout { disposition } => Some(if disposition.fail_open() {
                ExternalAuthFailureResolution::FailOpen
            } else {
                ExternalAuthFailureResolution::Reject {
                    status: http::StatusCode::GATEWAY_TIMEOUT,
                    body: b"external auth timeout\n",
                    timed_out: true,
                }
            }),
            Self::Error { disposition, .. } => Some(if disposition.fail_open() {
                ExternalAuthFailureResolution::FailOpen
            } else {
                ExternalAuthFailureResolution::Reject {
                    status: http::StatusCode::SERVICE_UNAVAILABLE,
                    body: b"external auth unavailable\n",
                    timed_out: false,
                }
            }),
            _ => None,
        }
    }
}

impl ExternalAuthDecision {
    pub fn status(&self) -> http::StatusCode {
        match self {
            Self::Allow { .. } => http::StatusCode::OK,
            Self::Deny(response) => response.status,
            Self::Redirect(response) => response.status,
            Self::Challenge(response) => response.status,
        }
    }
}

pub fn evaluate_external_auth_completion(
    result: ExternalAuthResult,
    disposition: ExternalAuthFailureDisposition,
) -> ExternalAuthCompletion {
    let outcome = ExternalAuthDecisionOutcome::from_result(result, disposition);
    let failure = outcome.failure_resolution();
    match outcome {
        ExternalAuthDecisionOutcome::Allow {
            request_header_mutations,
        } => ExternalAuthCompletion::Allow {
            request_header_mutations: request_header_mutations
                .into_iter()
                .map(Into::into)
                .collect(),
        },
        ExternalAuthDecisionOutcome::Deny(response) => {
            ExternalAuthCompletion::Respond(ExternalAuthDecision::Deny(response))
        }
        ExternalAuthDecisionOutcome::Redirect(response) => {
            ExternalAuthCompletion::Respond(ExternalAuthDecision::Redirect(response))
        }
        ExternalAuthDecisionOutcome::Challenge(response) => {
            ExternalAuthCompletion::Respond(ExternalAuthDecision::Challenge(response))
        }
        ExternalAuthDecisionOutcome::Timeout { .. } => match failure {
            Some(ExternalAuthFailureResolution::FailOpen) => ExternalAuthCompletion::FailOpen {
                timed_out: true,
                error: None,
            },
            Some(ExternalAuthFailureResolution::Reject { status, body, .. }) => {
                ExternalAuthCompletion::Reject {
                    status,
                    body,
                    timed_out: true,
                    error: None,
                }
            }
            None => unreachable!("timeout outcome must resolve"),
        },
        ExternalAuthDecisionOutcome::Error { error, .. } => match failure {
            Some(ExternalAuthFailureResolution::FailOpen) => ExternalAuthCompletion::FailOpen {
                timed_out: false,
                error: Some(error),
            },
            Some(ExternalAuthFailureResolution::Reject {
                status,
                body,
                timed_out,
            }) => ExternalAuthCompletion::Reject {
                status,
                body,
                timed_out,
                error: Some(error),
            },
            None => unreachable!("error outcome must resolve"),
        },
    }
}

pub fn oidc_authorization_check(authorization: Option<&str>) -> OidcAuthorizationCheck {
    let Some(authorization) = authorization else {
        return OidcAuthorizationCheck::Challenge(ExternalAuthChallengeResponse {
            status: http::StatusCode::UNAUTHORIZED,
            headers: Vec::new(),
            www_authenticate: "Bearer".to_string(),
            body: b"missing bearer token\n".to_vec(),
        });
    };
    let Some(token) = bearer_token_from_authorization_value(authorization) else {
        return OidcAuthorizationCheck::Challenge(ExternalAuthChallengeResponse {
            status: http::StatusCode::UNAUTHORIZED,
            headers: Vec::new(),
            www_authenticate: "Bearer".to_string(),
            body: b"invalid bearer token\n".to_vec(),
        });
    };
    OidcAuthorizationCheck::Token(token.to_string())
}

fn bearer_token_from_authorization_value(raw: &str) -> Option<&str> {
    let (scheme, value) = raw.split_once(char::is_whitespace)?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(value.trim())
}

pub fn auth_uri_scheme_permitted(uri: &http::Uri) -> bool {
    match uri.scheme_str() {
        Some("https") => uri.authority().is_some(),
        Some("http") => uri.host().is_some_and(uri_host_is_loopback),
        _ => false,
    }
}

fn uri_host_is_loopback(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

pub fn oidc_discovery_target(
    discovery_url: Option<&str>,
    issuer_url: Option<&str>,
) -> Result<OidcDiscoveryTarget, ProxyError> {
    let Some(url) = discovery_url.map(str::to_string).or_else(|| {
        issuer_url.map(|issuer| {
            format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            )
        })
    }) else {
        return Err(ProxyError::Transport(
            "oidc auth missing discovery metadata".into(),
        ));
    };
    let uri = url
        .parse::<http::Uri>()
        .map_err(|err| ProxyError::Transport(err.to_string()))?;
    if !auth_uri_scheme_permitted(&uri) {
        return Err(ProxyError::Transport(
            "oidc discovery endpoint must use https (http allowed only for loopback)".into(),
        ));
    }
    Ok(OidcDiscoveryTarget { url, uri })
}

pub fn validate_oidc_provider_metadata(
    document: &serde_json::Value,
) -> Result<OidcProviderMetadata, ProxyError> {
    let introspection_endpoint = document
        .get("introspection_endpoint")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ProxyError::Transport("oidc discovery missing introspection_endpoint".into())
        })?
        .to_string();
    let introspection_uri = introspection_endpoint
        .parse::<http::Uri>()
        .map_err(|err| ProxyError::Transport(err.to_string()))?;
    if !auth_uri_scheme_permitted(&introspection_uri) {
        return Err(ProxyError::Transport(
            "oidc introspection endpoint must use https (http allowed only for loopback)".into(),
        ));
    }
    Ok(OidcProviderMetadata {
        introspection_endpoint,
        introspection_uri,
    })
}

pub fn oidc_scope_satisfied(required_scopes: &[String], granted_scopes: &str) -> bool {
    let granted: std::collections::HashSet<&str> = granted_scopes.split_whitespace().collect();
    required_scopes
        .iter()
        .all(|scope| granted.contains(scope.as_str()))
}

pub fn oidc_audience_matches(expected: Option<&str>, value: Option<&serde_json::Value>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    match value {
        Some(serde_json::Value::String(single)) => single == expected,
        Some(serde_json::Value::Array(values)) => {
            values.iter().any(|value| value.as_str() == Some(expected))
        }
        _ => false,
    }
}

fn is_safe_auth_request_mutation_header(name: &str) -> bool {
    !name.eq_ignore_ascii_case(http::header::HOST.as_str())
        && !name.eq_ignore_ascii_case(http::header::CONNECTION.as_str())
        && !name.eq_ignore_ascii_case(http::header::CONTENT_LENGTH.as_str())
        && !name.eq_ignore_ascii_case(http::header::TRANSFER_ENCODING.as_str())
        && !name.eq_ignore_ascii_case(http::header::UPGRADE.as_str())
        && !name.eq_ignore_ascii_case(http::header::TE.as_str())
        && !name.eq_ignore_ascii_case(http::header::TRAILER.as_str())
        && !name.eq_ignore_ascii_case(http::header::EXPECT.as_str())
        && !name.eq_ignore_ascii_case(http::header::AUTHORIZATION.as_str())
        && !name.eq_ignore_ascii_case(http::header::LOCATION.as_str())
        && !name.eq_ignore_ascii_case(http::header::WWW_AUTHENTICATE.as_str())
        && !name.eq_ignore_ascii_case(http::header::FORWARDED.as_str())
        && !name.eq_ignore_ascii_case("x-forwarded-for")
        && !name.eq_ignore_ascii_case("x-forwarded-host")
        && !name.eq_ignore_ascii_case("x-forwarded-port")
        && !name.eq_ignore_ascii_case("x-forwarded-proto")
        && !name.eq_ignore_ascii_case("keep-alive")
        && !name.eq_ignore_ascii_case("proxy-connection")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthRequestMutationNameValidation {
    Allowed,
    Protected,
    Invalid,
}

fn validate_auth_request_mutation_name(name: &[u8]) -> AuthRequestMutationNameValidation {
    let Ok(name) = http::header::HeaderName::from_bytes(name) else {
        return AuthRequestMutationNameValidation::Invalid;
    };
    if is_safe_auth_request_mutation_header(name.as_str()) {
        AuthRequestMutationNameValidation::Allowed
    } else {
        AuthRequestMutationNameValidation::Protected
    }
}

fn normalize_auth_request_mutation(
    mutation: PendingHeaderMutation,
) -> Option<(String, PendingHeaderMutation)> {
    let (name, value) = match mutation {
        PendingHeaderMutation::Upsert { name, value } => (name, Some(value)),
        PendingHeaderMutation::Remove { name } => (name, None),
    };
    match validate_auth_request_mutation_name(&name) {
        AuthRequestMutationNameValidation::Allowed => {
            let normalized = http::header::HeaderName::from_bytes(&name)
                .ok()?
                .as_str()
                .to_string();
            let mutation = match value {
                Some(value) => PendingHeaderMutation::Upsert {
                    name: normalized.as_bytes().to_vec(),
                    value,
                },
                None => PendingHeaderMutation::Remove {
                    name: normalized.as_bytes().to_vec(),
                },
            };
            Some((normalized, mutation))
        }
        AuthRequestMutationNameValidation::Protected
        | AuthRequestMutationNameValidation::Invalid => None,
    }
}

pub fn canonicalize_auth_request_mutations<I>(mutations: I) -> Vec<PendingHeaderMutation>
where
    I: IntoIterator<Item = PendingHeaderMutation>,
{
    let normalized = mutations
        .into_iter()
        .enumerate()
        .filter_map(|(idx, mutation)| {
            normalize_auth_request_mutation(mutation).map(|(name, mutation)| (idx, name, mutation))
        })
        .collect::<Vec<_>>();
    let last_seen = normalized
        .iter()
        .map(|(idx, name, _)| (name.clone(), *idx))
        .collect::<HashMap<_, _>>();
    normalized
        .into_iter()
        .filter_map(|(idx, name, mutation)| {
            (last_seen.get(&name) == Some(&idx)).then_some(mutation)
        })
        .collect()
}

pub fn merge_auth_request_mutations<I>(existing: &mut Vec<PendingHeaderMutation>, incoming: I)
where
    I: IntoIterator<Item = PendingHeaderMutation>,
{
    existing.extend(incoming);
    let merged = canonicalize_auth_request_mutations(std::mem::take(existing));
    *existing = merged;
}

pub fn apply_auth_request_mutations(
    headers: &mut Vec<quiche::h3::Header>,
    mutations: &[PendingHeaderMutation],
) {
    for mutation in canonicalize_auth_request_mutations(mutations.iter().cloned()) {
        match mutation {
            PendingHeaderMutation::Upsert { name, value } => {
                headers.retain(|header| !header.name().eq_ignore_ascii_case(name.as_slice()));
                headers.push(quiche::h3::Header::new(name.as_slice(), value.as_slice()));
            }
            PendingHeaderMutation::Remove { name } => {
                headers.retain(|header| !header.name().eq_ignore_ascii_case(name.as_slice()));
            }
        }
    }
}

pub fn allowed_auth_headers(
    headers: &http::HeaderMap,
    allowlist: &[String],
) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            allowlist
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(name.as_str()))
                .then(|| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_string(), value.to_string()))
                })
                .flatten()
        })
        .collect()
}

pub fn auth_allow_mutations(
    headers: &http::HeaderMap,
    allowlist: &[String],
) -> Vec<PendingHeaderMutation> {
    canonicalize_auth_request_mutations(allowed_auth_headers(headers, allowlist).into_iter().map(
        |(name, value)| PendingHeaderMutation::Upsert {
            name: name.into_bytes(),
            value: value.into_bytes(),
        },
    ))
}

pub fn map_http_external_auth_response(
    metadata: ExternalAuthResponseMetadata<'_>,
    response_header_allowlist: &[String],
) -> ExternalAuthResult {
    let ExternalAuthResponseMetadata {
        status,
        headers,
        body,
    } = metadata;
    let location = headers
        .get(http::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let challenge = headers
        .get(http::header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let allowed_headers = allowed_auth_headers(headers, response_header_allowlist);
    if status.is_success() {
        return Ok(ExternalAuthDecision::Allow {
            request_header_mutations: auth_allow_mutations(headers, response_header_allowlist),
        });
    }
    if status.is_redirection() {
        if let Some(location) = location {
            return Ok(ExternalAuthDecision::Redirect(
                ExternalAuthRedirectResponse {
                    status,
                    headers: allowed_headers
                        .into_iter()
                        .filter(|(name, _)| {
                            !name.eq_ignore_ascii_case(http::header::LOCATION.as_str())
                        })
                        .collect(),
                    location,
                },
            ));
        }
        return Err(ProxyError::Transport(
            "external auth redirect missing location header".into(),
        ));
    }
    if status == http::StatusCode::UNAUTHORIZED
        && let Some(www_authenticate) = challenge
    {
        return Ok(ExternalAuthDecision::Challenge(
            ExternalAuthChallengeResponse {
                status,
                headers: allowed_headers
                    .into_iter()
                    .filter(|(name, _)| {
                        !name.eq_ignore_ascii_case(http::header::WWW_AUTHENTICATE.as_str())
                    })
                    .collect(),
                www_authenticate,
                body: body.to_vec(),
            },
        ));
    }
    if status.is_client_error() {
        return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
            status,
            headers: allowed_headers,
            body: body.to_vec(),
        }));
    }
    Err(ProxyError::Transport(format!(
        "external auth endpoint returned {status}"
    )))
}

/// Result type returned by the in-flight upstream forwarding task.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAuthDenyResponse {
    pub status: http::StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAuthRedirectResponse {
    pub status: http::StatusCode,
    pub headers: Vec<(String, String)>,
    pub location: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAuthChallengeResponse {
    pub status: http::StatusCode,
    pub headers: Vec<(String, String)>,
    pub www_authenticate: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingHeaderMutation {
    Upsert { name: Vec<u8>, value: Vec<u8> },
    Remove { name: Vec<u8> },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalize_auth_request_mutations_drops_protected_and_invalid_names() {
        let mutations = canonicalize_auth_request_mutations(vec![
            PendingHeaderMutation::Upsert {
                name: b"x-auth-user".to_vec(),
                value: b"alice".to_vec(),
            },
            PendingHeaderMutation::Upsert {
                name: b"authorization".to_vec(),
                value: b"Bearer blocked".to_vec(),
            },
            PendingHeaderMutation::Remove {
                name: b"bad name".to_vec(),
            },
        ]);

        assert_eq!(
            mutations,
            vec![PendingHeaderMutation::Upsert {
                name: b"x-auth-user".to_vec(),
                value: b"alice".to_vec(),
            }]
        );
    }

    #[test]
    fn canonicalize_auth_request_mutations_keeps_last_mutation_per_header() {
        let mutations = canonicalize_auth_request_mutations(vec![
            PendingHeaderMutation::Upsert {
                name: b"X-User".to_vec(),
                value: b"one".to_vec(),
            },
            PendingHeaderMutation::Upsert {
                name: b"x-team".to_vec(),
                value: b"red".to_vec(),
            },
            PendingHeaderMutation::Remove {
                name: b"x-user".to_vec(),
            },
            PendingHeaderMutation::Upsert {
                name: b"X-Team".to_vec(),
                value: b"blue".to_vec(),
            },
        ]);

        assert_eq!(
            mutations,
            vec![
                PendingHeaderMutation::Remove {
                    name: b"x-user".to_vec(),
                },
                PendingHeaderMutation::Upsert {
                    name: b"x-team".to_vec(),
                    value: b"blue".to_vec(),
                },
            ]
        );
    }

    #[test]
    fn apply_auth_request_mutations_resolves_conflicts_before_header_rewrite() {
        let mut headers = vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b"x-user", b"stale"),
            quiche::h3::Header::new(b"x-team", b"green"),
        ];
        let mutations = vec![
            PendingHeaderMutation::Upsert {
                name: b"X-User".to_vec(),
                value: b"alice".to_vec(),
            },
            PendingHeaderMutation::Remove {
                name: b"x-team".to_vec(),
            },
            PendingHeaderMutation::Upsert {
                name: b"x-user".to_vec(),
                value: b"fresh".to_vec(),
            },
        ];

        apply_auth_request_mutations(&mut headers, &mutations);

        assert!(headers.iter().any(|header| header.name() == b":method"));
        assert!(
            headers
                .iter()
                .any(|header| header.name() == b"x-user" && header.value() == b"fresh")
        );
        assert!(
            !headers
                .iter()
                .any(|header| header.name() == b"x-user" && header.value() == b"alice")
        );
        assert!(!headers.iter().any(|header| header.name() == b"x-team"));
    }

    #[test]
    fn oidc_authorization_check_maps_missing_and_invalid_bearer_tokens_to_challenges() {
        assert!(matches!(
            oidc_authorization_check(None),
            OidcAuthorizationCheck::Challenge(ExternalAuthChallengeResponse {
                status: http::StatusCode::UNAUTHORIZED,
                ..
            })
        ));

        let invalid = oidc_authorization_check(Some("Basic abc123"));
        match invalid {
            OidcAuthorizationCheck::Challenge(response) => {
                assert_eq!(response.www_authenticate, "Bearer");
                assert_eq!(response.body, b"invalid bearer token\n".to_vec());
            }
            other => panic!("unexpected authorization result: {other:?}"),
        }

        assert_eq!(
            oidc_authorization_check(Some("Bearer token-1")),
            OidcAuthorizationCheck::Token("token-1".to_string())
        );
    }

    #[test]
    fn oidc_discovery_target_derives_and_validates_provider_metadata_url() {
        let derived = oidc_discovery_target(None, Some("https://issuer.example.com/base/"))
            .expect("derived discovery target");
        assert_eq!(
            derived.url,
            "https://issuer.example.com/base/.well-known/openid-configuration"
        );

        let http_loopback = oidc_discovery_target(Some("http://127.0.0.1:9000/oidc"), None)
            .expect("loopback discovery should be allowed");
        assert_eq!(http_loopback.uri.scheme_str(), Some("http"));

        let err = oidc_discovery_target(Some("http://example.com/oidc"), None)
            .expect_err("non-loopback http discovery must be rejected");
        assert!(matches!(err, ProxyError::Transport(_)));
    }

    #[test]
    fn validate_oidc_provider_metadata_requires_safe_introspection_endpoint() {
        let valid = validate_oidc_provider_metadata(&json!({
            "introspection_endpoint": "https://issuer.example.com/oauth2/introspect"
        }))
        .expect("valid metadata");
        assert_eq!(
            valid.introspection_endpoint,
            "https://issuer.example.com/oauth2/introspect"
        );

        let missing = validate_oidc_provider_metadata(&json!({}))
            .expect_err("metadata without introspection endpoint must fail");
        assert!(matches!(missing, ProxyError::Transport(_)));

        let invalid = validate_oidc_provider_metadata(&json!({
            "introspection_endpoint": "http://example.com/oauth2/introspect"
        }))
        .expect_err("non-loopback http introspection endpoint must fail");
        assert!(matches!(invalid, ProxyError::Transport(_)));
    }

    #[test]
    fn oidc_helper_predicates_match_expected_scope_and_audience_shapes() {
        assert!(oidc_scope_satisfied(
            &["read".to_string(), "write".to_string()],
            "read write admin"
        ));
        assert!(!oidc_scope_satisfied(
            &["read".to_string(), "write".to_string()],
            "read"
        ));

        assert!(oidc_audience_matches(
            Some("api://edge"),
            Some(&json!("api://edge"))
        ));
        assert!(oidc_audience_matches(
            Some("api://edge"),
            Some(&json!(["other", "api://edge"]))
        ));
        assert!(!oidc_audience_matches(
            Some("api://edge"),
            Some(&json!("api://other"))
        ));
        assert!(oidc_audience_matches(None, None));
    }

    #[test]
    fn external_auth_task_config_tracks_timeout_and_disposition() {
        let auth = RuntimeExternalAuth::Http {
            endpoint: "http://127.0.0.1:9000/auth".to_string(),
            request_headers: Vec::new(),
            response_header_allowlist: Vec::new(),
            timeout_ms: 250,
            failure_mode: RuntimeExternalAuthFailureMode::FailOpen,
        };

        let config = ExternalAuthTaskConfig::from_external_auth(&auth);
        assert_eq!(config.timeout, Duration::from_millis(250));
        assert_eq!(config.disposition, ExternalAuthFailureDisposition::FailOpen);
    }

    #[test]
    fn evaluate_external_auth_completion_maps_fail_open_and_fail_closed_outcomes() {
        let fail_open = evaluate_external_auth_completion(
            Err(ProxyError::Transport("unavailable".into())),
            ExternalAuthFailureDisposition::FailOpen,
        );
        assert!(matches!(
            fail_open,
            ExternalAuthCompletion::FailOpen {
                timed_out: false,
                error: Some(ProxyError::Transport(_)),
            }
        ));

        let fail_closed = evaluate_external_auth_completion(
            Err(ProxyError::Timeout),
            ExternalAuthFailureDisposition::FailClosed,
        );
        assert!(matches!(
            fail_closed,
            ExternalAuthCompletion::Reject {
                status: http::StatusCode::GATEWAY_TIMEOUT,
                timed_out: true,
                ..
            }
        ));
    }
}
