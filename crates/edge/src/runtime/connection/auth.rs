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
}
