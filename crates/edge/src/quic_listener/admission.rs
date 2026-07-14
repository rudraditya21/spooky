#![allow(dead_code)]

use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use http::StatusCode;
use serde_json::Value;
use sha2::Sha256;
use spooky_config::runtime::{RuntimeJwtAuth, RuntimeUpstreamPolicy};
use subtle::ConstantTimeEq;

use super::LbHeaderLookup;
use crate::{
    metrics::OverloadShedReason,
    resilience::{
        brownout::BrownoutController,
        route_queue::RouteQueueRejection,
        scoped_rate_limit::{ScopedRateLimitRule, ScopedRateLimiters},
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthChallengeKind {
    ApiKey,
    Bearer,
}

impl AuthChallengeKind {
    pub(crate) fn as_www_authenticate(self) -> &'static str {
        match self {
            Self::ApiKey => "ApiKey",
            Self::Bearer => "Bearer",
        }
    }
}

impl OverloadDecisionReason {
    pub(crate) fn metrics_reason(self) -> OverloadShedReason {
        match self {
            Self::Brownout => OverloadShedReason::Brownout,
            Self::AdaptiveAdmission => OverloadShedReason::AdaptiveAdmission,
            Self::RouteCap => OverloadShedReason::RouteCap,
            Self::RouteGlobalCap => OverloadShedReason::RouteGlobalCap,
            Self::GlobalInflight => OverloadShedReason::GlobalInflight,
            Self::UpstreamInflight => OverloadShedReason::UpstreamInflight,
        }
    }

    fn response_body(self) -> &'static [u8] {
        match self {
            Self::Brownout => b"brownout active, non-core route shed\n",
            Self::AdaptiveAdmission => b"adaptive admission overload\n",
            Self::RouteCap => b"route queue cap exceeded\n",
            Self::RouteGlobalCap => b"global queue cap exceeded\n",
            Self::GlobalInflight => b"overloaded, retry later\n",
            Self::UpstreamInflight => b"upstream overloaded, retry later\n",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnauthorizedDecision {
    pub(crate) challenge: AuthChallengeKind,
    pub(crate) status: StatusCode,
    pub(crate) body: &'static [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RateLimitedDecision {
    pub(crate) rule_name: String,
    pub(crate) route: String,
    pub(crate) status: StatusCode,
    pub(crate) body: &'static [u8],
    pub(crate) retry_after_seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OverloadDecisionReason {
    Brownout,
    AdaptiveAdmission,
    RouteCap,
    RouteGlobalCap,
    GlobalInflight,
    UpstreamInflight,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OverloadDecision {
    pub(crate) reason: OverloadDecisionReason,
    pub(crate) status: StatusCode,
    pub(crate) body: &'static [u8],
    pub(crate) retry_after_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdmissionPolicyDecision {
    AdmitReady,
    Unauthorized(UnauthorizedDecision),
    RateLimited(RateLimitedDecision),
    Overloaded(OverloadDecision),
}

pub(crate) fn evaluate_local_auth_policy(
    policy: &RuntimeUpstreamPolicy,
    header_lookup: Option<&LbHeaderLookup<'_>>,
) -> AdmissionPolicyDecision {
    if !api_key_is_authorized(policy, header_lookup) {
        return AdmissionPolicyDecision::Unauthorized(UnauthorizedDecision {
            challenge: AuthChallengeKind::ApiKey,
            status: StatusCode::UNAUTHORIZED,
            body: b"unauthorized\n",
        });
    }

    if !jwt_is_authorized(policy, header_lookup) {
        return AdmissionPolicyDecision::Unauthorized(UnauthorizedDecision {
            challenge: AuthChallengeKind::Bearer,
            status: StatusCode::UNAUTHORIZED,
            body: b"unauthorized\n",
        });
    }

    AdmissionPolicyDecision::AdmitReady
}

pub(crate) fn evaluate_scoped_rate_limit_policy<F>(
    scoped_rate_limits: &ScopedRateLimiters,
    route: &str,
    key_for_rule: F,
) -> AdmissionPolicyDecision
where
    F: FnMut(&ScopedRateLimitRule) -> Option<String>,
{
    let Some(rejection) = scoped_rate_limits.check(route, key_for_rule) else {
        return AdmissionPolicyDecision::AdmitReady;
    };

    AdmissionPolicyDecision::RateLimited(RateLimitedDecision {
        rule_name: rejection.rule_name,
        route: rejection.route,
        status: StatusCode::TOO_MANY_REQUESTS,
        body: b"request rate limited\n",
        retry_after_seconds: rejection.retry_after_seconds,
    })
}

pub(crate) fn evaluate_brownout_policy(
    brownout: &BrownoutController,
    inflight_percent: u8,
    route: &str,
    retry_after_seconds: u32,
) -> AdmissionPolicyDecision {
    brownout.observe_admission_pressure(inflight_percent);
    if brownout.route_allowed(route) {
        return AdmissionPolicyDecision::AdmitReady;
    }

    overload_decision(OverloadDecisionReason::Brownout, retry_after_seconds)
}

pub(crate) fn overload_decision(
    reason: OverloadDecisionReason,
    retry_after_seconds: u32,
) -> AdmissionPolicyDecision {
    AdmissionPolicyDecision::Overloaded(OverloadDecision {
        reason,
        status: StatusCode::SERVICE_UNAVAILABLE,
        body: reason.response_body(),
        retry_after_seconds: retry_after_seconds.max(1),
    })
}

pub(crate) fn overload_decision_for_route_queue_rejection(
    rejection: RouteQueueRejection,
    retry_after_seconds: u32,
) -> AdmissionPolicyDecision {
    let reason = match rejection {
        RouteQueueRejection::GlobalCap => OverloadDecisionReason::RouteGlobalCap,
        RouteQueueRejection::RouteCap => OverloadDecisionReason::RouteCap,
    };
    overload_decision(reason, retry_after_seconds)
}

pub(crate) fn api_key_is_authorized(
    policy: &RuntimeUpstreamPolicy,
    header_lookup: Option<&LbHeaderLookup<'_>>,
) -> bool {
    let Some(api_key) = policy.upstream_auth.api_key.as_ref() else {
        return true;
    };
    let Some(provided) = header_lookup.and_then(|lookup| lookup(api_key.header_name.as_str()))
    else {
        return false;
    };
    let provided = provided.trim();
    !provided.is_empty()
        && api_key
            .keys
            .iter()
            .any(|expected| bool::from(provided.as_bytes().ct_eq(expected.as_bytes())))
}

pub(crate) fn jwt_is_authorized(
    policy: &RuntimeUpstreamPolicy,
    header_lookup: Option<&LbHeaderLookup<'_>>,
) -> bool {
    let Some(jwt) = policy.upstream_auth.jwt.as_ref() else {
        return true;
    };
    let Some(raw) = header_lookup.and_then(|lookup| lookup(http::header::AUTHORIZATION.as_str()))
    else {
        return false;
    };
    let Some(token) = bearer_token_from_authorization_value(&raw) else {
        return false;
    };
    let Some(claims) = validated_hs256_jwt_claims(token.as_str(), jwt, SystemTime::now()) else {
        return false;
    };
    jwt_claims_satisfy_rbac(policy, &claims)
}

pub(crate) fn validated_hs256_jwt_claims(
    token: &str,
    jwt: &RuntimeJwtAuth,
    now: SystemTime,
) -> Option<Value> {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let Ok(header_bytes) = URL_SAFE_NO_PAD.decode(header_b64) else {
        return None;
    };
    let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(payload_b64) else {
        return None;
    };
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signature_b64) else {
        return None;
    };
    let Ok(header) = serde_json::from_slice::<Value>(&header_bytes) else {
        return None;
    };
    if header.get("alg").and_then(Value::as_str) != Some("HS256") {
        return None;
    }

    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(jwt.secret.as_bytes()) else {
        return None;
    };
    mac.update(format!("{header_b64}.{payload_b64}").as_bytes());
    let expected = mac.finalize().into_bytes();
    if expected.len() != signature.len()
        || !bool::from(expected.as_slice().ct_eq(signature.as_slice()))
    {
        return None;
    }

    let Ok(claims) = serde_json::from_slice::<Value>(&payload_bytes) else {
        return None;
    };
    let Ok(now_secs) = now.duration_since(UNIX_EPOCH).map(|value| value.as_secs()) else {
        return None;
    };
    let exp = claims.get("exp").and_then(Value::as_u64)?;
    if now_secs > exp.saturating_add(jwt.clock_skew_secs) {
        return None;
    }
    if claims
        .get("nbf")
        .and_then(Value::as_u64)
        .is_some_and(|nbf| now_secs.saturating_add(jwt.clock_skew_secs) < nbf)
    {
        return None;
    }
    if claims
        .get("iat")
        .and_then(Value::as_u64)
        .is_some_and(|iat| now_secs.saturating_add(jwt.clock_skew_secs) < iat)
    {
        return None;
    }
    if jwt
        .issuer
        .as_deref()
        .is_some_and(|issuer| claims.get("iss").and_then(Value::as_str) != Some(issuer))
    {
        return None;
    }
    if let Some(audience) = jwt.audience.as_deref() {
        let claim_aud = claims.get("aud")?;
        match claim_aud {
            Value::String(value) if value == audience => {}
            Value::Array(values)
                if values
                    .iter()
                    .any(|value| value.as_str().is_some_and(|value| value == audience)) => {}
            _ => return None,
        }
    }

    Some(claims)
}

pub(crate) fn jwt_claims_satisfy_rbac(policy: &RuntimeUpstreamPolicy, claims: &Value) -> bool {
    let scopes = jwt_string_claim_values(claims, &["scope", "scp"]);
    let roles = jwt_string_claim_values(claims, &["roles", "role"]);
    policy
        .upstream_auth
        .required_scopes
        .iter()
        .all(|required| scopes.contains(required))
        && policy
            .upstream_auth
            .required_roles
            .iter()
            .all(|required| roles.contains(required))
}

fn bearer_token_from_authorization_value(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let split = raw.find(char::is_whitespace)?;
    let (scheme, rest) = raw.split_at(split);
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim_start();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

fn jwt_string_claim_values(claims: &Value, claim_names: &[&str]) -> HashSet<String> {
    let mut values = HashSet::new();
    for claim_name in claim_names {
        let Some(value) = claims.get(*claim_name) else {
            continue;
        };
        match value {
            Value::String(value) => {
                for item in value.split_whitespace() {
                    if !item.is_empty() {
                        values.insert(item.to_string());
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    if let Some(item) = item.as_str()
                        && !item.is_empty()
                    {
                        values.insert(item.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    values
}
