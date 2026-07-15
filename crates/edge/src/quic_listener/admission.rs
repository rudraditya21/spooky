use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use http::StatusCode;
use serde_json::Value;
use sha2::Sha256;
use spooky_config::runtime::{RuntimeJwtAuth, RuntimeUpstreamPolicy};
use spooky_lb::upstream_pool::UpstreamPool;
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use super::{LbHeaderLookup, QUICListener};
use crate::{
    RouteOutcome,
    metrics::OverloadShedReason,
    resilience::{
        adaptive_admission::AdaptivePermit,
        brownout::BrownoutController,
        route_queue::{RouteQueuePermit, RouteQueueRejection},
        runtime::RuntimeResilience,
        scoped_rate_limit::{ScopedRateLimitRule, ScopedRateLimiters},
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthChallengeKind {
    ApiKey,
    Bearer,
}

impl AuthChallengeKind {
    pub(super) fn as_www_authenticate(self) -> &'static str {
        match self {
            Self::ApiKey => "ApiKey",
            Self::Bearer => "Bearer",
        }
    }
}

impl OverloadDecisionReason {
    pub(super) fn metrics_reason(self) -> OverloadShedReason {
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
pub(super) struct UnauthorizedDecision {
    pub(super) challenge: AuthChallengeKind,
    pub(super) status: StatusCode,
    pub(super) body: &'static [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RateLimitedDecision {
    pub(super) rule_name: String,
    pub(super) route: String,
    pub(super) status: StatusCode,
    pub(super) body: &'static [u8],
    pub(super) retry_after_seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OverloadDecisionReason {
    Brownout,
    AdaptiveAdmission,
    RouteCap,
    RouteGlobalCap,
    GlobalInflight,
    UpstreamInflight,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OverloadDecision {
    pub(super) reason: OverloadDecisionReason,
    pub(super) status: StatusCode,
    pub(super) body: &'static [u8],
    pub(super) retry_after_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AdmissionRejectionResponse {
    pub(super) status: StatusCode,
    pub(super) body: &'static [u8],
    pub(super) www_authenticate: Option<&'static str>,
    pub(super) retry_after_seconds: Option<u32>,
}

#[derive(Debug, Clone)]
pub(super) struct PostAuthAdmissionFailure {
    pub(super) status: StatusCode,
    pub(super) body: &'static [u8],
    pub(super) overload_reason: Option<OverloadDecisionReason>,
    pub(super) route_outcome: Option<RouteOutcome>,
    pub(super) observe_adaptive_overload: bool,
}

pub(super) struct PostAuthAdmissionReady {
    pub(super) backend_index: usize,
    pub(super) upstream_pool: Arc<RwLock<UpstreamPool>>,
    pub(super) global_permit: OwnedSemaphorePermit,
    pub(super) upstream_permit: OwnedSemaphorePermit,
    pub(super) adaptive_permit: AdaptivePermit,
    pub(super) route_queue_permit: RouteQueuePermit,
    pub(super) waited_for_global_permit: bool,
    pub(super) waited_for_upstream_permit: bool,
}

#[derive(Debug, Clone)]
pub(super) enum PostAuthAdmissionRejection {
    Overloaded(OverloadDecision),
    Failed(PostAuthAdmissionFailure),
}

pub(super) enum PostAuthAdmissionExecution {
    Ready(PostAuthAdmissionReady),
    Rejected(PostAuthAdmissionRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AdmissionPolicyDecision {
    AdmitReady,
    Unauthorized(UnauthorizedDecision),
    RateLimited(RateLimitedDecision),
    Overloaded(OverloadDecision),
}

#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate_forwarding_pre_admission_policy<F>(
    policy: &RuntimeUpstreamPolicy,
    header_lookup: Option<&LbHeaderLookup<'_>>,
    brownout: &BrownoutController,
    inflight_percent: u8,
    route: &str,
    retry_after_seconds: u32,
    scoped_rate_limits: &ScopedRateLimiters,
    key_for_rule: F,
) -> AdmissionPolicyDecision
where
    F: FnMut(&ScopedRateLimitRule) -> Option<String>,
{
    let auth = evaluate_local_auth_policy(policy, header_lookup);
    if auth != AdmissionPolicyDecision::AdmitReady {
        return auth;
    }

    let brownout = evaluate_brownout_policy(brownout, inflight_percent, route, retry_after_seconds);
    if brownout != AdmissionPolicyDecision::AdmitReady {
        return brownout;
    }

    evaluate_scoped_rate_limit_policy(scoped_rate_limits, route, key_for_rule)
}

pub(super) fn evaluate_local_auth_policy(
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

pub(super) fn evaluate_scoped_rate_limit_policy<F>(
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

pub(super) fn evaluate_brownout_policy(
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

fn overload_decision(
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

fn overload_decision_for_route_queue_rejection(
    rejection: RouteQueueRejection,
    retry_after_seconds: u32,
) -> AdmissionPolicyDecision {
    let reason = match rejection {
        RouteQueueRejection::GlobalCap => OverloadDecisionReason::RouteGlobalCap,
        RouteQueueRejection::RouteCap => OverloadDecisionReason::RouteCap,
    };
    overload_decision(reason, retry_after_seconds)
}

pub(super) fn admission_rejection_response(
    decision: &AdmissionPolicyDecision,
) -> Option<AdmissionRejectionResponse> {
    match decision {
        AdmissionPolicyDecision::AdmitReady => None,
        AdmissionPolicyDecision::Unauthorized(decision) => Some(AdmissionRejectionResponse {
            status: decision.status,
            body: decision.body,
            www_authenticate: Some(decision.challenge.as_www_authenticate()),
            retry_after_seconds: None,
        }),
        AdmissionPolicyDecision::RateLimited(decision) => Some(AdmissionRejectionResponse {
            status: decision.status,
            body: decision.body,
            www_authenticate: None,
            retry_after_seconds: Some(decision.retry_after_seconds.max(1)),
        }),
        AdmissionPolicyDecision::Overloaded(decision) => Some(AdmissionRejectionResponse {
            status: decision.status,
            body: decision.body,
            www_authenticate: None,
            retry_after_seconds: Some(decision.retry_after_seconds.max(1)),
        }),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_forwarding_post_auth_admission(
    resilience: &RuntimeResilience,
    upstream_name: &str,
    upstream_pool: Option<&Arc<RwLock<UpstreamPool>>>,
    backend_index: Option<usize>,
    pending_forward_backend_index: usize,
    upstream_inflight: &HashMap<String, Arc<Semaphore>>,
    global_inflight: Arc<Semaphore>,
    inflight_acquire_wait: Duration,
) -> PostAuthAdmissionExecution {
    let adaptive_permit = match resilience.adaptive_admission.try_acquire() {
        Some(permit) => permit,
        None => {
            return PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Overloaded(
                overloaded(
                    OverloadDecisionReason::AdaptiveAdmission,
                    resilience.shed_retry_after_seconds,
                ),
            ));
        }
    };

    let route_queue_permit = match resilience.route_queue.try_acquire(upstream_name) {
        Ok(permit) => permit,
        Err(rejection) => {
            return PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Overloaded(
                overload_from_route_queue_rejection(rejection, resilience.shed_retry_after_seconds),
            ));
        }
    };

    let (global_permit, waited_for_global_permit) =
        match try_acquire_owned_with_micro_wait(global_inflight, inflight_acquire_wait) {
            Ok(value) => value,
            Err(_) => {
                return PostAuthAdmissionExecution::Rejected(
                    PostAuthAdmissionRejection::Overloaded(overloaded(
                        OverloadDecisionReason::GlobalInflight,
                        resilience.shed_retry_after_seconds,
                    )),
                );
            }
        };

    let (upstream_permit, waited_for_upstream_permit) =
        match upstream_inflight.get(upstream_name).cloned() {
            Some(semaphore) => {
                match try_acquire_owned_with_micro_wait(semaphore, inflight_acquire_wait) {
                    Ok(value) => value,
                    Err(_) => {
                        return PostAuthAdmissionExecution::Rejected(
                            PostAuthAdmissionRejection::Overloaded(overloaded(
                                OverloadDecisionReason::UpstreamInflight,
                                resilience.shed_retry_after_seconds,
                            )),
                        );
                    }
                }
            }
            None => {
                return PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Failed(
                    PostAuthAdmissionFailure {
                        status: StatusCode::SERVICE_UNAVAILABLE,
                        body: b"upstream admission limiter unavailable\n",
                        overload_reason: Some(OverloadDecisionReason::UpstreamInflight),
                        route_outcome: Some(RouteOutcome::OverloadShed),
                        observe_adaptive_overload: true,
                    },
                ));
            }
        };

    let backend_index = backend_index.unwrap_or(pending_forward_backend_index);
    let Some(upstream_pool) = upstream_pool.cloned() else {
        return PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Failed(
            PostAuthAdmissionFailure {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body: b"missing upstream pool\n",
                overload_reason: None,
                route_outcome: None,
                observe_adaptive_overload: false,
            },
        ));
    };

    let request_started = upstream_pool
        .read()
        .ok()
        .is_some_and(|pool| pool.begin_request_if_healthy(backend_index));
    if !request_started {
        return PostAuthAdmissionExecution::Rejected(PostAuthAdmissionRejection::Failed(
            PostAuthAdmissionFailure {
                status: StatusCode::SERVICE_UNAVAILABLE,
                body: b"selected backend no longer healthy\n",
                overload_reason: None,
                route_outcome: Some(RouteOutcome::Failure),
                observe_adaptive_overload: false,
            },
        ));
    }

    PostAuthAdmissionExecution::Ready(PostAuthAdmissionReady {
        backend_index,
        upstream_pool,
        global_permit,
        upstream_permit,
        adaptive_permit,
        route_queue_permit,
        waited_for_global_permit,
        waited_for_upstream_permit,
    })
}

pub(super) fn try_acquire_owned_with_micro_wait(
    semaphore: Arc<Semaphore>,
    _wait_budget: Duration,
) -> Result<(OwnedSemaphorePermit, bool), TryAcquireError> {
    // Never block the synchronous QUIC worker thread: acquire immediately or
    // shed. A blocking wait here stalls every connection on the shard.
    semaphore.try_acquire_owned().map(|permit| (permit, false))
}

pub(super) fn api_key_is_authorized(
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

pub(super) fn jwt_is_authorized(
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
    let Some(token) = QUICListener::bearer_token_from_authorization_value(&raw) else {
        return false;
    };
    let Some(claims) = validated_hs256_jwt_claims(token.as_str(), jwt, SystemTime::now()) else {
        return false;
    };
    jwt_claims_satisfy_rbac(policy, &claims)
}

pub(super) fn validated_hs256_jwt_claims(
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

pub(super) fn jwt_claims_satisfy_rbac(policy: &RuntimeUpstreamPolicy, claims: &Value) -> bool {
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

fn overloaded(reason: OverloadDecisionReason, retry_after_seconds: u32) -> OverloadDecision {
    match overload_decision(reason, retry_after_seconds) {
        AdmissionPolicyDecision::Overloaded(decision) => decision,
        _ => unreachable!("overload decision helper always returns overloaded"),
    }
}

fn overload_from_route_queue_rejection(
    rejection: RouteQueueRejection,
    retry_after_seconds: u32,
) -> OverloadDecision {
    match overload_decision_for_route_queue_rejection(rejection, retry_after_seconds) {
        AdmissionPolicyDecision::Overloaded(decision) => decision,
        _ => unreachable!("route queue overload helper always returns overloaded"),
    }
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
