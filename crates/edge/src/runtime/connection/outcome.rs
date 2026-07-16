use std::time::Duration;

use http::StatusCode;
use spooky_lb::health::HealthFailureReason;

use crate::OverloadShedReason;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalRouteOutcome {
    Success,
    UpstreamFailure,
    Timeout,
    OverloadShed,
    RateLimited,
    AuthDenied,
    Unrouted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalBackendOutcome {
    Success,
    UpstreamFailure,
    Timeout,
    OverloadShed,
    RateLimited,
    AuthDenied,
    Unrouted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeStatusClass {
    Informational,
    Success,
    Redirection,
    ClientError,
    ServerError,
    Other,
}

impl From<StatusCode> for OutcomeStatusClass {
    fn from(status: StatusCode) -> Self {
        match status.as_u16() {
            100..=199 => Self::Informational,
            200..=299 => Self::Success,
            300..=399 => Self::Redirection,
            400..=499 => Self::ClientError,
            500..=599 => Self::ServerError,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeResultClass {
    HttpStatus(OutcomeStatusClass),
    UpstreamError,
    Timeout,
    Overload,
    RateLimited,
    AuthDenied,
    Unrouted,
    InternalError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthEffectHint {
    None,
    Success,
    Neutral,
    Failure { reason: HealthFailureReason },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomeRouteTarget<'a> {
    pub route: &'a str,
}

impl<'a> OutcomeRouteTarget<'a> {
    pub const UNROUTED: Self = Self { route: "unrouted" };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomeBackendTarget<'a> {
    pub upstream: &'a str,
    pub backend_addr: Option<&'a str>,
    pub backend_index: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestOutcomeInput<'a> {
    pub request_outcome: CanonicalRouteOutcome,
    pub route_target: OutcomeRouteTarget<'a>,
    pub backend_target: Option<OutcomeBackendTarget<'a>>,
    pub elapsed: Duration,
    pub result_class: OutcomeResultClass,
    pub overload_reason: Option<OverloadShedReason>,
    pub health_effect: HealthEffectHint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestOutcomeDecision {
    pub route_outcome: CanonicalRouteOutcome,
    pub backend_outcome: CanonicalBackendOutcome,
    pub overload_reason: Option<OverloadShedReason>,
    pub health_effect: HealthEffectHint,
}
