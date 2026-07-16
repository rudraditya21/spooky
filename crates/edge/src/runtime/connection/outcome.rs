use std::time::Duration;

use http::StatusCode;
use spooky_errors::{PoolError, ProxyError};
use spooky_lb::health::HealthFailureReason;

use crate::{OverloadShedReason, RouteOutcome};

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

#[derive(Clone, Copy, Debug)]
pub struct RequestMetricsObservation<'a> {
    pub route_target: OutcomeRouteTarget<'a>,
    pub backend_target: Option<OutcomeBackendTarget<'a>>,
    pub elapsed: Duration,
    pub status: Option<u16>,
    pub metrics_outcome: RouteOutcome,
    pub overload_reason: Option<OverloadShedReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionOutcomeClass {
    AuthDenied,
    RateLimited,
    OverloadShed {
        reason: Option<OverloadShedReason>,
    },
    Failed {
        timed_out: bool,
    },
}

impl CanonicalRouteOutcome {
    pub fn as_metrics_outcome(self) -> RouteOutcome {
        match self {
            Self::Success => RouteOutcome::Success,
            Self::UpstreamFailure | Self::AuthDenied | Self::Unrouted => RouteOutcome::Failure,
            Self::Timeout => RouteOutcome::Timeout,
            Self::OverloadShed => RouteOutcome::OverloadShed,
            Self::RateLimited => RouteOutcome::RateLimited,
        }
    }
}

impl CanonicalBackendOutcome {
    fn from_route_outcome(outcome: CanonicalRouteOutcome) -> Self {
        match outcome {
            CanonicalRouteOutcome::Success => Self::Success,
            CanonicalRouteOutcome::UpstreamFailure => Self::UpstreamFailure,
            CanonicalRouteOutcome::Timeout => Self::Timeout,
            CanonicalRouteOutcome::OverloadShed => Self::OverloadShed,
            CanonicalRouteOutcome::RateLimited => Self::RateLimited,
            CanonicalRouteOutcome::AuthDenied => Self::AuthDenied,
            CanonicalRouteOutcome::Unrouted => Self::Unrouted,
        }
    }
}

fn health_effect_from_status_class(status_class: OutcomeStatusClass) -> HealthEffectHint {
    match status_class {
        OutcomeStatusClass::ServerError => HealthEffectHint::Failure {
            reason: HealthFailureReason::HttpStatus5xx,
        },
        OutcomeStatusClass::ClientError => HealthEffectHint::Neutral,
        OutcomeStatusClass::Informational
        | OutcomeStatusClass::Success
        | OutcomeStatusClass::Redirection => HealthEffectHint::Success,
        OutcomeStatusClass::Other => HealthEffectHint::None,
    }
}

pub fn classify_status_outcome(status: StatusCode) -> RequestOutcomeDecision {
    let status_class = OutcomeStatusClass::from(status);
    let route_outcome = match status_class {
        OutcomeStatusClass::Informational
        | OutcomeStatusClass::Success
        | OutcomeStatusClass::Redirection => CanonicalRouteOutcome::Success,
        OutcomeStatusClass::ClientError => CanonicalRouteOutcome::UpstreamFailure,
        OutcomeStatusClass::ServerError => CanonicalRouteOutcome::UpstreamFailure,
        OutcomeStatusClass::Other => CanonicalRouteOutcome::UpstreamFailure,
    };

    RequestOutcomeDecision {
        route_outcome,
        backend_outcome: CanonicalBackendOutcome::from_route_outcome(route_outcome),
        overload_reason: None,
        health_effect: health_effect_from_status_class(status_class),
    }
}

pub fn classify_proxy_error_outcome(
    err: &ProxyError,
    overload_reason: Option<OverloadShedReason>,
) -> RequestOutcomeDecision {
    let (route_outcome, health_effect) = match err {
        ProxyError::Timeout => (
            CanonicalRouteOutcome::Timeout,
            HealthEffectHint::Failure {
                reason: HealthFailureReason::Timeout,
            },
        ),
        ProxyError::Pool(PoolError::BackendOverloaded(_))
        | ProxyError::Pool(PoolError::CircuitOpen(_)) => {
            (CanonicalRouteOutcome::OverloadShed, HealthEffectHint::None)
        }
        ProxyError::Pool(PoolError::InflightLimiterClosed)
        | ProxyError::Pool(PoolError::UnknownBackend(_)) => {
            (CanonicalRouteOutcome::UpstreamFailure, HealthEffectHint::None)
        }
        ProxyError::Pool(PoolError::Send(_)) => (
            CanonicalRouteOutcome::UpstreamFailure,
            HealthEffectHint::Failure {
                reason: HealthFailureReason::Transport,
            },
        ),
        ProxyError::Transport(_) | ProxyError::Protocol(_) => (
            CanonicalRouteOutcome::UpstreamFailure,
            HealthEffectHint::Failure {
                reason: HealthFailureReason::Transport,
            },
        ),
        ProxyError::Tls(_) => (CanonicalRouteOutcome::UpstreamFailure, HealthEffectHint::None),
        ProxyError::Bridge(_) => (CanonicalRouteOutcome::UpstreamFailure, HealthEffectHint::None),
    };

    RequestOutcomeDecision {
        route_outcome,
        backend_outcome: CanonicalBackendOutcome::from_route_outcome(route_outcome),
        overload_reason,
        health_effect,
    }
}

pub fn classify_admission_outcome(outcome: AdmissionOutcomeClass) -> RequestOutcomeDecision {
    let (route_outcome, overload_reason) = match outcome {
        AdmissionOutcomeClass::AuthDenied => (CanonicalRouteOutcome::AuthDenied, None),
        AdmissionOutcomeClass::RateLimited => (CanonicalRouteOutcome::RateLimited, None),
        AdmissionOutcomeClass::OverloadShed { reason } => {
            (CanonicalRouteOutcome::OverloadShed, reason)
        }
        AdmissionOutcomeClass::Failed { timed_out } => (
            if timed_out {
                CanonicalRouteOutcome::Timeout
            } else {
                CanonicalRouteOutcome::UpstreamFailure
            },
            None,
        ),
    };

    RequestOutcomeDecision {
        route_outcome,
        backend_outcome: CanonicalBackendOutcome::from_route_outcome(route_outcome),
        overload_reason,
        health_effect: HealthEffectHint::None,
    }
}

pub fn classify_request_outcome(input: RequestOutcomeInput<'_>) -> RequestOutcomeDecision {
    let RequestOutcomeInput {
        request_outcome,
        result_class,
        overload_reason,
        health_effect,
        ..
    } = input;

    let decision = match result_class {
        OutcomeResultClass::HttpStatus(status_class) => RequestOutcomeDecision {
            route_outcome: match status_class {
                OutcomeStatusClass::Informational
                | OutcomeStatusClass::Success
                | OutcomeStatusClass::Redirection => CanonicalRouteOutcome::Success,
                OutcomeStatusClass::ClientError
                | OutcomeStatusClass::ServerError
                | OutcomeStatusClass::Other => request_outcome,
            },
            backend_outcome: CanonicalBackendOutcome::from_route_outcome(request_outcome),
            overload_reason,
            health_effect: health_effect_from_status_class(status_class),
        },
        OutcomeResultClass::UpstreamError | OutcomeResultClass::InternalError => {
            RequestOutcomeDecision {
                route_outcome: request_outcome,
                backend_outcome: CanonicalBackendOutcome::from_route_outcome(request_outcome),
                overload_reason,
                health_effect,
            }
        }
        OutcomeResultClass::Timeout => RequestOutcomeDecision {
            route_outcome: CanonicalRouteOutcome::Timeout,
            backend_outcome: CanonicalBackendOutcome::Timeout,
            overload_reason,
            health_effect,
        },
        OutcomeResultClass::Overload => RequestOutcomeDecision {
            route_outcome: CanonicalRouteOutcome::OverloadShed,
            backend_outcome: CanonicalBackendOutcome::OverloadShed,
            overload_reason,
            health_effect,
        },
        OutcomeResultClass::RateLimited => RequestOutcomeDecision {
            route_outcome: CanonicalRouteOutcome::RateLimited,
            backend_outcome: CanonicalBackendOutcome::RateLimited,
            overload_reason,
            health_effect,
        },
        OutcomeResultClass::AuthDenied => RequestOutcomeDecision {
            route_outcome: CanonicalRouteOutcome::AuthDenied,
            backend_outcome: CanonicalBackendOutcome::AuthDenied,
            overload_reason,
            health_effect,
        },
        OutcomeResultClass::Unrouted => RequestOutcomeDecision {
            route_outcome: CanonicalRouteOutcome::Unrouted,
            backend_outcome: CanonicalBackendOutcome::Unrouted,
            overload_reason,
            health_effect,
        },
    };

    RequestOutcomeDecision {
        route_outcome: decision.route_outcome,
        backend_outcome: decision.backend_outcome,
        overload_reason: decision.overload_reason,
        health_effect: decision.health_effect,
    }
}

pub fn record_request_metrics_observation(
    metrics: &crate::Metrics,
    observation: RequestMetricsObservation<'_>,
) {
    let RequestMetricsObservation {
        route_target,
        backend_target,
        elapsed,
        status,
        metrics_outcome,
        overload_reason,
    } = observation;

    if !matches!(metrics_outcome, RouteOutcome::Success) {
        metrics.inc_failure();
    }

    if matches!(metrics_outcome, RouteOutcome::OverloadShed) {
        if let Some(reason) = overload_reason {
            metrics.inc_overload_shed_reason(reason);
        } else {
            metrics.inc_overload_shed();
        }
    }

    metrics.record_route(route_target.route, elapsed, metrics_outcome);
    metrics.record_request_result(
        route_target.route,
        backend_target.and_then(|target| target.backend_addr),
        status,
        metrics_outcome,
        elapsed,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_success_status_as_success() {
        let decision = classify_status_outcome(StatusCode::OK);
        assert_eq!(decision.route_outcome, CanonicalRouteOutcome::Success);
        assert_eq!(decision.backend_outcome, CanonicalBackendOutcome::Success);
        assert_eq!(decision.health_effect, HealthEffectHint::Success);
    }

    #[test]
    fn classifies_timeout_proxy_error_as_timeout() {
        let decision = classify_proxy_error_outcome(&ProxyError::Timeout, None);
        assert_eq!(decision.route_outcome, CanonicalRouteOutcome::Timeout);
        assert_eq!(decision.backend_outcome, CanonicalBackendOutcome::Timeout);
        assert_eq!(
            decision.health_effect,
            HealthEffectHint::Failure {
                reason: HealthFailureReason::Timeout,
            }
        );
    }

    #[test]
    fn classifies_overload_admission_outcome() {
        let decision = classify_admission_outcome(AdmissionOutcomeClass::OverloadShed {
            reason: Some(OverloadShedReason::GlobalInflight),
        });
        assert_eq!(decision.route_outcome, CanonicalRouteOutcome::OverloadShed);
        assert_eq!(decision.backend_outcome, CanonicalBackendOutcome::OverloadShed);
        assert_eq!(decision.overload_reason, Some(OverloadShedReason::GlobalInflight));
    }
}
