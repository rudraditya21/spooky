use crate::routing::{
    decision::{RouteDecisionReason, RoutePreference, route_preference_reason},
    route::{HostLookupResult, HostMatchKind, IndexedRoute, RouteCandidate},
    util::prefix_boundary_matches,
};

#[inline(always)]
fn compare_route(current: IndexedRoute, candidate: IndexedRoute) -> RoutePreference {
    if candidate.path_len > current.path_len {
        RoutePreference::TakeCandidatePathLen
    } else if candidate.path_len == current.path_len
        && candidate.host_specific
        && !current.host_specific
    {
        RoutePreference::TakeCandidateHostSpecific
    } else if candidate.path_len == current.path_len
        && candidate.host_specific == current.host_specific
        && candidate.method_specific
        && !current.method_specific
    {
        RoutePreference::TakeCandidateMethodSpecific
    } else if candidate.path_len == current.path_len
        && candidate.host_specific == current.host_specific
        && candidate.method_specific == current.method_specific
        && candidate.order < current.order
    {
        RoutePreference::TakeCandidateLexicalOrder
    } else {
        RoutePreference::KeepCurrent
    }
}

#[inline(always)]
pub fn compare_route_candidate(
    current: RouteCandidate,
    candidate: RouteCandidate,
) -> RoutePreference {
    if candidate.route.path_len > current.route.path_len {
        RoutePreference::TakeCandidatePathLen
    } else if candidate.route.path_len == current.route.path_len
        && candidate.route.host_specific
        && !current.route.host_specific
    {
        RoutePreference::TakeCandidateHostSpecific
    } else if candidate.route.path_len == current.route.path_len
        && candidate.host_match_kind > current.host_match_kind
    {
        RoutePreference::TakeCandidateExactHost
    } else if candidate.route.path_len == current.route.path_len
        && candidate.host_match_kind == HostMatchKind::Wildcard
        && current.host_match_kind == HostMatchKind::Wildcard
        && candidate.wildcard_suffix_len > current.wildcard_suffix_len
    {
        RoutePreference::TakeCandidateWildcardSpecificity
    } else if candidate.route.path_len == current.route.path_len
        && candidate.host_match_kind == current.host_match_kind
        && candidate.route.method_specific
        && !current.route.method_specific
    {
        RoutePreference::TakeCandidateMethodSpecific
    } else if candidate.route.path_len == current.route.path_len
        && candidate.host_match_kind == current.host_match_kind
        && candidate.route.method_specific == current.route.method_specific
        && candidate.route.order < current.route.order
    {
        RoutePreference::TakeCandidateLexicalOrder
    } else {
        RoutePreference::KeepCurrent
    }
}

#[inline(always)]
pub fn prefer_route_candidate(
    current: Option<RouteCandidate>,
    candidate: Option<RouteCandidate>,
) -> Option<RouteCandidate> {
    match (current, candidate) {
        (None, None) => None,
        (Some(route), None) | (None, Some(route)) => Some(route),
        (Some(current), Some(candidate)) => match compare_route_candidate(current, candidate) {
            RoutePreference::KeepCurrent => Some(current),
            RoutePreference::TakeCandidatePathLen
            | RoutePreference::TakeCandidateHostSpecific
            | RoutePreference::TakeCandidateExactHost
            | RoutePreference::TakeCandidateWildcardSpecificity
            | RoutePreference::TakeCandidateMethodSpecific
            | RoutePreference::TakeCandidateLexicalOrder => Some(candidate),
        },
    }
}

#[inline(always)]
pub fn prefer_host_lookup_result(
    current: Option<HostLookupResult>,
    candidate: Option<HostLookupResult>,
) -> Option<HostLookupResult> {
    match (current, candidate) {
        (None, None) => None,
        (Some(route), None) => Some(route),
        (None, Some(candidate)) => Some(candidate),
        (Some(current), Some(candidate)) => {
            match compare_route_candidate(current.candidate, candidate.candidate) {
                RoutePreference::KeepCurrent => {
                    let decision_reason = current
                        .decision_reason
                        .or(candidate.decision_reason)
                        .or_else(|| {
                            route_preference_reason(compare_route_candidate(
                                candidate.candidate,
                                current.candidate,
                            ))
                        });
                    Some(HostLookupResult {
                        candidate: current.candidate,
                        decision_reason,
                    })
                }
                preference => Some(HostLookupResult {
                    candidate: candidate.candidate,
                    decision_reason: candidate
                        .decision_reason
                        .or_else(|| route_preference_reason(preference)),
                }),
            }
        }
    }
}

fn route_matches_method(
    route: IndexedRoute,
    method: Option<&str>,
    upstream_methods: &[Option<String>],
) -> bool {
    let Some(method) = method else {
        return true;
    };
    match upstream_methods
        .get(route.upstream_idx)
        .and_then(|value| value.as_deref())
    {
        Some(expected) => expected.eq_ignore_ascii_case(method),
        None => true,
    }
}

pub fn best_matching_route_with_reason(
    routes: &[IndexedRoute],
    path: &str,
    method: Option<&str>,
    upstream_methods: &[Option<String>],
    current: Option<(IndexedRoute, Option<RouteDecisionReason>)>,
) -> Option<(IndexedRoute, Option<RouteDecisionReason>)> {
    let mut best = current;
    for route in routes.iter().copied() {
        if !prefix_boundary_matches(path, route.path_len) {
            continue;
        }
        if !route_matches_method(route, method, upstream_methods) {
            continue;
        }
        best = match best {
            None => Some((route, None)),
            Some((current_route, current_reason)) => match compare_route(current_route, route) {
                RoutePreference::KeepCurrent => Some((
                    current_route,
                    current_reason
                        .or_else(|| route_preference_reason(compare_route(route, current_route))),
                )),
                preference => Some((route, route_preference_reason(preference))),
            },
        };
    }
    best
}
