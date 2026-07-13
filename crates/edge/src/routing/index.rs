use std::collections::HashMap;

use spooky_config::config::Upstream;

use crate::routing::{
    decision::{RouteDecision, RouteDecisionReason, RoutePreference},
    host::{ConfiguredHostPattern, normalize_host_for_routing, parse_configured_host_pattern},
    matcher::{compare_route_candidate, prefer_host_lookup_result, prefer_route_candidate},
    route::{HostLookupResult, HostMatchKind, IndexedRoute, RouteCandidate},
    trie::RouteTrie,
};
pub struct RouteIndex {
    host_tries: HashMap<String, RouteTrie>,
    pub wildcard_host_tries: HashMap<String, RouteTrie>,
    pub default_trie: RouteTrie,
    pub default_max_path_len: usize,
    pub upstream_names: Vec<String>,
    pub upstream_methods: Vec<Option<String>>,
}

impl RouteIndex {
    pub fn from_upstreams(upstreams: &HashMap<String, Upstream>) -> Self {
        let mut host_tries = HashMap::new();
        let mut wildcard_host_tries = HashMap::new();
        let mut default_trie = RouteTrie::default();
        let mut default_max_path_len = 0usize;
        let mut upstream_names = Vec::with_capacity(upstreams.len());
        let mut upstream_methods = Vec::with_capacity(upstreams.len());
        // Build a stable route list first. This keeps tie-breaking deterministic even if
        // upstreams came from a map with non-deterministic iteration order.
        let mut ordered: Vec<(&String, &Upstream)> = upstreams.iter().collect();
        ordered.sort_by_key(|(left, _)| *left);

        for (order, (name, upstream)) in ordered.into_iter().enumerate() {
            let upstream_idx = upstream_names.len();
            upstream_names.push(name.clone());
            upstream_methods.push(
                upstream
                    .route
                    .method
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| value.to_ascii_uppercase()),
            );
            let path_len = upstream
                .route
                .path_prefix
                .as_ref()
                .map(|prefix| prefix.len())
                .unwrap_or(0);

            let route = IndexedRoute {
                upstream_idx,
                path_len,
                host_specific: upstream.route.host.is_some(),
                method_specific: upstream.route.method.is_some(),
                order,
            };

            match upstream.route.host.as_deref() {
                Some(host) => match parse_configured_host_pattern(host) {
                    Some(ConfiguredHostPattern::WildcardSuffix(suffix)) => wildcard_host_tries
                        .entry(suffix)
                        .or_insert_with(RouteTrie::default)
                        .insert(upstream.route.path_prefix.as_deref(), route),
                    Some(ConfiguredHostPattern::Exact(normalized_host)) => host_tries
                        .entry(normalized_host)
                        .or_insert_with(RouteTrie::default)
                        .insert(upstream.route.path_prefix.as_deref(), route),
                    None => {}
                },
                None => {
                    default_max_path_len = default_max_path_len.max(path_len);
                    default_trie.insert(upstream.route.path_prefix.as_deref(), route);
                }
            }
        }

        Self {
            host_tries,
            wildcard_host_tries,
            default_trie,
            default_max_path_len,
            upstream_names,
            upstream_methods,
        }
    }

    pub fn lookup<'a>(&'a self, path: &str, host: Option<&str>) -> Option<&'a str> {
        self.lookup_for_method(path, host, None)
    }

    pub fn lookup_for_method<'a>(
        &'a self,
        path: &str,
        host: Option<&str>,
        method: Option<&str>,
    ) -> Option<&'a str> {
        let host_best = host
            .and_then(normalize_host_for_routing)
            .and_then(|normalized_host| {
                self.lookup_host_candidate(path, normalized_host.as_ref(), method)
            });

        if let Some(best) = host_best
            && best.candidate.route.path_len >= self.default_max_path_len
        {
            return Some(self.upstream_names[best.candidate.route.upstream_idx].as_str());
        }

        let best = prefer_route_candidate(
            self.default_trie
                .longest_prefix(path, method, &self.upstream_methods)
                .map(|route| RouteCandidate {
                    route,
                    host_match_kind: HostMatchKind::Default,
                    wildcard_suffix_len: 0,
                }),
            host_best.map(|value| value.candidate),
        );
        best.map(|candidate| self.upstream_names[candidate.route.upstream_idx].as_str())
    }

    #[allow(dead_code)]
    pub fn lookup_with_decision<'a>(
        &'a self,
        path: &str,
        host: Option<&str>,
    ) -> Option<RouteDecision<'a>> {
        self.lookup_with_decision_for_method(path, host, None)
    }

    pub fn lookup_with_decision_for_method<'a>(
        &'a self,
        path: &str,
        host: Option<&str>,
        method: Option<&str>,
    ) -> Option<RouteDecision<'a>> {
        let host_best = host
            .and_then(normalize_host_for_routing)
            .and_then(|normalized_host| {
                self.lookup_host_candidate(path, normalized_host.as_ref(), method)
            });

        let default_best = self
            .default_trie
            .longest_prefix(path, method, &self.upstream_methods)
            .map(|route| RouteCandidate {
                route,
                host_match_kind: HostMatchKind::Default,
                wildcard_suffix_len: 0,
            });
        if let Some(best) = host_best
            && best.candidate.route.path_len >= self.default_max_path_len
        {
            let fallback_reason = match default_best {
                None => RouteDecisionReason::HostTrieNoDefault,
                Some(default_route) => {
                    match compare_route_candidate(default_route, best.candidate) {
                        RoutePreference::TakeCandidateHostSpecific => {
                            RouteDecisionReason::HostSpecificTieBreak
                        }
                        RoutePreference::TakeCandidateExactHost => {
                            RouteDecisionReason::ExactHostTieBreak
                        }
                        RoutePreference::TakeCandidateWildcardSpecificity => {
                            RouteDecisionReason::WildcardSpecificityTieBreak
                        }
                        RoutePreference::TakeCandidateMethodSpecific => {
                            RouteDecisionReason::MethodSpecificTieBreak
                        }
                        RoutePreference::TakeCandidateLexicalOrder => {
                            RouteDecisionReason::LexicalTieBreak
                        }
                        _ => RouteDecisionReason::HostPathLongerOrEqual,
                    }
                }
            };
            return Some(RouteDecision {
                upstream: self.upstream_names[best.candidate.route.upstream_idx].as_str(),
                matched_path_len: best.candidate.route.path_len,
                host_specific: best.candidate.route.host_specific,
                reason: best.decision_reason.unwrap_or(fallback_reason),
            });
        }

        match (default_best, host_best) {
            (Some(default_route), None) => Some(RouteDecision {
                upstream: self.upstream_names[default_route.route.upstream_idx].as_str(),
                matched_path_len: default_route.route.path_len,
                host_specific: default_route.route.host_specific,
                reason: RouteDecisionReason::DefaultPathLonger,
            }),
            (None, Some(host_route)) => Some(RouteDecision {
                upstream: self.upstream_names[host_route.candidate.route.upstream_idx].as_str(),
                matched_path_len: host_route.candidate.route.path_len,
                host_specific: host_route.candidate.route.host_specific,
                reason: host_route
                    .decision_reason
                    .unwrap_or(RouteDecisionReason::HostTrieNoDefault),
            }),
            (Some(current), Some(candidate)) => {
                let preference = compare_route_candidate(current, candidate.candidate);
                let fallback_reason = match preference {
                    RoutePreference::TakeCandidatePathLen => {
                        RouteDecisionReason::HostPathLongerOrEqual
                    }
                    RoutePreference::TakeCandidateHostSpecific => {
                        RouteDecisionReason::HostSpecificTieBreak
                    }
                    RoutePreference::TakeCandidateExactHost => {
                        RouteDecisionReason::ExactHostTieBreak
                    }
                    RoutePreference::TakeCandidateWildcardSpecificity => {
                        RouteDecisionReason::WildcardSpecificityTieBreak
                    }
                    RoutePreference::TakeCandidateMethodSpecific => {
                        RouteDecisionReason::MethodSpecificTieBreak
                    }
                    RoutePreference::TakeCandidateLexicalOrder => {
                        RouteDecisionReason::LexicalTieBreak
                    }
                    RoutePreference::KeepCurrent => RouteDecisionReason::DefaultPathLonger,
                };
                let selected = match preference {
                    RoutePreference::KeepCurrent => current,
                    _ => candidate.candidate,
                };
                Some(RouteDecision {
                    upstream: self.upstream_names[selected.route.upstream_idx].as_str(),
                    matched_path_len: selected.route.path_len,
                    host_specific: selected.route.host_specific,
                    reason: if selected == candidate.candidate {
                        candidate.decision_reason.unwrap_or(fallback_reason)
                    } else {
                        fallback_reason
                    },
                })
            }
            (None, None) => None,
        }
    }

    fn lookup_host_candidate(
        &self,
        path: &str,
        normalized_host: &str,
        method: Option<&str>,
    ) -> Option<HostLookupResult> {
        let exact_best = self
            .host_tries
            .get(normalized_host)
            .and_then(|host_trie| {
                host_trie.longest_prefix_with_reason(path, method, &self.upstream_methods)
            })
            .map(|(route, decision_reason)| HostLookupResult {
                candidate: RouteCandidate {
                    route,
                    host_match_kind: HostMatchKind::Exact,
                    wildcard_suffix_len: 0,
                },
                decision_reason,
            });

        let mut wildcard_best: Option<HostLookupResult> = None;
        let mut remaining = normalized_host;
        while let Some(dot_idx) = remaining.find('.') {
            let suffix = &remaining[dot_idx + 1..];
            if suffix.is_empty() {
                break;
            }

            if let Some(trie) = self.wildcard_host_tries.get(suffix) {
                let candidate = trie
                    .longest_prefix_with_reason(path, method, &self.upstream_methods)
                    .map(|(route, decision_reason)| HostLookupResult {
                        candidate: RouteCandidate {
                            route,
                            host_match_kind: HostMatchKind::Wildcard,
                            wildcard_suffix_len: suffix.len(),
                        },
                        decision_reason,
                    });
                wildcard_best = prefer_host_lookup_result(wildcard_best, candidate);
            }
            remaining = suffix;
        }

        prefer_host_lookup_result(wildcard_best, exact_best)
    }
}
