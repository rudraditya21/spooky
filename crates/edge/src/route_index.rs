use std::borrow::Cow;
use std::collections::HashMap;

use spooky_config::config::Upstream;

#[inline(always)]
fn parsed_host_for_routing(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let host = if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        &rest[..end]
    } else if let Some((candidate_host, candidate_port)) = trimmed.rsplit_once(':') {
        if !candidate_host.contains(':') && candidate_port.chars().all(|c| c.is_ascii_digit()) {
            candidate_host
        } else {
            trimmed
        }
    } else {
        trimmed
    };

    let host = host.trim_end_matches('.');
    if host.is_empty() { None } else { Some(host) }
}

#[inline(always)]
fn host_has_uppercase_ascii(host: &str) -> bool {
    host.bytes().any(|byte| byte.is_ascii_uppercase())
}

pub(crate) fn normalize_host_for_routing(raw: &str) -> Option<Cow<'_, str>> {
    let host = parsed_host_for_routing(raw)?;
    if host_has_uppercase_ascii(host) {
        Some(Cow::Owned(host.to_ascii_lowercase()))
    } else {
        Some(Cow::Borrowed(host))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ConfiguredHostPattern {
    Exact(String),
    WildcardSuffix(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfiguredHostPatternRef<'a> {
    Exact(&'a str),
    WildcardSuffix(&'a str),
}

fn parse_configured_host_pattern(raw: &str) -> Option<ConfiguredHostPattern> {
    let normalized = normalize_host_for_routing(raw)?;
    let Some(wildcard_suffix) = normalized.strip_prefix("*.") else {
        return Some(ConfiguredHostPattern::Exact(normalized.into_owned()));
    };
    if wildcard_suffix.is_empty() || wildcard_suffix.contains('*') {
        return Some(ConfiguredHostPattern::Exact(normalized.into_owned()));
    }
    Some(ConfiguredHostPattern::WildcardSuffix(
        wildcard_suffix.to_string(),
    ))
}

fn parse_configured_host_pattern_ref(raw: &str) -> Option<ConfiguredHostPatternRef<'_>> {
    let host = parsed_host_for_routing(raw)?;
    let Some(wildcard_suffix) = host.strip_prefix("*.") else {
        return Some(ConfiguredHostPatternRef::Exact(host));
    };
    if wildcard_suffix.is_empty() || wildcard_suffix.contains('*') {
        return Some(ConfiguredHostPatternRef::Exact(host));
    }
    Some(ConfiguredHostPatternRef::WildcardSuffix(wildcard_suffix))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum HostMatchKind {
    Default,
    Wildcard,
    Exact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RouteCandidate {
    route: IndexedRoute,
    host_match_kind: HostMatchKind,
    wildcard_suffix_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostLookupResult {
    candidate: RouteCandidate,
    decision_reason: Option<RouteDecisionReason>,
}

/// Route precedence (deterministic):
/// 1) Longest matching path_prefix wins.
/// 2) On equal path length, host-specific routes win over host-agnostic routes.
/// 3) On equal host/path match, exact-host routes win over wildcard-host routes.
/// 4) On equal wildcard host/path match, longer wildcard suffixes win.
/// 5) On equal host/path match, method-specific routes win over method-agnostic routes.
/// 6) On remaining ties, lexicographically smaller upstream name wins.
///
/// `order` stores the lexicographic rank of upstream name (smaller rank = smaller name),
/// so trie updates are independent of HashMap insertion order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexedRoute {
    upstream_idx: usize,
    path_len: usize,
    host_specific: bool,
    method_specific: bool,
    order: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RoutePreference {
    KeepCurrent,
    TakeCandidatePathLen,
    TakeCandidateHostSpecific,
    TakeCandidateExactHost,
    TakeCandidateWildcardSpecificity,
    TakeCandidateMethodSpecific,
    TakeCandidateLexicalOrder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteDecisionReason {
    HostTrieNoDefault,
    HostPathLongerOrEqual,
    DefaultPathLonger,
    HostSpecificTieBreak,
    ExactHostTieBreak,
    WildcardSpecificityTieBreak,
    MethodSpecificTieBreak,
    LexicalTieBreak,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RouteDecision<'a> {
    pub upstream: &'a str,
    pub matched_path_len: usize,
    pub host_specific: bool,
    pub reason: RouteDecisionReason,
}

#[derive(Default)]
pub struct TrieNode {
    pub routes: Vec<IndexedRoute>,
    children: Vec<TrieEdge>,
}

#[derive(Default)]
struct TrieEdge {
    byte: u8,
    node: Box<TrieNode>,
}

impl TrieNode {
    fn update_route(&mut self, candidate: IndexedRoute) {
        if let Some(existing) = self
            .routes
            .iter_mut()
            .find(|route| route.upstream_idx == candidate.upstream_idx)
        {
            *existing = candidate;
            return;
        }
        self.routes.push(candidate);
    }

    #[inline(always)]
    fn child(&self, byte: u8) -> Option<&TrieNode> {
        match self.children.binary_search_by_key(&byte, |edge| edge.byte) {
            Ok(idx) => Some(self.children[idx].node.as_ref()),
            Err(_) => None,
        }
    }

    #[inline(always)]
    fn child_or_insert(&mut self, byte: u8) -> &mut TrieNode {
        match self.children.binary_search_by_key(&byte, |edge| edge.byte) {
            Ok(idx) => self.children[idx].node.as_mut(),
            Err(idx) => {
                self.children.insert(
                    idx,
                    TrieEdge {
                        byte,
                        node: Box::<TrieNode>::default(),
                    },
                );
                self.children[idx].node.as_mut()
            }
        }
    }
}

#[derive(Default)]
struct RouteTrie {
    root: TrieNode,
}

impl RouteTrie {
    fn insert(&mut self, prefix: Option<&str>, route: IndexedRoute) {
        let prefix = prefix.unwrap_or("");
        let mut node = &mut self.root;

        if prefix.is_empty() {
            node.update_route(route);
            return;
        }

        for byte in prefix.as_bytes() {
            node = node.child_or_insert(*byte);
        }

        node.update_route(route);
    }

    fn longest_prefix(
        &self,
        path: &str,
        method: Option<&str>,
        upstream_methods: &[Option<String>],
    ) -> Option<IndexedRoute> {
        self.longest_prefix_with_reason(path, method, upstream_methods)
            .map(|(route, _)| route)
    }

    fn longest_prefix_with_reason(
        &self,
        path: &str,
        method: Option<&str>,
        upstream_methods: &[Option<String>],
    ) -> Option<(IndexedRoute, Option<RouteDecisionReason>)> {
        let mut node = &self.root;
        let mut best =
            best_matching_route_with_reason(&node.routes, path, method, upstream_methods, None);

        for byte in path.as_bytes() {
            let Some(next) = node.child(*byte) else {
                break;
            };
            node = next;
            best =
                best_matching_route_with_reason(&node.routes, path, method, upstream_methods, best);
        }

        best
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

fn best_matching_route_with_reason(
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

#[inline(always)]
fn prefix_boundary_matches(path: &str, prefix_len: usize) -> bool {
    if prefix_len <= 1 {
        return true;
    }
    if path.len() == prefix_len {
        return true;
    }
    path.as_bytes().get(prefix_len) == Some(&b'/')
}

pub(crate) struct RouteIndex {
    host_tries: HashMap<String, RouteTrie>,
    wildcard_host_tries: HashMap<String, RouteTrie>,
    default_trie: RouteTrie,
    default_max_path_len: usize,
    upstream_names: Vec<String>,
    upstream_methods: Vec<Option<String>>,
}

impl RouteIndex {
    pub(crate) fn from_upstreams(upstreams: &HashMap<String, Upstream>) -> Self {
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

    pub(crate) fn lookup<'a>(&'a self, path: &str, host: Option<&str>) -> Option<&'a str> {
        self.lookup_for_method(path, host, None)
    }

    pub(crate) fn lookup_for_method<'a>(
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
    pub(crate) fn lookup_with_decision<'a>(
        &'a self,
        path: &str,
        host: Option<&str>,
    ) -> Option<RouteDecision<'a>> {
        self.lookup_with_decision_for_method(path, host, None)
    }

    pub(crate) fn lookup_with_decision_for_method<'a>(
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

#[inline(always)]
fn prefer_route_candidate(
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
fn route_preference_reason(preference: RoutePreference) -> Option<RouteDecisionReason> {
    match preference {
        RoutePreference::KeepCurrent => None,
        RoutePreference::TakeCandidatePathLen => Some(RouteDecisionReason::HostPathLongerOrEqual),
        RoutePreference::TakeCandidateHostSpecific => {
            Some(RouteDecisionReason::HostSpecificTieBreak)
        }
        RoutePreference::TakeCandidateExactHost => Some(RouteDecisionReason::ExactHostTieBreak),
        RoutePreference::TakeCandidateWildcardSpecificity => {
            Some(RouteDecisionReason::WildcardSpecificityTieBreak)
        }
        RoutePreference::TakeCandidateMethodSpecific => {
            Some(RouteDecisionReason::MethodSpecificTieBreak)
        }
        RoutePreference::TakeCandidateLexicalOrder => Some(RouteDecisionReason::LexicalTieBreak),
    }
}

#[inline(always)]
fn prefer_host_lookup_result(
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

#[inline(always)]
fn compare_route_candidate(current: RouteCandidate, candidate: RouteCandidate) -> RoutePreference {
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

pub(crate) fn scan_lookup<'a>(
    upstreams: &'a HashMap<String, Upstream>,
    path: &str,
    host: Option<&str>,
) -> Option<&'a str> {
    scan_lookup_for_method(upstreams, path, host, None)
}

pub(crate) fn scan_lookup_for_method<'a>(
    upstreams: &'a HashMap<String, Upstream>,
    path: &str,
    host: Option<&str>,
    method: Option<&str>,
) -> Option<&'a str> {
    let path_bytes = path.as_bytes();
    let normalized_request_host = host.and_then(normalize_host_for_routing);
    let mut best_match: Option<(&str, usize, bool, HostMatchKind, usize, bool)> = None;

    for (upstream_name, upstream) in upstreams {
        let has_method_match = match (
            upstream.route.method.as_deref().map(str::trim),
            method.map(str::trim),
        ) {
            (Some(route_method), Some(request_method)) => {
                route_method.eq_ignore_ascii_case(request_method)
            }
            (Some(_), None) => true,
            (None, _) => true,
        };
        if !has_method_match {
            continue;
        }

        let (has_host_match, host_match_kind, wildcard_suffix_len) =
            match (&upstream.route.host, normalized_request_host.as_deref()) {
                (None, _) => (true, HostMatchKind::Default, 0usize),
                (Some(_), None) => (false, HostMatchKind::Default, 0usize),
                (Some(route_host), Some(request_host)) => {
                    match parse_configured_host_pattern_ref(route_host) {
                        Some(ConfiguredHostPatternRef::Exact(route_host_exact)) => (
                            route_host_exact.eq_ignore_ascii_case(request_host),
                            HostMatchKind::Exact,
                            0,
                        ),
                        Some(ConfiguredHostPatternRef::WildcardSuffix(suffix)) => {
                            let suffix_start = request_host.len().saturating_sub(suffix.len());
                            (
                                request_host.len() > suffix.len() + 1
                                    && request_host
                                        .get(suffix_start..)
                                        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
                                    && request_host.as_bytes()[suffix_start - 1] == b'.',
                                HostMatchKind::Wildcard,
                                suffix.len(),
                            )
                        }
                        None => (false, HostMatchKind::Default, 0usize),
                    }
                }
            };

        let path_match_len = match &upstream.route.path_prefix {
            Some(path_prefix) => {
                let prefix = path_prefix.as_bytes();
                if prefix.len() > path_bytes.len() {
                    continue;
                }
                // Fast reject for same-length-ish prefixes before full starts_with.
                if let Some((&last, idx)) = prefix.last().zip(prefix.len().checked_sub(1))
                    && path_bytes[idx] != last
                {
                    continue;
                }
                if !path_bytes.starts_with(prefix) {
                    continue;
                }
                if !prefix_boundary_matches(path, prefix.len()) {
                    continue;
                }
                prefix.len()
            }
            None => 0,
        };

        if !has_host_match {
            continue;
        }
        let host_specific = upstream.route.host.is_some();
        let method_specific = upstream
            .route
            .method
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());

        match best_match {
            Some((
                best_name,
                best_len,
                best_host_specific,
                best_host_match_kind,
                best_wildcard_suffix_len,
                best_method_specific,
            )) => {
                if path_match_len > best_len
                    || (path_match_len == best_len && host_specific && !best_host_specific)
                    || (path_match_len == best_len
                        && host_specific == best_host_specific
                        && host_match_kind > best_host_match_kind)
                    || (path_match_len == best_len
                        && host_specific == best_host_specific
                        && host_match_kind == HostMatchKind::Wildcard
                        && best_host_match_kind == HostMatchKind::Wildcard
                        && wildcard_suffix_len > best_wildcard_suffix_len)
                    || (path_match_len == best_len
                        && host_specific == best_host_specific
                        && host_match_kind == best_host_match_kind
                        && method_specific
                        && !best_method_specific)
                    || (path_match_len == best_len
                        && host_specific == best_host_specific
                        && host_match_kind == best_host_match_kind
                        && method_specific == best_method_specific
                        && upstream_name.as_str() < best_name)
                {
                    best_match = Some((
                        upstream_name.as_str(),
                        path_match_len,
                        host_specific,
                        host_match_kind,
                        wildcard_suffix_len,
                        method_specific,
                    ));
                }
            }
            None => {
                best_match = Some((
                    upstream_name.as_str(),
                    path_match_len,
                    host_specific,
                    host_match_kind,
                    wildcard_suffix_len,
                    method_specific,
                ));
            }
        }
    }

    best_match.map(|(name, _, _, _, _, _)| name)
}

#[cfg(test)]
mod tests;
