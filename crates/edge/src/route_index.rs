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

/// Route precedence (deterministic):
/// 1) Longest matching path_prefix wins.
/// 2) On equal path length, host-specific routes win over host-agnostic routes.
/// 3) On equal host/path match, method-specific routes win over method-agnostic routes.
/// 4) On remaining ties, lexicographically smaller upstream name wins.
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
        let mut node = &self.root;
        let mut best = best_matching_route(&node.routes, path, method, upstream_methods, None);

        for byte in path.as_bytes() {
            let Some(next) = node.child(*byte) else {
                break;
            };
            node = next;
            best = best_matching_route(&node.routes, path, method, upstream_methods, best);
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

fn best_matching_route(
    routes: &[IndexedRoute],
    path: &str,
    method: Option<&str>,
    upstream_methods: &[Option<String>],
    current: Option<IndexedRoute>,
) -> Option<IndexedRoute> {
    let mut best = current;
    for route in routes.iter().copied() {
        if !prefix_boundary_matches(path, route.path_len) {
            continue;
        }
        if !route_matches_method(route, method, upstream_methods) {
            continue;
        }
        best = prefer_route(best, Some(route));
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
            && best.route.path_len >= self.default_max_path_len
        {
            return Some(self.upstream_names[best.route.upstream_idx].as_str());
        }

        let best = prefer_route_candidate(
            self.default_trie
                .longest_prefix(path, method, &self.upstream_methods)
                .map(|route| RouteCandidate {
                    route,
                    host_match_kind: HostMatchKind::Default,
                    wildcard_suffix_len: 0,
                }),
            host_best,
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
            && best.route.path_len >= self.default_max_path_len
        {
            let reason = match default_best {
                None => RouteDecisionReason::HostTrieNoDefault,
                Some(default_route) => match compare_route_candidate(default_route, best) {
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
                },
            };
            return Some(RouteDecision {
                upstream: self.upstream_names[best.route.upstream_idx].as_str(),
                matched_path_len: best.route.path_len,
                host_specific: best.route.host_specific,
                reason,
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
                upstream: self.upstream_names[host_route.route.upstream_idx].as_str(),
                matched_path_len: host_route.route.path_len,
                host_specific: host_route.route.host_specific,
                reason: RouteDecisionReason::HostTrieNoDefault,
            }),
            (Some(current), Some(candidate)) => {
                let reason = match compare_route_candidate(current, candidate) {
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
                let selected = match compare_route_candidate(current, candidate) {
                    RoutePreference::KeepCurrent => current,
                    _ => candidate,
                };
                Some(RouteDecision {
                    upstream: self.upstream_names[selected.route.upstream_idx].as_str(),
                    matched_path_len: selected.route.path_len,
                    host_specific: selected.route.host_specific,
                    reason,
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
    ) -> Option<RouteCandidate> {
        let exact_best = self
            .host_tries
            .get(normalized_host)
            .and_then(|host_trie| host_trie.longest_prefix(path, method, &self.upstream_methods))
            .map(|route| RouteCandidate {
                route,
                host_match_kind: HostMatchKind::Exact,
                wildcard_suffix_len: 0,
            });

        let mut wildcard_best: Option<RouteCandidate> = None;
        let mut remaining = normalized_host;
        while let Some(dot_idx) = remaining.find('.') {
            let suffix = &remaining[dot_idx + 1..];
            if suffix.is_empty() {
                break;
            }

            if let Some(trie) = self.wildcard_host_tries.get(suffix) {
                let candidate = trie
                    .longest_prefix(path, method, &self.upstream_methods)
                    .map(|route| RouteCandidate {
                        route,
                        host_match_kind: HostMatchKind::Wildcard,
                        wildcard_suffix_len: suffix.len(),
                    });
                wildcard_best = prefer_route_candidate(wildcard_best, candidate);
            }
            remaining = suffix;
        }

        prefer_route_candidate(wildcard_best, exact_best)
    }
}

#[inline(always)]
fn prefer_route(
    current: Option<IndexedRoute>,
    candidate: Option<IndexedRoute>,
) -> Option<IndexedRoute> {
    match (current, candidate) {
        (None, None) => None,
        (Some(route), None) | (None, Some(route)) => Some(route),
        (Some(current), Some(candidate)) => match compare_route(current, candidate) {
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
mod tests {
    use super::*;
    use spooky_config::config::{LoadBalancing, RouteMatch};
    use std::time::Instant;

    fn test_upstream(host: Option<&str>, path_prefix: Option<&str>) -> Upstream {
        test_upstream_with_method(host, path_prefix, None)
    }

    fn test_upstream_with_method(
        host: Option<&str>,
        path_prefix: Option<&str>,
        method: Option<&str>,
    ) -> Upstream {
        Upstream {
            load_balancing: LoadBalancing {
                lb_type: "random".to_string(),
                key: None,
            },
            host_policy: Default::default(),
            forwarded_headers: Default::default(),
            tls: None,
            route: RouteMatch {
                host: host.map(str::to_string),
                path_prefix: path_prefix.map(str::to_string),
                method: method.map(str::to_string),
            },
            backends: vec![],
        }
    }

    #[test]
    fn longest_prefix_lookup_works() {
        let mut upstreams = HashMap::new();
        upstreams.insert("root".to_string(), test_upstream(None, Some("/")));
        upstreams.insert("api".to_string(), test_upstream(None, Some("/api")));
        upstreams.insert("api-v1".to_string(), test_upstream(None, Some("/api/v1")));

        let index = RouteIndex::from_upstreams(&upstreams);
        let selected = index.lookup("/api/v1/users", None);
        assert_eq!(selected, Some("api-v1"));
    }

    #[test]
    fn indexed_lookup_matches_scan_lookup() {
        let mut upstreams = HashMap::new();
        upstreams.insert("default-root".to_string(), test_upstream(None, Some("/")));
        upstreams.insert("default-api".to_string(), test_upstream(None, Some("/api")));
        upstreams.insert(
            "api-host-only".to_string(),
            test_upstream(Some("api.example.com"), None),
        );
        upstreams.insert(
            "api-host-route".to_string(),
            test_upstream(Some("api.example.com"), Some("/api")),
        );
        upstreams.insert(
            "admin-host-route".to_string(),
            test_upstream(Some("admin.example.com"), Some("/admin")),
        );

        let index = RouteIndex::from_upstreams(&upstreams);
        let queries = vec![
            ("/", None),
            ("/api/users", None),
            ("/api/users", Some("api.example.com")),
            ("/admin/users", Some("admin.example.com")),
            ("/unknown", Some("api.example.com")),
            ("/unknown", Some("missing.example.com")),
        ];

        for (path, host) in queries {
            assert_eq!(
                index.lookup(path, host),
                scan_lookup(&upstreams, path, host)
            );
        }
    }

    #[test]
    fn host_specific_route_wins_on_tie() {
        let mut upstreams = HashMap::new();
        upstreams.insert("a-default".to_string(), test_upstream(None, Some("/api")));
        upstreams.insert(
            "z-host".to_string(),
            test_upstream(Some("api.example.com"), Some("/api")),
        );

        let index = RouteIndex::from_upstreams(&upstreams);
        assert_eq!(
            index.lookup("/api/users", Some("api.example.com")),
            Some("z-host")
        );
        assert_eq!(
            scan_lookup(&upstreams, "/api/users", Some("api.example.com")),
            Some("z-host")
        );
    }

    #[test]
    fn lookup_normalizes_request_host_case_and_port() {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "api".to_string(),
            test_upstream(Some("api.example.com"), Some("/api")),
        );
        upstreams.insert("default".to_string(), test_upstream(None, Some("/")));
        let index = RouteIndex::from_upstreams(&upstreams);

        assert_eq!(
            index.lookup("/api/v1", Some("API.EXAMPLE.COM:443")),
            Some("api")
        );
        assert_eq!(
            scan_lookup(&upstreams, "/api/v1", Some("API.EXAMPLE.COM:443")),
            Some("api")
        );
    }

    #[test]
    fn lookup_normalizes_configured_host_case() {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "api".to_string(),
            test_upstream(Some("API.Example.COM"), Some("/api")),
        );
        upstreams.insert("default".to_string(), test_upstream(None, Some("/")));
        let index = RouteIndex::from_upstreams(&upstreams);
        assert_eq!(
            index.lookup("/api/v1", Some("api.example.com")),
            Some("api")
        );
    }

    #[test]
    fn path_prefix_requires_segment_boundary() {
        let mut upstreams = HashMap::new();
        upstreams.insert("api".to_string(), test_upstream(None, Some("/api")));
        upstreams.insert("root".to_string(), test_upstream(None, Some("/")));
        let index = RouteIndex::from_upstreams(&upstreams);
        assert_eq!(index.lookup("/api", None), Some("api"));
        assert_eq!(index.lookup("/api/v1", None), Some("api"));
        assert_eq!(index.lookup("/api2", None), Some("root"));
        assert_eq!(scan_lookup(&upstreams, "/api2", None), Some("root"));
    }

    #[test]
    fn lookup_with_decision_reports_host_specific_tie_break() {
        let mut upstreams = HashMap::new();
        upstreams.insert("default-api".to_string(), test_upstream(None, Some("/api")));
        upstreams.insert(
            "host-api".to_string(),
            test_upstream(Some("api.example.com"), Some("/api")),
        );
        let index = RouteIndex::from_upstreams(&upstreams);

        let decision = index
            .lookup_with_decision("/api/v1", Some("api.example.com"))
            .expect("decision");
        assert_eq!(decision.upstream, "host-api");
        assert_eq!(decision.reason, RouteDecisionReason::HostSpecificTieBreak);
    }

    #[test]
    fn lookup_with_decision_reports_default_longer_path() {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "host-root".to_string(),
            test_upstream(Some("api.example.com"), Some("/")),
        );
        upstreams.insert(
            "default-api-v2".to_string(),
            test_upstream(None, Some("/api/v2")),
        );
        let index = RouteIndex::from_upstreams(&upstreams);

        let decision = index
            .lookup_with_decision("/api/v2/users", Some("api.example.com"))
            .expect("decision");
        assert_eq!(decision.upstream, "default-api-v2");
        assert_eq!(decision.reason, RouteDecisionReason::DefaultPathLonger);
    }

    #[test]
    fn method_specific_route_wins_on_tie() {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "all-api".to_string(),
            test_upstream_with_method(None, Some("/api"), None),
        );
        upstreams.insert(
            "post-api".to_string(),
            test_upstream_with_method(None, Some("/api"), Some("POST")),
        );
        let index = RouteIndex::from_upstreams(&upstreams);

        let get = index
            .lookup_with_decision_for_method("/api/items", None, Some("GET"))
            .expect("GET route");
        assert_eq!(get.upstream, "all-api");

        let post = index
            .lookup_with_decision_for_method("/api/items", None, Some("POST"))
            .expect("POST route");
        assert_eq!(post.upstream, "post-api");

        assert_eq!(
            scan_lookup_for_method(&upstreams, "/api/items", None, Some("POST")),
            Some("post-api")
        );
    }

    #[test]
    fn method_matching_is_case_insensitive() {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "post-api".to_string(),
            test_upstream_with_method(None, Some("/api"), Some("post")),
        );
        let index = RouteIndex::from_upstreams(&upstreams);

        assert_eq!(
            index.lookup_for_method("/api", None, Some("POST")),
            Some("post-api")
        );
    }

    #[test]
    fn lexical_tie_break_is_deterministic_for_default_routes() {
        let mut upstreams = HashMap::new();
        // Insert in reverse lexical order to prove insertion order does not matter.
        upstreams.insert("zeta".to_string(), test_upstream(None, Some("/api")));
        upstreams.insert("alpha".to_string(), test_upstream(None, Some("/api")));

        let index = RouteIndex::from_upstreams(&upstreams);
        assert_eq!(index.lookup("/api/users", None), Some("alpha"));
        assert_eq!(scan_lookup(&upstreams, "/api/users", None), Some("alpha"));
    }

    #[test]
    fn lexical_tie_break_is_deterministic_for_host_routes() {
        let mut upstreams = HashMap::new();
        // Insert in reverse lexical order to prove insertion order does not matter.
        upstreams.insert(
            "zeta-host".to_string(),
            test_upstream(Some("api.example.com"), Some("/api")),
        );
        upstreams.insert(
            "alpha-host".to_string(),
            test_upstream(Some("api.example.com"), Some("/api")),
        );

        let index = RouteIndex::from_upstreams(&upstreams);
        assert_eq!(
            index.lookup("/api/users", Some("api.example.com")),
            Some("alpha-host")
        );
        assert_eq!(
            scan_lookup(&upstreams, "/api/users", Some("api.example.com")),
            Some("alpha-host")
        );
    }

    #[test]
    fn indexed_lookup_is_insertion_order_invariant() {
        let mut upstreams_a = HashMap::new();
        upstreams_a.insert("zeta".to_string(), test_upstream(None, Some("/")));
        upstreams_a.insert(
            "beta-host".to_string(),
            test_upstream(Some("api.example.com"), Some("/api")),
        );
        upstreams_a.insert("alpha".to_string(), test_upstream(None, Some("/api")));

        let mut upstreams_b = HashMap::new();
        upstreams_b.insert("alpha".to_string(), test_upstream(None, Some("/api")));
        upstreams_b.insert("zeta".to_string(), test_upstream(None, Some("/")));
        upstreams_b.insert(
            "beta-host".to_string(),
            test_upstream(Some("api.example.com"), Some("/api")),
        );

        let index_a = RouteIndex::from_upstreams(&upstreams_a);
        let index_b = RouteIndex::from_upstreams(&upstreams_b);
        let queries = vec![
            ("/api/users", None),
            ("/api/users", Some("api.example.com")),
            ("/", None),
            ("/missing", Some("api.example.com")),
        ];

        for (path, host) in queries {
            assert_eq!(index_a.lookup(path, host), index_b.lookup(path, host));
        }
    }

    #[test]
    fn wildcard_host_route_matches_subdomains() {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "wildcard".to_string(),
            test_upstream(Some("*.example.com"), Some("/api")),
        );
        upstreams.insert("default".to_string(), test_upstream(None, Some("/")));
        let index = RouteIndex::from_upstreams(&upstreams);

        assert_eq!(
            index.lookup("/api/users", Some("tenant.example.com")),
            Some("wildcard")
        );
        assert_eq!(
            scan_lookup(&upstreams, "/api/users", Some("tenant.example.com")),
            Some("wildcard")
        );
        assert_eq!(
            index.lookup("/api/users", Some("example.com")),
            Some("default")
        );
    }

    #[test]
    fn exact_host_route_beats_wildcard_on_tie() {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "wildcard".to_string(),
            test_upstream(Some("*.example.com"), Some("/api")),
        );
        upstreams.insert(
            "exact".to_string(),
            test_upstream(Some("api.example.com"), Some("/api")),
        );
        let index = RouteIndex::from_upstreams(&upstreams);

        assert_eq!(
            index.lookup("/api/users", Some("api.example.com")),
            Some("exact")
        );
        assert_eq!(
            scan_lookup(&upstreams, "/api/users", Some("api.example.com")),
            Some("exact")
        );
    }

    #[test]
    fn more_specific_wildcard_beats_less_specific_wildcard() {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "wide".to_string(),
            test_upstream(Some("*.example.com"), Some("/api")),
        );
        upstreams.insert(
            "narrow".to_string(),
            test_upstream(Some("*.a.example.com"), Some("/api")),
        );
        upstreams.insert("default".to_string(), test_upstream(None, Some("/")));
        let index = RouteIndex::from_upstreams(&upstreams);

        assert_eq!(
            index.lookup("/api/users", Some("x.a.example.com")),
            Some("narrow")
        );
        assert_eq!(
            scan_lookup(&upstreams, "/api/users", Some("x.a.example.com")),
            Some("narrow")
        );
        assert_eq!(
            index
                .lookup_with_decision("/api/users", Some("x.a.example.com"))
                .map(|decision| decision.reason),
            Some(RouteDecisionReason::HostPathLongerOrEqual)
        );
    }

    #[test]
    fn wildcard_keeps_method_and_path_precedence() {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "wildcard-post".to_string(),
            test_upstream_with_method(Some("*.example.com"), Some("/api"), Some("POST")),
        );
        upstreams.insert(
            "wildcard-all".to_string(),
            test_upstream_with_method(Some("*.example.com"), Some("/api"), None),
        );
        upstreams.insert(
            "wildcard-deep".to_string(),
            test_upstream(Some("*.example.com"), Some("/api/v2")),
        );
        let index = RouteIndex::from_upstreams(&upstreams);

        assert_eq!(
            index.lookup_for_method("/api/items", Some("tenant.example.com"), Some("POST")),
            Some("wildcard-post")
        );
        assert_eq!(
            scan_lookup_for_method(
                &upstreams,
                "/api/items",
                Some("tenant.example.com"),
                Some("POST")
            ),
            Some("wildcard-post")
        );

        assert_eq!(
            index.lookup_for_method("/api/v2/items", Some("tenant.example.com"), Some("GET")),
            Some("wildcard-deep")
        );
        assert_eq!(
            scan_lookup_for_method(
                &upstreams,
                "/api/v2/items",
                Some("tenant.example.com"),
                Some("GET")
            ),
            Some("wildcard-deep")
        );
    }

    fn build_route_table(route_count: usize) -> HashMap<String, Upstream> {
        let mut upstreams = HashMap::with_capacity(route_count);
        for i in 0..route_count {
            let name = format!("upstream-{i:05}");
            let path = format!("/svc/{i:05}");
            let host = (i % 2 == 1).then_some("bench.example.com");
            upstreams.insert(name, test_upstream(host, Some(&path)));
        }
        upstreams
    }

    fn measure_lookup<F>(iterations: usize, mut lookup: F) -> std::time::Duration
    where
        F: FnMut() -> Option<String>,
    {
        let start = Instant::now();
        let mut sink = 0usize;
        for _ in 0..iterations {
            if let Some(value) = lookup() {
                sink ^= value.len();
            }
        }
        std::hint::black_box(sink);
        start.elapsed()
    }

    #[test]
    #[ignore = "microbenchmark"]
    fn route_lookup_microbenchmarks() {
        for route_count in [100usize, 1_000, 10_000] {
            let upstreams = build_route_table(route_count);
            let index = RouteIndex::from_upstreams(&upstreams);
            let query_path = format!("/svc/{:05}/resource", route_count - 1);
            let host = Some("bench.example.com");
            let iterations = match route_count {
                100 => 200_000,
                1_000 => 100_000,
                _ => 20_000,
            };

            assert_eq!(
                index.lookup(&query_path, host),
                scan_lookup(&upstreams, &query_path, host)
            );

            let scan_time = measure_lookup(iterations, || {
                scan_lookup(&upstreams, &query_path, host).map(str::to_string)
            });
            let indexed_time = measure_lookup(iterations, || {
                index.lookup(&query_path, host).map(str::to_string)
            });
            let speedup = scan_time.as_secs_f64() / indexed_time.as_secs_f64();

            eprintln!(
                "routes={route_count:>5} scan={scan_time:?} indexed={indexed_time:?} speedup={speedup:.2}x"
            );

            if route_count >= 1_000 {
                assert!(
                    indexed_time < scan_time,
                    "expected indexed lookup to be faster for {route_count} routes"
                );
            }
        }
    }
}
