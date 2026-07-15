use super::*;

pub(in crate::quic_listener) struct RouteResolutionRequest<'a> {
    pub(in crate::quic_listener) method: &'a str,
    pub(in crate::quic_listener) path: &'a str,
    pub(in crate::quic_listener) authority: Option<&'a str>,
    pub(in crate::quic_listener) cid_key: Option<&'a str>,
    pub(in crate::quic_listener) header_lookup: Option<&'a LbHeaderLookup<'a>>,
}

impl<'a> RouteResolutionRequest<'a> {
    pub(in crate::quic_listener) fn new(
        method: &'a str,
        path: &'a str,
        authority: Option<&'a str>,
        cid_key: Option<&'a str>,
        header_lookup: Option<&'a LbHeaderLookup<'a>>,
    ) -> Self {
        Self {
            method,
            path,
            authority,
            cid_key,
            header_lookup,
        }
    }
}

pub(crate) struct ResolvedRoute {
    pub(crate) upstream_name: String,
    pub(crate) upstream_pool: Arc<RwLock<UpstreamPool>>,
    pub(crate) route_path_len: usize,
    pub(crate) route_host_specific: bool,
    pub(crate) route_reason: RouteDecisionReason,
}

pub(crate) struct SelectedBackend {
    pub(crate) backend_addr: String,
    pub(crate) backend_index: usize,
    pub(crate) backend_lb: String,
}

pub(crate) struct ResolvedBackend {
    pub(crate) route: ResolvedRoute,
    pub(crate) backend: SelectedBackend,
}

impl QUICListener {
    #[allow(clippy::type_complexity)]
    fn resolve_route_target(
        request: &RouteResolutionRequest<'_>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        routing_index: &RouteIndex,
    ) -> Result<ResolvedRoute, ProxyError> {
        if request.method.is_empty() || request.path.is_empty() {
            return Err(ProxyError::Transport("empty method or path".into()));
        }

        let route_decision = routing_index
            .lookup_with_decision_for_method(request.path, request.authority, Some(request.method))
            .ok_or_else(|| ProxyError::Transport(format!("no route for {}", request.path)))?;
        let upstream_name = route_decision.upstream.to_string();
        let upstream_pool = upstream_pools
            .get(route_decision.upstream)
            .ok_or_else(|| ProxyError::Transport(format!("pool not found: {upstream_name}")))?
            .clone();

        Ok(ResolvedRoute {
            upstream_name,
            upstream_pool,
            route_path_len: route_decision.matched_path_len,
            route_host_specific: route_decision.host_specific,
            route_reason: route_decision.reason,
        })
    }

    fn select_backend_from_pool(
        request: &RouteResolutionRequest<'_>,
        upstream_pool: &Arc<RwLock<UpstreamPool>>,
        begin_request: bool,
    ) -> Result<SelectedBackend, ProxyError> {
        let (backend_index, backend_lb, backend_addr) = {
            let (read_lb_type, read_fast_selected) = {
                let pool = upstream_pool
                    .read()
                    .map_err(|_| ProxyError::Transport("upstream pool lock poisoned".into()))?;
                if pool.pool.is_empty() {
                    return Err(ProxyError::Transport("no servers in upstream".into()));
                }
                let lb_type = pool.lb_name();
                let key = Self::resolve_lb_request_key(
                    lb_type,
                    pool.lb_key(),
                    request.method,
                    request.path,
                    request.authority,
                    request.cid_key,
                    request.header_lookup,
                );
                let fast_selected = if pool.pool.readmit_due() {
                    None
                } else {
                    pool.pick_readonly(key.as_str())
                        .and_then(|idx| pool.pool.address(idx).map(|addr| (idx, addr.to_string())))
                        .and_then(|(idx, addr)| {
                            (!begin_request || pool.begin_request_if_healthy(idx))
                                .then_some((idx, addr))
                        })
                };
                (lb_type, fast_selected)
            };

            if let Some((idx, addr)) = read_fast_selected {
                (idx, read_lb_type, addr)
            } else {
                let mut pool = upstream_pool
                    .write()
                    .map_err(|_| ProxyError::Transport("upstream pool lock poisoned".into()))?;
                if pool.pool.is_empty() {
                    return Err(ProxyError::Transport("no servers in upstream".into()));
                }
                let lb_type = pool.lb_name();
                let key = Self::resolve_lb_request_key(
                    lb_type,
                    pool.lb_key(),
                    request.method,
                    request.path,
                    request.authority,
                    request.cid_key,
                    request.header_lookup,
                );
                let idx = if begin_request {
                    pool.pick(key.as_str())
                } else {
                    pool.pick_without_begin(key.as_str())
                }
                .ok_or_else(|| {
                    let total = pool.pool.len();
                    let healthy = pool.pool.healthy_len();
                    error!(
                        "no healthy backends available: {}/{} backends healthy",
                        healthy, total
                    );
                    ProxyError::Transport("no healthy servers".into())
                })?;
                let backend_addr = pool
                    .pool
                    .address(idx)
                    .map(str::to_string)
                    .ok_or_else(|| ProxyError::Transport("invalid server address".into()))?;
                (idx, lb_type, backend_addr)
            }
        };

        Ok(SelectedBackend {
            backend_addr,
            backend_index,
            backend_lb: backend_lb.to_string(),
        })
    }

    fn log_backend_selection(
        backend_addr: &str,
        lb_type: &str,
        upstream_name: &str,
        route_path_len: usize,
        route_host_specific: bool,
        route_reason: &RouteDecisionReason,
    ) {
        debug!(
            "Selected backend {} via {} route={} path_len={} host_specific={} reason={:?}",
            backend_addr, lb_type, upstream_name, route_path_len, route_host_specific, route_reason
        );
    }

    fn resolve_backend_internal(
        request: &RouteResolutionRequest<'_>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        routing_index: &RouteIndex,
        begin_request: bool,
    ) -> Result<ResolvedBackend, ProxyError> {
        let route = Self::resolve_route_target(request, upstream_pools, routing_index)?;
        let backend = Self::select_backend_from_pool(request, &route.upstream_pool, begin_request)?;

        Self::log_backend_selection(
            &backend.backend_addr,
            &backend.backend_lb,
            &route.upstream_name,
            route.route_path_len,
            route.route_host_specific,
            &route.route_reason,
        );
        Ok(ResolvedBackend { route, backend })
    }

    pub(super) fn resolve_backend_without_inflight_request(
        request: &RouteResolutionRequest<'_>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        routing_index: &RouteIndex,
    ) -> Result<ResolvedBackend, ProxyError> {
        Self::resolve_backend_internal(request, upstream_pools, routing_index, false)
    }

    /// Resolve routing + LB for a request, returning `(backend_addr, backend_index, pool)`.
    pub(in crate::quic_listener) fn resolve_backend_request(
        request: &RouteResolutionRequest<'_>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        routing_index: &RouteIndex,
    ) -> Result<ResolvedBackend, ProxyError> {
        Self::resolve_backend_internal(request, upstream_pools, routing_index, true)
    }
}
