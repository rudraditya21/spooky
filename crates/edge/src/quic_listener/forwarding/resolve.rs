use super::*;

pub(crate) struct ResolvedBackend {
    pub(crate) upstream_name: String,
    pub(crate) backend_addr: String,
    pub(crate) backend_index: usize,
    pub(crate) upstream_pool: Arc<RwLock<UpstreamPool>>,
    pub(crate) backend_lb: String,
    pub(crate) route_path_len: usize,
    pub(crate) route_host_specific: bool,
    pub(crate) route_reason: RouteDecisionReason,
}

impl QUICListener {
    #[allow(clippy::type_complexity)]
    fn resolve_route_target(
        method: &str,
        path: &str,
        authority: Option<&str>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        routing_index: &RouteIndex,
    ) -> Result<
        (
            String,
            Arc<RwLock<UpstreamPool>>,
            usize,
            bool,
            RouteDecisionReason,
        ),
        ProxyError,
    > {
        if method.is_empty() || path.is_empty() {
            return Err(ProxyError::Transport("empty method or path".into()));
        }

        let route_decision = routing_index
            .lookup_with_decision_for_method(path, authority, Some(method))
            .ok_or_else(|| ProxyError::Transport(format!("no route for {path}")))?;
        let upstream_name = route_decision.upstream.to_string();
        let upstream_pool = upstream_pools
            .get(route_decision.upstream)
            .ok_or_else(|| ProxyError::Transport(format!("pool not found: {upstream_name}")))?
            .clone();

        Ok((
            upstream_name,
            upstream_pool,
            route_decision.matched_path_len,
            route_decision.host_specific,
            route_decision.reason,
        ))
    }

    fn select_backend_from_pool(
        method: &str,
        path: &str,
        authority: Option<&str>,
        cid_key: Option<&str>,
        upstream_pool: &Arc<RwLock<UpstreamPool>>,
        header_lookup: Option<&LbHeaderLookup<'_>>,
        begin_request: bool,
    ) -> Result<(usize, String, String), ProxyError> {
        let (backend_index, lb_type, backend_addr) = {
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
                    method,
                    path,
                    authority,
                    cid_key,
                    header_lookup,
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
                    method,
                    path,
                    authority,
                    cid_key,
                    header_lookup,
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

        Ok((backend_index, lb_type.to_string(), backend_addr))
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

    pub(super) fn resolve_backend_without_inflight(
        method: &str,
        path: &str,
        authority: Option<&str>,
        cid_key: Option<&str>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        routing_index: &RouteIndex,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> Result<ResolvedBackend, ProxyError> {
        let (upstream_name, upstream_pool, route_path_len, route_host_specific, route_reason) =
            Self::resolve_route_target(method, path, authority, upstream_pools, routing_index)?;
        let (backend_index, backend_lb, backend_addr) = Self::select_backend_from_pool(
            method,
            path,
            authority,
            cid_key,
            &upstream_pool,
            header_lookup,
            false,
        )?;

        Self::log_backend_selection(
            &backend_addr,
            &backend_lb,
            &upstream_name,
            route_path_len,
            route_host_specific,
            &route_reason,
        );
        Ok(ResolvedBackend {
            upstream_name,
            backend_addr,
            backend_index,
            upstream_pool,
            backend_lb,
            route_path_len,
            route_host_specific,
            route_reason,
        })
    }

    /// Resolve routing + LB for a request, returning `(backend_addr, backend_index, pool)`.
    pub(crate) fn resolve_backend(
        method: &str,
        path: &str,
        authority: Option<&str>,
        cid_key: Option<&str>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        routing_index: &RouteIndex,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> Result<ResolvedBackend, ProxyError> {
        let (upstream_name, upstream_pool, route_path_len, route_host_specific, route_reason) =
            Self::resolve_route_target(method, path, authority, upstream_pools, routing_index)?;
        let (backend_index, backend_lb, backend_addr) = Self::select_backend_from_pool(
            method,
            path,
            authority,
            cid_key,
            &upstream_pool,
            header_lookup,
            true,
        )?;

        Self::log_backend_selection(
            &backend_addr,
            &backend_lb,
            &upstream_name,
            route_path_len,
            route_host_specific,
            &route_reason,
        );
        Ok(ResolvedBackend {
            upstream_name,
            backend_addr,
            backend_index,
            upstream_pool,
            backend_lb,
            route_path_len,
            route_host_specific,
            route_reason,
        })
    }
}
