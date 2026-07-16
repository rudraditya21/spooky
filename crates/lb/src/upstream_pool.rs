use std::time::Duration;

use spooky_config::runtime::{
    RuntimeAlternateBackendPolicy, RuntimeLoadBalancingPolicy, RuntimeLoadBalancingStrategy,
    RuntimeRequestKeySpec, RuntimeUpstream,
};

use crate::{backend::BackendState, backend_pool::BackendPool, load_balancing::LoadBalancing};

pub struct UpstreamPool {
    pub pool: BackendPool,
    pub load_balancer: LoadBalancing,
    lb_policy: RuntimeLoadBalancingPolicy,
}

impl UpstreamPool {
    pub fn from_upstream(upstream: &spooky_config::config::Upstream) -> Result<Self, String> {
        let backends = upstream.backends.iter().map(BackendState::new).collect();
        let lb_policy = RuntimeLoadBalancingPolicy::normalize(&upstream.load_balancing)
            .map_err(|err| err.to_string())?;
        let load_balancer = LoadBalancing::from_runtime_strategy(lb_policy.strategy)?;

        Ok(Self {
            pool: BackendPool::new_from_states(backends),
            load_balancer,
            lb_policy,
        })
    }

    pub fn from_runtime_upstream(upstream: &RuntimeUpstream) -> Result<Self, String> {
        let backends = upstream
            .backends
            .iter()
            .map(|backend| BackendState::new(&backend.backend))
            .collect();

        let lb_policy = upstream.load_balancing.clone();
        let load_balancer = LoadBalancing::from_runtime_strategy(lb_policy.strategy)?;

        Ok(Self {
            pool: BackendPool::new_from_states(backends),
            load_balancer,
            lb_policy,
        })
    }

    pub fn pick(&mut self, key: &str) -> Option<usize> {
        self.pool.reconcile_readmit();
        let selected = self.load_balancer.pick(key, &self.pool)?;
        self.pool.begin_request(selected);
        Some(selected)
    }

    pub fn pick_readonly(&self, key: &str) -> Option<usize> {
        self.load_balancer.pick_readonly(key, &self.pool)
    }

    pub fn pick_without_begin(&mut self, key: &str) -> Option<usize> {
        self.pool.reconcile_readmit();
        self.load_balancer.pick(key, &self.pool)
    }

    pub fn begin_request_if_healthy(&self, index: usize) -> bool {
        if self.pool.is_healthy_index(index) {
            self.pool.begin_request(index);
            true
        } else {
            false
        }
    }

    pub fn finish_request(&mut self, index: usize, latency: Duration, status: Option<u16>) {
        self.pool.finish_request(index, latency, status);
    }

    pub fn lb_policy(&self) -> &RuntimeLoadBalancingPolicy {
        &self.lb_policy
    }

    pub fn lb_strategy(&self) -> RuntimeLoadBalancingStrategy {
        self.lb_policy.strategy
    }

    pub fn lb_key_spec(&self) -> Option<&RuntimeRequestKeySpec> {
        self.lb_policy.key_spec.as_ref()
    }

    pub fn alternate_backend_policy(&self) -> RuntimeAlternateBackendPolicy {
        self.lb_policy.alternate_backend
    }

    #[cfg(test)]
    pub(crate) fn set_alternate_backend_policy(&mut self, policy: RuntimeAlternateBackendPolicy) {
        self.lb_policy.alternate_backend = policy;
    }
}
