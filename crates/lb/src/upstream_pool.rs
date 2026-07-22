//! Canonical upstream pool façade.
//!
//! [`UpstreamPool`] owns balancing primitives plus the narrow lifecycle-facing
//! mutation surface that edge/runtime code is allowed to use. Strategy state is
//! encapsulated here; callers should not reach into [`BackendPool`] directly.

use std::time::Duration;

use spooky_config::runtime::{
    RuntimeAlternateBackendPolicy, RuntimeLoadBalancingPolicy, RuntimeLoadBalancingStrategy,
    RuntimeRequestKeySpec, RuntimeUpstream,
};

use crate::{
    backend::{BackendState, HealthTransition},
    backend_pool::BackendPool,
    health::HealthFailureReason,
    load_balancing::LoadBalancing,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamPoolMembershipSummary {
    pub total_backends: usize,
    pub healthy_backends: usize,
    pub membership_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UpstreamBackendRuntimeState {
    pub healthy: bool,
    pub active_requests: usize,
    pub ewma_latency_ms: Option<f64>,
}

pub struct UpstreamPool {
    pool: BackendPool,
    load_balancer: LoadBalancing,
    lb_policy: RuntimeLoadBalancingPolicy,
}

impl UpstreamPool {
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

    pub fn mark_backend_healthy(&mut self, index: usize) -> Option<HealthTransition> {
        self.pool.mark_success(index)
    }

    pub fn mark_backend_failure_from_active_check(
        &mut self,
        index: usize,
    ) -> Option<HealthTransition> {
        self.pool.mark_failure(index)
    }

    pub fn mark_backend_request_failure(
        &mut self,
        index: usize,
        reason: HealthFailureReason,
    ) -> Option<HealthTransition> {
        self.pool.mark_request_failure(index, reason)
    }

    pub fn backend_address(&self, index: usize) -> Option<&str> {
        self.pool.address(index)
    }

    pub fn backend_count(&self) -> usize {
        self.pool.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }

    pub fn backend_indices(&self) -> Vec<usize> {
        self.pool.all_indices()
    }

    pub fn is_backend_healthy(&self, index: usize) -> bool {
        self.pool.is_healthy_index(index)
    }

    pub fn begin_request_for_accounting(&self, index: usize) {
        self.pool.begin_request(index);
    }

    pub fn backend_runtime_state(&self, index: usize) -> Option<UpstreamBackendRuntimeState> {
        let backend = self.pool.backend(index)?;
        Some(UpstreamBackendRuntimeState {
            healthy: self.pool.is_healthy_index(index),
            active_requests: backend.active_requests(),
            ewma_latency_ms: backend.ewma_latency_ms(),
        })
    }

    pub fn healthy_backend_indices_iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.pool.healthy_indices_iter()
    }

    pub fn membership_summary(&self) -> UpstreamPoolMembershipSummary {
        UpstreamPoolMembershipSummary {
            total_backends: self.pool.len(),
            healthy_backends: self.pool.healthy_len(),
            membership_epoch: self.pool.membership_epoch(),
        }
    }

    pub fn lb_policy(&self) -> &RuntimeLoadBalancingPolicy {
        &self.lb_policy
    }

    pub fn lb_strategy(&self) -> RuntimeLoadBalancingStrategy {
        self.lb_policy.strategy
    }

    pub fn load_balancer_name(&self) -> &'static str {
        self.load_balancer.name()
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
