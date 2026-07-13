use std::time::Duration;

use crate::{backend::BackendState, backend_pool::BackendPool, load_balancing::LoadBalancing};

pub struct UpstreamPool {
    pub pool: BackendPool,
    pub load_balancer: LoadBalancing,
    lb_key: Option<String>,
}

impl UpstreamPool {
    pub fn from_upstream(upstream: &spooky_config::config::Upstream) -> Result<Self, String> {
        let backends = upstream.backends.iter().map(BackendState::new).collect();

        let load_balancer = LoadBalancing::from_config(&upstream.load_balancing.lb_type)?;
        let lb_key = upstream
            .load_balancing
            .key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);

        Ok(Self {
            pool: BackendPool::new_from_states(backends),
            load_balancer,
            lb_key,
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

    pub fn lb_name(&self) -> &'static str {
        self.load_balancer.name()
    }

    pub fn lb_key(&self) -> Option<&str> {
        self.lb_key.as_deref()
    }
}
