use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::SystemTime,
};

use crate::runtime::backend::{
    resolution::RuntimeBackendResolution, update::RuntimeBackendResolutionUpdate,
};

#[derive(Debug, Clone, Default)]
pub struct RuntimeBackendResolutionStore {
    entries: Arc<RwLock<HashMap<String, RuntimeBackendResolution>>>,
}

impl RuntimeBackendResolutionStore {
    pub fn new<I>(entries: I) -> Self
    where
        I: IntoIterator<Item = RuntimeBackendResolution>,
    {
        let entries = entries
            .into_iter()
            .map(|entry| (entry.backend_addr.clone(), entry))
            .collect();
        Self {
            entries: Arc::new(RwLock::new(entries)),
        }
    }

    pub fn get(&self, backend_addr: &str) -> Option<RuntimeBackendResolution> {
        self.entries
            .read()
            .ok()
            .and_then(|guard| guard.get(backend_addr).cloned())
    }

    pub fn snapshot(&self) -> HashMap<String, RuntimeBackendResolution> {
        self.entries
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    pub fn hostname_entries(&self) -> Vec<RuntimeBackendResolution> {
        self.entries
            .read()
            .map(|guard| {
                guard
                    .values()
                    .filter(|entry| entry.is_hostname())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn update_hostname_resolution(
        &self,
        backend_addr: &str,
        resolved_addrs: Vec<SocketAddr>,
        refreshed_at: SystemTime,
    ) -> Option<RuntimeBackendResolutionUpdate> {
        let resolved_addrs = canonicalize_socket_addrs(resolved_addrs);
        let mut guard = self.entries.write().ok()?;
        let entry = guard.get_mut(backend_addr)?;
        if !entry.is_hostname() {
            return None;
        }

        let previous_addrs = std::mem::replace(&mut entry.resolved_addrs, resolved_addrs.clone());
        entry.last_refresh_success_at = Some(refreshed_at);
        entry.refresh_generation = entry.refresh_generation.saturating_add(1);

        Some(RuntimeBackendResolutionUpdate {
            backend_addr: entry.backend_addr.clone(),
            authority_host: entry.authority_host.clone(),
            authority_port: entry.authority_port,
            address_kind: entry.address_kind,
            previous_addrs,
            current_addrs: resolved_addrs,
            last_refresh_success_at: entry.last_refresh_success_at,
            refresh_generation: entry.refresh_generation,
        })
    }
}

fn canonicalize_socket_addrs(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    addrs.sort_unstable();
    addrs.dedup();
    addrs
}
