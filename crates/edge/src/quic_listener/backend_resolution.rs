use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use log::{debug, error, info, warn};

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
enum BackendDnsRefreshOutcome {
    Updated {
        backend_addr: String,
        authority_host: String,
        previous_addrs: Vec<SocketAddr>,
        current_addrs: Vec<SocketAddr>,
        generation: u64,
    },
    Unchanged {
        backend_addr: String,
        authority_host: String,
        current_addrs: Vec<SocketAddr>,
        generation: u64,
    },
    EmptyAnswerRetained {
        backend_addr: String,
        authority_host: String,
        retained_addrs: Vec<SocketAddr>,
    },
    LookupFailed {
        backend_addr: String,
        authority_host: String,
        retained_addrs: Vec<SocketAddr>,
        error: String,
    },
}

impl QUICListener {
    pub(super) fn spawn_backend_dns_refresh(
        config: &RuntimeConfig,
        backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
        backend_dns_resolver: SharedDnsResolver,
        metrics: Arc<Metrics>,
    ) {
        if !config.performance.backend_dns_refresh_enabled {
            return;
        }

        if backend_resolution_store.hostname_entries().is_empty() {
            debug!("backend DNS refresh disabled: no hostname-based backends configured");
            return;
        }

        let interval_ms = config.performance.backend_dns_refresh_interval_ms.max(1);
        let handle = match runtime_handle() {
            Some(handle) => handle,
            None => {
                error!("Backend DNS refresh disabled: no Tokio runtime available");
                return;
            }
        };

        spawn_supervised_async_task(&handle, "backend-dns-refresh", Some(metrics), async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                ticker.tick().await;
                for backend in backend_resolution_store.hostname_entries() {
                    match refresh_backend_hostname(
                        &backend,
                        &backend_resolution_store,
                        &backend_dns_resolver,
                    )
                    .await
                    {
                        BackendDnsRefreshOutcome::Updated {
                            backend_addr,
                            authority_host,
                            previous_addrs,
                            current_addrs,
                            generation,
                        } => {
                            info!(
                                "backend DNS refresh updated '{}' (backend '{}'): {:?} -> {:?} generation={}",
                                authority_host,
                                backend_addr,
                                previous_addrs,
                                current_addrs,
                                generation
                            );
                        }
                        BackendDnsRefreshOutcome::Unchanged {
                            backend_addr,
                            authority_host,
                            current_addrs,
                            generation,
                        } => {
                            debug!(
                                "backend DNS refresh unchanged for '{}' (backend '{}') addrs={:?} generation={}",
                                authority_host, backend_addr, current_addrs, generation
                            );
                        }
                        BackendDnsRefreshOutcome::EmptyAnswerRetained {
                            backend_addr,
                            authority_host,
                            retained_addrs,
                        } => {
                            warn!(
                                "backend DNS refresh returned no addresses for '{}' (backend '{}'); retaining {:?}",
                                authority_host, backend_addr, retained_addrs
                            );
                        }
                        BackendDnsRefreshOutcome::LookupFailed {
                            backend_addr,
                            authority_host,
                            retained_addrs,
                            error,
                        } => {
                            warn!(
                                "backend DNS refresh failed for '{}' (backend '{}'): {}; retaining {:?}",
                                authority_host, backend_addr, error, retained_addrs
                            );
                        }
                    }
                }
            }
        });
    }
}

async fn refresh_backend_hostname(
    backend: &RuntimeBackendResolution,
    backend_resolution_store: &RuntimeBackendResolutionStore,
    backend_dns_resolver: &SharedDnsResolver,
) -> BackendDnsRefreshOutcome {
    let resolved = match tokio::net::lookup_host((backend.authority_host.as_str(), 0)).await {
        Ok(addrs) => addrs
            .map(|addr| SocketAddr::new(addr.ip(), backend.authority_port))
            .collect::<Vec<_>>(),
        Err(err) => {
            return BackendDnsRefreshOutcome::LookupFailed {
                backend_addr: backend.backend_addr.clone(),
                authority_host: backend.authority_host.clone(),
                retained_addrs: backend.resolved_addrs.clone(),
                error: err.to_string(),
            };
        }
    };

    if resolved.is_empty() {
        return BackendDnsRefreshOutcome::EmptyAnswerRetained {
            backend_addr: backend.backend_addr.clone(),
            authority_host: backend.authority_host.clone(),
            retained_addrs: backend.resolved_addrs.clone(),
        };
    }

    let refreshed_at = SystemTime::now();
    let update = backend_resolution_store
        .update_hostname_resolution(&backend.backend_addr, resolved.clone(), refreshed_at)
        .expect("hostname backend must exist in resolution store");

    let _ = backend_dns_resolver.replace_host_addrs(
        &backend.authority_host,
        resolved
            .into_iter()
            .map(|addr| SocketAddr::new(ip_only(addr), 0)),
    );

    if update.changed() {
        BackendDnsRefreshOutcome::Updated {
            backend_addr: update.backend_addr,
            authority_host: update.authority_host,
            previous_addrs: update.previous_addrs,
            current_addrs: update.current_addrs,
            generation: update.refresh_generation,
        }
    } else {
        BackendDnsRefreshOutcome::Unchanged {
            backend_addr: update.backend_addr,
            authority_host: update.authority_host,
            current_addrs: update.current_addrs,
            generation: update.refresh_generation,
        }
    }
}

fn ip_only(addr: SocketAddr) -> IpAddr {
    addr.ip()
}
