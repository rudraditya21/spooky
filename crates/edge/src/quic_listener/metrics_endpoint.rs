use std::{
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

use hyper::{Request, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use log::{debug, error, info};
use spooky_config::config::MetricsEndpoint;
use spooky_errors::ProxyError;

use super::{
    QUICListener, runtime_endpoint::RuntimeConnectionSlotGuard, runtime_handle,
    spawn_supervised_async_task,
};
use crate::{Metrics, runtime::bundle::RuntimeBundleHandle};

struct MetricsEndpointBinding {
    bind: String,
    listener: tokio::net::TcpListener,
    active_connections: Arc<AtomicUsize>,
}

pub(super) struct MetricsEndpointState {
    pub(super) metrics_path: String,
    pub(super) max_connections: usize,
    pub(super) connection_timeout: Duration,
    pub(super) metrics: Arc<Metrics>,
}

impl QUICListener {
    pub(super) fn spawn_metrics_endpoint(
        config: &spooky_config::runtime::RuntimeConfig,
        metrics: Arc<Metrics>,
        runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
    ) -> Result<(), ProxyError> {
        let endpoint = &config.observability.metrics;
        if runtime_bundle.is_none() && !endpoint.enabled {
            return Ok(());
        }
        let required = endpoint.required;
        let startup_endpoint = endpoint.clone();
        let startup_metrics_path = startup_endpoint.path.clone();
        let startup_max_connections = startup_endpoint.max_connections.max(1);
        let startup_connection_timeout =
            Duration::from_millis(startup_endpoint.connection_timeout_ms.max(1));

        let handle = match runtime_handle() {
            Some(handle) => handle,
            None => {
                let msg = "metrics endpoint disabled (no Tokio runtime available)".to_string();
                if required {
                    return Err(ProxyError::Transport(msg));
                }
                error!("{}", msg);
                return Ok(());
            }
        };

        let initial_binding = if startup_endpoint.enabled {
            let bind = format!("{}:{}", startup_endpoint.address, startup_endpoint.port);
            match Self::bind_tcp_listener(&bind, Some(&handle), "metrics endpoint") {
                Ok(listener) => Some(MetricsEndpointBinding {
                    bind,
                    listener,
                    active_connections: Arc::new(AtomicUsize::new(0)),
                }),
                Err(msg) => {
                    if required {
                        return Err(ProxyError::Transport(msg));
                    }
                    error!("{}", msg);
                    None
                }
            }
        } else {
            None
        };

        spawn_supervised_async_task(
            &handle,
            "metrics-endpoint",
            Some(Arc::clone(&metrics)),
            async move {
                let mut listener_binding = initial_binding;

                loop {
                    let endpoint = Self::current_metrics_endpoint_config(
                        runtime_bundle.as_ref(),
                        &startup_endpoint,
                    );
                    let desired_bind = format!("{}:{}", endpoint.address, endpoint.port);

                    if !endpoint.enabled {
                        if let Some(binding) = listener_binding.take() {
                            info!(
                                "Metrics endpoint disabled via runtime reload on {}",
                                binding.bind
                            );
                        }
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }

                    let needs_rebind = match listener_binding.as_ref() {
                        Some(binding) => binding.bind != desired_bind,
                        None => true,
                    };
                    if needs_rebind {
                        match Self::bind_tcp_listener(&desired_bind, None, "metrics endpoint") {
                            Ok(listener) => {
                                info!(
                                    "Metrics endpoint ready bind=http://{}{}",
                                    desired_bind, endpoint.path,
                                );
                                info!(
                                    "Metrics endpoint limits bind={} max_connections={} connection_timeout_ms={}",
                                    desired_bind,
                                    endpoint.max_connections.max(1),
                                    endpoint.connection_timeout_ms.max(1)
                                );
                                listener_binding = Some(MetricsEndpointBinding {
                                    bind: desired_bind.clone(),
                                    listener,
                                    active_connections: Arc::new(AtomicUsize::new(0)),
                                });
                            }
                            Err(err) => {
                                error!("{}", err);
                                tokio::time::sleep(Duration::from_millis(200)).await;
                                continue;
                            }
                        }
                    }

                    let Some(binding) = listener_binding.as_mut() else {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    };

                    let accept_result = tokio::select! {
                        accept = binding.listener.accept() => Some(accept),
                        _ = tokio::time::sleep(Duration::from_millis(200)) => None,
                    };
                    let Some(accept_result) = accept_result else {
                        continue;
                    };
                    let (stream, _peer) = match accept_result {
                        Ok(v) => v,
                        Err(err) => {
                            error!("Metrics endpoint accept failed: {}", err);
                            continue;
                        }
                    };
                    let runtime_state = Self::metrics_endpoint_state(
                        runtime_bundle.as_ref(),
                        startup_metrics_path.clone(),
                        startup_max_connections,
                        startup_connection_timeout,
                        Arc::clone(&metrics),
                    );
                    let active_connections = Arc::clone(&binding.active_connections);
                    if !Self::try_claim_runtime_connection_slot(
                        &active_connections,
                        runtime_state.max_connections,
                    ) {
                        continue;
                    }

                    let io = TokioIo::new(stream);
                    let metrics = Arc::clone(&runtime_state.metrics);
                    let metrics_path = runtime_state.metrics_path.clone();
                    let timeout = runtime_state.connection_timeout;

                    tokio::spawn(async move {
                        let _connection_guard = RuntimeConnectionSlotGuard::new(active_connections);
                        let service = service_fn(move |req: Request<Incoming>| {
                            let metrics = Arc::clone(&metrics);
                            let metrics_path = metrics_path.clone();
                            async move {
                                Ok::<_, hyper::Error>(Self::handle_metrics_request(
                                    req,
                                    &metrics_path,
                                    metrics,
                                ))
                            }
                        });

                        let serve = http1::Builder::new().serve_connection(io, service);
                        match tokio::time::timeout(timeout, serve).await {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) => {
                                error!("Metrics endpoint connection failed: {}", err);
                            }
                            Err(_) => {
                                debug!("Metrics endpoint connection timed out");
                            }
                        }
                    });
                }
            },
        );
        Ok(())
    }

    pub(super) fn current_metrics_endpoint_config(
        runtime_bundle: Option<&Arc<RuntimeBundleHandle>>,
        startup_endpoint: &MetricsEndpoint,
    ) -> MetricsEndpoint {
        runtime_bundle
            .map(|handle| {
                handle
                    .current()
                    .runtime_config
                    .observability
                    .metrics
                    .clone()
            })
            .unwrap_or_else(|| startup_endpoint.clone())
    }

    pub(super) fn metrics_endpoint_state(
        runtime_bundle: Option<&Arc<RuntimeBundleHandle>>,
        startup_metrics_path: String,
        startup_max_connections: usize,
        startup_connection_timeout: Duration,
        startup_metrics: Arc<Metrics>,
    ) -> MetricsEndpointState {
        if let Some(handle) = runtime_bundle {
            let runtime = handle.current();
            let endpoint = &runtime.runtime_config.observability.metrics;
            return MetricsEndpointState {
                metrics_path: endpoint.path.clone(),
                max_connections: endpoint.max_connections.max(1),
                connection_timeout: Duration::from_millis(endpoint.connection_timeout_ms.max(1)),
                metrics: runtime.shared_state.metrics.clone(),
            };
        }

        MetricsEndpointState {
            metrics_path: startup_metrics_path,
            max_connections: startup_max_connections,
            connection_timeout: startup_connection_timeout,
            metrics: startup_metrics,
        }
    }
}
