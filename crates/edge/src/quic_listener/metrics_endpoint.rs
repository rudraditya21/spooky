use std::{
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;
use hyper::{Request, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use log::{debug, error, info};
use spooky_config::config::MetricsEndpoint;
use spooky_errors::ProxyError;

use super::{
    QUICListener,
    runtime_endpoint::RuntimeConnectionSlotGuard,
    runtime_handle,
    runtime_state::{ControlPlaneBootstrap, MetricsServiceCtx},
    spawn_supervised_async_task,
};
use crate::Metrics;

struct MetricsEndpointBinding {
    bind: String,
    listener: tokio::net::TcpListener,
    active_connections: Arc<AtomicUsize>,
}

#[derive(Clone)]
pub(super) struct MetricsEndpointState {
    pub(super) endpoint: MetricsEndpoint,
    pub(super) metrics: Arc<Metrics>,
}

impl MetricsServiceCtx {
    fn current_state(&self) -> MetricsEndpointState {
        let runtime = self.runtime.current_view();
        MetricsEndpointState {
            endpoint: runtime.runtime_config().observability.metrics.clone(),
            metrics: runtime.metrics(),
        }
    }
}

impl QUICListener {
    pub(super) fn spawn_metrics_endpoint(
        bootstrap: &ControlPlaneBootstrap<'_>,
    ) -> Result<(), ProxyError> {
        let service_ctx = bootstrap.metrics_service_ctx();
        let startup_state = service_ctx.current_state();
        if bootstrap.runtime_bundle.is_none() && !startup_state.endpoint.enabled {
            return Ok(());
        }
        let required = startup_state.endpoint.required;

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

        let initial_binding = if startup_state.endpoint.enabled {
            let bind = format!(
                "{}:{}",
                startup_state.endpoint.address, startup_state.endpoint.port
            );
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
            Some(Arc::clone(&startup_state.metrics)),
            async move {
                let mut listener_binding = initial_binding;

                loop {
                    let runtime_state = Self::current_metrics_endpoint_state(
                        &service_ctx,
                    );
                    let endpoint = &runtime_state.endpoint;
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
                    let runtime_state = Self::current_metrics_endpoint_state(
                        &service_ctx,
                    );
                    let active_connections = Arc::clone(&binding.active_connections);
                    if !Self::try_claim_runtime_connection_slot(
                        &active_connections,
                        runtime_state.endpoint.max_connections.max(1),
                    ) {
                        continue;
                    }

                    let io = TokioIo::new(stream);
                    let metrics = Arc::clone(&runtime_state.metrics);
                    let metrics_path = runtime_state.endpoint.path.clone();
                    let timeout =
                        Duration::from_millis(runtime_state.endpoint.connection_timeout_ms.max(1));

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

    pub(super) fn current_metrics_endpoint_state(
        service_ctx: &MetricsServiceCtx,
    ) -> MetricsEndpointState {
        service_ctx.current_state()
    }

    fn handle_metrics_request(
        req: Request<Incoming>,
        metrics_path: &str,
        metrics: Arc<Metrics>,
    ) -> Response<Full<Bytes>> {
        if req.uri().path() != metrics_path {
            return match Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from_static(b"not found\n")))
            {
                Ok(resp) => resp,
                Err(_) => Response::new(Full::new(Bytes::from_static(b"not found\n"))),
            };
        }

        let body = metrics.render_prometheus();
        match Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4")
            .body(Full::new(Bytes::from(body)))
        {
            Ok(resp) => resp,
            Err(_) => Response::new(Full::new(Bytes::from_static(b"failed to render metrics\n"))),
        }
    }
}
