use super::*;

#[derive(Clone)]
pub(in crate::quic_listener) struct MetricsEndpointState {
    pub(in crate::quic_listener) endpoint: MetricsEndpoint,
    pub(in crate::quic_listener) metrics: Arc<Metrics>,
}

impl MetricsServiceCtx {
    pub(in crate::quic_listener) fn current_state(&self) -> MetricsEndpointState {
        let runtime = self.runtime.current_view();
        MetricsEndpointState {
            endpoint: runtime.runtime_config().observability.metrics.clone(),
            metrics: runtime.metrics(),
        }
    }
}

impl QUICListener {
    pub(in crate::quic_listener) fn current_metrics_endpoint_state(
        service_ctx: &MetricsServiceCtx,
    ) -> MetricsEndpointState {
        service_ctx.current_state()
    }

    pub(super) fn handle_metrics_request(
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
