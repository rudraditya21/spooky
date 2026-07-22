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
}
