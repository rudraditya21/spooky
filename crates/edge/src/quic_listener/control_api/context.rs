use std::sync::atomic::AtomicUsize;

use super::{state::ControlApiPaths, *};
use crate::quic_listener::runtime_state::ControlApiServiceCtx;

#[derive(Clone)]
pub(super) struct ControlApiServiceState {
    pub(super) endpoint: ControlApiConfig,
    pub(super) paths: ControlApiPaths,
    pub(super) metrics: Arc<Metrics>,
}

pub(super) struct ControlApiListenerBinding {
    pub(super) bind: String,
    pub(super) listener: tokio::net::TcpListener,
    pub(super) active_connections: Arc<AtomicUsize>,
}

pub(super) struct ConnectionSlotGuard {
    active_connections: Arc<AtomicUsize>,
}

impl ConnectionSlotGuard {
    pub(super) fn new(active_connections: Arc<AtomicUsize>) -> Self {
        Self { active_connections }
    }
}

impl Drop for ConnectionSlotGuard {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ControlApiServiceCtx {
    pub(super) fn current_service_state(&self) -> ControlApiServiceState {
        let endpoint = self.current_control_api();
        let paths = ControlApiPaths::from_endpoint(&endpoint);
        ControlApiServiceState {
            endpoint,
            paths,
            metrics: self.current_metrics(),
        }
    }
}
