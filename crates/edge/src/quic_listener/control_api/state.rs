use super::*;
use crate::quic_listener::runtime_state::ControlApiServiceCtx;

#[derive(Clone)]
pub(super) struct ControlApiPaths {
    pub(super) health_path: String,
    pub(super) ready_path: String,
    pub(super) runtime_path: String,
    pub(super) restart_path: String,
    pub(super) reload_path: String,
    pub(super) reload_certs_path: String,
}

impl ControlApiPaths {
    pub(super) fn from_endpoint(endpoint: &ControlApiConfig) -> Self {
        Self {
            health_path: endpoint.health_path.clone(),
            ready_path: endpoint.ready_path.clone(),
            runtime_path: endpoint.runtime_path.clone(),
            restart_path: endpoint.restart_path.clone(),
            reload_path: endpoint.reload_path.clone(),
            reload_certs_path: endpoint.reload_certs_path.clone(),
        }
    }
}

pub(super) type ControlApiState = ControlApiServiceCtx;

impl ControlApiServiceCtx {
    #[cfg(test)]
    pub(super) fn current_generation(
        &self,
    ) -> Option<crate::runtime::bundle::ActiveRuntimeGeneration> {
        self.current_service_state().generation
    }

    #[cfg(test)]
    pub(super) fn current_control_api(&self) -> ControlApiConfig {
        self.current_service_state().endpoint
    }

    #[cfg(test)]
    pub(super) fn current_paths(&self) -> ControlApiPaths {
        self.current_service_state().paths
    }

    #[cfg(test)]
    pub(super) fn current_primary_listener_label(&self) -> Option<String> {
        self.current_service_state().primary_listener_label
    }
}
