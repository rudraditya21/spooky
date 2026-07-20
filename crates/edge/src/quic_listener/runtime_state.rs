use std::{
    net::UdpSocket,
    sync::{Arc, atomic::AtomicBool},
};

use spooky_config::runtime::{ListenerRuntimeConfig, RuntimeConfig};
use spooky_errors::ProxyError;

use crate::runtime::{
    bundle::RuntimeBundleHandle,
    generation::{RuntimeGenerationState, RuntimeGenerationView, RuntimeSharedServices},
    shared_state::SharedRuntimeState,
};

pub(super) enum CanonicalRuntimeView<'a> {
    Startup {
        runtime_config: &'a RuntimeConfig,
        shared_state: &'a SharedRuntimeState,
    },
    Active(RuntimeGenerationView<'a>),
}

impl<'a> CanonicalRuntimeView<'a> {
    pub(super) fn runtime_config(&self) -> &RuntimeConfig {
        match self {
            Self::Startup { runtime_config, .. } => runtime_config,
            Self::Active(view) => view.runtime_config,
        }
    }

    pub(super) fn shared_services(&self) -> &RuntimeSharedServices {
        match self {
            Self::Startup { shared_state, .. } => shared_state.shared_services(),
            Self::Active(view) => view.shared,
        }
    }

    pub(super) fn generation_state(&self) -> &RuntimeGenerationState {
        match self {
            Self::Startup { shared_state, .. } => shared_state.generation_state(),
            Self::Active(view) => view.state,
        }
    }
}

pub(super) struct PreparedListenerStartup {
    pub(super) listener_config: ListenerRuntimeConfig,
    pub(super) shared_state: Arc<SharedRuntimeState>,
    pub(super) socket: UdpSocket,
}

pub(super) struct ControlPlaneBootstrap<'a> {
    pub(super) runtime_config: &'a RuntimeConfig,
    pub(super) shared_state: &'a SharedRuntimeState,
    pub(super) runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
    pub(super) worker_count: usize,
}

impl<'a> ControlPlaneBootstrap<'a> {
    pub(super) fn with_runtime_view<R>(&self, f: impl FnOnce(CanonicalRuntimeView<'_>) -> R) -> R {
        match self.runtime_bundle.as_ref() {
            Some(handle) => handle.with_current_view(|view| f(CanonicalRuntimeView::Active(view))),
            None => f(CanonicalRuntimeView::Startup {
                runtime_config: self.runtime_config,
                shared_state: self.shared_state,
            }),
        }
    }
}

pub struct ListenerWorkerRuntimeState {
    pub listener_config: ListenerRuntimeConfig,
    pub shared_state: Arc<SharedRuntimeState>,
    pub runtime_bundle: Arc<RuntimeBundleHandle>,
    pub shutdown: Arc<AtomicBool>,
}

impl ListenerWorkerRuntimeState {
    pub fn listener_label(&self) -> String {
        crate::quic_listener::QUICListener::listener_label(&self.listener_config)
    }
}

pub(super) fn initialize_listener_from_runtime(
    socket: UdpSocket,
    startup_listener_config: &ListenerRuntimeConfig,
    startup_shared_state: Arc<SharedRuntimeState>,
    runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
) -> Result<crate::runtime::listener::QUICListener, ProxyError> {
    let listener_label =
        crate::quic_listener::QUICListener::listener_label(startup_listener_config);
    if let Some(runtime_bundle) = runtime_bundle {
        return crate::quic_listener::QUICListener::new_with_socket_and_runtime_bundle(
            &listener_label,
            socket,
            runtime_bundle,
        );
    }

    crate::quic_listener::QUICListener::new_with_socket_and_shared_state(
        startup_listener_config.clone(),
        socket,
        startup_shared_state,
    )
}
