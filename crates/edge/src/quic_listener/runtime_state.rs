use std::{
    net::UdpSocket,
    sync::{Arc, atomic::AtomicBool},
};

use spooky_config::runtime::{ListenerRuntimeConfig, RuntimeConfig};

use crate::runtime::{bundle::RuntimeBundleHandle, shared_state::SharedRuntimeState};

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

pub struct ListenerWorkerRuntimeState {
    pub listener_config: ListenerRuntimeConfig,
    pub shared_state: Arc<SharedRuntimeState>,
    pub runtime_bundle: Arc<RuntimeBundleHandle>,
    pub shutdown: Arc<AtomicBool>,
}
