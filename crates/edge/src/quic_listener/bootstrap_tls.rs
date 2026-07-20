use std::sync::{Arc, atomic::AtomicBool};

use spooky_config::runtime::ListenerRuntimeConfig;
use spooky_errors::ProxyError;

#[cfg(test)]
use super::bootstrap::BootstrapStartupState;
use super::bootstrap::spawn_bootstrap_tls_listener;
#[cfg(test)]
use super::bootstrap::{BootstrapConnectionState, bootstrap_connection_state};
use crate::runtime::{bundle::RuntimeBundleHandle, shared_state::SharedRuntimeState};

impl super::QUICListener {
    pub fn spawn_bootstrap_tls_listener(
        config: &ListenerRuntimeConfig,
        shared_state: &SharedRuntimeState,
        runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
        shutdown_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), ProxyError> {
        spawn_bootstrap_tls_listener(config, shared_state, runtime_bundle, shutdown_signal)
    }

    #[cfg(test)]
    pub(super) fn bootstrap_connection_state(
        listener_label: &str,
        runtime_bundle: Option<&Arc<RuntimeBundleHandle>>,
        startup: &BootstrapStartupState,
    ) -> Option<BootstrapConnectionState> {
        bootstrap_connection_state(listener_label, runtime_bundle, startup)
    }
}
