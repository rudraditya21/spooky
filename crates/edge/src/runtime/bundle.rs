use std::sync::{Arc, RwLock};

use spooky_config::runtime::{ListenerRuntimeConfig, RuntimeConfig};
use spooky_errors::ProxyError;

use crate::runtime::{
    generation::{RuntimeGenerationView, StartupOwnedRuntimeState},
    shared_state::SharedRuntimeState,
    tasks::RuntimeTaskRegistry,
};

#[derive(Clone)]
pub struct RuntimeBundle {
    pub generation: u64,
    pub startup: StartupOwnedRuntimeState,
    pub runtime_config: RuntimeConfig,
    pub shared_state: Arc<SharedRuntimeState>,
}

impl RuntimeBundle {
    pub fn startup(&self) -> &StartupOwnedRuntimeState {
        &self.startup
    }

    pub fn generation_view(&self) -> RuntimeGenerationView<'_> {
        RuntimeGenerationView {
            generation: self.generation,
            startup: &self.startup,
            runtime_config: &self.runtime_config,
            shared: self.shared_state.shared_services(),
            state: self.shared_state.generation_state(),
        }
    }

    pub fn listener_runtime_config(&self, label: &str) -> Option<ListenerRuntimeConfig> {
        self.generation_view().listener_runtime_config(label)
    }
}

#[derive(Clone)]
pub struct RuntimeBundleHandle {
    inner: Arc<RwLock<Arc<RuntimeBundle>>>,
}

impl RuntimeBundleHandle {
    pub fn new(bundle: RuntimeBundle) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(bundle))),
        }
    }

    pub fn current(&self) -> Arc<RuntimeBundle> {
        self.inner
            .read()
            .map(|bundle| Arc::clone(&*bundle))
            .unwrap_or_else(|_| panic!("runtime bundle lock poisoned"))
    }

    pub fn generation(&self) -> u64 {
        self.current().generation
    }

    pub fn with_current_view<R>(&self, f: impl FnOnce(RuntimeGenerationView<'_>) -> R) -> R {
        let current = self.current();
        f(current.generation_view())
    }

    pub fn replace(
        &self,
        bundle: RuntimeBundle,
    ) -> Result<(u64, Arc<RuntimeTaskRegistry>), ProxyError> {
        let generation = bundle.generation;
        let next_tasks = Arc::clone(&bundle.shared_state.generation_state().generation_tasks);
        let previous = {
            let mut guard = match self.inner.write() {
                Ok(guard) => guard,
                Err(_) => {
                    next_tasks.abort_all();
                    return Err(ProxyError::Transport(
                        "runtime bundle lock poisoned".to_string(),
                    ));
                }
            };
            std::mem::replace(&mut *guard, Arc::new(bundle))
        };
        let retired_tasks = Arc::clone(&previous.shared_state.generation_state().generation_tasks);
        Ok((generation, retired_tasks))
    }
}
