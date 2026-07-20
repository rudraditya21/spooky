use std::{sync::Mutex, time::Duration};

use log::warn;
use tokio::{sync::oneshot, task::AbortHandle};

pub struct RuntimeTaskRegistry {
    state: Mutex<RuntimeTaskRegistryState>,
}

impl RuntimeTaskRegistry {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(RuntimeTaskRegistryState {
                retired: false,
                tasks: Vec::new(),
            }),
        }
    }

    pub(crate) fn register(&self, task: RuntimeTaskRegistration) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.retired {
            task.abort.abort();
        } else {
            state.tasks.push(task);
        }
    }

    fn begin_generation_retirement(&self) -> Vec<oneshot::Receiver<()>> {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.retired {
            return Vec::new();
        }
        state.retired = true;
        state
            .tasks
            .drain(..)
            .map(|task| {
                task.abort.abort();
                task.completion
            })
            .collect()
    }

    pub(crate) fn abort_generation(&self) {
        let _ = self.begin_generation_retirement();
    }

    async fn wait_for_generation_retirement(
        completions: Vec<oneshot::Receiver<()>>,
        timeout: Duration,
    ) {
        if completions.is_empty() {
            return;
        }

        let wait_for_completion = async {
            for completion in completions {
                let _ = completion.await;
            }
        };

        if tokio::time::timeout(timeout, wait_for_completion)
            .await
            .is_err()
        {
            warn!(
                "generation background tasks did not stop within {:?}; continuing reload",
                timeout
            );
        }
    }

    pub(crate) fn retire_generation(&self, timeout: Duration) {
        let completions = self.begin_generation_retirement();
        if completions.is_empty() {
            return;
        }

        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    Self::wait_for_generation_retirement(completions, timeout).await;
                });
            }
            Err(_) => {
                warn!(
                    "generation background tasks retired without an active Tokio runtime; completion wait skipped"
                );
            }
        }
    }
}

impl Drop for RuntimeTaskRegistry {
    fn drop(&mut self) {
        self.abort_generation();
    }
}

struct RuntimeTaskRegistryState {
    retired: bool,
    tasks: Vec<RuntimeTaskRegistration>,
}

pub(crate) struct RuntimeTaskRegistration {
    abort: AbortHandle,
    completion: oneshot::Receiver<()>,
}

impl RuntimeTaskRegistration {
    pub(crate) fn new(abort: AbortHandle, completion: oneshot::Receiver<()>) -> Self {
        Self { abort, completion }
    }
}
