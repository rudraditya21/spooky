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

    fn retire_now(&self) -> Vec<oneshot::Receiver<()>> {
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

    pub(crate) fn abort_all(&self) {
        let _ = self.retire_now();
    }

    pub(crate) async fn retire_with_timeout(&self, timeout: Duration) {
        let completions = self.retire_now();
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
}

impl Drop for RuntimeTaskRegistry {
    fn drop(&mut self) {
        self.abort_all();
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
