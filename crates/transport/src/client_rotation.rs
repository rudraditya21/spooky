#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendClientRotationState {
    MissingBackend,
    Recreated,
    Rotated {
        previous_generation: u64,
        current_generation: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendClientRotation {
    state: BackendClientRotationState,
}

impl BackendClientRotation {
    pub fn missing_backend() -> Self {
        Self {
            state: BackendClientRotationState::MissingBackend,
        }
    }

    pub fn recreated() -> Self {
        Self {
            state: BackendClientRotationState::Recreated,
        }
    }

    pub fn rotated(previous_generation: u64, current_generation: u64) -> Self {
        Self {
            state: BackendClientRotationState::Rotated {
                previous_generation,
                current_generation,
            },
        }
    }

    pub fn state(self) -> BackendClientRotationState {
        self.state
    }

    pub fn changed(self) -> bool {
        !matches!(self.state, BackendClientRotationState::MissingBackend)
    }

    pub fn generations(self) -> Option<(u64, u64)> {
        match self.state {
            BackendClientRotationState::Rotated {
                previous_generation,
                current_generation,
            } => Some((previous_generation, current_generation)),
            _ => None,
        }
    }
}
