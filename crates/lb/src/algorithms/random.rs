use std::cell::RefCell;

use rand::{Rng, SeedableRng, rngs::StdRng};

use crate::backend_pool::BackendPool;

thread_local! {
    static LB_RANDOM_RNG: RefCell<StdRng> = RefCell::new(StdRng::from_entropy());
}

pub struct Random;

impl Random {
    pub fn new() -> Self {
        Self
    }

    pub fn pick(&mut self, pool: &BackendPool) -> Option<usize> {
        self.pick_readonly(pool)
    }

    pub fn pick_readonly(&self, pool: &BackendPool) -> Option<usize> {
        if pool.healthy.is_empty() {
            return None;
        }

        let idx = LB_RANDOM_RNG.with(|state| {
            let mut rng = state.borrow_mut();
            rng.gen_range(0..pool.healthy.len())
        });
        Some(pool.healthy[idx])
    }
}

impl Default for Random {
    fn default() -> Self {
        Self::new()
    }
}
