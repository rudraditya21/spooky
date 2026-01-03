// Random load balancing strategy implementation
use log::{error, info};

use rand::{seq::SliceRandom, thread_rng};

use crate::{config::config::Backend, lb::Random};

impl Random {
    pub fn new(backends: &[Backend]) -> Self {
        Self { backends }
    }
}

impl super::lb::LoadBalancer for Random {
    fn pick(&self, _: &str) -> Option<&Backend> {
        let mut rng = thread_rng();

        let healthy_backends: Vec<&Backend> = self.backends.iter().filter(|b| b.is_healthy()).collect();

        match healthy_backends.choose(&mut rng) {
            Some(random_backend) => {
                info!("Selected backend address: {}", random_backend.address);
                Some(random_backend)
            }
            None => {
                error!("No backend avaliable");
                None
            }
        }
    }
}