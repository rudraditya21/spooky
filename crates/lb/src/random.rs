// Random load balancing strategy implementation
use log::{error, info};

use rand::{seq::SliceRandom, thread_rng};

use spooky_config::config::Backend;

use crate::Random;

impl<'l> Random<'l> {
    pub fn new(backends: &'l [Backend]) -> Self {
        Self { backends }
    }
}

impl<'l> super::LoadBalancer<'l> for Random<'l> {
    fn pick(&'l self, _: &str) -> Option<&'l Backend> {
        let mut rng = thread_rng();

        let healthy_backends: Vec<&Backend> =
            self.backends.iter().filter(|b| b.is_healthy()).collect();

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
