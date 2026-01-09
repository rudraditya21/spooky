//! Load balancing strategies module
//! 
//! TODO: Implement round-robin strategy
//! TODO: Implement least-connections strategy  
//! TODO: Implement weighted round-robin strategy
//! TODO: Implement IP hash strategy
//! TODO: Implement least response time strategy

use crate::config::config::Backend;

pub mod random;

pub struct Random<'l> {
    backends: &'l[Backend],
}

pub trait LoadBalancer<'l> {
    fn pick(&'l self, key: &str) -> Option<&'l Backend>;
}
