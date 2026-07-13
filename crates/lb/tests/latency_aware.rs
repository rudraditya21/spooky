mod common;
use std::time::Duration;

use spooky_lb::{algorithms::latency_aware::LatencyAware, backend_pool::BackendPool};

use crate::common::create_backend_state;

#[test]
fn latency_aware_prefers_lower_ewma() {
    let mut pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 1),
        create_backend_state("10.0.0.2:1", 1),
    ]);

    pool.finish_request(0, Duration::from_millis(150), Some(200));
    pool.finish_request(1, Duration::from_millis(20), Some(200));

    let mut lb = LatencyAware::new();
    assert_eq!(lb.pick(&pool), Some(1));
}
