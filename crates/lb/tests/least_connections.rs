mod common;
use spooky_lb::{algorithms::least_connections::LeastConnections, backend_pool::BackendPool};

use crate::common::create_backend_state;

#[test]
fn least_connections_picks_lowest_active() {
    let pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 1),
        create_backend_state("10.0.0.2:1", 1),
        create_backend_state("10.0.0.3:1", 1),
    ]);
    pool.begin_request(0);
    pool.begin_request(0);
    pool.begin_request(1);

    let mut lb = LeastConnections::new();
    assert_eq!(lb.pick(&pool), Some(2));
}
