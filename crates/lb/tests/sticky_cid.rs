mod common;
use spooky_lb::{algorithms::sticky_cid::StickyCid, backend_pool::BackendPool};

use crate::common::create_backend_state;

#[test]
fn sticky_cid_is_deterministic_for_same_key() {
    let pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 1),
        create_backend_state("10.0.0.2:1", 1),
        create_backend_state("10.0.0.3:1", 1),
    ]);

    let mut lb = StickyCid::new(16);
    let first = lb.pick("cid:abc123", &pool);
    let second = lb.pick("cid:abc123", &pool);
    assert_eq!(first, second);
}
