mod common;
use spooky_lb::{algorithms::consistent_hash::ConsistentHash, backend_pool::BackendPool};

use crate::common::create_backend_state;

#[test]
fn consistent_hash_is_stable() {
    let pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 1),
        create_backend_state("10.0.0.2:1", 1),
        create_backend_state("10.0.0.3:1", 1),
    ]);

    let mut ch = ConsistentHash::new(16);
    let first = ch.pick("user:123", &pool);
    let second = ch.pick("user:123", &pool);
    assert_eq!(first, second);
}

#[test]
fn consistent_hash_rebuilds_only_when_membership_changes() {
    let mut pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 1),
        create_backend_state("10.0.0.2:1", 1),
        create_backend_state("10.0.0.3:1", 1),
    ]);

    let mut ch = ConsistentHash::new(16);

    let _ = ch.pick("user:123", &pool);
    let first_rebuilds = ch.ring_rebuilds;
    let first_len = ch.ring.len();
    assert_eq!(first_rebuilds, 1);

    for key in ["user:123", "user:124", "user:125", "user:126"] {
        let _ = ch.pick(key, &pool);
    }
    assert_eq!(ch.ring_rebuilds, first_rebuilds);
    assert_eq!(ch.ring.len(), first_len);

    pool.mark_failure(0);
    pool.mark_failure(0);
    pool.mark_failure(0);

    let _ = ch.pick("user:127", &pool);
    assert_eq!(ch.ring_rebuilds, first_rebuilds + 1);
    assert!(ch.ring.len() < first_len);
}

#[test]
fn consistent_hash_ring_size_matches_weighted_healthy_membership() {
    let mut pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 2),
        create_backend_state("10.0.0.2:1", 3),
    ]);

    let mut ch = ConsistentHash::new(8);

    let _ = ch.pick("user:1", &pool);
    assert_eq!(ch.ring.len(), (8 * (2 + 3)) as usize);

    pool.mark_failure(0);
    pool.mark_failure(0);
    pool.mark_failure(0);

    let _ = ch.pick("user:2", &pool);
    assert_eq!(ch.ring.len(), (8 * 3) as usize);
}
