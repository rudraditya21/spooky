mod common;
use common::create_backend_state;

use spooky_lb::backend_pool::BackendPool;

#[test]
fn backend_pool_epoch_changes_only_on_health_membership_transition() {
    let mut pool = BackendPool::new_from_states(vec![create_backend_state("10.0.0.1:1", 1)]);
    assert_eq!(pool.membership_epoch(), 0);

    pool.mark_failure(0);
    pool.mark_failure(0);
    assert_eq!(pool.membership_epoch(), 0);

    pool.mark_failure(0);
    assert_eq!(pool.membership_epoch(), 1);

    pool.mark_failure(0);
    assert_eq!(pool.membership_epoch(), 1);

    pool.mark_success(0);
    assert_eq!(pool.membership_epoch(), 2);

    pool.mark_success(0);
    assert_eq!(pool.membership_epoch(), 2);
}

#[test]
fn healthy_cache_tracks_membership_changes_without_duplicates() {
    let mut pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 1),
        create_backend_state("10.0.0.2:1", 1),
        create_backend_state("10.0.0.3:1", 1),
    ]);

    assert_eq!(pool.healthy_indices(), vec![0, 1, 2]);

    pool.mark_failure(1);
    pool.mark_failure(1);
    pool.mark_failure(1);
    assert_eq!(pool.healthy_indices(), vec![0, 2]);

    pool.mark_failure(1);
    assert_eq!(pool.healthy_indices(), vec![0, 2]);

    pool.mark_success(1);
    let healthy = pool.healthy_indices();
    assert_eq!(healthy.len(), 3);
    assert!(healthy.contains(&0));
    assert!(healthy.contains(&1));
    assert!(healthy.contains(&2));
}

#[test]
fn backend_recovers_after_success_threshold() {
    let mut pool = BackendPool::new_from_states(vec![create_backend_state("10.0.0.1:1", 1)]);
    pool.mark_failure(0);
    pool.mark_failure(0);
    pool.mark_failure(0);

    assert!(pool.healthy_indices().is_empty());
    pool.mark_success(0);
    assert_eq!(pool.healthy_indices(), vec![0]);
}
