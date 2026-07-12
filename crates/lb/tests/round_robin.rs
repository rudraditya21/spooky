mod common;
use crate::common::create_backend_state;
use spooky_lb::algorithms::round_robin::RoundRobin;
use spooky_lb::backend_pool::BackendPool;

#[test]
fn round_robin_cycles() {
    let pool = BackendPool::new_from_states(vec![
        create_backend_state("127.0.0.1:1", 1),
        create_backend_state("127.0.0.1:2", 1),
        create_backend_state("127.0.0.1:3", 1),
    ]);
    let mut rr = RoundRobin::new();

    let picks: Vec<usize> = (0..6).filter_map(|_| rr.pick(&pool)).collect();
    assert_eq!(picks, vec![0, 1, 2, 0, 1, 2]);
}

#[test]
fn unhealthy_backends_are_skipped() {
    let mut pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 1),
        create_backend_state("10.0.0.2:1", 1),
    ]);

    pool.mark_failure(0);
    pool.mark_failure(0);
    pool.mark_failure(0);

    let mut rr = RoundRobin::new();
    let pick = rr.pick(&pool).unwrap();
    assert_eq!(pick, 1);
}

#[test]
fn no_healthy_backends_returns_none() {
    let mut pool = BackendPool::new_from_states(vec![create_backend_state("10.0.0.1:1", 1)]);
    pool.mark_failure(0);
    pool.mark_failure(0);
    pool.mark_failure(0);

    let mut rr = RoundRobin::new();
    assert!(rr.pick(&pool).is_none());
}
