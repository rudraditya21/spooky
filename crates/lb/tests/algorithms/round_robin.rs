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
