use spooky_errors::{PoolError, ProxyError};

#[test]
fn pool_and_transport_errors_have_distinct_display_text() {
    let pool = ProxyError::Pool(PoolError::UnknownBackend("api-a".to_string()));
    let transport = ProxyError::Transport("api-a".to_string());

    assert_eq!(pool.to_string(), "pool error: unknown backend: api-a");
    assert_eq!(transport.to_string(), "transport error: api-a");
}

#[test]
fn overloaded_pool_error_keeps_pool_specific_prefix() {
    let err = ProxyError::Pool(PoolError::BackendOverloaded("api-b".to_string()));

    assert_eq!(err.to_string(), "pool error: backend overloaded: api-b");
}
