use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, RwLock},
    time::Duration,
};

use http_body_util::combinators::BoxBody;
use hyper::Request;
use hyper::body::{Bytes, Incoming};
use tokio::sync::{Semaphore, TryAcquireError};

use crate::h1_client::H1Client;
use crate::h2_client::SharedDnsResolver;
pub use spooky_errors::PoolError;

struct BackendClientState {
    client: Arc<H1Client>,
}

struct BackendHandle {
    state: RwLock<BackendClientState>,
    inflight: Arc<Semaphore>,
}

pub struct H1Pool {
    backends: HashMap<String, BackendHandle>,
    max_idle_per_backend: usize,
    pool_idle_timeout: Duration,
    connect_timeout: Duration,
    dns_resolver: SharedDnsResolver,
}

impl H1Pool {
    pub fn new<I>(
        backends: I,
        max_inflight: usize,
        max_idle_per_backend: usize,
        pool_idle_timeout: Duration,
        connect_timeout: Duration,
        dns_resolver: SharedDnsResolver,
    ) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let inflight = max_inflight.max(1);
        let max_idle_per_backend = max_idle_per_backend.max(1);
        let mut map = HashMap::new();
        for backend in backends {
            let client = Arc::new(H1Client::new(
                max_idle_per_backend,
                pool_idle_timeout,
                connect_timeout,
                dns_resolver.clone(),
            ));
            map.insert(
                backend,
                BackendHandle {
                    state: RwLock::new(BackendClientState { client }),
                    inflight: Arc::new(Semaphore::new(inflight)),
                },
            );
        }

        Self {
            backends: map,
            max_idle_per_backend,
            pool_idle_timeout,
            connect_timeout,
            dns_resolver,
        }
    }

    pub async fn send(
        &self,
        backend: &str,
        req: Request<BoxBody<Bytes, Infallible>>,
    ) -> Result<hyper::Response<Incoming>, PoolError> {
        let handle = self
            .backends
            .get(backend)
            .ok_or_else(|| PoolError::UnknownBackend(backend.to_string()))?;
        let client = handle
            .state
            .read()
            .map(|state| Arc::clone(&state.client))
            .map_err(|_| PoolError::InflightLimiterClosed)?;

        let _permit = match Arc::clone(&handle.inflight).try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                return Err(PoolError::BackendOverloaded(backend.to_string()));
            }
            Err(TryAcquireError::Closed) => return Err(PoolError::InflightLimiterClosed),
        };

        client.send(req).await.map_err(PoolError::Send)
    }

    pub fn rotate_backend_client(&self, backend: &str) -> Result<bool, String> {
        let Some(handle) = self.backends.get(backend) else {
            return Ok(false);
        };

        let client = Arc::new(H1Client::new(
            self.max_idle_per_backend,
            self.pool_idle_timeout,
            self.connect_timeout,
            self.dns_resolver.clone(),
        ));

        let mut state = handle
            .state
            .write()
            .map_err(|_| format!("backend client state poisoned for '{backend}'"))?;
        state.client = client;
        Ok(true)
    }
}
