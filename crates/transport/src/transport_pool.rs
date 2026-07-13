use std::{collections::HashMap, convert::Infallible, time::Duration};

use http_body_util::combinators::BoxBody;
use hyper::{
    Request,
    body::{Bytes, Incoming},
};
pub use spooky_errors::PoolError;

use crate::{
    h1_pool::H1Pool,
    h2_client::{ConnectObserver, SharedDnsResolver, TlsClientConfig},
    h2_pool::H2Pool,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendTransportKind {
    Http1,
    H2,
}

pub struct UpstreamTransportPool {
    backend_kinds: HashMap<String, BackendTransportKind>,
    h1_pool: H1Pool,
    h2_pool: H2Pool,
}

impl UpstreamTransportPool {
    pub fn new<I>(
        backends: I,
        backend_tls: HashMap<String, TlsClientConfig>,
        max_inflight: usize,
        max_idle_per_backend: usize,
        pool_idle_timeout: Duration,
        connect_timeout: Duration,
        dns_resolver: SharedDnsResolver,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = (String, BackendTransportKind)>,
    {
        Self::new_with_observer(
            backends,
            backend_tls,
            max_inflight,
            max_idle_per_backend,
            pool_idle_timeout,
            connect_timeout,
            dns_resolver,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_observer<I>(
        backends: I,
        backend_tls: HashMap<String, TlsClientConfig>,
        max_inflight: usize,
        max_idle_per_backend: usize,
        pool_idle_timeout: Duration,
        connect_timeout: Duration,
        dns_resolver: SharedDnsResolver,
        connect_observer: Option<ConnectObserver>,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = (String, BackendTransportKind)>,
    {
        let mut backend_kinds = HashMap::new();
        let mut h1_backends = Vec::new();
        let mut h2_backends = Vec::new();

        for (backend, kind) in backends {
            backend_kinds.insert(backend.clone(), kind);
            match kind {
                BackendTransportKind::Http1 => h1_backends.push(backend),
                BackendTransportKind::H2 => h2_backends.push(backend),
            }
        }

        let h1_pool = H1Pool::new_with_observer(
            h1_backends,
            max_inflight,
            max_idle_per_backend,
            pool_idle_timeout,
            connect_timeout,
            dns_resolver.clone(),
            connect_observer.clone(),
        );
        let h2_pool = H2Pool::new_with_observer(
            h2_backends,
            backend_tls,
            max_inflight,
            max_idle_per_backend,
            pool_idle_timeout,
            connect_timeout,
            dns_resolver,
            connect_observer,
        )?;

        Ok(Self {
            backend_kinds,
            h1_pool,
            h2_pool,
        })
    }

    pub async fn send(
        &self,
        backend: &str,
        req: Request<BoxBody<Bytes, Infallible>>,
    ) -> Result<hyper::Response<Incoming>, PoolError> {
        match self.backend_kinds.get(backend).copied() {
            Some(BackendTransportKind::Http1) => self.h1_pool.send(backend, req).await,
            Some(BackendTransportKind::H2) => self.h2_pool.send(backend, req).await,
            None => Err(PoolError::UnknownBackend(backend.to_string())),
        }
    }

    pub fn rotate_backend_client(&self, backend: &str) -> Result<bool, String> {
        match self.backend_kinds.get(backend).copied() {
            Some(BackendTransportKind::Http1) => self.h1_pool.rotate_backend_client(backend),
            Some(BackendTransportKind::H2) => self
                .h2_pool
                .rotate_backend_client(backend)
                .map(|rotation| rotation.is_some()),
            None => Ok(false),
        }
    }
}
