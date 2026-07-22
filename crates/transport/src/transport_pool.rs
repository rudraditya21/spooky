//! Canonical transport execution façade.
//!
//! This module owns runtime-selected backend protocol dispatch, transport-level
//! timeout application, connection reuse, and backend client rotation. Callers
//! should hand it a backend identity plus a canonical request and avoid
//! reconstructing H1/H2 selection logic themselves.

use std::{collections::HashMap, convert::Infallible, time::Duration};

use http_body_util::combinators::BoxBody;
use hyper::{
    Request,
    body::{Bytes, Incoming},
};
use spooky_config::runtime::{
    RuntimeBackendConnectionPolicy, RuntimeBackendTransportKind, RuntimeUpstream,
};
use spooky_errors::{PoolError, ProxyError};

use crate::{
    client_rotation::BackendClientRotation,
    h1_pool::H1Pool,
    h2_client::{ConnectObserver, SharedDnsResolver, TlsClientConfig},
    h2_pool::H2Pool,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendTransportEntry {
    Http1,
    H2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportClientRotation {
    rotation: BackendClientRotation,
}

impl TransportClientRotation {
    /// Returns true when transport rotated or recreated the backend client.
    pub fn rotated(self) -> bool {
        self.rotation.changed()
    }

    /// Returns generation movement for protocols that track reusable client generations.
    pub fn generations(self) -> Option<(u64, u64)> {
        self.rotation.generations()
    }
}

/// Canonical transport façade used by edge/runtime code for backend execution.
pub struct UpstreamTransportPool {
    backend_entries: HashMap<String, BackendTransportEntry>,
    h1_pool: H1Pool,
    h2_pool: H2Pool,
    execution_timeout: Duration,
}

impl UpstreamTransportPool {
    /// Execute a canonical upstream request against the resolved backend target.
    pub async fn send_backend_request(
        &self,
        backend: &str,
        req: Request<BoxBody<Bytes, Infallible>>,
    ) -> Result<hyper::Response<Incoming>, ProxyError> {
        self.execute(backend, req).await
    }

    /// Build a transport pool from already-interpreted backend transport entries.
    pub fn new_from_runtime_backends<I>(
        backends: I,
        backend_tls: HashMap<String, TlsClientConfig>,
        connection_policy: RuntimeBackendConnectionPolicy,
        dns_resolver: SharedDnsResolver,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = (String, RuntimeBackendTransportKind)>,
    {
        Self::new_runtime_with_observer(
            backends,
            backend_tls,
            connection_policy.max_inflight,
            connection_policy.max_idle_per_backend,
            connection_policy.pool_idle_timeout,
            connection_policy.connect_timeout,
            connection_policy.execution_timeout,
            dns_resolver,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_runtime_with_observer<I>(
        backends: I,
        backend_tls: HashMap<String, TlsClientConfig>,
        max_inflight: usize,
        max_idle_per_backend: usize,
        pool_idle_timeout: Duration,
        connect_timeout: Duration,
        execution_timeout: Duration,
        dns_resolver: SharedDnsResolver,
        connect_observer: Option<ConnectObserver>,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = (String, RuntimeBackendTransportKind)>,
    {
        let mut backend_entries = HashMap::new();
        let mut h1_backends = Vec::new();
        let mut h2_backends = Vec::new();

        for (backend, runtime_transport) in backends {
            let entry = Self::resolve_runtime_transport(runtime_transport);
            backend_entries.insert(backend.clone(), entry);
            match entry {
                BackendTransportEntry::Http1 => h1_backends.push(backend),
                BackendTransportEntry::H2 => h2_backends.push(backend),
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
            backend_entries,
            h1_pool,
            h2_pool,
            execution_timeout,
        })
    }

    fn resolve_runtime_transport(transport: RuntimeBackendTransportKind) -> BackendTransportEntry {
        match transport {
            RuntimeBackendTransportKind::Http1 => BackendTransportEntry::Http1,
            RuntimeBackendTransportKind::H2 => BackendTransportEntry::H2,
        }
    }

    /// Build the canonical transport façade directly from runtime upstream definitions.
    pub fn from_runtime_upstreams<'a, I>(
        upstreams: I,
        connection_policy: &RuntimeBackendConnectionPolicy,
        dns_resolver: SharedDnsResolver,
        connect_observer: Option<ConnectObserver>,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = &'a RuntimeUpstream>,
    {
        let mut backends = Vec::new();
        let mut backend_tls = HashMap::new();

        for upstream in upstreams {
            for backend in &upstream.backends {
                let backend_addr = backend.backend.address.clone();
                backends.push((backend_addr.clone(), backend.endpoint.transport_kind));
                if matches!(
                    backend.endpoint.transport_kind,
                    RuntimeBackendTransportKind::H2
                ) {
                    backend_tls.insert(
                        backend_addr,
                        TlsClientConfig::from(upstream.backend_tls_policy()),
                    );
                }
            }
        }

        Self::new_runtime_with_observer(
            backends,
            backend_tls,
            connection_policy.max_inflight,
            connection_policy.max_idle_per_backend,
            connection_policy.pool_idle_timeout,
            connection_policy.connect_timeout,
            connection_policy.execution_timeout,
            dns_resolver,
            connect_observer,
        )
    }

    fn backend_entry(&self, backend: &str) -> Option<BackendTransportEntry> {
        self.backend_entries.get(backend).copied()
    }

    async fn execute(
        &self,
        backend: &str,
        req: Request<BoxBody<Bytes, Infallible>>,
    ) -> Result<hyper::Response<Incoming>, ProxyError> {
        match self.backend_entry(backend) {
            Some(BackendTransportEntry::Http1) => {
                self.execute_with_timeout(backend, self.h1_pool.send(backend, req))
                    .await
            }
            Some(BackendTransportEntry::H2) => {
                self.execute_with_timeout(backend, self.h2_pool.send(backend, req))
                    .await
            }
            None => Err(ProxyError::Pool(PoolError::UnknownBackend(
                backend.to_string(),
            ))),
        }
    }

    pub fn rotate_backend_client(&self, backend: &str) -> Result<TransportClientRotation, String> {
        match self.backend_entry(backend) {
            Some(BackendTransportEntry::Http1) => self
                .h1_pool
                .rotate_backend_client(backend)
                .map(Self::transport_rotation),
            Some(BackendTransportEntry::H2) => self
                .h2_pool
                .rotate_backend_client(backend)
                .map(Self::transport_rotation),
            None => Ok(TransportClientRotation {
                rotation: BackendClientRotation::missing_backend(),
            }),
        }
    }

    fn transport_rotation(rotation: BackendClientRotation) -> TransportClientRotation {
        TransportClientRotation { rotation }
    }

    async fn execute_with_timeout<F>(
        &self,
        _backend: &str,
        send: F,
    ) -> Result<hyper::Response<Incoming>, ProxyError>
    where
        F: std::future::Future<Output = Result<hyper::Response<Incoming>, PoolError>>,
    {
        tokio::time::timeout(self.execution_timeout, send)
            .await
            .map_err(|_| ProxyError::Timeout)?
            .map_err(ProxyError::Pool)
    }
}
