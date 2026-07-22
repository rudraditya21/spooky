use std::{collections::HashMap, convert::Infallible, time::Duration};

use http_body_util::combinators::BoxBody;
use hyper::{
    Request,
    body::{Bytes, Incoming},
};
use spooky_config::runtime::{
    RuntimeBackendConnectionPolicy, RuntimeBackendTransportKind, RuntimeUpstream,
};
pub use spooky_errors::PoolError;

use crate::{
    h1_pool::H1Pool,
    h2_client::{ConnectObserver, SharedDnsResolver, TlsClientConfig},
    h2_pool::H2Pool,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedBackendTransport {
    Http1,
    H2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendTransportEntry {
    Http1,
    H2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportExecutionTarget<'a> {
    backend: &'a str,
}

impl<'a> TransportExecutionTarget<'a> {
    pub fn new(backend: &'a str) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &'a str {
        self.backend
    }
}

pub struct TransportExecutionResult {
    transport: ResolvedBackendTransport,
    response: hyper::Response<Incoming>,
}

impl TransportExecutionResult {
    fn new(
        transport: ResolvedBackendTransport,
        response: hyper::Response<Incoming>,
    ) -> Self {
        Self {
            transport,
            response,
        }
    }

    pub fn into_response(self) -> hyper::Response<Incoming> {
        self.response
    }

    pub fn protocol_name(&self) -> &'static str {
        match self.transport {
            ResolvedBackendTransport::Http1 => "http1",
            ResolvedBackendTransport::H2 => "h2",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportClientRotationState {
    MissingBackend,
    Recreated,
    Rotated {
        previous_generation: u64,
        current_generation: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportClientRotation {
    transport: Option<ResolvedBackendTransport>,
    state: TransportClientRotationState,
}

impl TransportClientRotation {
    pub fn rotated(self) -> bool {
        !matches!(self.state, TransportClientRotationState::MissingBackend)
    }

    pub fn protocol_name(self) -> Option<&'static str> {
        self.transport.map(|transport| match transport {
            ResolvedBackendTransport::Http1 => "http1",
            ResolvedBackendTransport::H2 => "h2",
        })
    }

    pub fn generations(self) -> Option<(u64, u64)> {
        match self.state {
            TransportClientRotationState::Rotated {
                previous_generation,
                current_generation,
            } => Some((previous_generation, current_generation)),
            _ => None,
        }
    }
}

pub struct UpstreamTransportPool {
    backend_entries: HashMap<String, BackendTransportEntry>,
    h1_pool: H1Pool,
    h2_pool: H2Pool,
}

impl UpstreamTransportPool {
    pub fn new_from_runtime_backends<I>(
        backends: I,
        backend_tls: HashMap<String, TlsClientConfig>,
        max_inflight: usize,
        max_idle_per_backend: usize,
        pool_idle_timeout: Duration,
        connect_timeout: Duration,
        dns_resolver: SharedDnsResolver,
    ) -> Result<Self, String>
    where
        I: IntoIterator<Item = (String, RuntimeBackendTransportKind)>,
    {
        Self::new_runtime_with_observer(
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
    fn new_runtime_with_observer<I>(
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
        })
    }

    fn resolve_runtime_transport(
        transport: RuntimeBackendTransportKind,
    ) -> BackendTransportEntry {
        match transport {
            RuntimeBackendTransportKind::Http1 => BackendTransportEntry::Http1,
            RuntimeBackendTransportKind::H2 => BackendTransportEntry::H2,
        }
    }

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
                if matches!(backend.endpoint.transport_kind, RuntimeBackendTransportKind::H2) {
                    backend_tls.insert(
                        backend_addr,
                        TlsClientConfig::from(&upstream.policy_set.transport.tls),
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
            dns_resolver,
            connect_observer,
        )
    }

    fn backend_entry(&self, target: TransportExecutionTarget<'_>) -> Option<BackendTransportEntry> {
        self.backend_entries.get(target.backend()).copied()
    }

    pub async fn execute(
        &self,
        target: TransportExecutionTarget<'_>,
        req: Request<BoxBody<Bytes, Infallible>>,
    ) -> Result<TransportExecutionResult, PoolError> {
        match self.backend_entry(target) {
            Some(BackendTransportEntry::Http1) => self
                .h1_pool
                .send(target.backend(), req)
                .await
                .map(|response| {
                    TransportExecutionResult::new(ResolvedBackendTransport::Http1, response)
                }),
            Some(BackendTransportEntry::H2) => self
                .h2_pool
                .send(target.backend(), req)
                .await
                .map(|response| {
                    TransportExecutionResult::new(ResolvedBackendTransport::H2, response)
                }),
            None => Err(PoolError::UnknownBackend(target.backend().to_string())),
        }
    }

    pub fn rotate_backend_client(
        &self,
        target: TransportExecutionTarget<'_>,
    ) -> Result<TransportClientRotation, String> {
        match self.backend_entry(target) {
            Some(BackendTransportEntry::Http1) => self
                .h1_pool
                .rotate_backend_client(target.backend())
                .map(|rotated| {
                    if rotated {
                        TransportClientRotation {
                            transport: Some(ResolvedBackendTransport::Http1),
                            state: TransportClientRotationState::Recreated,
                        }
                    } else {
                        TransportClientRotation {
                            transport: None,
                            state: TransportClientRotationState::MissingBackend,
                        }
                    }
                }),
            Some(BackendTransportEntry::H2) => self
                .h2_pool
                .rotate_backend_client(target.backend())
                .map(|rotation| match rotation {
                    Some(rotation) => TransportClientRotation {
                        transport: Some(ResolvedBackendTransport::H2),
                        state: TransportClientRotationState::Rotated {
                            previous_generation: rotation.previous_generation,
                            current_generation: rotation.current_generation,
                        },
                    },
                    None => TransportClientRotation {
                        transport: None,
                        state: TransportClientRotationState::MissingBackend,
                    },
                }),
            None => Ok(TransportClientRotation {
                transport: None,
                state: TransportClientRotationState::MissingBackend,
            }),
        }
    }
}
