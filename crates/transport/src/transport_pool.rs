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
pub enum ResolvedBackendTransport {
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
    pub transport: ResolvedBackendTransport,
    response: hyper::Response<Incoming>,
}

impl TransportExecutionResult {
    pub fn new(
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportClientRotation {
    MissingBackend,
    Recreated {
        transport: ResolvedBackendTransport,
    },
    Rotated {
        transport: ResolvedBackendTransport,
        previous_generation: u64,
        current_generation: u64,
    },
}

impl TransportClientRotation {
    pub fn rotated(self) -> bool {
        !matches!(self, Self::MissingBackend)
    }

    pub fn transport(self) -> Option<ResolvedBackendTransport> {
        match self {
            Self::MissingBackend => None,
            Self::Recreated { transport } | Self::Rotated { transport, .. } => Some(transport),
        }
    }
}

pub struct UpstreamTransportPool {
    backend_transports: HashMap<String, ResolvedBackendTransport>,
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
        I: IntoIterator<Item = (String, ResolvedBackendTransport)>,
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
        I: IntoIterator<Item = (String, ResolvedBackendTransport)>,
    {
        let mut backend_transports = HashMap::new();
        let mut h1_backends = Vec::new();
        let mut h2_backends = Vec::new();

        for (backend, transport) in backends {
            backend_transports.insert(backend.clone(), transport);
            match transport {
                ResolvedBackendTransport::Http1 => h1_backends.push(backend),
                ResolvedBackendTransport::H2 => h2_backends.push(backend),
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
            backend_transports,
            h1_pool,
            h2_pool,
        })
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
                let transport = match backend.endpoint.transport_kind {
                    RuntimeBackendTransportKind::Http1 => ResolvedBackendTransport::Http1,
                    RuntimeBackendTransportKind::H2 => ResolvedBackendTransport::H2,
                };
                backends.push((backend_addr.clone(), transport));
                if matches!(transport, ResolvedBackendTransport::H2) {
                    backend_tls.insert(
                        backend_addr,
                        TlsClientConfig::from(&upstream.policy_set.transport.tls),
                    );
                }
            }
        }

        Self::new_with_observer(
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

    pub fn resolve_backend_transport(
        &self,
        target: TransportExecutionTarget<'_>,
    ) -> Option<ResolvedBackendTransport> {
        self.backend_transports.get(target.backend()).copied()
    }

    pub async fn execute(
        &self,
        target: TransportExecutionTarget<'_>,
        req: Request<BoxBody<Bytes, Infallible>>,
    ) -> Result<TransportExecutionResult, PoolError> {
        match self.resolve_backend_transport(target) {
            Some(ResolvedBackendTransport::Http1) => self
                .h1_pool
                .send(target.backend(), req)
                .await
                .map(|response| {
                    TransportExecutionResult::new(ResolvedBackendTransport::Http1, response)
                }),
            Some(ResolvedBackendTransport::H2) => self
                .h2_pool
                .send(target.backend(), req)
                .await
                .map(|response| TransportExecutionResult::new(ResolvedBackendTransport::H2, response)),
            None => Err(PoolError::UnknownBackend(target.backend().to_string())),
        }
    }

    pub fn rotate_backend_client(
        &self,
        target: TransportExecutionTarget<'_>,
    ) -> Result<TransportClientRotation, String> {
        match self.resolve_backend_transport(target) {
            Some(ResolvedBackendTransport::Http1) => self
                .h1_pool
                .rotate_backend_client(target.backend())
                .map(|rotated| {
                    if rotated {
                        TransportClientRotation::Recreated {
                            transport: ResolvedBackendTransport::Http1,
                        }
                    } else {
                        TransportClientRotation::MissingBackend
                    }
                }),
            Some(ResolvedBackendTransport::H2) => self
                .h2_pool
                .rotate_backend_client(target.backend())
                .map(|rotation| match rotation {
                    Some(rotation) => TransportClientRotation::Rotated {
                        transport: ResolvedBackendTransport::H2,
                        previous_generation: rotation.previous_generation,
                        current_generation: rotation.current_generation,
                    },
                    None => TransportClientRotation::MissingBackend,
                }),
            None => Ok(TransportClientRotation::MissingBackend),
        }
    }
}
