mod client_rotation;
mod h1_client;
mod h1_pool;
mod h2_client;
mod h2_pool;
mod transport_pool;

pub use transport_pool::{
    ConnectObservation, ConnectObserver, SharedDnsResolver, TlsClientConfig,
    TransportClientRotation, UpstreamTransportPool,
};
