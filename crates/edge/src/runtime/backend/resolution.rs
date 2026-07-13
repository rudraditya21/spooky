use std::{net::SocketAddr, time::SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBackendResolution {
    pub backend_addr: String,
    pub authority_host: String,
    pub authority_port: u16,
    pub address_kind: RuntimeBackendAddressKind,
    pub resolved_addrs: Vec<SocketAddr>,
    pub last_refresh_success_at: Option<SystemTime>,
    pub refresh_generation: u64,
}

impl RuntimeBackendResolution {
    pub fn hostname(backend_addr: String, authority_host: String, authority_port: u16) -> Self {
        Self {
            backend_addr,
            authority_host,
            authority_port,
            address_kind: RuntimeBackendAddressKind::Hostname,
            resolved_addrs: Vec::new(),
            last_refresh_success_at: None,
            refresh_generation: 0,
        }
    }

    pub fn ip_literal(
        backend_addr: String,
        authority_host: String,
        authority_port: u16,
        resolved_addrs: Vec<SocketAddr>,
    ) -> Self {
        Self {
            backend_addr,
            authority_host,
            authority_port,
            address_kind: RuntimeBackendAddressKind::IpLiteral,
            resolved_addrs,
            last_refresh_success_at: None,
            refresh_generation: 0,
        }
    }

    pub fn is_hostname(&self) -> bool {
        self.address_kind == RuntimeBackendAddressKind::Hostname
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeBackendAddressKind {
    Hostname,
    IpLiteral,
}
