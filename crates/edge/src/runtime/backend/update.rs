use std::{net::SocketAddr, time::SystemTime};

use crate::runtime::backend::resolution::RuntimeBackendAddressKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBackendResolutionUpdate {
    pub backend_addr: String,
    pub authority_host: String,
    pub authority_port: u16,
    pub address_kind: RuntimeBackendAddressKind,
    pub previous_addrs: Vec<SocketAddr>,
    pub current_addrs: Vec<SocketAddr>,
    pub last_refresh_success_at: Option<SystemTime>,
    pub refresh_generation: u64,
}

impl RuntimeBackendResolutionUpdate {
    pub fn changed(&self) -> bool {
        self.previous_addrs != self.current_addrs
    }

    pub fn cleared(&self) -> bool {
        self.current_addrs.is_empty()
    }
}
