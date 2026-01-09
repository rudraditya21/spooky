use std::net::UdpSocket;

use quiche::Config;

use crate::{config::config::Config as SpookyConfig, edge::QUICListener};



impl QUICListener {
    pub fn new(config: SpookyConfig) -> Self {
        let socket = UdpSocket::bind(&config.listen.address).unwrap();

        let mut quic_config = Config::new(quiche::PROTOCOL_VERSION).expect("REASON");
        quic_config.load_cert_chain_from_pem_file(&config.listen.tls.cert);
        quic_config.load_priv_key_from_pem_file(&config.listen.tls.key);
        quic_config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL).unwrap();
        quic_config.set_max_idle_timeout(5000);
        quic_config.enable_early_data();

        Self { socket, config, quic_config }
    }

    pub fn poll(&self) {
        // recvmsg → quiche::accept → Connection
    }
}