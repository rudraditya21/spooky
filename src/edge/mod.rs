use std::net::UdpSocket;

use crate::config::config::Config;

pub mod quic_listener;

pub struct QUICListener {
    socket: UdpSocket,
    config: Config,
    quic_config: quiche::Config
}