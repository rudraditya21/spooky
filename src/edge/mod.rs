use std::{collections::HashMap, net::UdpSocket};

use core::net::SocketAddr;

use crate::config::config::Config;

pub mod quic_listener;

pub struct QUICListener {
    socket: UdpSocket,
    config: Config,
    quic_config: quiche::Config,

    recv_buf: [u8; 65535],
    send_buf: [u8; 65535],

    connections: HashMap<SocketAddr, QuicConnection> // for future can think of key is dcid (destination connection id) or scid (source connection id)
}

pub struct QuicConnection {
    pub quic: quiche::Connection,
    pub h3: quiche::h3::Connection,
}