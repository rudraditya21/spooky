use std::{collections::HashMap, net::UdpSocket};

use core::net::SocketAddr;

use crate::config::config::Config;

pub mod quic_listener;

pub struct QUICListener {
    pub socket: UdpSocket,
    pub config: Config,
    pub quic_config: quiche::Config,

    pub recv_buf: [u8; 65535], // array initialization, let arr [<data type>, <no of elements>] = [<value of all>, <no of elements>]
    pub send_buf: [u8; 65535],

    pub connections: HashMap<SocketAddr, QuicConnection> // for future can think of key is dcid (destination connection id) or scid (source connection id), use DCID
}

pub struct QuicConnection {
    pub quic: quiche::Connection,
    pub h3: quiche::h3::Connection,

    pub peer_address: SocketAddr
}