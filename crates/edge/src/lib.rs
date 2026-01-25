use std::{collections::HashMap, net::UdpSocket, sync::Arc, time::Instant};

use core::net::SocketAddr;

use spooky_config::config::Config;

pub mod quic_listener;

pub struct QUICListener {
    pub socket: UdpSocket,
    pub config: Config,
    pub quic_config: quiche::Config,
    pub h3_config: Arc<quiche::h3::Config>,

    pub recv_buf: [u8; 65535], // array initialization, let arr [<data type>, <no of elements>] = [<value of all>, <no of elements>]
    pub send_buf: [u8; 65535],

    pub connections: HashMap<SocketAddr, QuicConnection>, // future: key by dcid/scid instead of peer addr
}

pub struct QuicConnection {
    pub quic: quiche::Connection,
    pub h3: Option<quiche::h3::Connection>,
    pub h3_config: Arc<quiche::h3::Config>,

    pub peer_address: SocketAddr,
    pub last_activity: Instant,
}
