use std::{collections::HashMap, net::UdpSocket};

use core::net::SocketAddr;

use log::{debug, error, info};
use quiche::Config;

use crate::{config::config::Config as SpookyConfig, edge::{QUICListener, QuicConnection}};


impl QUICListener {
    pub fn new(config: SpookyConfig) -> Self {
        let socket_address = format!("{}:{}", &config.listen.address, &config.listen.port);
        
        let socket = UdpSocket::bind(socket_address.as_str())
            .expect("Failed to bind UDP socker");

        let mut quic_config = Config::new(quiche::PROTOCOL_VERSION).expect("REASON");
        
        let _ = quic_config.load_cert_chain_from_pem_file(&config.listen.tls.cert);
        let _ = quic_config.load_priv_key_from_pem_file(&config.listen.tls.key);
        quic_config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL).unwrap();
        quic_config.set_max_idle_timeout(5000);
        quic_config.enable_early_data();

        debug!("Listening on {}", socket_address);

        Self { 
            socket, 
            config, 
            quic_config,
            recv_buf: [0; 65535],
            send_buf: [0; 65535],
            connections: HashMap::new()
        }
    }

    // Get existing connection or get new one
    pub fn get_or_create_connection(
        &mut self, 
        peer: SocketAddr, 
        local_addr: SocketAddr,
        packets: &[u8]
    ) -> Option<&mut QuicConnection> {

        let mut buf = packets.to_vec();
        let header = match quiche::Header::from_slice(
            &mut buf, 
            quiche::MAX_CONN_ID_LEN
        ) {
            Ok(hdr) => hdr,
            Err(_) => {
                error!("Wrong QUIC HEADER");
                return None;
            }
        };

        let scid = header.dcid.clone();

        if self.connections.contains_key(&peer) {
            return self.connections.get_mut(&peer);
        }

        let mut quic_connection = quiche::accept(
            &scid,
            None,
            local_addr,
            peer,
            &mut self.quic_config
        ).ok()?;

        let h3_connection = quiche::h3::Connection::with_transport(
            &mut quic_connection,
            &quiche::h3::Config::new().unwrap()
        ).ok()?;

        self.connections.insert(
            peer, 
            QuicConnection {
                quic: quic_connection,
                h3: h3_connection,
                peer_address: peer
            }
        );

        self.connections.get_mut(&peer)
             
    }

    pub fn poll(&mut self) {


        // Read a UDP datagram and feed it into quiche.
        let (len, peer) = match self.socket.recv_from(&mut self.recv_buf) {
            Ok(v) => v,
            Err(_) => return,
        };

        info!("Length of data recived: {}", len);

        let local_addr = match self.socket.local_addr() {
            Ok(addr) => addr,
            Err(_) => return,
        };

        // copy the data for memory safety
        let mut recv_data = self.recv_buf[..len].to_vec();

        // info!("recvied some data {:?}", recv_data);
        
        let connection = match self.get_or_create_connection(peer, local_addr, &recv_data) {
            Some(conn) => conn,
            None => return,
        };
        
        let recv_info = quiche::RecvInfo {
            from: peer,
            to: local_addr
        };

        if let Err(e) = connection.quic.recv(&mut recv_data, recv_info) {
            error!("QUIC recv failed: {:?}", e);
            return;
        }
            
        // Convert HTTP/3 headers with bridge::h3_to_h2.
        // Forward the normalized request via the HTTP/2 client.
    }
}
