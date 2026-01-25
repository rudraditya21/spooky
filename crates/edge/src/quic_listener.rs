use std::{collections::HashMap, net::UdpSocket, sync::Arc, time::Instant};

use core::net::SocketAddr;

use log::{debug, error, info};
use quiche::Config;
use quiche::h3::NameValue;

use spooky_config::config::Config as SpookyConfig;

use crate::{QuicConnection, QUICListener};


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
        quic_config.set_max_recv_udp_payload_size(1350);
        quic_config.set_max_send_udp_payload_size(1350);
        quic_config.set_initial_max_data(10_000_000);
        quic_config.set_initial_max_stream_data_bidi_local(1_000_000);
        quic_config.set_initial_max_stream_data_bidi_remote(1_000_000);
        quic_config.set_initial_max_stream_data_uni(1_000_000);
        quic_config.set_initial_max_streams_bidi(100);
        quic_config.set_initial_max_streams_uni(100);
        quic_config.set_disable_active_migration(true);
        quic_config.enable_early_data();

        debug!("Listening on {}", socket_address);

        let h3_config = Arc::new(quiche::h3::Config::new().expect("Failed to create HTTP/3 config"));

        Self { 
            socket, 
            config, 
            quic_config,
            h3_config,
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

        let quic_connection = quiche::accept(
            &scid,
            None,
            local_addr,
            peer,
            &mut self.quic_config
        ).ok()?;

        self.connections.insert(
            peer, 
            QuicConnection {
                quic: quic_connection,
                h3: None,
                h3_config: self.h3_config.clone(),
                peer_address: peer,
                last_activity: Instant::now(),
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

        let socket = match self.socket.try_clone() {
            Ok(sock) => sock,
            Err(e) => {
                error!("Failed to clone UDP socket: {:?}", e);
                return;
            }
        };

        let mut recv_data = self.recv_buf[..len].to_vec();

        let connection = match self.get_or_create_connection(peer, local_addr, &recv_data) {
            Some(conn) => conn,
            None => return,
        };

        let recv_info = quiche::RecvInfo { from: peer, to: local_addr };

        if let Err(e) = connection.quic.recv(&mut recv_data, recv_info) {
            error!("QUIC recv failed: {:?}", e);
            return;
        }

        connection.last_activity = Instant::now();

        if connection.quic.is_established() || connection.quic.is_in_early_data() {
            if let Err(e) = Self::handle_h3(connection) {
                error!("HTTP/3 handling failed: {:?}", e);
            }
        }

        let mut send_buf = [0u8; 65_535];

        Self::flush_send(&socket, &mut send_buf, connection);
        Self::handle_timeout(&socket, &mut send_buf, connection);
    }

    fn handle_timeout(
        socket: &UdpSocket,
        send_buf: &mut [u8],
        connection: &mut QuicConnection,
    ) {
        let timeout = match connection.quic.timeout() {
            Some(timeout) => timeout,
            None => return,
        };

        if connection.last_activity.elapsed() >= timeout {
            connection.quic.on_timeout();
            connection.last_activity = Instant::now();
            Self::flush_send(socket, send_buf, connection);
        }
    }

    fn handle_h3(connection: &mut QuicConnection) -> Result<(), quiche::h3::Error> {
        let mut body_buf = [0u8; 65_535];

        if connection.h3.is_none() {
            connection.h3 = Some(quiche::h3::Connection::with_transport(
                &mut connection.quic,
                &connection.h3_config,
            )?);
        }

        let h3 = match connection.h3.as_mut() {
            Some(h3) => h3,
            None => return Ok(()),
        };

        loop {
            match h3.poll(&mut connection.quic) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    let mut method = None;
                    let mut path = None;

                    for header in list {
                        match header.name() {
                            b":method" => method = Some(String::from_utf8_lossy(header.value()).to_string()),
                            b":path" => path = Some(String::from_utf8_lossy(header.value()).to_string()),
                            _ => {}
                        }
                    }

                    if let (Some(m), Some(p)) = (method, path) {
                        info!("HTTP/3 request {} {}", m, p);
                    }

                    let resp_headers = vec![
                        quiche::h3::Header::new(b":status", b"200"),
                        quiche::h3::Header::new(b"content-type", b"text/plain"),
                        quiche::h3::Header::new(b"server", b"spooky"),
                    ];

                    h3.send_response(&mut connection.quic, stream_id, &resp_headers, false)?;

                    let body = b"spooky edge ok\n";
                    h3.send_body(&mut connection.quic, stream_id, body, true)?;
                }
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    loop {
                        match h3.recv_body(&mut connection.quic, stream_id, &mut body_buf) {
                            Ok(_) => {}
                            Err(quiche::h3::Error::Done) => break,
                            Err(e) => return Err(e),
                        }
                    }
                }
                Ok((_stream_id, quiche::h3::Event::Finished)) => {}
                Ok((_stream_id, quiche::h3::Event::Reset(_))) => {}
                Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
                Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    fn flush_send(socket: &UdpSocket, send_buf: &mut [u8], connection: &mut QuicConnection) {
        loop {
            match connection.quic.send(send_buf) {
                Ok((write, send_info)) => {
                    if let Err(e) = socket.send_to(&send_buf[..write], send_info.to) {
                        error!("Failed to send UDP packet: {:?}", e);
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("QUIC send failed: {:?}", e);
                    break;
                }
            }
        }
    }
}
