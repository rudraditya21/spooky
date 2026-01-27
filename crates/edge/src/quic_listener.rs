use std::{
    collections::HashMap,
    net::UdpSocket,
    sync::Arc,
    time::{Duration, Instant},
};

use core::net::SocketAddr;

use bytes::Bytes;
use http_body_util::BodyExt;
use log::{debug, error, info};
use quiche::Config;
use quiche::h3::NameValue;
use rand::RngCore;
use spooky_bridge::h3_to_h2::{build_h2_request, BridgeError};
use spooky_lb::{BackendPool, LoadBalancing};
use spooky_transport::h2_client::H2Client;
use tokio::runtime::Handle;

use spooky_config::config::Config as SpookyConfig;

use crate::{Metrics, QuicConnection, QUICListener, RequestEnvelope};

#[derive(Debug)]
enum ProxyError {
    Bridge(BridgeError),
    Transport(String),
    Timeout,
}

fn is_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn request_hash_key(req: &RequestEnvelope) -> String {
    if let Some(authority) = &req.authority {
        return authority.clone();
    }

    if !req.path.is_empty() {
        return req.path.clone();
    }

    req.method.clone()
}

const BACKEND_TIMEOUT: Duration = Duration::from_secs(2);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

fn lb_name(lb: &LoadBalancing) -> &'static str {
    match lb {
        LoadBalancing::RoundRobin(_) => "round-robin",
        LoadBalancing::ConsistentHash(_) => "consistent-hash",
        LoadBalancing::Random(_) => "random",
    }
}


impl QUICListener {
    pub fn new(config: SpookyConfig) -> Self {
        let socket_address = format!("{}:{}", &config.listen.address, &config.listen.port);
        
        let socket = UdpSocket::bind(socket_address.as_str())
            .expect("Failed to bind UDP socker");
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("Failed to set UDP read timeout");

        let mut quic_config = Config::new(quiche::PROTOCOL_VERSION).expect("REASON");
        
        match quic_config.load_cert_chain_from_pem_file(&config.listen.tls.cert) {
            Ok(_) => debug!("Certificate loaded successfully"),
            Err(e) => error!("Failed to load certificate: {:?}", e),
        }

        match quic_config.load_priv_key_from_pem_file(&config.listen.tls.key) {
            Ok(_) => debug!("Private key loaded successfully"),
            Err(e) => error!("Failed to load private key: {:?}", e),
        }
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
        quic_config.verify_peer(false); // for local development
        // quic_config.enable_early_data(); // diable 0-RTT (h3 does not need this to work)
        // curl will attempt 0-RTT, your server can’t validate it, TLS aborts.

        debug!("Listening on {}", socket_address);

        let h3_config =
            Arc::new(quiche::h3::Config::new().expect("Failed to create HTTP/3 config"));
        let h2_client = Arc::new(H2Client::new());
        let backend_pool = BackendPool::new(config.backends.clone());
        let load_balancer = LoadBalancing::from_config(&config.load_balancing.lb_type)
            .expect("Invalid load balancing configuration");
        let metrics = Metrics::default();

        Self { 
            socket, 
            config, 
            quic_config,
            h3_config,
            h2_client,
            backend_pool,
            load_balancer,
            metrics,
            draining: false,
            drain_start: None,
            recv_buf: [0; 65535],
            send_buf: [0; 65535],
            connections: HashMap::new()
        }
    }

    pub fn start_draining(&mut self) {
        if self.draining {
            return;
        }
        self.draining = true;
        self.drain_start = Some(Instant::now());
        info!("Draining connections");
    }

    pub fn drain_complete(&mut self) -> bool {
        if !self.draining {
            return self.connections.is_empty();
        }

        if self.connections.is_empty() {
            return true;
        }

        if let Some(start) = self.drain_start {
            if start.elapsed() >= DRAIN_TIMEOUT {
                self.close_all();
                return true;
            }
        }

        false
    }

    fn close_all(&mut self) {
        let socket = match self.socket.try_clone() {
            Ok(sock) => sock,
            Err(e) => {
                error!("Failed to clone UDP socket: {:?}", e);
                return;
            }
        };

        let mut send_buf = [0u8; 65_535];
        for connection in self.connections.values_mut() {
            let _ = connection.quic.close(true, 0x0, b"draining");
            Self::flush_send(&socket, &mut send_buf, connection);
        }

        self.connections.clear();
    }

    fn take_or_create_connection(
        &mut self,
        peer: SocketAddr,
        local_addr: SocketAddr,
        packets: &[u8],
    ) -> Option<QuicConnection> {
        if let Some(connection) = self.connections.remove(&peer) {
            return Some(connection);
        }

        if self.draining {
            return None;
        }

        let mut buf = packets.to_vec();
        let header = match quiche::Header::from_slice(&mut buf, quiche::MAX_CONN_ID_LEN) {
            Ok(hdr) => hdr,
            Err(_) => {
                error!("Wrong QUIC HEADER");
                return None;
            }
        };

        // If this is a 0-RTT packet without a valid token, we need to reject it
        if header.ty == quiche::Type::Initial && header.token.is_some() {
            debug!("Received 0-RTT attempt, will negotiate fresh connection");
            // return None;
        }

        let mut scid_bytes = [0u8; 16]; // scid must be >= 8 bytes, 16 is perfect
        rand::thread_rng().fill_bytes(&mut scid_bytes);

        // let scid = header.dcid.clone();
        let scid = quiche::ConnectionId::from_ref(&scid_bytes);
        // let odcid = header.dcid.clone();
        
        let quic_connection =
            quiche::accept(&scid, None, local_addr, peer, &mut self.quic_config).ok()?;

        Some(QuicConnection {
            quic: quic_connection,
            h3: None,
            h3_config: self.h3_config.clone(),
            streams: HashMap::new(),
            peer_address: peer,
            last_activity: Instant::now(),
        })
    }

    pub fn poll(&mut self) {
        // Read a UDP datagram and feed it into quiche.
        let (len, peer) = match self.socket.recv_from(&mut self.recv_buf) {
            Ok(v) => v,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                self.handle_timeouts();
                return;
            }
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

        let recv_data = self.recv_buf[..len].to_vec();

        let h2_client = self.h2_client.clone();

        let mut connection = match self.take_or_create_connection(peer, local_addr, &recv_data) {
            Some(conn) => {
                debug!("Got connection for {}", peer);
                conn
            },
            None => {
                error!("Failed to create connection for {}", peer);
                return;
            }
        };

        let recv_info = quiche::RecvInfo { from: peer, to: local_addr };

        if let Err(e) = connection.quic.recv(&mut self.recv_buf[..len], recv_info) {
            error!("QUIC recv failed: {:?}", e);
            return;
        }

        if let Some(err) = connection.quic.peer_error() {
            error!("🔴 Peer error: {:?}", err);
        }

        if let Some(err) = connection.quic.local_error() {
            error!("🔴 Local error: {:?}", err);
        }


        connection.last_activity = Instant::now();

        // Debug logs
        debug!("QUIC connection state - established: {}, in_early_data: {}, closed: {}", 
            connection.quic.is_established(),
            connection.quic.is_in_early_data(), 
            connection.quic.is_closed()
        );

        if connection.quic.is_established() || connection.quic.is_in_early_data() {
            if let Err(e) = Self::handle_h3(
                &mut connection,
                &h2_client,
                &mut self.backend_pool,
                &mut self.load_balancer,
                &self.metrics,
            ) {
                error!("HTTP/3 handling failed: {:?}", e);
            }
        }

        let mut send_buf = [0u8; 65_535];

        Self::flush_send(&socket, &mut send_buf, &mut connection);
        Self::handle_timeout(&socket, &mut send_buf, &mut connection);

        if !connection.quic.is_closed() {
            self.connections.insert(peer, connection);
        }
    }

    fn handle_timeouts(&mut self) {
        if self.connections.is_empty() {
            return;
        }

        let socket = match self.socket.try_clone() {
            Ok(sock) => sock,
            Err(e) => {
                error!("Failed to clone UDP socket: {:?}", e);
                return;
            }
        };

        let mut send_buf = [0u8; 65_535];
        let mut to_remove = Vec::new();

        for (peer, connection) in self.connections.iter_mut() {
            let timeout = match connection.quic.timeout() {
                Some(timeout) => timeout,
                None => {
                    if connection.quic.is_closed() {
                        to_remove.push(*peer);
                    }
                    continue;
                }
            };

            if connection.last_activity.elapsed() >= timeout {
                connection.quic.on_timeout();
                connection.last_activity = Instant::now();
                Self::flush_send(&socket, &mut send_buf, connection);
            }

            if connection.quic.is_closed() {
                to_remove.push(*peer);
            }
        }

        for peer in to_remove {
            self.connections.remove(&peer);
        }
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

    fn handle_h3(
        connection: &mut QuicConnection,
        h2_client: &H2Client,
        backend_pool: &mut BackendPool,
        load_balancer: &mut LoadBalancing,
        metrics: &Metrics,
    ) -> Result<(), quiche::h3::Error> {
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
                    let mut method = String::new();
                    let mut path = String::new();
                    let mut authority = None;
                    let mut headers = Vec::with_capacity(list.len());

                    for header in list {
                        headers.push((header.name().to_vec(), header.value().to_vec()));
                        match header.name() {
                            b":method" => method = String::from_utf8_lossy(header.value()).to_string(),
                            b":path" => path = String::from_utf8_lossy(header.value()).to_string(),
                            b":authority" | b"host" => {
                                authority = Some(String::from_utf8_lossy(header.value()).to_string())
                            }
                            _ => {}
                        }
                    }

                    let envelope = RequestEnvelope {
                        method: method.clone(),
                        path: path.clone(),
                        authority,
                        headers,
                        body: Vec::new(),
                        start: Instant::now(),
                    };

                    metrics.inc_total();
                    connection.streams.insert(stream_id, envelope);

                    if !method.is_empty() && !path.is_empty() {
                        info!("HTTP/3 request {} {}", method, path);
                    }
                }
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    loop {
                        match h3.recv_body(&mut connection.quic, stream_id, &mut body_buf) {
                            Ok(read) => {
                                if let Some(req) = connection.streams.get_mut(&stream_id) {
                                    req.body.extend_from_slice(&body_buf[..read]);
                                }
                            }
                            Err(quiche::h3::Error::Done) => break,
                            Err(e) => return Err(e),
                        }
                    }
                }
                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    if let Some(req) = connection.streams.remove(&stream_id) {
                        Self::handle_request_finish(
                            h3,
                            &mut connection.quic,
                            stream_id,
                            req,
                            h2_client,
                            backend_pool,
                            load_balancer,
                            metrics,
                        )?;
                    }
                }
                Ok((stream_id, quiche::h3::Event::Reset(_))) => {
                    connection.streams.remove(&stream_id);
                }
                Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
                Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    fn handle_request_finish(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        req: RequestEnvelope,
        h2_client: &H2Client,
        backend_pool: &mut BackendPool,
        load_balancer: &mut LoadBalancing,
        metrics: &Metrics,
    ) -> Result<(), quiche::h3::Error> {
        let start = req.start;
        if req.method.is_empty() || req.path.is_empty() {
            return Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::BAD_REQUEST,
                b"invalid request\n",
            );
        }

        if backend_pool.is_empty() {
            return Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::SERVICE_UNAVAILABLE,
                b"no backend configured\n",
            );
        }

        let key = request_hash_key(&req);
        let backend_index = match load_balancer.pick(&key, backend_pool) {
            Some(index) => index,
            None => {
                return Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    b"no healthy backends\n",
                );
            }
        };

        let backend_addr = match backend_pool.address(backend_index) {
            Some(addr) => addr.to_string(),
            None => {
                return Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    b"invalid backend\n",
                );
            }
        };

        info!(
            "Selected backend {} via {}",
            backend_addr,
            lb_name(load_balancer)
        );

        match Self::forward_request(&backend_addr, h2_client, req) {
            Ok((status, headers, body)) => {
                backend_pool.mark_success(backend_index);
                metrics.inc_success();
                let latency = start.elapsed().as_millis();
                info!(
                    "Upstream {} status {} latency_ms {}",
                    backend_addr, status, latency
                );
                Self::send_backend_response(h3, quic, stream_id, status, &headers, &body)
            }
            Err(ProxyError::Bridge(err)) => {
                error!("Bridge error: {:?}", err);
                backend_pool.mark_failure(backend_index);
                metrics.inc_failure();
                let latency = start.elapsed().as_millis();
                info!("Upstream {} status 400 latency_ms {}", backend_addr, latency);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_REQUEST,
                    b"invalid request\n",
                )
            }
            Err(ProxyError::Transport(err)) => {
                error!("Transport error: {}", err);
                backend_pool.mark_failure(backend_index);
                metrics.inc_failure();
                metrics.inc_backend_error();
                let latency = start.elapsed().as_millis();
                info!("Upstream {} status 502 latency_ms {}", backend_addr, latency);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_GATEWAY,
                    b"upstream error\n",
                )
            }
            Err(ProxyError::Timeout) => {
                error!("Backend timeout");
                backend_pool.mark_failure(backend_index);
                metrics.inc_failure();
                metrics.inc_timeout();
                let latency = start.elapsed().as_millis();
                info!("Upstream {} status 503 latency_ms {}", backend_addr, latency);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    b"upstream timeout\n",
                )
            }
        }
    }

    fn forward_request(
        backend_addr: &str,
        h2_client: &H2Client,
        req: RequestEnvelope,
    ) -> Result<(http::StatusCode, http::HeaderMap, Bytes), ProxyError> {
        let request = build_h2_request(
            backend_addr,
            &req.method,
            &req.path,
            &req.headers,
            &req.body,
        )
        .map_err(ProxyError::Bridge)?;

        let response = run_blocking(|| async {
            tokio::time::timeout(BACKEND_TIMEOUT, h2_client.send(request)).await
        })
        .map_err(|e| ProxyError::Transport(format!("send: {e}")))?;

        let response = match response {
            Ok(inner) => inner.map_err(|e| ProxyError::Transport(format!("send: {e:?}")))?,
            Err(_) => return Err(ProxyError::Timeout),
        };

        let (parts, body) = response.into_parts();

        let body_bytes = run_blocking(|| async {
            tokio::time::timeout(BACKEND_TIMEOUT, body.collect()).await
        })
        .map_err(|e| ProxyError::Transport(format!("body: {e}")))?;

        let body_bytes = match body_bytes {
            Ok(inner) => inner.map(|c| c.to_bytes()).map_err(|e| {
                ProxyError::Transport(format!("body: {e:?}"))
            })?,
            Err(_) => return Err(ProxyError::Timeout),
        };

        Ok((parts.status, parts.headers, body_bytes))
    }

    fn send_backend_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        status: http::StatusCode,
        headers: &http::HeaderMap,
        body: &Bytes,
    ) -> Result<(), quiche::h3::Error> {
        let mut resp_headers = Vec::with_capacity(headers.len() + 2);

        resp_headers.push(quiche::h3::Header::new(
            b":status",
            status.as_str().as_bytes(),
        ));

        for (name, value) in headers.iter() {
            if is_hop_header(name.as_str()) || name == http::header::CONTENT_LENGTH {
                continue;
            }
            resp_headers.push(quiche::h3::Header::new(
                name.as_str().as_bytes(),
                value.as_bytes(),
            ));
        }

        resp_headers.push(quiche::h3::Header::new(
            b"content-length",
            body.len().to_string().as_bytes(),
        ));

        h3.send_response(quic, stream_id, &resp_headers, false)?;
        h3.send_body(quic, stream_id, body, true)?;
        Ok(())
    }

    fn send_simple_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        status: http::StatusCode,
        body: &[u8],
    ) -> Result<(), quiche::h3::Error> {
        let resp_headers = vec![
            quiche::h3::Header::new(b":status", status.as_str().as_bytes()),
            quiche::h3::Header::new(b"content-type", b"text/plain"),
            quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
        ];

        h3.send_response(quic, stream_id, &resp_headers, false)?;
        h3.send_body(quic, stream_id, body, true)?;
        Ok(())
    }

    fn flush_send(socket: &UdpSocket, send_buf: &mut [u8], connection: &mut QuicConnection) {
        let mut packet_count = 0;

        loop {
            match connection.quic.send(send_buf) {
                Ok((write, send_info)) => {
                    packet_count += 1;
                    debug!("Sending {} bytes to {}", write, send_info.to);
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

        if packet_count > 0 {
            debug!("Sent {} packets", packet_count);
        }
    }
}

fn run_blocking<F, Fut, T>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    match Handle::try_current() {
        Ok(handle) => Ok(tokio::task::block_in_place(|| handle.block_on(f()))),
        Err(_) => {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| format!("runtime: {e}"))?;
            Ok(rt.block_on(f()))
        }
    }
}
