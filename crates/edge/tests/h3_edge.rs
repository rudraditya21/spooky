use std::{
    net::UdpSocket,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use rand::RngCore;
use rcgen::{Certificate, CertificateParams, SanType};
use tempfile::{tempdir, TempDir};

use spooky_config::config::{
    Backend, Config, HealthCheck, Listen, LoadBalancing, Log, Tls,
};
use spooky_edge::QUICListener;

fn write_test_certs(dir: &TempDir) -> (String, String) {
    let mut params = CertificateParams::new(vec!["localhost".into()]);
    params.subject_alt_names.push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
    let cert = Certificate::from_params(params).expect("failed to build cert");

    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    std::fs::write(&cert_path, cert.serialize_pem().unwrap()).unwrap();
    std::fs::write(&key_path, cert.serialize_private_key_pem()).unwrap();

    (
        cert_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
    )
}

fn make_config(port: u32, cert: String, key: String) -> Config {
    Config {
        listen: Listen {
            protocol: "http3".to_string(),
            port,
            address: "127.0.0.1".to_string(),
            tls: Tls { cert, key },
        },
        backends: vec![Backend {
            id: "backend1".to_string(),
            address: "127.0.0.1:1".to_string(),
            weight: 1,
            health_check: HealthCheck {
                path: "/health".to_string(),
                interval: 1000,
            },
        }],
        load_balancing: LoadBalancing {
            lb_type: "random".to_string(),
        },
        log: Log {
            level: "info".to_string(),
        },
    }
}

fn run_h3_client(addr: std::net::SocketAddr) -> Result<String, String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let local_addr = socket.local_addr().map_err(|e| e.to_string())?;

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| format!("config: {e:?}"))?;
    config.verify_peer(false);
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| format!("alpn: {e:?}"))?;
    config.set_max_idle_timeout(5_000);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::thread_rng().fill_bytes(&mut scid_bytes);
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);

    let mut conn = quiche::connect(Some("localhost"), &scid, local_addr, addr, &mut config)
        .map_err(|e| format!("connect: {e:?}"))?;

    let h3_config = quiche::h3::Config::new().map_err(|e| format!("h3: {e:?}"))?;
    let mut h3_conn: Option<quiche::h3::Connection> = None;

    let mut out = [0u8; 1350];
    let mut buf = [0u8; 65_535];

    let (write, send_info) = conn.send(&mut out).map_err(|e| format!("send: {e:?}"))?;
    socket
        .send_to(&out[..write], send_info.to)
        .map_err(|e| format!("send_to: {e:?}"))?;

    let start = Instant::now();
    let mut req_sent = false;
    let mut response_body = Vec::new();

    loop {
        loop {
            match conn.send(&mut out) {
                Ok((write, send_info)) => {
                    let _ = socket.send_to(&out[..write], send_info.to);
                }
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(format!("send loop: {e:?}")),
            }
        }

        let timeout = conn.timeout().unwrap_or(Duration::from_millis(50));
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| format!("timeout: {e:?}"))?;

        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let recv_info = quiche::RecvInfo { from, to: local_addr };
                conn.recv(&mut buf[..len], recv_info)
                    .map_err(|e| format!("recv: {e:?}"))?;
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(e) => return Err(format!("recv: {e:?}")),
        }

        if conn.is_established() && h3_conn.is_none() {
            h3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .map_err(|e| format!("h3 conn: {e:?}"))?,
            );
        }

        if let Some(h3) = h3_conn.as_mut() {
            if conn.is_established() && !req_sent {
                let req = vec![
                    quiche::h3::Header::new(b":method", b"GET"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", b"localhost"),
                    quiche::h3::Header::new(b":path", b"/"),
                    quiche::h3::Header::new(b"user-agent", b"spooky-test"),
                ];
                h3.send_request(&mut conn, &req, true)
                    .map_err(|e| format!("send_request: {e:?}"))?;
                req_sent = true;
            }

            loop {
                match h3.poll(&mut conn) {
                    Ok((stream_id, quiche::h3::Event::Data)) => loop {
                        match h3.recv_body(&mut conn, stream_id, &mut buf) {
                            Ok(read) => response_body.extend_from_slice(&buf[..read]),
                            Err(quiche::h3::Error::Done) => break,
                            Err(e) => return Err(format!("recv_body: {e:?}")),
                        }
                    },
                    Ok((_stream_id, quiche::h3::Event::Headers { .. })) => {}
                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        let body = String::from_utf8_lossy(&response_body).to_string();
                        return Ok(body);
                    }
                    Ok((_stream_id, quiche::h3::Event::Reset(_))) => {
                        return Err("stream reset".to_string());
                    }
                    Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
                    Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(format!("poll: {e:?}")),
                }
            }
        }

        if start.elapsed() > Duration::from_secs(5) {
            return Err("timeout waiting for response".to_string());
        }
    }
}

#[test]
fn http3_request_is_accepted_and_parsed() {
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let config = make_config(0, cert, key);
    let mut listener = QUICListener::new(config);
    let addr = listener.socket.local_addr().unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = stop.clone();

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let handle = rt.spawn_blocking(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            listener.poll();
        }
    });

    let body = run_h3_client(addr).expect("client request failed");
    stop.store(true, Ordering::Relaxed);
    handle.abort();

    assert!(body.contains("upstream error"));
}
