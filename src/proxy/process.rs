
use h3::client;
use h3_quinn::Connection as H3QuinnConnection;
use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};

use std::{net::SocketAddr, sync::Arc};

use bytes::Bytes;
use log::{info, warn, debug, trace, error};

use super::Server;

use crate::{lb::random::random, utils::tls::load_tls};


impl Server {
    pub async fn process_connection(&self, connection: quinn::Connection) {
        use h3::{server};
        use bytes::Bytes;
        use h3_quinn::Connection as H3QuinnConnection;

        trace!("Creating H3 connection from QUIC connection");
        let h3_connection = H3QuinnConnection::new(connection);

        let mut h3_server: h3::server::Connection<_, Bytes> = server::builder()
            .max_field_section_size(8192)
            .build(h3_connection)
            .await
            .expect("Failed to build h3 server");

        debug!("H3 server connection established, waiting for requests");

        loop {
            match h3_server.accept().await {
                Ok(Some(req_resolver)) => {
                    match req_resolver.resolve_request().await {
                        Ok((req, mut stream)) => {
                            info!("Received HTTP/3 request: {} {}", req.method(), req.uri());
                            debug!("Request headers: {:?}", req.headers());

                            // Select backend using configured strategy
                            let selected_backend = match random(&self.config.backends) {
                                Some(backend) => backend,
                                None => {
                                    error!("No healthy backends available");
                                    // Send 503 Service Unavailable
                                    let resp = http::Response::builder()
                                        .status(503)
                                        .body(())
                                        .unwrap();
                                    if let Err(e) = stream.send_response(resp).await {
                                        error!("Failed to send 503 response: {e:?}");
                                    }
                                    continue;
                                }
                            };

                            info!("Proxying to backend: {}", selected_backend.address);

                                // Forward request to backend
                            match self.forward_to_backend(req, &mut stream, &selected_backend.address).await {
                                Ok(_) => debug!("Successfully proxied request"),
                                Err(e) => {
                                    error!("Failed to proxy request: {e:?}");
                                    // Try to send 502 Bad Gateway if stream still open
                                    let resp = http::Response::builder()
                                        .status(502)
                                        .body(())
                                        .unwrap();
                                    let _ = stream.send_response(resp);
                                }
                            }
                        },
                        Err(e) => {
                            error!("Error: {e:?}");
                            break;
                        }
                    }
                }
                Ok(None) => {
                    debug!("Connection closed gracefully");
                    break;
                }
                Err(e) => {
                    warn!("Connection closed with error: {e:?}");
                    break;
                }
            }
        }
    }

    async fn forward_to_backend(
        &self,
        req: http::Request<()>,
        client_stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        backend_addr: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {

        // Parse backend address
        let backend_socket: SocketAddr = backend_addr.parse()?;

        let (certs, _key) = load_tls(
            &self.config.listen.tls.cert,
            &self.config.listen.tls.key
        );

        trace!("Creating TLS configuration");
        let crypto_provider = rustls::crypto::ring::default_provider();

        let mut root_cert_store = rustls::RootCertStore::empty();

        for cert in certs {
            root_cert_store.add(cert)?
        }

        let mut client_tls_config = rustls::ClientConfig::builder_with_provider(crypto_provider.into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();  // Or load client cert if mTLS is needed

        // Set ALPN protocols - HTTP/3 uses "h3"
        debug!("Setting ALPN protocols to 'h3' for HTTP/3");
        client_tls_config.alpn_protocols = vec![b"h3".to_vec()];

        trace!("Creating QUIC client configuration");
        let client_config = ClientConfig::new(
            Arc::new(QuicClientConfig::try_from(client_tls_config)?)
        );
        
        // Create QUIC endpoint for client
        let mut endpoint = Endpoint::client("[::]:0".parse()?)?;
        // TODO: set default client config 
        endpoint.set_default_client_config(client_config);

        // Connect to backend
        let quinn_conn = endpoint
            .connect(backend_socket, "localhost")?
            .await?;

        let h3_backend = H3QuinnConnection::new(quinn_conn);
        
        // Build the h3 client connection
        let (_h3_conn, mut h3_request_sender) = client::builder()
            .max_field_section_size(8192)
            .build::<_,_, Bytes>(h3_backend)
            .await?;

        // Send request to backend and get the request stream
        let mut request_stream    = h3_request_sender.send_request(req).await?;
 
        // Finish sending the request (no body in this case)
        request_stream.finish().await?;

        // Receive response from backend
        let backend_resp = request_stream.recv_response().await?;
        
        debug!("Received response from backend: {}", backend_resp.status());

        // Send response headers to client
        client_stream.send_response(backend_resp).await?;

        // Stream response body from backend to client
        while let Some(mut chunk) = request_stream.recv_data().await? {
            use bytes::Buf;
            // Convert the Buf to Bytes
            let data = chunk.copy_to_bytes(chunk.remaining());
            client_stream.send_data(data).await?;
        }

        // Finish client stream
        client_stream.finish().await?;

        Ok(())
    }
 
}