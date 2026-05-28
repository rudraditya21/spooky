use std::convert::Infallible;
use std::ffi::OsStr;
use std::fs::File;
use std::future::Future;
use std::io::BufReader;
use std::path::Path;
use std::time::Duration;

use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::{Request, rt::Executor};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};

#[derive(Debug, Clone)]
pub struct TlsClientConfig {
    pub verify_certificates: bool,
    pub strict_sni: bool,
    pub ca_file: Option<String>,
    pub ca_dir: Option<String>,
}

impl Default for TlsClientConfig {
    fn default() -> Self {
        Self {
            verify_certificates: true,
            strict_sni: true,
            ca_file: None,
            ca_dir: None,
        }
    }
}

pub struct H2Client {
    client: Client<HttpsConnector<HttpConnector>, BoxBody<Bytes, Infallible>>,
}

#[derive(Clone, Copy)]
struct TokioExecutor;

impl<F> Executor<F> for TokioExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::spawn(fut);
    }
}

impl H2Client {
    pub fn new(
        max_idle_per_host: usize,
        pool_idle_timeout: Duration,
        connect_timeout: Duration,
        tls: TlsClientConfig,
    ) -> Result<Self, String> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(connect_timeout));

        let tls_config = build_tls_config(&tls)?;
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http2()
            .wrap_connector(http);

        let client = Client::builder(TokioExecutor)
            .http2_only(true)
            .pool_max_idle_per_host(max_idle_per_host)
            .pool_idle_timeout(pool_idle_timeout)
            .build(https);

        Ok(Self { client })
    }

    pub async fn send(
        &self,
        req: Request<BoxBody<Bytes, Infallible>>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, hyper_util::client::legacy::Error> {
        self.client.request(req).await
    }
    
    pub fn try_default() -> Result<Self, String> {
        Self::new(
            64,
            Duration::from_secs(30),
            Duration::from_secs(2),
            TlsClientConfig::default(),
        )
    }
}

fn build_tls_config(tls: &TlsClientConfig) -> Result<ClientConfig, String> {
    if !tls.verify_certificates {
        return Err(
            "upstream_tls.verify_certificates=false is not allowed; enable certificate verification"
                .to_string(),
        );
    }

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(ca_file) = tls.ca_file.as_ref() {
        let path = Path::new(ca_file);
        for cert in read_pem_certificates(path)? {
            roots.add(cert).map_err(|err| {
                format!(
                    "failed to add certificate from upstream_tls.ca_file '{}': {}",
                    path.display(),
                    err
                )
            })?;
        }
    }

    if let Some(ca_dir) = tls.ca_dir.as_ref() {
        let loaded = load_ca_directory(&mut roots, Path::new(ca_dir))?;
        if loaded == 0 {
            return Err(format!(
                "upstream_tls.ca_dir '{}' did not contain any readable PEM certificates",
                ca_dir
            ));
        }
    }

    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.enable_sni = tls.strict_sni;
    Ok(cfg)
}

fn read_pem_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = File::open(path).map_err(|err| {
        format!(
            "failed to open certificate file '{}': {}",
            path.display(),
            err
        )
    })?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            format!(
                "failed to parse PEM certificates from '{}': {}",
                path.display(),
                err
            )
        })?;
    if certs.is_empty() {
        return Err(format!(
            "certificate file '{}' does not contain any PEM certificates",
            path.display()
        ));
    }
    Ok(certs)
}

fn load_ca_directory(roots: &mut RootCertStore, dir: &Path) -> Result<usize, String> {
    let entries = std::fs::read_dir(dir).map_err(|err| {
        format!(
            "failed to read upstream_tls.ca_dir '{}': {}",
            dir.display(),
            err
        )
    })?;

    let mut loaded = 0usize;
    for entry in entries {
        let entry = entry.map_err(|err| {
            format!(
                "failed to read entry in upstream_tls.ca_dir '{}': {}",
                dir.display(),
                err
            )
        })?;
        let path = entry.path();
        if !path.is_file() || !is_pem_like_path(&path) {
            continue;
        }

        for cert in read_pem_certificates(&path)? {
            roots.add(cert).map_err(|err| {
                format!(
                    "failed to add certificate from '{}': {}",
                    path.display(),
                    err
                )
            })?;
            loaded = loaded.saturating_add(1);
        }
    }

    Ok(loaded)
}

fn is_pem_like_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(OsStr::to_str),
        Some("pem" | "crt" | "cer" | "PEM" | "CRT" | "CER")
    )
}

#[cfg(test)]
mod tests {
    use super::{H2Client, TlsClientConfig};
    use std::time::Duration;

    #[test]
    fn default_tls_client_config_builds_h2_client() {
        assert!(H2Client::try_default().is_ok());
    }

    #[test]
    fn invalid_ca_file_is_rejected() {
        let unique = format!(
            "spooky-invalid-ca-{}-{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::write(&path, b"not-a-pem-certificate").expect("write temp file");

        let client = H2Client::new(
            8,
            Duration::from_secs(5),
            Duration::from_secs(1),
            TlsClientConfig {
                verify_certificates: true,
                strict_sni: true,
                ca_file: Some(path.to_string_lossy().to_string()),
                ca_dir: None,
            },
        );
        assert!(client.is_err());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn disabling_certificate_verification_is_rejected() {
        let client = H2Client::new(
            8,
            Duration::from_secs(5),
            Duration::from_secs(1),
            TlsClientConfig {
                verify_certificates: false,
                strict_sni: true,
                ca_file: None,
                ca_dir: None,
            },
        );
        assert!(client.is_err());
    }
}
