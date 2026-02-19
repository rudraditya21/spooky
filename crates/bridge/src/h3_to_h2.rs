use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, Uri};
use http_body_util::Full;

#[derive(Debug)]
pub enum BridgeError {
    InvalidMethod,
    InvalidUri,
    InvalidHeader,
    Build(http::Error),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::InvalidMethod => write!(f, "invalid method"),
            BridgeError::InvalidUri => write!(f, "invalid uri"),
            BridgeError::InvalidHeader => write!(f, "invalid header"),
            BridgeError::Build(e) => write!(f, "request build error: {e}"),
        }
    }
}

impl std::error::Error for BridgeError {}

pub fn build_h2_request(
    backend: &str,
    method: &str,
    path: &str,
    headers: &[(Vec<u8>, Vec<u8>)],
    body: &[u8],
) -> Result<Request<Full<Bytes>>, BridgeError> {
    let method = Method::from_bytes(method.as_bytes()).map_err(|_| BridgeError::InvalidMethod)?;

    let request_path = if path.is_empty() { "/" } else { path };
    let uri = format!("http://{backend}{request_path}");
    let uri = Uri::try_from(uri).map_err(|_| BridgeError::InvalidUri)?;

    let mut builder = Request::builder().method(method).uri(uri);

    let mut saw_host = false;
    for (name, value) in headers {
        if name.starts_with(b":") {
            continue;
        }

        let header_name = HeaderName::from_bytes(name).map_err(|_| BridgeError::InvalidHeader)?;
        if header_name == http::header::HOST {
            saw_host = true;
        }

        if header_name == http::header::CONTENT_LENGTH {
            continue;
        }

        let header_value =
            HeaderValue::from_bytes(value).map_err(|_| BridgeError::InvalidHeader)?;
        builder = builder.header(header_name, header_value);
    }

    if !saw_host {
        builder = builder.header(http::header::HOST, backend);
    }

    if !body.is_empty() {
        builder = builder.header(http::header::CONTENT_LENGTH, body.len());
    }

    builder
        .body(Full::new(Bytes::copy_from_slice(body)))
        .map_err(BridgeError::Build)
}
