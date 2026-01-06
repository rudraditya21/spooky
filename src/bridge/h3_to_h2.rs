
use quiche::h3::NameValue;
use http::{Request, HeaderName, HeaderValue};

pub fn h3_headers_to_h2(headers: &[NameValue]) -> Request<()> {
    let mut req = Request::builder();

    for h in headers {
        if h.name() == ":method" {
            req = req.method(h.value());
        } else if h.name() == ":path" {
            req = req.uri(h.value());
        } else if !h.name().starts_with(':') {
            req = req.header(
                HeaderName::from_bytes(h.name().as_bytes()).unwrap(),
                HeaderValue::from_bytes(h.value().as_bytes()).unwrap(),
            );
        }
    }

    req.body(()).unwrap()
}
