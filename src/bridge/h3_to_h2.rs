use quiche::h3::NameValue;
use http::{Request, HeaderName, HeaderValue};

pub fn h3_headers_to_h2(headers: &[&dyn NameValue]) -> Request<()> {
    let mut req = Request::builder();

    for h in headers {
        match h.name() {
            b":method" => {
                req = req.method(h.value());
            }
            b":path" => {
                req = req.uri(h.value());
            }
            b":authority" => {
                req = req.header("host", h.value());
            }
            name if !name.starts_with(b":") => {
                req = req.header(
                    HeaderName::from_bytes(name).unwrap(),
                    HeaderValue::from_bytes(h.value()).unwrap(),
                );
            }
            _ => {}
        }
    }

    req.body(()).unwrap()
}
