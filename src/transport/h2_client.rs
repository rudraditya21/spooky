
use hyper::{Client, Request, Body};
use hyper::client::HttpConnector;
use hyper::client::conn::Builder;

pub struct H2Client {
    client: Client<HttpConnector, Body>,
}

impl H2Client {
    pub fn new() -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        let client = Client::builder()
            .http2_only(true)
            .build(http);

        Self { client }
    }

    pub async fn send(&self, req: Request<Body>) -> hyper::Result<hyper::Response<Body>> {
        self.client.request(req).await
    }
}
