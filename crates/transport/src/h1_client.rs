use http_body_util::combinators::BoxBody;
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use std::convert::Infallible;

use crate::h2_client::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_IDLE_PER_HOST, DEFAULT_POOL_IDLE_TIMEOUT,
    SharedDnsResolver, TokioExecutor,
};

pub struct H1Client {
    client: Client<HttpConnector<SharedDnsResolver>, BoxBody<Bytes, Infallible>>,
}

impl Default for H1Client {
    fn default() -> Self {
        let dns_resolver = SharedDnsResolver::new();
        let mut http = HttpConnector::new_with_resolver(dns_resolver);
        http.enforce_http(true);
        http.set_connect_timeout(Some(DEFAULT_CONNECT_TIMEOUT));

        let client = Client::builder(TokioExecutor)
            .pool_max_idle_per_host(DEFAULT_MAX_IDLE_PER_HOST)
            .pool_idle_timeout(DEFAULT_POOL_IDLE_TIMEOUT)
            .build(http);

        Self { client }
    }
}

impl H1Client {
    pub fn new(
        max_idle_per_host: usize,
        pool_idle_timeout: std::time::Duration,
        connect_timeout: std::time::Duration,
        dns_resolver: SharedDnsResolver,
    ) -> Self {
        let mut http = HttpConnector::new_with_resolver(dns_resolver);
        http.enforce_http(true);
        http.set_connect_timeout(Some(connect_timeout));

        let client = Client::builder(TokioExecutor)
            .pool_max_idle_per_host(max_idle_per_host)
            .pool_idle_timeout(pool_idle_timeout)
            .build(http);

        Self { client }
    }

    pub async fn send(
        &self,
        req: Request<BoxBody<Bytes, Infallible>>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, hyper_util::client::legacy::Error> {
        self.client.request(req).await
    }

    pub fn try_default() -> Self {
        Self::new(
            DEFAULT_MAX_IDLE_PER_HOST,
            DEFAULT_POOL_IDLE_TIMEOUT,
            DEFAULT_CONNECT_TIMEOUT,
            SharedDnsResolver::new(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::H1Client;

    #[test]
    fn default_h1_client_does_not_panic() {
        let _client = H1Client::default();
    }

    #[test]
    fn default_h1_client_builds() {
        let _client = H1Client::try_default();
    }
}
