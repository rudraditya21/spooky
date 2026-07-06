use super::*;
use crate::types::{
    ExternalAuthChallengeResponse, ExternalAuthDecision, ExternalAuthDenyResponse,
    ExternalAuthRedirectResponse, ExternalAuthResult,
};
use crate::{PendingForward, PendingHeaderMutation, StreamAdmissionState};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use serde_json::Value;
use sha2::Sha256;
use spooky_config::config::ScopedRateLimitScope;
use spooky_config::runtime::{RuntimeExternalAuth, RuntimeExternalAuthFailureMode};
use std::convert::Infallible;
use std::error::Error as StdError;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

impl PendingForward {
    fn request_headers(&self) -> Vec<quiche::h3::Header> {
        let mut headers = self.headers.as_ref().clone();
        for mutation in &self.auth_header_mutations {
            match mutation {
                PendingHeaderMutation::Upsert { name, value } => {
                    headers.retain(|header| !header.name().eq_ignore_ascii_case(name.as_slice()));
                    headers.push(quiche::h3::Header::new(name.as_slice(), value.as_slice()));
                }
                PendingHeaderMutation::Remove { name } => {
                    headers.retain(|header| !header.name().eq_ignore_ascii_case(name.as_slice()));
                }
            }
        }
        headers
    }

    fn forwarded_context(&self) -> ForwardedContext<'_> {
        ForwardedContext {
            client_addr: self.client_addr,
            request_authority: self.authority.as_deref(),
            request_id: self.request_id,
            traceparent: self.traceparent.as_deref(),
        }
    }

    fn build_request(
        &self,
        endpoint: &BackendEndpoint,
        body: BoxBody<Bytes, std::convert::Infallible>,
        content_length: Option<usize>,
    ) -> Result<Request<BoxBody<Bytes, std::convert::Infallible>>, ProxyError> {
        let headers = self.request_headers();
        if endpoint.scheme() == BackendScheme::Http {
            build_h1_request_for_endpoint_with_host_policy(
                endpoint,
                &self.host_policy,
                &self.forwarded_header_policy,
                &self.method,
                &self.path,
                &headers,
                body,
                content_length,
                self.forwarded_context(),
            )
            .map_err(ProxyError::from)
        } else {
            build_h2_request_for_endpoint_with_host_policy(
                endpoint,
                &self.host_policy,
                &self.forwarded_header_policy,
                &self.method,
                &self.path,
                &headers,
                body,
                content_length,
                self.forwarded_context(),
            )
            .map_err(ProxyError::from)
        }
    }

    pub(super) fn build_bodyless_request(
        &self,
        endpoint: &BackendEndpoint,
    ) -> Result<Request<BoxBody<Bytes, std::convert::Infallible>>, ProxyError> {
        self.build_request(endpoint, BoxBody::new(Full::new(Bytes::new())), Some(0))
    }

    fn build_http1_websocket_tunnel_request(
        &self,
        endpoint: &BackendEndpoint,
    ) -> Result<Request<BoxBody<Bytes, std::convert::Infallible>>, ProxyError> {
        let mut request_headers = self.request_headers();
        let has_upgrade = request_headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case(b"upgrade"));
        if !has_upgrade {
            request_headers.push(quiche::h3::Header::new(b"upgrade", b"websocket"));
        }
        let has_connection = request_headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case(b"connection"));
        if !has_connection {
            request_headers.push(quiche::h3::Header::new(b"connection", b"upgrade"));
        }

        build_h1_request_for_endpoint_with_host_policy(
            endpoint,
            &self.host_policy,
            &self.forwarded_header_policy,
            "GET",
            &self.path,
            &request_headers,
            BoxBody::new(Full::new(Bytes::new())),
            None,
            self.forwarded_context(),
        )
        .map_err(ProxyError::from)
    }
}

struct AuthHttpClient {
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>, BoxBody<Bytes, Infallible>>,
}

static AUTH_HTTP_CLIENT: OnceLock<AuthHttpClient> = OnceLock::new();

impl AuthHttpClient {
    fn shared() -> &'static Self {
        AUTH_HTTP_CLIENT.get_or_init(|| {
            let https = HttpsConnectorBuilder::new()
                .with_webpki_roots()
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build();
            let client = Client::builder(hyper_util::rt::TokioExecutor::new())
                .pool_max_idle_per_host(32)
                .pool_idle_timeout(Duration::from_secs(30))
                .build(https);
            Self { client }
        })
    }

    async fn send(
        &self,
        request: Request<BoxBody<Bytes, Infallible>>,
    ) -> Result<Response<Incoming>, ProxyError> {
        self.client
            .request(request)
            .await
            .map_err(|err| ProxyError::Transport(err.to_string()))
    }
}

struct AuthStart {
    rx: oneshot::Receiver<ExternalAuthResult>,
    deadline: Instant,
    fail_open: bool,
}

fn auth_failure_mode(external_auth: &RuntimeExternalAuth) -> RuntimeExternalAuthFailureMode {
    match external_auth {
        RuntimeExternalAuth::Http { failure_mode, .. }
        | RuntimeExternalAuth::Oidc { failure_mode, .. } => *failure_mode,
    }
}

fn auth_timeout_ms(external_auth: &RuntimeExternalAuth) -> u64 {
    match external_auth {
        RuntimeExternalAuth::Http { timeout_ms, .. }
        | RuntimeExternalAuth::Oidc { timeout_ms, .. } => *timeout_ms,
    }
}

fn fail_open(mode: RuntimeExternalAuthFailureMode) -> bool {
    matches!(mode, RuntimeExternalAuthFailureMode::FailOpen)
}

fn allowed_auth_headers(headers: &http::HeaderMap, allowlist: &[String]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            allowlist
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(name.as_str()))
                .then(|| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_string(), value.to_string()))
                })
                .flatten()
        })
        .collect()
}

fn auth_allow_mutations(
    headers: &http::HeaderMap,
    allowlist: &[String],
) -> Vec<PendingHeaderMutation> {
    allowed_auth_headers(headers, allowlist)
        .into_iter()
        .map(|(name, value)| PendingHeaderMutation::Upsert {
            name: name.into_bytes(),
            value: value.into_bytes(),
        })
        .collect()
}

fn append_auth_request_headers(
    builder: &mut http::request::Builder,
    pending_forward: &PendingForward,
    configured_headers: &[spooky_config::runtime::RuntimeExternalAuthRequestHeader],
) {
    for header in pending_forward.request_headers() {
        if header.name().starts_with(b":") {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(header.name()),
            http::header::HeaderValue::from_bytes(header.value()),
        ) && let Some(headers) = builder.headers_mut()
        {
            headers.append(name, value);
        }
    }
    for header in configured_headers {
        builder.headers_mut().into_iter().for_each(|headers| {
            if let (Ok(name), Ok(value)) = (
                http::header::HeaderName::from_bytes(header.name.as_bytes()),
                http::header::HeaderValue::from_str(&header.value),
            ) {
                headers.insert(name, value);
            }
        });
    }
    if let Some(headers) = builder.headers_mut() {
        if let Ok(value) = http::header::HeaderValue::from_str(&pending_forward.method) {
            headers.insert(
                http::header::HeaderName::from_static("x-spooky-original-method"),
                value,
            );
        }
        if let Ok(value) = http::header::HeaderValue::from_str(&pending_forward.path) {
            headers.insert(
                http::header::HeaderName::from_static("x-spooky-original-path"),
                value,
            );
        }
        if let Some(authority) = pending_forward.authority.as_deref()
            && let Ok(value) = http::header::HeaderValue::from_str(authority)
        {
            headers.insert(
                http::header::HeaderName::from_static("x-spooky-original-authority"),
                value,
            );
        }
        if let Ok(value) = http::header::HeaderValue::from_str(&pending_forward.upstream_name) {
            headers.insert(
                http::header::HeaderName::from_static("x-spooky-route-upstream"),
                value,
            );
        }
        if let Ok(value) = http::header::HeaderValue::from_str(&pending_forward.backend_addr) {
            headers.insert(
                http::header::HeaderName::from_static("x-spooky-backend-address"),
                value,
            );
        }
    }
}

async fn collect_auth_body(body: Incoming) -> Result<Vec<u8>, ProxyError> {
    http_body_util::BodyExt::collect(body)
        .await
        .map(|body| body.to_bytes().to_vec())
        .map_err(|err| ProxyError::Transport(err.to_string()))
}

fn authorization_header_from_pending_forward(pending_forward: &PendingForward) -> Option<String> {
    pending_forward
        .request_headers()
        .into_iter()
        .find(|header| {
            header
                .name()
                .eq_ignore_ascii_case(http::header::AUTHORIZATION.as_str().as_bytes())
        })
        .and_then(|header| std::str::from_utf8(header.value()).ok().map(str::to_string))
}

fn percent_encode_component(raw: &str) -> String {
    raw.bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{:02X}", byte).chars().collect::<Vec<_>>(),
        })
        .collect()
}

async fn send_auth_request(
    request: Request<BoxBody<Bytes, Infallible>>,
    timeout: Duration,
) -> Result<Response<Incoming>, ProxyError> {
    tokio::time::timeout(timeout, AuthHttpClient::shared().send(request))
        .await
        .map_err(|_| ProxyError::Timeout)?
}

fn header_value(response: &Response<Incoming>, name: http::header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

async fn run_http_external_auth(
    pending_forward: Arc<PendingForward>,
    endpoint: String,
    request_headers: Vec<spooky_config::runtime::RuntimeExternalAuthRequestHeader>,
    response_header_allowlist: Vec<String>,
    timeout: Duration,
) -> ExternalAuthResult {
    let mut builder = Request::builder().method(http::Method::GET).uri(endpoint);
    append_auth_request_headers(&mut builder, &pending_forward, &request_headers);
    let request = builder
        .body(BoxBody::new(Full::new(Bytes::new())))
        .map_err(|err| ProxyError::Transport(err.to_string()))?;
    let response = send_auth_request(request, timeout).await?;
    let status = response.status();
    let location = header_value(&response, http::header::LOCATION);
    let challenge = header_value(&response, http::header::WWW_AUTHENTICATE);
    let allowed_headers = allowed_auth_headers(response.headers(), &response_header_allowlist);
    if status.is_success() {
        return Ok(ExternalAuthDecision::Allow {
            request_header_mutations: auth_allow_mutations(
                response.headers(),
                &response_header_allowlist,
            ),
        });
    }
    if status.is_redirection() {
        if let Some(location) = location {
            return Ok(ExternalAuthDecision::Redirect(
                ExternalAuthRedirectResponse {
                    status,
                    headers: allowed_headers,
                    location,
                },
            ));
        }
        return Err(ProxyError::Transport(
            "external auth redirect missing location header".into(),
        ));
    }
    let body = collect_auth_body(response.into_body()).await?;
    if status == http::StatusCode::UNAUTHORIZED {
        if let Some(www_authenticate) = challenge {
            return Ok(ExternalAuthDecision::Challenge(
                ExternalAuthChallengeResponse {
                    status,
                    headers: allowed_headers,
                    www_authenticate,
                    body,
                },
            ));
        }
    }
    if status.is_client_error() {
        return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
            status,
            headers: allowed_headers,
            body,
        }));
    }
    Err(ProxyError::Transport(format!(
        "external auth endpoint returned {status}"
    )))
}

async fn fetch_json_document(uri: String, timeout: Duration) -> Result<Value, ProxyError> {
    let request = Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .body(BoxBody::new(Full::new(Bytes::new())))
        .map_err(|err| ProxyError::Transport(err.to_string()))?;
    let response = send_auth_request(request, timeout).await?;
    if !response.status().is_success() {
        return Err(ProxyError::Transport(format!(
            "oidc discovery returned {}",
            response.status()
        )));
    }
    let body = collect_auth_body(response.into_body()).await?;
    serde_json::from_slice(&body).map_err(|err| ProxyError::Transport(err.to_string()))
}

fn oidc_discovery_url(discovery_url: Option<String>, issuer_url: Option<String>) -> Option<String> {
    discovery_url.or_else(|| {
        issuer_url.map(|issuer| {
            format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            )
        })
    })
}

fn oidc_scope_satisfied(required_scopes: &[String], granted_scopes: &str) -> bool {
    let granted: std::collections::HashSet<&str> = granted_scopes.split_whitespace().collect();
    required_scopes
        .iter()
        .all(|scope| granted.contains(scope.as_str()))
}

fn oidc_audience_matches(expected: Option<&str>, value: Option<&Value>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    match value {
        Some(Value::String(single)) => single == expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

async fn run_oidc_external_auth(
    pending_forward: Arc<PendingForward>,
    discovery_url: Option<String>,
    issuer_url: Option<String>,
    client_id: String,
    client_secret: Option<String>,
    audience: Option<String>,
    scopes: Vec<String>,
    request_headers: Vec<spooky_config::runtime::RuntimeExternalAuthRequestHeader>,
    timeout: Duration,
) -> ExternalAuthResult {
    let Some(authorization) = authorization_header_from_pending_forward(&pending_forward) else {
        return Ok(ExternalAuthDecision::Challenge(
            ExternalAuthChallengeResponse {
                status: http::StatusCode::UNAUTHORIZED,
                headers: Vec::new(),
                www_authenticate: "Bearer".to_string(),
                body: b"missing bearer token\n".to_vec(),
            },
        ));
    };
    let Some(token) = QUICListener::bearer_token_from_authorization_value(&authorization) else {
        return Ok(ExternalAuthDecision::Challenge(
            ExternalAuthChallengeResponse {
                status: http::StatusCode::UNAUTHORIZED,
                headers: Vec::new(),
                www_authenticate: "Bearer".to_string(),
                body: b"invalid bearer token\n".to_vec(),
            },
        ));
    };
    let discovery = oidc_discovery_url(discovery_url, issuer_url.clone())
        .ok_or_else(|| ProxyError::Transport("oidc auth missing discovery metadata".into()))?;
    let document = fetch_json_document(discovery, timeout).await?;
    let introspection_endpoint = document
        .get("introspection_endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProxyError::Transport("oidc discovery missing introspection_endpoint".into())
        })?;

    let mut body = format!(
        "token={}&client_id={}",
        percent_encode_component(&token),
        percent_encode_component(&client_id)
    );
    if let Some(secret) = client_secret.as_deref() {
        body.push_str("&client_secret=");
        body.push_str(&percent_encode_component(secret));
    }
    if let Some(audience) = audience.as_deref() {
        body.push_str("&audience=");
        body.push_str(&percent_encode_component(audience));
    }

    let mut builder = Request::builder()
        .method(http::Method::POST)
        .uri(introspection_endpoint)
        .header(
            http::header::CONTENT_TYPE,
            http::header::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
    append_auth_request_headers(&mut builder, &pending_forward, &request_headers);
    let request = builder
        .body(BoxBody::new(Full::new(Bytes::from(body))))
        .map_err(|err| ProxyError::Transport(err.to_string()))?;
    let response = send_auth_request(request, timeout).await?;
    if !response.status().is_success() {
        if response.status().is_client_error() {
            return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
                status: http::StatusCode::FORBIDDEN,
                headers: Vec::new(),
                body: b"oidc token rejected\n".to_vec(),
            }));
        }
        return Err(ProxyError::Transport(format!(
            "oidc introspection returned {}",
            response.status()
        )));
    }
    let payload = collect_auth_body(response.into_body()).await?;
    let value: Value =
        serde_json::from_slice(&payload).map_err(|err| ProxyError::Transport(err.to_string()))?;
    if !value
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
            status: http::StatusCode::FORBIDDEN,
            headers: Vec::new(),
            body: b"inactive oidc token\n".to_vec(),
        }));
    }
    if let Some(issuer_url) = issuer_url.as_deref()
        && value.get("iss").and_then(Value::as_str) != Some(issuer_url)
    {
        return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
            status: http::StatusCode::FORBIDDEN,
            headers: Vec::new(),
            body: b"unexpected oidc issuer\n".to_vec(),
        }));
    }
    if !oidc_audience_matches(audience.as_deref(), value.get("aud")) {
        return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
            status: http::StatusCode::FORBIDDEN,
            headers: Vec::new(),
            body: b"unexpected oidc audience\n".to_vec(),
        }));
    }
    if !scopes.is_empty() {
        let Some(scope_value) = value.get("scope").and_then(Value::as_str) else {
            return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
                status: http::StatusCode::FORBIDDEN,
                headers: Vec::new(),
                body: b"missing oidc scopes
"
                .to_vec(),
            }));
        };
        if !oidc_scope_satisfied(&scopes, scope_value) {
            return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
                status: http::StatusCode::FORBIDDEN,
                headers: Vec::new(),
                body: b"missing oidc scopes
"
                .to_vec(),
            }));
        }
    }

    Ok(ExternalAuthDecision::Allow {
        request_header_mutations: Vec::new(),
    })
}

async fn run_external_auth(
    pending_forward: Arc<PendingForward>,
    external_auth: RuntimeExternalAuth,
) -> ExternalAuthResult {
    let timeout = Duration::from_millis(auth_timeout_ms(&external_auth).max(1));
    match external_auth {
        RuntimeExternalAuth::Http {
            endpoint,
            request_headers,
            response_header_allowlist,
            ..
        } => {
            run_http_external_auth(
                pending_forward,
                endpoint,
                request_headers,
                response_header_allowlist,
                timeout,
            )
            .await
        }
        RuntimeExternalAuth::Oidc {
            discovery_url,
            issuer_url,
            client_id,
            client_secret,
            audience,
            scopes,
            request_headers,
            ..
        } => {
            run_oidc_external_auth(
                pending_forward,
                discovery_url,
                issuer_url,
                client_id,
                client_secret,
                audience,
                scopes,
                request_headers,
                timeout,
            )
            .await
        }
    }
}

fn start_external_auth_task(
    pending_forward: Arc<PendingForward>,
    external_auth: RuntimeExternalAuth,
) -> Result<AuthStart, ProxyError> {
    let timeout_ms = auth_timeout_ms(&external_auth).max(1);
    let mode = auth_failure_mode(&external_auth);
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let (tx, rx) = oneshot::channel();
    let fut = async move {
        let result = run_external_auth(pending_forward, external_auth).await;
        let _ = tx.send(result);
    };
    if !spawn_async_task(fut, "external-auth") {
        return Err(ProxyError::Transport(
            "dropping external auth task: no runtime available".into(),
        ));
    }
    Ok(AuthStart {
        rx,
        deadline,
        fail_open: fail_open(mode),
    })
}

pub(crate) fn abort_stream(req: &mut RequestEnvelope, metrics: &Metrics) -> StreamPhase {
    let phase = req.phase.clone();
    if req.backend_request_started && !req.backend_request_finished {
        if let (Some(pool), Some(index)) = (&req.upstream_pool, req.backend_index)
            && let Ok(mut guard) = pool.write()
        {
            guard.finish_request(
                index,
                req.start.elapsed(),
                req.response_status.or(Some(503)),
            );
        }
        req.backend_request_finished = true;
    }
    if req.body_buf_bytes > 0 {
        metrics.release_request_buffer(req.body_buf_bytes);
        req.body_buf_bytes = 0;
    }
    req.body_buf.clear();
    req.body_tx = None;
    req.auth_result_rx = None;
    req.upstream_result_rx = None;
    req.response_chunk_rx = None;
    req.pending_chunk = None;
    req.pending_forward = None;
    req.auth_deadline = None;
    req.global_inflight_permit = None;
    req.upstream_inflight_permit = None;
    req.adaptive_admission_permit = None;
    req.route_queue_permit = None;
    phase
}

impl QUICListener {
    pub(super) fn classify_upstream_failure_reason(
        is_connect: bool,
        detail: &str,
    ) -> (HealthFailureReason, &'static str) {
        let normalized = detail.to_ascii_lowercase();
        if normalized.contains("timeout") || normalized.contains("timed out") {
            return (HealthFailureReason::Timeout, "timeout");
        }

        if is_connect {
            if normalized.contains("unknownissuer") || normalized.contains("unknown issuer") {
                return (HealthFailureReason::Tls, "unknown_issuer");
            }
            if normalized.contains("expired")
                || normalized.contains("not yet valid")
                || normalized.contains("validity")
            {
                return (HealthFailureReason::Tls, "expired_certificate");
            }
            if normalized.contains("hostname")
                || normalized.contains("dns name")
                || normalized.contains("subjectaltname")
                || normalized.contains("not valid for")
            {
                return (HealthFailureReason::Tls, "hostname_mismatch");
            }
            if normalized.contains("alpn") {
                return (HealthFailureReason::Tls, "alpn");
            }
            if normalized.contains("invalidcertificate")
                || normalized.contains("certificate")
                || normalized.contains("x509")
                || normalized.contains("rustls")
                || normalized.contains("webpki")
                || normalized.contains("tls")
            {
                return (HealthFailureReason::Tls, "handshake");
            }
        }

        (HealthFailureReason::Transport, "transport")
    }

    pub(super) fn send_error_health_failure_reason(
        err: &hyper_util::client::legacy::Error,
    ) -> (HealthFailureReason, &'static str) {
        let detail = Self::format_error_chain(err);
        Self::classify_upstream_failure_reason(err.is_connect(), &detail)
    }

    pub(super) fn format_error_chain(err: &(dyn StdError + 'static)) -> String {
        let mut detail = err.to_string();
        let mut source = err.source();
        while let Some(cause) = source {
            detail.push_str(": ");
            detail.push_str(&cause.to_string());
            source = cause.source();
        }
        detail
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_http1_websocket_tunnel(
        endpoint: BackendEndpoint,
        pending_forward: Arc<PendingForward>,
        mut body_rx: mpsc::Receiver<Bytes>,
        backend_timeout: Duration,
        metrics: Arc<Metrics>,
    ) -> ForwardResult {
        let request = pending_forward.build_http1_websocket_tunnel_request(&endpoint)?;

        let stream = tokio::time::timeout(
            backend_timeout,
            tokio::net::TcpStream::connect(endpoint.authority()),
        )
        .await
        .map_err(|_| ProxyError::Timeout)?
        .map_err(|err| ProxyError::Transport(err.to_string()))?;
        let resolved_addr = stream
            .peer_addr()
            .map_err(|err| ProxyError::Transport(err.to_string()))?;
        metrics.record_backend_connect(
            endpoint.authority(),
            endpoint.authority_host(),
            resolved_addr,
        );
        let io = TokioIo::new(stream);
        let (mut sender, conn) = client_http1::handshake(io)
            .await
            .map_err(|err| ProxyError::Transport(err.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });

        let mut response = tokio::time::timeout(backend_timeout, sender.send_request(request))
            .await
            .map_err(|_| ProxyError::Timeout)?
            .map_err(|err| ProxyError::Transport(err.to_string()))?;

        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            let status = response.status();
            let headers = response.headers().clone();
            return Ok(ForwardSuccess::Response {
                status,
                headers,
                body: response.into_body(),
            });
        }

        let upgraded = upgrade::on(&mut response);
        let headers = response.headers().clone();
        let (chunk_tx, chunk_rx) = mpsc::channel(RESPONSE_CHUNK_CHANNEL_CAPACITY);
        let fut = async move {
            let upgraded = match upgraded.await {
                Ok(upgraded) => upgraded,
                Err(err) => {
                    let _ = chunk_tx
                        .send(ResponseChunk::Error(ProxyError::Transport(err.to_string())))
                        .await;
                    return;
                }
            };
            let io = TokioIo::new(upgraded);
            let (mut reader, mut writer) = tokio::io::split(io);
            let write_fut = async {
                while let Some(chunk) = body_rx.recv().await {
                    writer.write_all(&chunk).await?;
                }
                writer.shutdown().await
            };
            let read_fut = async {
                let mut buf = [0u8; RESPONSE_CHUNK_BYTES_LIMIT];
                loop {
                    match reader.read(&mut buf).await {
                        Ok(0) => return Ok::<(), std::io::Error>(()),
                        Ok(read) => {
                            if chunk_tx
                                .send(ResponseChunk::Data(Bytes::copy_from_slice(&buf[..read])))
                                .await
                                .is_err()
                            {
                                return Ok(());
                            }
                        }
                        Err(err) => return Err(err),
                    }
                }
            };
            match tokio::try_join!(write_fut, read_fut) {
                Ok(((), ())) => {
                    let _ = chunk_tx.send(ResponseChunk::End).await;
                }
                Err(err) => {
                    let _ = chunk_tx
                        .send(ResponseChunk::Error(ProxyError::Transport(err.to_string())))
                        .await;
                }
            }
        };
        let _ = spawn_async_task(fut, "ws-h1-tunnel");

        Ok(ForwardSuccess::Tunnel {
            status: StatusCode::OK,
            headers,
            response_chunk_rx: chunk_rx,
        })
    }

    fn is_internal_pool_control_error(error: &PoolError) -> bool {
        matches!(
            error,
            PoolError::InflightLimiterClosed | PoolError::UnknownBackend(_)
        )
    }

    fn request_metrics_outcome_for_status(status: StatusCode) -> (bool, RouteOutcome) {
        if status.is_server_error() {
            (false, RouteOutcome::Failure)
        } else {
            (true, RouteOutcome::Success)
        }
    }

    pub(super) fn pick_alternate_backend(
        upstream_pool: &Arc<RwLock<UpstreamPool>>,
        primary_index: usize,
    ) -> Option<(String, usize)> {
        let pool = upstream_pool.read().ok()?;
        for index in pool.pool.healthy_indices_iter() {
            if index == primary_index {
                continue;
            }
            if let Some(address) = pool.pool.address(index) {
                return Some((address.to_string(), index));
            }
        }
        None
    }

    pub(super) fn log_access(req: &RequestEnvelope, status: u16) {
        let trace_id = req.trace_id.as_deref().unwrap_or("-");
        let span_id = req.span_id.as_deref().unwrap_or("-");
        let latency_ms = req.start.elapsed().as_millis() as u64;
        if req.routing_transparency_enabled {
            let reason = if req.routing_transparency_include_reason {
                req.route_reason.as_deref().unwrap_or("-")
            } else {
                "-"
            };
            info!(
                "request_id={} route_upstream={} route_path_len={} route_host_specific={} route_reason={} lb={}",
                req.request_id,
                req.upstream_name.as_deref().unwrap_or("-"),
                req.route_path_len.unwrap_or_default(),
                req.route_host_specific.unwrap_or(false),
                reason,
                req.backend_lb.as_deref().unwrap_or("-")
            );
        }

        if let Some(span) = req.trace_span.as_ref() {
            span.in_scope(|| match req.error_kind.as_ref() {
                Some(e) => tracing::warn!(
                    request_id = req.request_id,
                    trace_id = trace_id,
                    span_id = span_id,
                    method = %req.method,
                    path = %req.path,
                    status = status,
                    backend = %req.backend_addr.as_deref().unwrap_or("-"),
                    upstream = %req.upstream_name.as_deref().unwrap_or("-"),
                    latency_ms = latency_ms,
                    retries = req.retry_count,
                    error = %e,
                    "request completed with error"
                ),
                None => tracing::info!(
                    request_id = req.request_id,
                    trace_id = trace_id,
                    span_id = span_id,
                    method = %req.method,
                    path = %req.path,
                    status = status,
                    backend = %req.backend_addr.as_deref().unwrap_or("-"),
                    upstream = %req.upstream_name.as_deref().unwrap_or("-"),
                    latency_ms = latency_ms,
                    retries = req.retry_count,
                    "request completed"
                ),
            });
        }

        match req.error_kind {
            Some(e) => info!(
                "request_id={} trace_id={} span_id={} method={} path={} status={} backend={} upstream={} latency_ms={} retries={} error={}",
                req.request_id,
                trace_id,
                span_id,
                req.method,
                req.path,
                status,
                req.backend_addr.as_deref().unwrap_or("-"),
                req.upstream_name.as_deref().unwrap_or("-"),
                latency_ms,
                req.retry_count,
                e,
            ),
            None => info!(
                "request_id={} trace_id={} span_id={} method={} path={} status={} backend={} upstream={} latency_ms={} retries={}",
                req.request_id,
                trace_id,
                span_id,
                req.method,
                req.path,
                status,
                req.backend_addr.as_deref().unwrap_or("-"),
                req.upstream_name.as_deref().unwrap_or("-"),
                latency_ms,
                req.retry_count,
            ),
        }
    }

    fn record_request_observation(
        metrics: &Metrics,
        req: &RequestEnvelope,
        status: Option<u16>,
        outcome: RouteOutcome,
    ) {
        metrics.record_request_result(
            req.upstream_name.as_deref().unwrap_or("unrouted"),
            req.backend_addr.as_deref(),
            status,
            outcome,
            req.start.elapsed(),
        );
    }

    /// Handle an already-resolved `ForwardResult`, applying health transitions
    /// and sending the H3 response.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_forward_result(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        req: &RequestEnvelope,
        result: ForwardResult,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        routing_index: &RouteIndex,
        metrics: &Metrics,
        overload_retry_after_seconds: u32,
    ) -> Result<(), quiche::h3::Error> {
        let start = req.start;
        let route_label = req.upstream_name.as_deref().unwrap_or("unrouted");

        // If routing failed at Headers time, return an appropriate error now.
        let (backend_addr, backend_index) = match (&req.backend_addr, req.backend_index) {
            (Some(a), Some(i)) => (a.as_str(), i),
            _ => {
                metrics.inc_failure();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::Failure);
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(if req.method.is_empty() || req.path.is_empty() {
                        http::StatusCode::BAD_REQUEST.as_u16()
                    } else {
                        http::StatusCode::SERVICE_UNAVAILABLE.as_u16()
                    }),
                    RouteOutcome::Failure,
                );
                return Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    if req.method.is_empty() || req.path.is_empty() {
                        http::StatusCode::BAD_REQUEST
                    } else {
                        http::StatusCode::SERVICE_UNAVAILABLE
                    },
                    b"no upstream available\n",
                );
            }
        };

        // Re-acquire the upstream pool for health marking.
        let upstream_name = routing_index.lookup(&req.path, req.authority.as_deref());
        let upstream_pool = req
            .upstream_pool
            .as_ref()
            .cloned()
            .or_else(|| upstream_name.and_then(|n| upstream_pools.get(n)).cloned());

        match result {
            Ok(_) => {
                error!("Unexpected successful forward result in error handler path");
                metrics.inc_failure();
                metrics.inc_backend_error();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::BackendError);
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(http::StatusCode::BAD_GATEWAY.as_u16()),
                    RouteOutcome::BackendError,
                );
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_GATEWAY,
                    b"unexpected upstream state\n",
                )
            }
            Err(ProxyError::Bridge(err)) => {
                error!("Bridge error: {:?}", err);
                metrics.inc_failure();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::Failure);
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(http::StatusCode::BAD_REQUEST.as_u16()),
                    RouteOutcome::Failure,
                );
                Self::log_access(req, 400);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_REQUEST,
                    b"invalid request\n",
                )
            }
            Err(ProxyError::Pool(PoolError::BackendOverloaded(reason))) => {
                metrics.inc_failure();
                if reason.contains("unknown-length response prebuffer limit exceeded") {
                    metrics.inc_response_prebuffer_limit_reject();
                    metrics.inc_overload_shed_reason(OverloadShedReason::ResponsePrebufferCap);
                } else {
                    metrics.inc_overload_shed_reason(OverloadShedReason::BackendInflight);
                }
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::OverloadShed);
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(http::StatusCode::SERVICE_UNAVAILABLE.as_u16()),
                    RouteOutcome::OverloadShed,
                );
                Self::log_access(req, 503);
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    b"backend overloaded, retry later\n",
                    overload_retry_after_seconds,
                )
            }
            Err(ProxyError::Pool(PoolError::CircuitOpen(_))) => {
                metrics.inc_failure();
                metrics.inc_circuit_breaker_rejected();
                metrics.inc_overload_shed_reason(OverloadShedReason::CircuitOpen);
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::OverloadShed);
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(http::StatusCode::SERVICE_UNAVAILABLE.as_u16()),
                    RouteOutcome::OverloadShed,
                );
                Self::log_access(req, 503);
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    b"backend circuit open, retry later\n",
                    overload_retry_after_seconds,
                )
            }
            Err(ProxyError::Pool(PoolError::Send(ref send_err))) => {
                // Log full upstream send/connect detail and map it into a backend
                // health failure reason so repeated failures can eject unhealthy backends.
                let send_err_detail = Self::format_error_chain(send_err);
                let (failure_reason, tls_reason) = Self::send_error_health_failure_reason(send_err);
                error!(
                    "Upstream send failed for {} (health_reason={:?}, tls_reason={}): {}",
                    backend_addr, failure_reason, tls_reason, send_err_detail
                );
                metrics.inc_health_failure(failure_reason);
                if failure_reason == HealthFailureReason::Tls {
                    metrics.record_upstream_tls_failure(backend_addr, "data_plane", tls_reason);
                }
                if let Some(pool) = &upstream_pool
                    && let Some(t) = pool.write().ok().and_then(|mut p| {
                        p.pool.mark_request_failure(backend_index, failure_reason)
                    })
                {
                    Self::log_health_transition(backend_addr, t);
                }
                metrics.inc_failure();
                metrics.inc_backend_error();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::BackendError);
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(http::StatusCode::BAD_GATEWAY.as_u16()),
                    RouteOutcome::BackendError,
                );
                Self::log_access(req, 502);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_GATEWAY,
                    b"upstream error\n",
                )
            }
            Err(ProxyError::Transport(err)) => {
                error!(
                    "request_id={} upstream={} backend={} Upstream transport error: {}",
                    req.request_id,
                    req.upstream_name.as_deref().unwrap_or("-"),
                    backend_addr,
                    err
                );
                metrics.inc_health_failure(HealthFailureReason::Transport);
                if let Some(pool) = &upstream_pool
                    && let Some(t) = pool.write().ok().and_then(|mut p| {
                        p.pool
                            .mark_request_failure(backend_index, HealthFailureReason::Transport)
                    })
                {
                    Self::log_health_transition(backend_addr, t);
                }
                metrics.inc_failure();
                metrics.inc_backend_error();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::BackendError);
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(http::StatusCode::BAD_GATEWAY.as_u16()),
                    RouteOutcome::BackendError,
                );
                Self::log_access(req, 502);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_GATEWAY,
                    b"upstream error\n",
                )
            }
            Err(ProxyError::Pool(pool_err @ PoolError::InflightLimiterClosed))
            | Err(ProxyError::Pool(pool_err @ PoolError::UnknownBackend(_))) => {
                debug_assert!(Self::is_internal_pool_control_error(&pool_err));
                match &pool_err {
                    PoolError::InflightLimiterClosed => {
                        error!("Upstream pool inflight limiter closed");
                    }
                    PoolError::UnknownBackend(_) => {
                        error!("Upstream pool unknown backend");
                    }
                    _ => {}
                }
                metrics.inc_failure();
                metrics.inc_backend_error();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::BackendError);
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(http::StatusCode::BAD_GATEWAY.as_u16()),
                    RouteOutcome::BackendError,
                );
                Self::log_access(req, 502);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_GATEWAY,
                    b"upstream error\n",
                )
            }
            Err(ProxyError::Protocol(err)) => {
                error!("request_id={} Protocol error: {}", req.request_id, err);
                metrics.inc_failure();
                metrics.inc_backend_error();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::BackendError);
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(http::StatusCode::BAD_GATEWAY.as_u16()),
                    RouteOutcome::BackendError,
                );
                Self::log_access(req, 502);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::BAD_GATEWAY,
                    b"upstream protocol error\n",
                )
            }
            Err(ProxyError::Timeout) => {
                error!("request_id={} Upstream request timed out", req.request_id);
                metrics.inc_health_failure(HealthFailureReason::Timeout);
                if let Some(pool) = &upstream_pool
                    && let Some(t) = pool.write().ok().and_then(|mut p| {
                        p.pool
                            .mark_request_failure(backend_index, HealthFailureReason::Timeout)
                    })
                {
                    Self::log_health_transition(backend_addr, t);
                }
                metrics.inc_failure();
                metrics.inc_timeout();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::Timeout);
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(http::StatusCode::SERVICE_UNAVAILABLE.as_u16()),
                    RouteOutcome::Timeout,
                );
                Self::log_access(req, 503);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    b"upstream timeout\n",
                )
            }
            Err(ProxyError::Tls(err)) => {
                error!("TLS error: {}", err);
                metrics.inc_health_failure(HealthFailureReason::Tls);
                metrics.inc_failure();
                metrics.record_route(route_label, start.elapsed(), RouteOutcome::Failure);
                Self::record_request_observation(
                    metrics,
                    req,
                    Some(http::StatusCode::INTERNAL_SERVER_ERROR.as_u16()),
                    RouteOutcome::Failure,
                );
                Self::log_access(req, 500);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    b"internal server error\n",
                )
            }
        }
    }

    pub(super) fn send_simple_response(
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

    pub(super) fn send_overload_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        body: &[u8],
        retry_after_seconds: u32,
    ) -> Result<(), quiche::h3::Error> {
        let retry_after = retry_after_seconds.max(1).to_string();
        let resp_headers = vec![
            quiche::h3::Header::new(
                b":status",
                http::StatusCode::SERVICE_UNAVAILABLE.as_str().as_bytes(),
            ),
            quiche::h3::Header::new(b"content-type", b"text/plain"),
            quiche::h3::Header::new(b"retry-after", retry_after.as_bytes()),
            quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
        ];

        h3.send_response(quic, stream_id, &resp_headers, false)?;
        h3.send_body(quic, stream_id, body, true)?;
        Ok(())
    }

    pub(super) fn send_rate_limited_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        body: &[u8],
        retry_after_seconds: u32,
    ) -> Result<(), quiche::h3::Error> {
        let retry_after = retry_after_seconds.max(1).to_string();
        let resp_headers = vec![
            quiche::h3::Header::new(
                b":status",
                http::StatusCode::TOO_MANY_REQUESTS.as_str().as_bytes(),
            ),
            quiche::h3::Header::new(b"content-type", b"text/plain"),
            quiche::h3::Header::new(b"retry-after", retry_after.as_bytes()),
            quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
        ];

        h3.send_response(quic, stream_id, &resp_headers, false)?;
        h3.send_body(quic, stream_id, body, true)?;
        Ok(())
    }

    pub(super) fn send_unauthorized_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        body: &[u8],
        challenge: &[u8],
    ) -> Result<(), quiche::h3::Error> {
        let resp_headers = vec![
            quiche::h3::Header::new(
                b":status",
                http::StatusCode::UNAUTHORIZED.as_str().as_bytes(),
            ),
            quiche::h3::Header::new(b"content-type", b"text/plain"),
            quiche::h3::Header::new(b"www-authenticate", challenge),
            quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
        ];

        h3.send_response(quic, stream_id, &resp_headers, false)?;
        h3.send_body(quic, stream_id, body, true)?;
        Ok(())
    }

    fn send_response_with_headers(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        status: http::StatusCode,
        body: &[u8],
        headers: &[(String, String)],
    ) -> Result<(), quiche::h3::Error> {
        let mut resp_headers = vec![quiche::h3::Header::new(
            b":status",
            status.as_str().as_bytes(),
        )];
        let mut has_content_type = false;
        let mut has_content_length = false;
        for (name, value) in headers {
            if name.eq_ignore_ascii_case(http::header::CONTENT_TYPE.as_str()) {
                has_content_type = true;
            }
            if name.eq_ignore_ascii_case(http::header::CONTENT_LENGTH.as_str()) {
                has_content_length = true;
            }
            resp_headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
        }
        if !has_content_type {
            resp_headers.push(quiche::h3::Header::new(b"content-type", b"text/plain"));
        }
        if !has_content_length {
            resp_headers.push(quiche::h3::Header::new(
                b"content-length",
                body.len().to_string().as_bytes(),
            ));
        }
        h3.send_response(quic, stream_id, &resp_headers, false)?;
        h3.send_body(quic, stream_id, body, true)?;
        Ok(())
    }

    fn send_external_auth_decision_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        decision: &ExternalAuthDecision,
    ) -> Result<(), quiche::h3::Error> {
        match decision {
            ExternalAuthDecision::Allow { .. } => Ok(()),
            ExternalAuthDecision::Deny(response) => Self::send_response_with_headers(
                h3,
                quic,
                stream_id,
                response.status,
                &response.body,
                &response.headers,
            ),
            ExternalAuthDecision::Redirect(response) => {
                let mut headers = response.headers.clone();
                headers.push((
                    http::header::LOCATION.as_str().to_string(),
                    response.location.clone(),
                ));
                Self::send_response_with_headers(
                    h3,
                    quic,
                    stream_id,
                    response.status,
                    &[],
                    &headers,
                )
            }
            ExternalAuthDecision::Challenge(response) => {
                let mut headers = response.headers.clone();
                headers.push((
                    http::header::WWW_AUTHENTICATE.as_str().to_string(),
                    response.www_authenticate.clone(),
                ));
                Self::send_response_with_headers(
                    h3,
                    quic,
                    stream_id,
                    response.status,
                    &response.body,
                    &headers,
                )
            }
        }
    }

    fn spawn_upstream_forward_task(
        req: &RequestEnvelope,
        pending_forward: Arc<PendingForward>,
        backend_endpoint: BackendEndpoint,
        request: Option<Request<BoxBody<Bytes, Infallible>>>,
        websocket_tunnel_body_rx: Option<mpsc::Receiver<Bytes>>,
        transport_pool: Arc<UpstreamTransportPool>,
        backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
        backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
        backend_timeout: Duration,
        metrics: Arc<Metrics>,
        resilience: &RuntimeResilience,
    ) -> Result<oneshot::Receiver<UpstreamResult>, ProxyError> {
        let fwd_addr = pending_forward.backend_addr.to_string();
        let cb = Arc::clone(&resilience.circuit_breakers);
        let retry_budget = Arc::clone(&resilience.retry_budget);
        let route_name = pending_forward.upstream_name.to_string();
        let _backend_resolutions = Arc::clone(&backend_resolution_store);
        let transport = Arc::clone(&transport_pool);
        let allow_hedge = req.tunnel_mode == TunnelMode::None
            && req.bodyless_mode
            && resilience.hedging_allowed_for(&req.method, &route_name, true);
        let hedge_delay = resilience.hedging_delay;
        let alternate_backend = req.upstream_pool.as_ref().and_then(|upstream_pool| {
            Self::pick_alternate_backend(upstream_pool, pending_forward.backend_index)
        });
        let trace_span_for_upstream = req.trace_span.clone();
        let pending_forward_for_upstream = Arc::clone(&pending_forward);
        let (result_tx, result_rx) = oneshot::channel::<UpstreamResult>();
        let tunnel_mode = req.tunnel_mode;
        let bodyless_mode = req.bodyless_mode;
        let request_id = req.request_id;
        let fut = async move {
            let mut hedge_telemetry = crate::HedgeTelemetry::default();
            let mut retry_count: u8 = 0;
            let mut retry_attempt_reason: Option<RetryReason> = None;
            let mut retry_denial_reason: Option<RetryReason> = None;
            let result: ForwardResult = async {
                retry_budget.mark_primary(&route_name);

                let send_once =
                    |backend: String,
                     req: http::Request<BoxBody<Bytes, std::convert::Infallible>>,
                     cb: Arc<crate::resilience::CircuitBreakers>,
                     transport: Arc<UpstreamTransportPool>| async move {
                        if !cb.allow_request(&backend) {
                            return Err(ProxyError::Pool(PoolError::CircuitOpen(backend)));
                        }
                        let send_result = tokio::time::timeout(
                            backend_timeout,
                            transport.send(&backend, req),
                        )
                        .await
                        .map_err(|_| ProxyError::Timeout);
                        match &send_result {
                            Ok(Ok(_)) => cb.record_success(&backend),
                            _ => cb.record_failure(&backend),
                        }
                        Ok(send_result??)
                    };

                let forward_success: ForwardSuccess = if tunnel_mode == TunnelMode::Websocket
                    && backend_endpoint.scheme() == BackendScheme::Http
                {
                    let Some(body_rx) = websocket_tunnel_body_rx else {
                        return Err(ProxyError::Transport(
                            "websocket H1 tunnels require a downstream body channel".into(),
                        ));
                    };
                    Self::forward_http1_websocket_tunnel(
                        backend_endpoint.clone(),
                        Arc::clone(&pending_forward_for_upstream),
                        body_rx,
                        backend_timeout,
                        Arc::clone(&metrics),
                    )
                    .await?
                } else {
                    let request = request.ok_or_else(|| {
                        ProxyError::Transport(
                            "missing upstream request for non-websocket forward".into(),
                        )
                    })?;
                    let response: Response<Incoming> = if allow_hedge {
                        let hedge_candidate = alternate_backend.clone().and_then(|(backend, _idx)| {
                            let endpoint = backend_endpoints.get(&backend)?;
                            pending_forward_for_upstream
                                .build_bodyless_request(endpoint)
                                .ok()
                                .map(|req| (backend, req))
                        });

                        if let Some((hedge_backend, hedge_request)) = hedge_candidate {
                            let primary_started = Instant::now();
                            let primary_backend = fwd_addr.clone();
                            let primary_fut = send_once(
                                primary_backend,
                                request,
                                Arc::clone(&cb),
                                Arc::clone(&transport),
                            );
                            tokio::pin!(primary_fut);
                            let hedge_sleep = tokio::time::sleep(hedge_delay);
                            tokio::pin!(hedge_sleep);

                            if let Some(result) = tokio::select! {
                                result = &mut primary_fut => Some(result),
                                _ = &mut hedge_sleep => None,
                            } {
                                result?
                            } else if retry_budget.allow_retry(&route_name).is_ok() {
                                hedge_telemetry.launched = true;
                                let hedge_fut = send_once(
                                    hedge_backend,
                                    hedge_request,
                                    Arc::clone(&cb),
                                    Arc::clone(&transport),
                                );
                                tokio::pin!(hedge_fut);
                                tokio::select! {
                                    result = &mut primary_fut => {
                                        hedge_telemetry.primary_won_after_trigger = true;
                                        hedge_telemetry.hedge_wasted = true;
                                        result?
                                    },
                                    result = &mut hedge_fut => {
                                        hedge_telemetry.hedge_won = true;
                                        let elapsed_ms = primary_started.elapsed().as_millis() as u64;
                                        let delay_ms = hedge_delay.as_millis() as u64;
                                        hedge_telemetry.primary_late_ms = elapsed_ms.saturating_sub(delay_ms);
                                        result?
                                    },
                                }
                            } else {
                                primary_fut.await?
                            }
                        } else {
                            send_once(
                                fwd_addr.clone(),
                                request,
                                Arc::clone(&cb),
                                Arc::clone(&transport),
                            )
                            .await?
                        }
                    } else {
                        match send_once(
                            fwd_addr.clone(),
                            request,
                            Arc::clone(&cb),
                            Arc::clone(&transport),
                        )
                        .await
                        {
                            Ok(response) => response,
                            Err(primary_err) => {
                                let retry_reason = classify_retry_reason(&primary_err);
                                let is_retryable_err = is_retryable(&primary_err);
                                let budget_ok = retry_budget.allow_retry(&route_name).is_ok();
                                let can_retry = bodyless_mode
                                    && is_retryable_err
                                    && budget_ok
                                    && alternate_backend.is_some();
                                if !can_retry {
                                    if !bodyless_mode {
                                        retry_denial_reason = Some(RetryReason::NotBodylessMode);
                                    } else if !is_retryable_err {
                                        retry_denial_reason = None;
                                    } else if !budget_ok {
                                        retry_denial_reason = Some(RetryReason::BudgetDenied);
                                    } else {
                                        retry_denial_reason = Some(RetryReason::NoAlternateBackend);
                                    }
                                    return Err(primary_err);
                                }
                                if let Some((retry_backend, _)) = alternate_backend.clone()
                                    && let Some(endpoint) = backend_endpoints.get(&retry_backend)
                                    && let Ok(retry_request) =
                                        pending_forward_for_upstream.build_bodyless_request(endpoint)
                                {
                                    retry_count = retry_count.saturating_add(1);
                                    retry_attempt_reason = Some(retry_reason);
                                    info!(
                                        "request_id={} retrying request on alternate backend: route={} reason={:?}",
                                        request_id, route_name, retry_reason
                                    );
                                    send_once(
                                        retry_backend,
                                        retry_request,
                                        Arc::clone(&cb),
                                        Arc::clone(&transport),
                                    )
                                    .await?
                                } else {
                                    return Err(primary_err);
                                }
                            }
                        }
                    };

                    let (parts, body) = response.into_parts();
                    ForwardSuccess::Response {
                        status: parts.status,
                        headers: parts.headers,
                        body,
                    }
                };
                Ok(forward_success)
            }
            .await;
            let _ = result_tx.send(UpstreamResult {
                forward: result,
                hedge: hedge_telemetry,
                retry_count,
                retry_attempt_reason,
                retry_denial_reason,
            });
        };
        let spawned = match trace_span_for_upstream {
            Some(span) => spawn_async_task(fut.instrument(span), "upstream"),
            None => spawn_async_task(fut, "upstream"),
        };
        if !spawned {
            return Err(ProxyError::Transport(
                "dropping upstream task: no runtime available".into(),
            ));
        }
        Ok(result_rx)
    }

    fn materialize_forward_after_auth(
        stream_id: u64,
        req: &mut RequestEnvelope,
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        transport_pool: Arc<UpstreamTransportPool>,
        backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
        backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
        upstream_inflight: &HashMap<String, Arc<Semaphore>>,
        global_inflight: Arc<Semaphore>,
        backend_timeout: Duration,
        resilience: &RuntimeResilience,
        metrics: Arc<Metrics>,
        inflight_acquire_wait: Duration,
    ) -> Result<bool, quiche::h3::Error> {
        let Some(pending_forward) = req.pending_forward.as_ref().cloned() else {
            metrics.inc_failure();
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                b"missing deferred forward snapshot\n",
            )?;
            return Ok(false);
        };
        let Some(upstream_name) = req.upstream_name.clone() else {
            metrics.inc_failure();
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                b"missing upstream route\n",
            )?;
            return Ok(false);
        };
        let header_lookup = |name: &str| {
            pending_forward
                .headers
                .iter()
                .find(|header| header.name().eq_ignore_ascii_case(name.as_bytes()))
                .and_then(|header| std::str::from_utf8(header.value()).ok())
                .map(str::to_string)
        };

        resilience
            .brownout
            .observe_admission_pressure(resilience.adaptive_admission.inflight_percent());
        metrics.set_brownout_active(resilience.brownout.is_active());
        if !resilience.brownout.route_allowed(&upstream_name) {
            metrics.inc_failure();
            metrics.inc_overload_shed_reason(OverloadShedReason::Brownout);
            metrics.record_route(
                &upstream_name,
                req.start.elapsed(),
                RouteOutcome::OverloadShed,
            );
            Self::send_overload_response(
                h3,
                quic,
                stream_id,
                b"brownout active, non-core route shed\n",
                resilience.shed_retry_after_seconds,
            )?;
            resilience
                .adaptive_admission
                .observe(req.start.elapsed(), true);
            return Ok(false);
        }

        if let Some(rejection) = resilience.scoped_rate_limits.check(&upstream_name, |rule| {
            Self::resolve_scoped_rate_limit_key(
                rule,
                &upstream_name,
                &req.method,
                &req.path,
                req.authority.as_deref(),
                pending_forward.client_addr,
                Some(&header_lookup),
            )
        }) {
            metrics.inc_failure();
            metrics.inc_request_rate_limited();
            metrics.record_route(
                &upstream_name,
                req.start.elapsed(),
                RouteOutcome::RateLimited,
            );
            warn!(
                "request_id={} route={} scoped rate limit exceeded by rule={}",
                req.request_id, rejection.route, rejection.rule_name
            );
            Self::send_rate_limited_response(
                h3,
                quic,
                stream_id,
                b"request rate limited\n",
                rejection.retry_after_seconds,
            )?;
            return Ok(false);
        }

        let adaptive_permit = match resilience.adaptive_admission.try_acquire() {
            Some(permit) => permit,
            None => {
                metrics.inc_failure();
                metrics.inc_overload_shed_reason(OverloadShedReason::AdaptiveAdmission);
                metrics.record_route(
                    &upstream_name,
                    req.start.elapsed(),
                    RouteOutcome::OverloadShed,
                );
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    b"adaptive admission overload\n",
                    resilience.shed_retry_after_seconds,
                )?;
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                return Ok(false);
            }
        };

        let route_queue_permit = match resilience.route_queue.try_acquire(&upstream_name) {
            Ok(permit) => permit,
            Err(RouteQueueRejection::RouteCap) => {
                metrics.inc_failure();
                metrics.inc_overload_shed_reason(OverloadShedReason::RouteCap);
                metrics.record_route(
                    &upstream_name,
                    req.start.elapsed(),
                    RouteOutcome::OverloadShed,
                );
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    b"route queue cap exceeded\n",
                    resilience.shed_retry_after_seconds,
                )?;
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                return Ok(false);
            }
            Err(RouteQueueRejection::GlobalCap) => {
                metrics.inc_failure();
                metrics.inc_overload_shed_reason(OverloadShedReason::RouteGlobalCap);
                metrics.record_route(
                    &upstream_name,
                    req.start.elapsed(),
                    RouteOutcome::OverloadShed,
                );
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    b"global queue cap exceeded\n",
                    resilience.shed_retry_after_seconds,
                )?;
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                return Ok(false);
            }
        };

        let global_permit = match Self::try_acquire_owned_with_micro_wait(
            Arc::clone(&global_inflight),
            inflight_acquire_wait,
        ) {
            Ok((permit, waited)) => {
                if waited {
                    metrics.inc_inflight_wait_admit_global();
                }
                permit
            }
            Err(_) => {
                drop(route_queue_permit);
                drop(adaptive_permit);
                metrics.inc_failure();
                metrics.inc_overload_shed_reason(OverloadShedReason::GlobalInflight);
                metrics.record_route(
                    &upstream_name,
                    req.start.elapsed(),
                    RouteOutcome::OverloadShed,
                );
                Self::send_overload_response(
                    h3,
                    quic,
                    stream_id,
                    b"overloaded, retry later\n",
                    resilience.shed_retry_after_seconds,
                )?;
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                return Ok(false);
            }
        };

        let upstream_permit = match upstream_inflight.get(&upstream_name).cloned() {
            Some(semaphore) => {
                match Self::try_acquire_owned_with_micro_wait(semaphore, inflight_acquire_wait) {
                    Ok((permit, waited)) => {
                        if waited {
                            metrics.inc_inflight_wait_admit_upstream();
                        }
                        permit
                    }
                    Err(_) => {
                        drop(global_permit);
                        drop(route_queue_permit);
                        drop(adaptive_permit);
                        metrics.inc_failure();
                        metrics.inc_overload_shed_reason(OverloadShedReason::UpstreamInflight);
                        metrics.record_route(
                            &upstream_name,
                            req.start.elapsed(),
                            RouteOutcome::OverloadShed,
                        );
                        Self::send_overload_response(
                            h3,
                            quic,
                            stream_id,
                            b"upstream overloaded, retry later\n",
                            resilience.shed_retry_after_seconds,
                        )?;
                        resilience
                            .adaptive_admission
                            .observe(req.start.elapsed(), true);
                        return Ok(false);
                    }
                }
            }
            None => {
                drop(global_permit);
                drop(route_queue_permit);
                drop(adaptive_permit);
                metrics.inc_failure();
                metrics.inc_overload_shed_reason(OverloadShedReason::UpstreamInflight);
                metrics.record_route(
                    &upstream_name,
                    req.start.elapsed(),
                    RouteOutcome::OverloadShed,
                );
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    b"upstream admission limiter unavailable\n",
                )?;
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                return Ok(false);
            }
        };

        let backend_index = req.backend_index.unwrap_or(pending_forward.backend_index);
        let Some(upstream_pool) = req.upstream_pool.as_ref().cloned() else {
            drop(upstream_permit);
            drop(global_permit);
            drop(route_queue_permit);
            drop(adaptive_permit);
            metrics.inc_failure();
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                b"missing upstream pool\n",
            )?;
            return Ok(false);
        };
        let request_started = upstream_pool
            .read()
            .ok()
            .is_some_and(|pool| pool.begin_request_if_healthy(backend_index));
        if !request_started {
            drop(upstream_permit);
            drop(global_permit);
            drop(route_queue_permit);
            drop(adaptive_permit);
            metrics.inc_failure();
            metrics.record_route(&upstream_name, req.start.elapsed(), RouteOutcome::Failure);
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::SERVICE_UNAVAILABLE,
                b"selected backend no longer healthy\n",
            )?;
            return Ok(false);
        }

        let backend_addr = pending_forward.backend_addr.to_string();
        let Some(backend_endpoint) = backend_endpoints.get(&backend_addr).cloned() else {
            if let Ok(mut guard) = upstream_pool.write() {
                guard.finish_request(backend_index, req.start.elapsed(), Some(503));
            }
            drop(upstream_permit);
            drop(global_permit);
            drop(route_queue_permit);
            drop(adaptive_permit);
            metrics.inc_failure();
            metrics.record_route(&upstream_name, req.start.elapsed(), RouteOutcome::Failure);
            Self::send_simple_response(
                h3,
                quic,
                stream_id,
                http::StatusCode::BAD_GATEWAY,
                b"unknown backend endpoint\n",
            )?;
            return Ok(false);
        };

        let websocket_h1_tunnel = req.tunnel_mode == TunnelMode::Websocket
            && backend_endpoint.scheme() == BackendScheme::Http;
        let (body_tx, websocket_tunnel_body_rx, request_body) = if req.bodyless_mode {
            (None, None, Some(BoxBody::new(Full::new(Bytes::new()))))
        } else if websocket_h1_tunnel {
            let (tx, rx) = mpsc::channel::<Bytes>(REQUEST_CHUNK_CHANNEL_CAPACITY);
            (Some(tx), Some(rx), None)
        } else {
            let (tx, channel_body) = ChannelBody::channel(REQUEST_CHUNK_CHANNEL_CAPACITY);
            (Some(tx), None, Some(channel_body.boxed()))
        };

        let request = if websocket_h1_tunnel {
            None
        } else {
            match pending_forward.build_request(
                &backend_endpoint,
                request_body
                    .expect("request body must exist for non-websocket auth materialization"),
                None,
            ) {
                Ok(request) => Some(request),
                Err(err) => {
                    if let Ok(mut guard) = upstream_pool.write() {
                        guard.finish_request(backend_index, req.start.elapsed(), Some(503));
                    }
                    metrics.inc_failure();
                    metrics.record_route(
                        &upstream_name,
                        req.start.elapsed(),
                        RouteOutcome::Failure,
                    );
                    Self::send_simple_response(
                        h3,
                        quic,
                        stream_id,
                        http::StatusCode::BAD_REQUEST,
                        b"invalid request
",
                    )?;
                    error!("failed to build upstream request after auth: {}", err);
                    resilience
                        .adaptive_admission
                        .observe(req.start.elapsed(), true);
                    return Ok(false);
                }
            }
        };

        let result_rx = match Self::spawn_upstream_forward_task(
            req,
            Arc::clone(&pending_forward),
            backend_endpoint,
            request,
            websocket_tunnel_body_rx,
            transport_pool,
            backend_endpoints,
            backend_resolution_store,
            backend_timeout,
            Arc::clone(&metrics),
            resilience,
        ) {
            Ok(result_rx) => result_rx,
            Err(err) => {
                if let Ok(mut guard) = upstream_pool.write() {
                    guard.finish_request(backend_index, req.start.elapsed(), Some(503));
                }
                metrics.inc_failure();
                metrics.record_route(&upstream_name, req.start.elapsed(), RouteOutcome::Failure);
                Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    b"upstream runtime unavailable
",
                )?;
                error!("failed to spawn upstream task after auth: {}", err);
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                return Ok(false);
            }
        };

        req.backend_request_started = true;
        req.backend_request_finished = false;
        req.body_tx = body_tx;
        req.upstream_result_rx = Some(result_rx);
        req.global_inflight_permit = Some(global_permit);
        req.upstream_inflight_permit = Some(upstream_permit);
        req.adaptive_admission_permit = Some(adaptive_permit);
        req.route_queue_permit = Some(route_queue_permit);
        req.admission_state = StreamAdmissionState::ReadyToForward;
        req.phase = if req.request_fin_received {
            StreamPhase::AwaitingUpstream
        } else {
            StreamPhase::ReceivingRequest
        };
        Self::flush_request_buffer(req, &metrics);
        if req.request_fin_received && req.body_buf.is_empty() {
            req.body_tx = None;
            req.phase = StreamPhase::AwaitingUpstream;
        }
        Ok(true)
    }

    fn complete_auth_result(
        stream_id: u64,
        req: &mut RequestEnvelope,
        result: ExternalAuthResult,
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        transport_pool: Arc<UpstreamTransportPool>,
        backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
        backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
        upstream_inflight: &HashMap<String, Arc<Semaphore>>,
        global_inflight: Arc<Semaphore>,
        backend_timeout: Duration,
        resilience: &RuntimeResilience,
        metrics: Arc<Metrics>,
        inflight_acquire_wait: Duration,
    ) -> Result<bool, quiche::h3::Error> {
        req.auth_result_rx = None;
        req.auth_deadline = None;
        match result {
            Ok(ExternalAuthDecision::Allow {
                request_header_mutations,
            }) => {
                metrics.inc_external_auth_allowed();
                if let Some(pending_forward) = req.pending_forward.as_mut() {
                    Arc::make_mut(pending_forward)
                        .auth_header_mutations
                        .extend(request_header_mutations);
                }
                Self::materialize_forward_after_auth(
                    stream_id,
                    req,
                    h3,
                    quic,
                    transport_pool,
                    backend_endpoints,
                    backend_resolution_store,
                    upstream_inflight,
                    global_inflight,
                    backend_timeout,
                    resilience,
                    metrics,
                    inflight_acquire_wait,
                )
            }
            Ok(decision) => {
                req.admission_state = StreamAdmissionState::Denied;
                req.response_status = match &decision {
                    ExternalAuthDecision::Deny(response) => Some(response.status.as_u16()),
                    ExternalAuthDecision::Redirect(response) => Some(response.status.as_u16()),
                    ExternalAuthDecision::Challenge(response) => Some(response.status.as_u16()),
                    ExternalAuthDecision::Allow { .. } => None,
                };
                metrics.inc_failure();
                metrics.inc_policy_denied();
                metrics.inc_external_auth_denied();
                metrics.record_route(
                    req.upstream_name.as_deref().unwrap_or("unrouted"),
                    req.start.elapsed(),
                    RouteOutcome::Failure,
                );
                warn!(
                    "request_id={} route={} external auth denied with status={}",
                    req.request_id,
                    req.upstream_name.as_deref().unwrap_or("unrouted"),
                    req.response_status.unwrap_or(0)
                );
                Self::send_external_auth_decision_response(h3, quic, stream_id, &decision)?;
                Ok(false)
            }
            Err(err) if req.auth_fail_open => {
                match &err {
                    ProxyError::Timeout => metrics.inc_external_auth_timeout(),
                    _ => metrics.inc_external_auth_error(),
                }
                warn!(
                    "request_id={} route={} external auth failed open: {:?}",
                    req.request_id,
                    req.upstream_name.as_deref().unwrap_or("unrouted"),
                    err
                );
                Self::materialize_forward_after_auth(
                    stream_id,
                    req,
                    h3,
                    quic,
                    transport_pool,
                    backend_endpoints,
                    backend_resolution_store,
                    upstream_inflight,
                    global_inflight,
                    backend_timeout,
                    resilience,
                    metrics,
                    inflight_acquire_wait,
                )
            }
            Err(err) => {
                metrics.inc_failure();
                let route_label = req.upstream_name.as_deref().unwrap_or("unrouted");
                let (status, body, outcome) = match err {
                    ProxyError::Timeout => {
                        metrics.inc_external_auth_timeout();
                        (
                            http::StatusCode::GATEWAY_TIMEOUT,
                            b"external auth timeout\n".as_slice(),
                            RouteOutcome::Timeout,
                        )
                    }
                    _ => {
                        metrics.inc_external_auth_error();
                        (
                            http::StatusCode::SERVICE_UNAVAILABLE,
                            b"external auth unavailable\n".as_slice(),
                            RouteOutcome::Failure,
                        )
                    }
                };
                req.admission_state = StreamAdmissionState::Denied;
                req.response_status = Some(status.as_u16());
                metrics.record_route(route_label, req.start.elapsed(), outcome);
                Self::send_simple_response(h3, quic, stream_id, status, body)?;
                Ok(false)
            }
        }
    }

    pub(super) fn flush_send(
        socket: &UdpSocket,
        send_buf: &mut [u8],
        connection: &mut QuicConnection,
    ) {
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

    pub(super) fn log_health_transition(addr: &str, transition: HealthTransition) {
        match transition {
            HealthTransition::BecameHealthy => {
                info!("Backend {} became healthy", addr);
            }
            HealthTransition::BecameUnhealthy => {
                error!("Backend {} became unhealthy", addr);
            }
        }
    }
}

impl QUICListener {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_h3(
        connection: &mut QuicConnection,
        transport_pool: Arc<UpstreamTransportPool>,
        backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
        backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
        upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        upstream_inflight: &HashMap<String, Arc<Semaphore>>,
        global_inflight: Arc<Semaphore>,
        backend_timeout: Duration,
        backend_body_idle_timeout: Duration,
        backend_body_total_timeout: Duration,
        backend_total_request_timeout: Duration,
        routing_index: &RouteIndex,
        metrics: Arc<Metrics>,
        resilience: &RuntimeResilience,
        max_request_body_bytes: usize,
        max_response_body_bytes: usize,
        request_buffer_global_cap_bytes: usize,
        unknown_length_response_prebuffer_bytes: usize,
        client_body_idle_timeout: Duration,
        inflight_acquire_wait: Duration,
        tracing_enabled: bool,
        routing_transparency_enabled: bool,
        routing_transparency_include_reason: bool,
        listen_port: u16,
        max_streams_per_connection: usize,
    ) -> Result<(), quiche::h3::Error> {
        let mut body_buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];

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
                    let request = match validate_request_headers(&list, resilience) {
                        Ok(request) => request,
                        Err((status, body, is_policy)) => {
                            metrics.inc_failure();
                            metrics.inc_request_validation_reject();
                            if is_policy {
                                metrics.inc_policy_denied();
                            }
                            metrics.record_route(
                                "unrouted",
                                Duration::from_millis(0),
                                RouteOutcome::Failure,
                            );
                            let _ = Self::send_simple_response(
                                h3,
                                &mut connection.quic,
                                stream_id,
                                status,
                                body,
                            );
                            continue;
                        }
                    };
                    let method = request.method;
                    let path = request.path;
                    let authority = request.authority;
                    let content_length = request.content_length;
                    let websocket_tunnel = request.websocket_tunnel;
                    let tunnel_mode = if websocket_tunnel {
                        TunnelMode::Websocket
                    } else if is_connect_method(&method) {
                        TunnelMode::Connect
                    } else {
                        TunnelMode::None
                    };

                    metrics.inc_total();
                    let request_start = Instant::now();

                    if connection.quic.is_in_early_data() {
                        if resilience.early_data_allowed_for(&method) {
                            metrics.inc_early_data_accepted();
                        } else {
                            metrics.inc_failure();
                            metrics.inc_early_data_rejected();
                            metrics.inc_policy_denied();
                            metrics.record_route(
                                "unrouted",
                                request_start.elapsed(),
                                RouteOutcome::Failure,
                            );
                            Self::send_simple_response(
                                h3,
                                &mut connection.quic,
                                stream_id,
                                http::StatusCode::TOO_EARLY,
                                b"request blocked by early-data policy\n",
                            )?;
                            continue;
                        }
                    }

                    // Route lookup now only selects an upstream/backend; actual
                    // backend/inflight admission is deferred until local auth
                    // succeeds immediately or async external auth completes.
                    let sticky_cid_key = hex::encode(connection.primary_scid.as_ref());
                    let lb_header_lookup = |name: &str| {
                        list.iter()
                            .find(|header| header.name().eq_ignore_ascii_case(name.as_bytes()))
                            .and_then(|header| std::str::from_utf8(header.value()).ok())
                            .map(str::to_string)
                    };
                    let route_method = if websocket_tunnel { "GET" } else { &method };
                    let resolved = Self::resolve_backend_without_inflight(
                        route_method,
                        &path,
                        authority.as_deref(),
                        Some(sticky_cid_key.as_str()),
                        upstream_pools,
                        routing_index,
                        Some(&lb_header_lookup),
                    );

                    let (
                        upstream_name,
                        backend_addr,
                        backend_index,
                        upstream_pool,
                        backend_lb,
                        route_path_len,
                        route_host_specific,
                        route_reason,
                        request_id,
                        trace_id,
                        span_id,
                        traceparent,
                        trace_span,
                        bodyless_mode,
                        request_fin_received,
                        pending_forward,
                        auth_start,
                        auth_requested,
                        auth_fail_open,
                    ) = match resolved {
                        Ok(ResolvedBackend {
                            upstream_name,
                            backend_addr,
                            backend_index,
                            upstream_pool,
                            backend_lb,
                            route_path_len,
                            route_host_specific,
                            route_reason,
                        }) => {
                            let upstream_policy = upstream_policies
                                .get(&upstream_name)
                                .cloned()
                                .unwrap_or_default();
                            let denied_challenge = if !Self::api_key_is_authorized(
                                &upstream_policy,
                                Some(&lb_header_lookup),
                            ) {
                                Some(b"ApiKey".as_slice())
                            } else if !Self::jwt_is_authorized(
                                &upstream_policy,
                                Some(&lb_header_lookup),
                            ) {
                                Some(b"Bearer".as_slice())
                            } else {
                                None
                            };
                            if let Some(challenge) = denied_challenge {
                                metrics.inc_failure();
                                metrics.inc_policy_denied();
                                metrics.record_route(
                                    &upstream_name,
                                    request_start.elapsed(),
                                    RouteOutcome::Failure,
                                );
                                warn!(
                                    "request_id=unassigned route={} denied by local auth policy",
                                    upstream_name
                                );
                                Self::send_unauthorized_response(
                                    h3,
                                    &mut connection.quic,
                                    stream_id,
                                    b"unauthorized\n",
                                    challenge,
                                )?;
                                continue;
                            }

                            let request_id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
                            let incoming_traceparent = extract_header_value(&list, b"traceparent")
                                .and_then(parse_traceparent);
                            let trace_id = incoming_traceparent
                                .as_ref()
                                .map(|(trace_id, _)| trace_id.clone())
                                .or_else(|| {
                                    tracing_enabled.then(|| {
                                        generated_trace_id(connection.quic.trace_id(), request_id)
                                    })
                                });
                            let span_id = trace_id.as_ref().map(|_| generated_span_id(request_id));
                            let traceparent = trace_id
                                .as_ref()
                                .zip(span_id.as_ref())
                                .map(|(trace_id, span_id)| format!("00-{trace_id}-{span_id}-01"));
                            let trace_span = trace_id.as_ref().zip(span_id.as_ref()).map(
                                |(trace_id, span_id)| {
                                    info_span!(
                                        "spooky.request",
                                        request_id = request_id,
                                        trace_id = %trace_id,
                                        span_id = %span_id,
                                        method = %method,
                                        path = %path
                                    )
                                },
                            );
                            let bodyless_mode = !is_tunnel_mode(tunnel_mode)
                                && is_bodyless_request_mode(&method, content_length);
                            let request_fin_received = bodyless_mode;
                            let pending_forward = Arc::new(PendingForward {
                                method: Arc::<str>::from(method.as_str()),
                                path: Arc::<str>::from(path.as_str()),
                                authority: authority.as_deref().map(Arc::<str>::from),
                                headers: Arc::new(list.clone()),
                                upstream_name: Arc::<str>::from(upstream_name.as_str()),
                                route_reason: Arc::<str>::from(format!("{route_reason:?}")),
                                route_path_len,
                                route_host_specific,
                                backend_addr: Arc::<str>::from(backend_addr.as_str()),
                                backend_index,
                                backend_lb: Some(Arc::<str>::from(backend_lb.as_str())),
                                client_addr: connection.peer_address,
                                request_id,
                                trace_id: trace_id.as_deref().map(Arc::<str>::from),
                                span_id: span_id.as_deref().map(Arc::<str>::from),
                                traceparent: traceparent.as_deref().map(Arc::<str>::from),
                                host_policy: upstream_policy.host.0.clone(),
                                forwarded_header_policy: upstream_policy
                                    .forwarded_headers
                                    .0
                                    .clone(),
                                auth_header_mutations: Vec::new(),
                            });

                            let external_auth = upstream_policy.upstream_auth.external_auth.clone();
                            let auth_fail_open = external_auth
                                .as_ref()
                                .map(|auth| fail_open(auth_failure_mode(auth)))
                                .unwrap_or(false);
                            let auth_start = if let Some(external_auth) = external_auth.clone() {
                                match start_external_auth_task(
                                    Arc::clone(&pending_forward),
                                    external_auth,
                                ) {
                                    Ok(start) => Some(start),
                                    Err(err) if auth_fail_open => {
                                        warn!(
                                            "request_id={} route={} external auth startup failed open: {:?}",
                                            request_id, upstream_name, err
                                        );
                                        None
                                    }
                                    Err(err) => {
                                        metrics.inc_failure();
                                        metrics.record_route(
                                            &upstream_name,
                                            request_start.elapsed(),
                                            RouteOutcome::Failure,
                                        );
                                        error!(
                                            "request_id={} route={} external auth startup failed: {:?}",
                                            request_id, upstream_name, err
                                        );
                                        Self::send_simple_response(
                                            h3,
                                            &mut connection.quic,
                                            stream_id,
                                            http::StatusCode::SERVICE_UNAVAILABLE,
                                            b"external auth unavailable\n",
                                        )?;
                                        continue;
                                    }
                                }
                            } else {
                                None
                            };
                            let auth_requested = external_auth.is_some() && auth_start.is_some();

                            (
                                upstream_name,
                                backend_addr,
                                backend_index,
                                upstream_pool,
                                backend_lb,
                                route_path_len,
                                route_host_specific,
                                format!("{route_reason:?}"),
                                request_id,
                                trace_id,
                                span_id,
                                traceparent,
                                trace_span,
                                bodyless_mode,
                                request_fin_received,
                                pending_forward,
                                auth_start,
                                auth_requested,
                                auth_fail_open,
                            )
                        }
                        Err(err) => {
                            metrics.inc_failure();
                            metrics.record_route(
                                "unrouted",
                                request_start.elapsed(),
                                RouteOutcome::Failure,
                            );
                            let (status, body): (http::StatusCode, &[u8]) = match err {
                                ProxyError::Transport(_) => (
                                    http::StatusCode::SERVICE_UNAVAILABLE,
                                    b"no upstream available\n",
                                ),
                                ProxyError::Bridge(_) => {
                                    (http::StatusCode::BAD_REQUEST, b"invalid request\n")
                                }
                                _ => (
                                    http::StatusCode::INTERNAL_SERVER_ERROR,
                                    b"internal proxy error\n",
                                ),
                            };
                            Self::send_simple_response(
                                h3,
                                &mut connection.quic,
                                stream_id,
                                status,
                                body,
                            )?;
                            resilience
                                .adaptive_admission
                                .observe(request_start.elapsed(), true);
                            continue;
                        }
                    };

                    // App-level stream count cap: mirrors the QUIC max_streams_bidi
                    // limit so the streams HashMap can never grow beyond what the
                    // transport layer allows even if a race or misconfiguration
                    // delivers a stream-open event before the flow-control frame
                    // reaches the client.
                    if connection.streams.len() >= max_streams_per_connection {
                        warn!(
                            "stream limit reached ({} streams), rejecting stream {}",
                            max_streams_per_connection, stream_id
                        );
                        Self::send_simple_response(
                            h3,
                            &mut connection.quic,
                            stream_id,
                            http::StatusCode::SERVICE_UNAVAILABLE,
                            b"too many concurrent streams\n",
                        )?;
                        continue;
                    }

                    let (auth_result_rx, auth_deadline, auth_fail_open, admission_state) =
                        match auth_start {
                            Some(start) => (
                                Some(start.rx),
                                Some(start.deadline),
                                start.fail_open,
                                StreamAdmissionState::WaitingForAuth,
                            ),
                            None => (
                                None,
                                None,
                                auth_fail_open,
                                StreamAdmissionState::ReadyToForward,
                            ),
                        };
                    connection.streams.insert(
                        stream_id,
                        RequestEnvelope {
                            request_id,
                            trace_id,
                            span_id,
                            traceparent,
                            trace_span,
                            method,
                            path,
                            authority,
                            body_tx: None,
                            body_buf: std::collections::VecDeque::new(),
                            body_buf_bytes: 0,
                            body_bytes_received: 0,
                            last_body_activity: request_start,
                            backend_addr: Some(backend_addr),
                            backend_index: Some(backend_index),
                            upstream_name: Some(upstream_name),
                            route_reason: Some(route_reason),
                            route_path_len: Some(route_path_len),
                            route_host_specific: Some(route_host_specific),
                            backend_lb: Some(backend_lb),
                            upstream_pool: Some(upstream_pool),
                            routing_transparency_enabled,
                            routing_transparency_include_reason,
                            response_status: None,
                            backend_request_started: false,
                            backend_request_finished: false,
                            global_inflight_permit: None,
                            upstream_inflight_permit: None,
                            adaptive_admission_permit: None,
                            route_queue_permit: None,
                            start: request_start,
                            total_request_deadline: request_start + backend_total_request_timeout,
                            bodyless_mode,
                            tunnel_mode,
                            retry_count: 0,
                            error_kind: None,
                            pending_forward: Some(pending_forward),
                            auth_result_rx,
                            auth_fail_open,
                            auth_deadline,
                            phase: StreamPhase::ReceivingRequest,
                            admission_state,
                            request_fin_received,
                            upstream_result_rx: None,
                            response_chunk_rx: None,
                            response_headers_sent: false,
                            pending_chunk: None,
                        },
                    );
                    if !auth_requested {
                        let keep_stream = if let Some(req) = connection.streams.get_mut(&stream_id)
                        {
                            Self::materialize_forward_after_auth(
                                stream_id,
                                req,
                                h3,
                                &mut connection.quic,
                                Arc::clone(&transport_pool),
                                Arc::clone(&backend_endpoints),
                                Arc::clone(&backend_resolution_store),
                                upstream_inflight,
                                Arc::clone(&global_inflight),
                                backend_timeout,
                                resilience,
                                Arc::clone(&metrics),
                                inflight_acquire_wait,
                            )?
                        } else {
                            false
                        };
                        if !keep_stream {
                            if let Some(req) = connection.streams.get_mut(&stream_id) {
                                abort_stream(req, &metrics);
                            }
                            connection.streams.remove(&stream_id);
                            continue;
                        }
                    }
                    if let Some(req) = connection.streams.get(&stream_id) {
                        debug!(
                            "request_id={} method={} path={} stream_id={}",
                            req.request_id, req.method, req.path, stream_id
                        );
                    }
                }
                Ok((stream_id, quiche::h3::Event::Data)) => loop {
                    match h3.recv_body(&mut connection.quic, stream_id, &mut body_buf) {
                        Ok(read) => {
                            let mut shed_due_to_buffer_pressure = false;
                            let mut reject_body_for_bodyless = None::<(String, Duration)>;
                            let mut payload_too_large = None::<(String, Duration)>;
                            if let Some(req) = connection.streams.get_mut(&stream_id) {
                                if read > 0 {
                                    req.last_body_activity = Instant::now();
                                }
                                if req.bodyless_mode && read > 0 {
                                    reject_body_for_bodyless = Some((
                                        req.upstream_name
                                            .clone()
                                            .unwrap_or_else(|| "unrouted".to_string()),
                                        req.start.elapsed(),
                                    ));
                                }
                                if reject_body_for_bodyless.is_none() {
                                    // Enforce cap on total bytes received for the stream,
                                    // including chunks already forwarded to the H2 body channel.
                                    let next_total = req.body_bytes_received.saturating_add(read);
                                    let request_is_connect = is_connect_method(&req.method);
                                    if !request_is_connect && next_total > max_request_body_bytes {
                                        payload_too_large = Some((
                                            req.upstream_name
                                                .clone()
                                                .unwrap_or_else(|| "unrouted".to_string()),
                                            req.start.elapsed(),
                                        ));
                                    } else {
                                        req.body_bytes_received = next_total;

                                        for chunk_slice in
                                            body_buf[..read].chunks(REQUEST_CHUNK_BYTES_LIMIT)
                                        {
                                            let chunk = Bytes::copy_from_slice(chunk_slice);
                                            if let Err(err) = Self::enqueue_request_chunk(
                                                req,
                                                chunk,
                                                &metrics,
                                                max_request_body_bytes,
                                                request_buffer_global_cap_bytes,
                                            ) {
                                                shed_due_to_buffer_pressure = true;
                                                metrics.inc_request_buffer_limit_reject();
                                                if err == RequestBufferError::GlobalCap {
                                                    debug!("global request buffer cap reached");
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some((route_label, elapsed)) = reject_body_for_bodyless {
                                metrics.inc_failure();
                                metrics.record_route(&route_label, elapsed, RouteOutcome::Failure);
                                Self::send_simple_response(
                                    h3,
                                    &mut connection.quic,
                                    stream_id,
                                    http::StatusCode::BAD_REQUEST,
                                    b"request body not allowed for this request\n",
                                )?;
                                if let Some(req) = connection.streams.get_mut(&stream_id) {
                                    abort_stream(req, &metrics);
                                }
                                connection.streams.remove(&stream_id);
                                resilience.adaptive_admission.observe(elapsed, true);
                                break;
                            }
                            if let Some((route_label, elapsed)) = payload_too_large {
                                metrics.inc_failure();
                                metrics.record_route(&route_label, elapsed, RouteOutcome::Failure);
                                Self::send_simple_response(
                                    h3,
                                    &mut connection.quic,
                                    stream_id,
                                    http::StatusCode::PAYLOAD_TOO_LARGE,
                                    b"request body too large\n",
                                )?;
                                if let Some(req) = connection.streams.get_mut(&stream_id) {
                                    abort_stream(req, &metrics);
                                }
                                connection.streams.remove(&stream_id);
                                resilience.adaptive_admission.observe(elapsed, true);
                                break;
                            }
                            if shed_due_to_buffer_pressure
                                && let Some(req) = connection.streams.get(&stream_id)
                            {
                                metrics.inc_failure();
                                metrics
                                    .inc_overload_shed_reason(OverloadShedReason::RequestBufferCap);
                                let route_label =
                                    req.upstream_name.as_deref().unwrap_or("unrouted");
                                metrics.record_route(
                                    route_label,
                                    req.start.elapsed(),
                                    RouteOutcome::OverloadShed,
                                );
                                Self::send_overload_response(
                                    h3,
                                    &mut connection.quic,
                                    stream_id,
                                    b"request body backpressure overload\n",
                                    resilience.shed_retry_after_seconds,
                                )?;
                                resilience
                                    .adaptive_admission
                                    .observe(req.start.elapsed(), true);
                                if let Some(req) = connection.streams.get_mut(&stream_id) {
                                    abort_stream(req, &metrics);
                                }
                                connection.streams.remove(&stream_id);
                                break;
                            }
                        }
                        Err(quiche::h3::Error::Done) => break,
                        Err(err) => {
                            let rid = connection.streams.get(&stream_id).map(|r| r.request_id);
                            error!(
                                "request_id={} HTTP/3 recv_body protocol error on stream {}: {:?}",
                                rid.map_or_else(|| "-".to_string(), |id| id.to_string()),
                                stream_id,
                                err
                            );
                            if let Some(req) = connection.streams.get(&stream_id) {
                                metrics.inc_failure();
                                let route_label =
                                    req.upstream_name.as_deref().unwrap_or("unrouted");
                                metrics.record_route(
                                    route_label,
                                    req.start.elapsed(),
                                    RouteOutcome::Failure,
                                );
                                resilience
                                    .adaptive_admission
                                    .observe(req.start.elapsed(), true);
                            }
                            if let Some(req) = connection.streams.get_mut(&stream_id) {
                                abort_stream(req, &metrics);
                            }
                            connection.streams.remove(&stream_id);
                            let _ = Self::send_simple_response(
                                h3,
                                &mut connection.quic,
                                stream_id,
                                http::StatusCode::BAD_REQUEST,
                                b"malformed request stream\n",
                            );
                            break;
                        }
                    }
                },
                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    if let Some(req) = connection.streams.get_mut(&stream_id) {
                        req.request_fin_received = true;

                        Self::flush_request_buffer(req, &metrics);
                        // If buffer is now empty, drop body_tx to signal end-of-body.
                        if req.body_buf.is_empty() {
                            req.body_tx = None;
                        }
                        // Only move to AwaitingUpstream once auth has allowed the request
                        // and an upstream task/body channel actually exists.
                        if req.admission_state == StreamAdmissionState::ReadyToForward {
                            req.phase = StreamPhase::AwaitingUpstream;
                        }
                        // Upstream polling and response dispatch are handled entirely
                        // by advance_streams_non_blocking, called unconditionally below.
                    }
                }
                Ok((stream_id, quiche::h3::Event::Reset(error_code))) => {
                    if let Some(req) = connection.streams.get_mut(&stream_id) {
                        let phase = abort_stream(req, &metrics);
                        debug!(
                            "stream {} reset by client (error_code={}, phase={:?}): resources released",
                            stream_id, error_code, phase
                        );
                    }
                    connection.streams.remove(&stream_id);
                }
                Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
                Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(e) => return Err(e),
            }
        }

        Self::advance_streams_non_blocking(
            &mut connection.streams,
            &mut connection.quic,
            h3,
            Arc::clone(&transport_pool),
            Arc::clone(&backend_endpoints),
            Arc::clone(&backend_resolution_store),
            upstream_pools,
            upstream_inflight,
            Arc::clone(&global_inflight),
            backend_timeout,
            routing_index,
            backend_body_idle_timeout,
            backend_body_total_timeout,
            Arc::clone(&metrics),
            backend_total_request_timeout,
            resilience,
            max_response_body_bytes,
            unknown_length_response_prebuffer_bytes,
            client_body_idle_timeout,
            inflight_acquire_wait,
            listen_port,
        )?;

        Ok(())
    }

    /// Advance all in-flight streams without blocking.
    ///
    /// Called after every packet-driven `handle_h3` pass and from
    /// `handle_timeouts` so progress continues even when no new client
    /// packets arrive.
    ///
    /// Per stream, in order:
    /// 1. Drain request body buffer → body channel (`try_send`).
    /// 2. Close body channel once FIN received and buffer empty.
    /// 3. Poll `upstream_result_rx` (`try_recv`).
    ///    - Error result  → send error response, mark terminal.
    ///    - Ok result     → send H3 response headers, spawn body-pump task,
    ///      store `response_chunk_rx`, transition to SendingResponse.
    /// 4. Flush `response_chunk_rx` chunks into H3 (`try_recv` loop).
    ///    - `Data`  → `h3.send_body(..., false)`
    ///    - `Trailers` → `h3.send_additional_headers(..., true, false)`
    ///    - `End`   → `h3.send_body(..., true)`, mark Completed
    ///    - `Error` → send 502, mark Failed
    /// 5. Remove streams in terminal phase (Completed / Failed).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn advance_streams_non_blocking(
        streams: &mut HashMap<u64, RequestEnvelope>,
        quic: &mut quiche::Connection,
        h3: &mut quiche::h3::Connection,
        transport_pool: Arc<UpstreamTransportPool>,
        backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
        backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        upstream_inflight: &HashMap<String, Arc<Semaphore>>,
        global_inflight: Arc<Semaphore>,
        backend_timeout: Duration,
        routing_index: &RouteIndex,
        backend_body_idle_timeout: Duration,
        backend_body_total_timeout: Duration,
        metrics: Arc<Metrics>,
        _backend_total_request_timeout: Duration,
        resilience: &RuntimeResilience,
        max_response_body_bytes: usize,
        unknown_length_response_prebuffer_bytes: usize,
        client_body_idle_timeout: Duration,
        inflight_acquire_wait: Duration,
        listen_port: u16,
    ) -> Result<(), quiche::h3::Error> {
        let stream_ids: Vec<u64> = streams.keys().copied().collect();

        for stream_id in stream_ids {
            if let Some(req) = streams.get(&stream_id)
                && Instant::now() >= req.total_request_deadline
            {
                if let Err(protocol_err) = Self::handle_forward_result(
                    h3,
                    quic,
                    stream_id,
                    req,
                    Err(ProxyError::Timeout),
                    upstream_pools,
                    routing_index,
                    &metrics,
                    resilience.shed_retry_after_seconds,
                ) {
                    error!(
                        "failed to emit timeout response for stream {}: {:?}",
                        stream_id, protocol_err
                    );
                }
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                if let Some(req) = streams.get_mut(&stream_id) {
                    abort_stream(req, &metrics);
                }
                streams.remove(&stream_id);
                continue;
            }

            if let Some(req) = streams.get(&stream_id)
                && req.phase == StreamPhase::ReceivingRequest
                && !req.request_fin_received
                && !req.bodyless_mode
                && Instant::now().saturating_duration_since(req.last_body_activity)
                    >= client_body_idle_timeout
            {
                metrics.inc_failure();
                metrics.inc_timeout();
                let route_label = req.upstream_name.as_deref().unwrap_or("unrouted");
                metrics.record_route(route_label, req.start.elapsed(), RouteOutcome::Timeout);
                let _ = Self::send_simple_response(
                    h3,
                    quic,
                    stream_id,
                    http::StatusCode::REQUEST_TIMEOUT,
                    b"request body idle timeout\n",
                );
                resilience
                    .adaptive_admission
                    .observe(req.start.elapsed(), true);
                if let Some(req) = streams.get_mut(&stream_id) {
                    abort_stream(req, &metrics);
                }
                streams.remove(&stream_id);
                continue;
            }

            // ── 1 & 2: request body drain ────────────────────────────────────
            if let Some(req) = streams.get_mut(&stream_id) {
                Self::flush_request_buffer(req, &metrics);
                if req.request_fin_received && req.body_buf.is_empty() {
                    req.body_tx = None; // signals EOF to the upstream H2 task
                }
            }

            // ── 3: poll external auth first, then upstream oneshot ─────────────
            let auth_ready: Option<ExternalAuthResult> = if streams
                .get(&stream_id)
                .is_some_and(|req| req.admission_state == StreamAdmissionState::WaitingForAuth)
            {
                if streams
                    .get(&stream_id)
                    .and_then(|req| req.auth_deadline)
                    .is_some_and(|deadline| Instant::now() >= deadline)
                {
                    Some(Err(ProxyError::Timeout))
                } else {
                    streams
                        .get_mut(&stream_id)
                        .and_then(|req| req.auth_result_rx.as_mut())
                        .and_then(|rx| match rx.try_recv() {
                            Ok(result) => Some(result),
                            Err(oneshot::error::TryRecvError::Empty) => None,
                            Err(oneshot::error::TryRecvError::Closed) => Some(Err(
                                ProxyError::Transport("external auth task dropped sender".into()),
                            )),
                        })
                }
            } else {
                None
            };

            if let Some(auth_result) = auth_ready {
                let keep_stream = if let Some(req) = streams.get_mut(&stream_id) {
                    Self::complete_auth_result(
                        stream_id,
                        req,
                        auth_result,
                        h3,
                        quic,
                        Arc::clone(&transport_pool),
                        Arc::clone(&backend_endpoints),
                        Arc::clone(&backend_resolution_store),
                        upstream_inflight,
                        Arc::clone(&global_inflight),
                        backend_timeout,
                        resilience,
                        Arc::clone(&metrics),
                        inflight_acquire_wait,
                    )?
                } else {
                    false
                };
                if !keep_stream {
                    if let Some(req) = streams.get_mut(&stream_id) {
                        abort_stream(req, &metrics);
                    }
                    streams.remove(&stream_id);
                    continue;
                }
            }

            let can_poll_upstream = streams
                .get(&stream_id)
                .is_some_and(can_poll_upstream_result);
            let upstream_ready: Option<UpstreamResult> = if can_poll_upstream {
                streams
                    .get_mut(&stream_id)
                    .and_then(|req| req.upstream_result_rx.as_mut())
                    .and_then(|rx| match rx.try_recv() {
                        Ok(result) => Some(result),
                        Err(oneshot::error::TryRecvError::Empty) => None,
                        Err(oneshot::error::TryRecvError::Closed) => Some(UpstreamResult {
                            forward: Err(ProxyError::Transport(
                                "upstream task dropped sender".into(),
                            )),
                            hedge: crate::HedgeTelemetry::default(),
                            retry_count: 0,
                            retry_attempt_reason: None,
                            retry_denial_reason: None,
                        }),
                    })
            } else {
                None
            };

            if let Some(forward_result) = upstream_ready {
                if forward_result.hedge.launched {
                    metrics.inc_hedge_triggered();
                }
                if forward_result.hedge.hedge_won {
                    metrics.inc_hedge_won();
                }
                if forward_result.hedge.hedge_wasted {
                    metrics.inc_hedge_wasted();
                }
                if forward_result.hedge.primary_won_after_trigger {
                    metrics.inc_hedge_primary_won_after_trigger();
                }
                if forward_result.hedge.primary_late_ms > 0 {
                    metrics.observe_hedge_primary_late_ms(forward_result.hedge.primary_late_ms);
                }
                if let Some(reason) = forward_result.retry_attempt_reason {
                    metrics.inc_retry_attempt(reason);
                }
                if let Some(reason) = forward_result.retry_denial_reason {
                    metrics.inc_retry_denied(reason);
                }

                if let Some(req) = streams.get_mut(&stream_id) {
                    req.upstream_result_rx = None;
                    req.retry_count = forward_result.retry_count;
                    req.error_kind = match &forward_result.forward {
                        Err(ProxyError::Timeout) => Some("timeout"),
                        Err(ProxyError::Tls(_)) => Some("tls"),
                        Err(ProxyError::Transport(_)) => Some("transport"),
                        Err(ProxyError::Pool(_)) => Some("pool"),
                        Err(ProxyError::Protocol(_)) => Some("protocol"),
                        Err(ProxyError::Bridge(_)) => Some("bridge"),
                        Ok(_) => None,
                    };
                }
                match forward_result.forward {
                    Ok(success) => {
                        let (status, resp_headers, response_body, prebuilt_response_chunk_rx) =
                            match success {
                                ForwardSuccess::Response {
                                    status,
                                    headers,
                                    body,
                                } => (status, headers, Some(body), None),
                                ForwardSuccess::Tunnel {
                                    status,
                                    headers,
                                    response_chunk_rx,
                                } => (status, headers, None, Some(response_chunk_rx)),
                            };
                        let suppress_downstream_body = streams
                            .get(&stream_id)
                            .is_some_and(|req| is_head_method(&req.method));
                        let tunnel_response = streams
                            .get(&stream_id)
                            .is_some_and(|req| is_tunnel_response(req.tunnel_mode, status));
                        // If upstream advertised a response length beyond our hard cap,
                        // fail fast with 503 before sending any downstream headers/body.
                        let upstream_content_length = resp_headers
                            .get(http::header::CONTENT_LENGTH)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<usize>().ok());
                        if !tunnel_response
                            && !suppress_downstream_body
                            && upstream_content_length
                                .is_some_and(|len| len > max_response_body_bytes)
                        {
                            if let Some(req) = streams.get(&stream_id) {
                                metrics.inc_failure();
                                metrics.inc_overload_shed_reason(
                                    OverloadShedReason::ResponsePrebufferCap,
                                );
                                let route_label =
                                    req.upstream_name.as_deref().unwrap_or("unrouted");
                                metrics.record_route(
                                    route_label,
                                    req.start.elapsed(),
                                    RouteOutcome::OverloadShed,
                                );
                                resilience
                                    .adaptive_admission
                                    .observe(req.start.elapsed(), true);
                                warn!(
                                    "request_id={} upstream declared content-length over cap ({} > {}) on stream {}",
                                    req.request_id,
                                    upstream_content_length.unwrap_or_default(),
                                    max_response_body_bytes,
                                    stream_id
                                );
                                let _ = Self::send_simple_response(
                                    h3,
                                    quic,
                                    stream_id,
                                    http::StatusCode::SERVICE_UNAVAILABLE,
                                    b"upstream response body too large\n",
                                );
                            }
                            if let Some(req) = streams.get_mut(&stream_id) {
                                abort_stream(req, &metrics);
                            }
                            streams.remove(&stream_id);
                            continue;
                        }

                        let mut owned_h3_headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
                        let response_connection_tokens = connection_header_tokens(&resp_headers);
                        for (name, value) in resp_headers.iter() {
                            if should_strip_h3_response_header(name, &response_connection_tokens) {
                                continue;
                            }
                            owned_h3_headers.push((
                                name.as_str().as_bytes().to_vec(),
                                value.as_bytes().to_vec(),
                            ));
                        }
                        owned_h3_headers.push((
                            b"alt-svc".to_vec(),
                            format!("h3=\":{}\"; ma=86400", listen_port).into_bytes(),
                        ));

                        let defer_headers_until_body_validated = upstream_content_length.is_none()
                            && !tunnel_response
                            && !suppress_downstream_body;
                        let immediate_end = suppress_downstream_body
                            || (!tunnel_response
                                && (upstream_content_length == Some(0)
                                    || status == http::StatusCode::NO_CONTENT
                                    || status == http::StatusCode::NOT_MODIFIED));
                        let mut immediate_terminal = false;

                        if !defer_headers_until_body_validated {
                            // For declared-length responses within cap, emit headers immediately
                            // and stream body progressively.
                            let mut h3_headers = Vec::with_capacity(owned_h3_headers.len() + 1);
                            h3_headers.push(quiche::h3::Header::new(
                                b":status",
                                status.as_str().as_bytes(),
                            ));
                            for (name, value) in &owned_h3_headers {
                                h3_headers.push(quiche::h3::Header::new(name, value));
                            }
                            if let Err(err) =
                                h3.send_response(quic, stream_id, &h3_headers, immediate_end)
                            {
                                if let Some(req) = streams.get(&stream_id) {
                                    let protocol = ProxyError::Protocol(format!(
                                        "failed to send HTTP/3 response headers: {:?}",
                                        err
                                    ));
                                    if let Err(protocol_err) = Self::handle_forward_result(
                                        h3,
                                        quic,
                                        stream_id,
                                        req,
                                        Err(protocol),
                                        upstream_pools,
                                        routing_index,
                                        &metrics,
                                        resilience.shed_retry_after_seconds,
                                    ) {
                                        error!(
                                            "failed to emit protocol recovery response on stream {}: {:?}",
                                            stream_id, protocol_err
                                        );
                                    }
                                    resilience
                                        .adaptive_admission
                                        .observe(req.start.elapsed(), true);
                                }
                                if let Some(req) = streams.get_mut(&stream_id) {
                                    abort_stream(req, &metrics);
                                }
                                streams.remove(&stream_id);
                                continue;
                            }
                        }

                        if immediate_end {
                            if defer_headers_until_body_validated {
                                let mut h3_headers = Vec::with_capacity(owned_h3_headers.len() + 1);
                                h3_headers.push(quiche::h3::Header::new(
                                    b":status",
                                    status.as_str().as_bytes(),
                                ));
                                for (name, value) in &owned_h3_headers {
                                    h3_headers.push(quiche::h3::Header::new(name, value));
                                }
                                if let Err(err) =
                                    h3.send_response(quic, stream_id, &h3_headers, true)
                                {
                                    if let Some(req) = streams.get(&stream_id) {
                                        let protocol = ProxyError::Protocol(format!(
                                            "failed to send HTTP/3 response headers: {:?}",
                                            err
                                        ));
                                        if let Err(protocol_err) = Self::handle_forward_result(
                                            h3,
                                            quic,
                                            stream_id,
                                            req,
                                            Err(protocol),
                                            upstream_pools,
                                            routing_index,
                                            &metrics,
                                            resilience.shed_retry_after_seconds,
                                        ) {
                                            error!(
                                                "failed to emit protocol recovery response on stream {}: {:?}",
                                                stream_id, protocol_err
                                            );
                                        }
                                        resilience
                                            .adaptive_admission
                                            .observe(req.start.elapsed(), true);
                                    }
                                    if let Some(req) = streams.get_mut(&stream_id) {
                                        abort_stream(req, &metrics);
                                    }
                                    streams.remove(&stream_id);
                                    continue;
                                }
                            }
                            if let Some(req) = streams.get_mut(&stream_id) {
                                req.response_chunk_rx = None;
                                req.response_headers_sent = true;
                                req.phase = StreamPhase::Completed;
                                req.response_status = Some(status.as_u16());
                            }
                            immediate_terminal = true;
                        } else {
                            // Spawn a task that pumps body frames into a ResponseChunk channel.
                            // Enforces body deadlines and a hard running body-size cap. For
                            // unknown-length responses it additionally prebuffers until size
                            // validation completes before emitting headers.
                            if let Some(chunk_rx) = prebuilt_response_chunk_rx {
                                if let Some(req) = streams.get_mut(&stream_id) {
                                    req.response_chunk_rx = Some(chunk_rx);
                                    req.response_headers_sent = true;
                                    req.phase = StreamPhase::SendingResponse;
                                    req.response_status = Some(status.as_u16());
                                }
                            } else {
                                let (chunk_tx, chunk_rx) =
                                    mpsc::channel::<ResponseChunk>(RESPONSE_CHUNK_CHANNEL_CAPACITY);
                                let fail_tx = chunk_tx.clone();
                                // `backend_body_total_timeout` is used as a pre-first-byte guard:
                                // once the upstream starts making body progress, the idle timeout
                                // governs pacing and the stream may continue until request deadline.
                                let first_byte_deadline =
                                    tokio::time::Instant::now() + backend_body_total_timeout;
                                let deferred_status = status;
                                let deferred_headers = owned_h3_headers.clone();
                                let tunnel_mode = tunnel_response;
                                let fut = async move {
                                    use http_body_util::BodyExt;
                                    let Some(mut body) = response_body else {
                                        let _ = chunk_tx
                                            .send(ResponseChunk::Error(ProxyError::Transport(
                                                "non-tunnel responses must carry an HTTP body stream".into(),
                                            )))
                                            .await;
                                        return;
                                    };
                                    let mut response_bytes_received: usize = 0;
                                    let mut buffered_chunks: Vec<Bytes> = Vec::new();
                                    let mut buffered_trailers: Option<Vec<(Vec<u8>, Vec<u8>)>> =
                                        None;
                                    let mut saw_body_progress = false;
                                    loop {
                                        let frame_fut = BodyExt::frame(&mut body);
                                        let now = tokio::time::Instant::now();
                                        if !saw_body_progress && now >= first_byte_deadline {
                                            let _ = chunk_tx
                                                .send(ResponseChunk::Error(ProxyError::Timeout))
                                                .await;
                                            return;
                                        }
                                        let wait_timeout = if saw_body_progress {
                                            backend_body_idle_timeout
                                        } else {
                                            first_byte_deadline
                                                .saturating_duration_since(now)
                                                .min(backend_body_idle_timeout)
                                        };
                                        let result =
                                            tokio::time::timeout(wait_timeout, frame_fut).await;
                                        match result {
                                            Err(_elapsed) => {
                                                // Body read idle timeout — signal timeout to flush loop.
                                                let _ = chunk_tx
                                                    .send(ResponseChunk::Error(ProxyError::Timeout))
                                                    .await;
                                                return;
                                            }
                                            Ok(Some(Ok(f))) => match f.into_data() {
                                                Ok(data) => {
                                                    if !data.is_empty() {
                                                        saw_body_progress = true;
                                                    }
                                                    if !tunnel_mode
                                                        && response_size_exceeded_after_chunk(
                                                            &mut response_bytes_received,
                                                            data.len(),
                                                            max_response_body_bytes,
                                                        )
                                                    {
                                                        let _ = chunk_tx
                                                        .send(ResponseChunk::Error(ProxyError::Pool(
                                                            PoolError::BackendOverloaded(
                                                                "upstream response body too large"
                                                                    .into(),
                                                            ),
                                                        )))
                                                        .await;
                                                        return;
                                                    }
                                                    if defer_headers_until_body_validated {
                                                        if response_bytes_received
                                                        > unknown_length_response_prebuffer_bytes
                                                    {
                                                        let _ = chunk_tx
                                                            .send(ResponseChunk::Error(ProxyError::Pool(
                                                                PoolError::BackendOverloaded(
                                                                    "unknown-length response prebuffer limit exceeded"
                                                                        .into(),
                                                                ),
                                                            )))
                                                            .await;
                                                        return;
                                                    }
                                                        for start in (0..data.len())
                                                            .step_by(RESPONSE_CHUNK_BYTES_LIMIT)
                                                        {
                                                            let end = (start
                                                                + RESPONSE_CHUNK_BYTES_LIMIT)
                                                                .min(data.len());
                                                            buffered_chunks
                                                                .push(data.slice(start..end));
                                                        }
                                                    } else {
                                                        for start in (0..data.len())
                                                            .step_by(RESPONSE_CHUNK_BYTES_LIMIT)
                                                        {
                                                            let end = (start
                                                                + RESPONSE_CHUNK_BYTES_LIMIT)
                                                                .min(data.len());
                                                            if chunk_tx
                                                                .send(ResponseChunk::Data(
                                                                    data.slice(start..end),
                                                                ))
                                                                .await
                                                                .is_err()
                                                            {
                                                                return;
                                                            }
                                                        }
                                                    }
                                                }
                                                Err(frame) => {
                                                    if let Ok(trailers) = frame.into_trailers() {
                                                        let trailer_headers =
                                                            collect_h3_trailers(&trailers);
                                                        if !trailer_headers.is_empty() {
                                                            if defer_headers_until_body_validated {
                                                                buffered_trailers =
                                                                    Some(trailer_headers);
                                                            } else if chunk_tx
                                                                .send(ResponseChunk::Trailers {
                                                                    headers: trailer_headers,
                                                                })
                                                                .await
                                                                .is_err()
                                                            {
                                                                return;
                                                            }
                                                        }
                                                    }
                                                }
                                            },
                                            Ok(Some(Err(_))) => {
                                                let _ = chunk_tx
                                                    .send(ResponseChunk::Error(
                                                        ProxyError::Transport(
                                                            "upstream body error".into(),
                                                        ),
                                                    ))
                                                    .await;
                                                return;
                                            }
                                            Ok(None) => {
                                                if defer_headers_until_body_validated {
                                                    if chunk_tx
                                                        .send(ResponseChunk::Start {
                                                            status: deferred_status,
                                                            headers: deferred_headers,
                                                        })
                                                        .await
                                                        .is_err()
                                                    {
                                                        return;
                                                    }
                                                    for chunk in buffered_chunks {
                                                        if chunk_tx
                                                            .send(ResponseChunk::Data(chunk))
                                                            .await
                                                            .is_err()
                                                        {
                                                            return;
                                                        }
                                                    }
                                                }
                                                if let Some(headers) = buffered_trailers
                                                    && chunk_tx
                                                        .send(ResponseChunk::Trailers { headers })
                                                        .await
                                                        .is_err()
                                                {
                                                    return;
                                                }
                                                let _ = chunk_tx.send(ResponseChunk::End).await;
                                                return;
                                            }
                                        }
                                    }
                                };
                                let request_span = streams
                                    .get(&stream_id)
                                    .and_then(|req| req.trace_span.clone());
                                let spawned = match request_span {
                                    Some(span) => {
                                        spawn_async_task(fut.instrument(span), "body-pump")
                                    }
                                    None => spawn_async_task(fut, "body-pump"),
                                };
                                if !spawned {
                                    let _ = fail_tx.try_send(ResponseChunk::Error(
                                        ProxyError::Transport("runtime unavailable".into()),
                                    ));
                                }

                                if let Some(req) = streams.get_mut(&stream_id) {
                                    req.response_chunk_rx = Some(chunk_rx);
                                    req.response_headers_sent = !defer_headers_until_body_validated;
                                    req.phase = StreamPhase::SendingResponse;
                                    req.response_status = Some(status.as_u16());
                                }
                            }
                        }

                        // Update health/metrics for upstream response.
                        if let Some(req) = streams.get(&stream_id) {
                            if let (Some(addr), Some(idx)) = (&req.backend_addr, req.backend_index)
                                && let Some(pool) = req.upstream_pool.as_ref()
                            {
                                let transition = pool.write().ok().and_then(|mut p| {
                                    match outcome_from_status(status) {
                                        crate::HealthClassification::Success => {
                                            p.pool.mark_success(idx)
                                        }
                                        crate::HealthClassification::Failure => {
                                            p.pool.mark_request_failure(
                                                idx,
                                                HealthFailureReason::HttpStatus5xx,
                                            )
                                        }
                                        crate::HealthClassification::Neutral => None,
                                    }
                                });
                                if let Some(t) = transition {
                                    Self::log_health_transition(addr, t);
                                }
                            }
                            let (is_success, route_outcome) =
                                Self::request_metrics_outcome_for_status(status);
                            if is_success {
                                metrics.inc_success();
                            } else {
                                metrics.inc_failure();
                            }
                            let route_label = req.upstream_name.as_deref().unwrap_or("unrouted");
                            metrics.record_route(route_label, req.start.elapsed(), route_outcome);
                            Self::record_request_observation(
                                &metrics,
                                req,
                                Some(status.as_u16()),
                                route_outcome,
                            );
                            resilience
                                .adaptive_admission
                                .observe(req.start.elapsed(), false);
                            Self::log_access(req, status.as_u16());
                        }
                        if immediate_terminal {
                            if let Some(req) = streams.get_mut(&stream_id) {
                                abort_stream(req, &metrics);
                            }
                            streams.remove(&stream_id);
                            continue;
                        }
                    }
                    Err(err) => {
                        // Send error response first, then remove the stream so
                        // cleanup only happens after the response has been emitted.
                        if let Some(req) = streams.get(&stream_id) {
                            if let Err(protocol_err) = Self::handle_forward_result(
                                h3,
                                quic,
                                stream_id,
                                req,
                                Err(err),
                                upstream_pools,
                                routing_index,
                                &metrics,
                                resilience.shed_retry_after_seconds,
                            ) {
                                error!(
                                    "failed to emit recoverable forward error response on stream {}: {:?}",
                                    stream_id, protocol_err
                                );
                            }
                            resilience
                                .adaptive_admission
                                .observe(req.start.elapsed(), true);
                        }
                        if let Some(req) = streams.get_mut(&stream_id) {
                            abort_stream(req, &metrics);
                        }
                        streams.remove(&stream_id);
                        continue;
                    }
                }
            }

            // ── 4: flush response chunks ──────────────────────────────────────
            let mut terminal = false;
            if let Some(req) = streams.get_mut(&stream_id)
                && let Some(rx) = &mut req.response_chunk_rx
            {
                // Drain as many chunks as quiche will accept this iteration.
                loop {
                    // Retry any chunk that previously hit backpressure.
                    let chunk = match req.pending_chunk.take() {
                        Some(c) => c,
                        None => match rx.try_recv() {
                            Ok(c) => c,
                            Err(TryRecvError::Empty) => break,
                            Err(TryRecvError::Disconnected) => {
                                req.phase = StreamPhase::Failed;
                                terminal = true;
                                break;
                            }
                        },
                    };
                    match chunk {
                        ResponseChunk::Start { status, headers } => {
                            let mut h3_headers = Vec::with_capacity(headers.len() + 1);
                            h3_headers.push(quiche::h3::Header::new(
                                b":status",
                                status.as_str().as_bytes(),
                            ));
                            for (name, value) in &headers {
                                h3_headers.push(quiche::h3::Header::new(name, value));
                            }
                            match h3.send_response(quic, stream_id, &h3_headers, false) {
                                Ok(_) => {
                                    req.response_headers_sent = true;
                                }
                                Err(quiche::h3::Error::StreamBlocked) => {
                                    req.pending_chunk =
                                        Some(ResponseChunk::Start { status, headers });
                                    break;
                                }
                                Err(err) => {
                                    error!(
                                        "HTTP/3 send_response protocol error on stream {}: {:?}",
                                        stream_id, err
                                    );
                                    req.phase = StreamPhase::Failed;
                                    metrics.inc_failure();
                                    metrics.inc_backend_error();
                                    let route_label =
                                        req.upstream_name.as_deref().unwrap_or("unrouted");
                                    metrics.record_route(
                                        route_label,
                                        req.start.elapsed(),
                                        RouteOutcome::BackendError,
                                    );
                                    Self::record_request_observation(
                                        &metrics,
                                        req,
                                        Some(status.as_u16()),
                                        RouteOutcome::BackendError,
                                    );
                                    resilience
                                        .adaptive_admission
                                        .observe(req.start.elapsed(), true);
                                    terminal = true;
                                    break;
                                }
                            }
                        }
                        ResponseChunk::Data(data) => {
                            match h3.send_body(quic, stream_id, &data, false) {
                                Ok(_) => {}
                                Err(quiche::h3::Error::StreamBlocked) => {
                                    // QUIC flow-control backpressure — retry next poll.
                                    req.pending_chunk = Some(ResponseChunk::Data(data));
                                    break;
                                }
                                Err(err) => {
                                    error!(
                                        "HTTP/3 send_body data protocol error on stream {}: {:?}",
                                        stream_id, err
                                    );
                                    req.phase = StreamPhase::Failed;
                                    metrics.inc_failure();
                                    metrics.inc_backend_error();
                                    let route_label =
                                        req.upstream_name.as_deref().unwrap_or("unrouted");
                                    metrics.record_route(
                                        route_label,
                                        req.start.elapsed(),
                                        RouteOutcome::BackendError,
                                    );
                                    Self::record_request_observation(
                                        &metrics,
                                        req,
                                        req.response_status,
                                        RouteOutcome::BackendError,
                                    );
                                    resilience
                                        .adaptive_admission
                                        .observe(req.start.elapsed(), true);
                                    terminal = true;
                                    break;
                                }
                            }
                        }
                        ResponseChunk::Trailers { headers } => {
                            let mut h3_headers = Vec::with_capacity(headers.len());
                            for (name, value) in &headers {
                                h3_headers.push(quiche::h3::Header::new(name, value));
                            }
                            match h3.send_additional_headers(
                                quic,
                                stream_id,
                                &h3_headers,
                                false,
                                false,
                            ) {
                                Ok(_) => {}
                                Err(quiche::h3::Error::StreamBlocked) => {
                                    req.pending_chunk = Some(ResponseChunk::Trailers { headers });
                                    break;
                                }
                                Err(err) => {
                                    error!(
                                        "HTTP/3 send_additional_headers protocol error on stream {}: {:?}",
                                        stream_id, err
                                    );
                                    req.phase = StreamPhase::Failed;
                                    metrics.inc_failure();
                                    metrics.inc_backend_error();
                                    let route_label =
                                        req.upstream_name.as_deref().unwrap_or("unrouted");
                                    metrics.record_route(
                                        route_label,
                                        req.start.elapsed(),
                                        RouteOutcome::BackendError,
                                    );
                                    Self::record_request_observation(
                                        &metrics,
                                        req,
                                        req.response_status,
                                        RouteOutcome::BackendError,
                                    );
                                    resilience
                                        .adaptive_admission
                                        .observe(req.start.elapsed(), true);
                                    terminal = true;
                                    break;
                                }
                            }
                        }
                        ResponseChunk::End => match h3.send_body(quic, stream_id, b"", true) {
                            Ok(_) => {
                                req.phase = StreamPhase::Completed;
                                terminal = true;
                                break;
                            }
                            Err(quiche::h3::Error::StreamBlocked) => {
                                req.pending_chunk = Some(ResponseChunk::End);
                                break;
                            }
                            Err(err) => {
                                error!(
                                    "HTTP/3 send_body end protocol error on stream {}: {:?}",
                                    stream_id, err
                                );
                                req.phase = StreamPhase::Failed;
                                metrics.inc_failure();
                                metrics.inc_backend_error();
                                let route_label =
                                    req.upstream_name.as_deref().unwrap_or("unrouted");
                                metrics.record_route(
                                    route_label,
                                    req.start.elapsed(),
                                    RouteOutcome::BackendError,
                                );
                                Self::record_request_observation(
                                    &metrics,
                                    req,
                                    req.response_status,
                                    RouteOutcome::BackendError,
                                );
                                resilience
                                    .adaptive_admission
                                    .observe(req.start.elapsed(), true);
                                terminal = true;
                                break;
                            }
                        },
                        ResponseChunk::Error(err) => {
                            // If headers are not emitted yet, return a deterministic
                            // HTTP error status instead of resetting or truncating.
                            if !req.response_headers_sent {
                                let (status, body): (http::StatusCode, &[u8]) = match &err {
                                    ProxyError::Timeout => (
                                        http::StatusCode::SERVICE_UNAVAILABLE,
                                        b"upstream timeout\n",
                                    ),
                                    ProxyError::Pool(PoolError::BackendOverloaded(_)) => (
                                        http::StatusCode::SERVICE_UNAVAILABLE,
                                        b"upstream response body too large\n",
                                    ),
                                    _ => (http::StatusCode::BAD_GATEWAY, b"upstream error\n"),
                                };
                                let _ =
                                    Self::send_simple_response(h3, quic, stream_id, status, body);
                            } else {
                                // Best-effort: close the stream.
                                let _ = h3.send_body(quic, stream_id, b"", true);
                            }
                            req.phase = StreamPhase::Failed;
                            // Mirror the health/metrics updates from the old
                            // send_backend_response timeout/error paths.
                            let upstream_name =
                                routing_index.lookup(&req.path, req.authority.as_deref());
                            if let (Some(idx), Some(pool)) = (
                                req.backend_index,
                                upstream_name.and_then(|n| upstream_pools.get(n)),
                            ) && let Some(t) = pool.write().ok().and_then(|mut p| {
                                p.pool
                                    .mark_request_failure(idx, HealthFailureReason::HttpStatus5xx)
                            }) && let Some(addr) = &req.backend_addr
                            {
                                Self::log_health_transition(addr, t);
                            }
                            match err {
                                ProxyError::Timeout => {
                                    metrics.inc_failure();
                                    metrics.inc_timeout();
                                    let route_label =
                                        req.upstream_name.as_deref().unwrap_or("unrouted");
                                    metrics.record_route(
                                        route_label,
                                        req.start.elapsed(),
                                        RouteOutcome::Timeout,
                                    );
                                    Self::record_request_observation(
                                        &metrics,
                                        req,
                                        req.response_status.or(Some(
                                            http::StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                                        )),
                                        RouteOutcome::Timeout,
                                    );
                                    resilience
                                        .adaptive_admission
                                        .observe(req.start.elapsed(), true);
                                    debug!(
                                        "Upstream {} body timeout latency_ms {}",
                                        req.backend_addr.as_deref().unwrap_or("?"),
                                        req.start.elapsed().as_millis()
                                    );
                                }
                                ProxyError::Pool(PoolError::BackendOverloaded(reason)) => {
                                    metrics.inc_failure();
                                    if reason.contains(
                                        "unknown-length response prebuffer limit exceeded",
                                    ) {
                                        metrics.inc_response_prebuffer_limit_reject();
                                        metrics.inc_overload_shed_reason(
                                            OverloadShedReason::ResponsePrebufferCap,
                                        );
                                    } else {
                                        metrics.inc_overload_shed_reason(
                                            OverloadShedReason::BackendInflight,
                                        );
                                    }
                                    let route_label =
                                        req.upstream_name.as_deref().unwrap_or("unrouted");
                                    metrics.record_route(
                                        route_label,
                                        req.start.elapsed(),
                                        RouteOutcome::OverloadShed,
                                    );
                                    Self::record_request_observation(
                                        &metrics,
                                        req,
                                        req.response_status.or(Some(
                                            http::StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                                        )),
                                        RouteOutcome::OverloadShed,
                                    );
                                    resilience
                                        .adaptive_admission
                                        .observe(req.start.elapsed(), true);
                                    error!(
                                        "Upstream {} overload in response body path: {}",
                                        req.backend_addr.as_deref().unwrap_or("?"),
                                        reason
                                    );
                                }
                                _ => {
                                    metrics.inc_failure();
                                    metrics.inc_backend_error();
                                    let route_label =
                                        req.upstream_name.as_deref().unwrap_or("unrouted");
                                    metrics.record_route(
                                        route_label,
                                        req.start.elapsed(),
                                        RouteOutcome::BackendError,
                                    );
                                    Self::record_request_observation(
                                        &metrics,
                                        req,
                                        req.response_status
                                            .or(Some(http::StatusCode::BAD_GATEWAY.as_u16())),
                                        RouteOutcome::BackendError,
                                    );
                                    resilience
                                        .adaptive_admission
                                        .observe(req.start.elapsed(), true);
                                    error!(
                                        "Upstream {} body error: {:?}",
                                        req.backend_addr.as_deref().unwrap_or("?"),
                                        err
                                    );
                                }
                            }
                            terminal = true;
                            break;
                        }
                    }
                }
            }

            // ── 5: remove terminal streams ────────────────────────────────────
            if terminal {
                if let Some(req) = streams.get_mut(&stream_id) {
                    abort_stream(req, &metrics);
                }
                streams.remove(&stream_id);
            }
        }

        Ok(())
    }

    pub(super) fn resolve_backend_without_inflight(
        method: &str,
        path: &str,
        authority: Option<&str>,
        cid_key: Option<&str>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        routing_index: &RouteIndex,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> Result<ResolvedBackend, ProxyError> {
        if method.is_empty() || path.is_empty() {
            return Err(ProxyError::Transport("empty method or path".into()));
        }

        let route_decision = routing_index
            .lookup_with_decision_for_method(path, authority, Some(method))
            .ok_or_else(|| ProxyError::Transport(format!("no route for {path}")))?;
        let upstream_name = route_decision.upstream;

        let upstream_pool = upstream_pools
            .get(upstream_name)
            .ok_or_else(|| ProxyError::Transport(format!("pool not found: {upstream_name}")))?
            .clone();

        let (backend_index, lb_type, backend_addr) = {
            let (read_lb_type, read_fast_selected) = {
                let pool = upstream_pool
                    .read()
                    .map_err(|_| ProxyError::Transport("upstream pool lock poisoned".into()))?;
                if pool.pool.is_empty() {
                    return Err(ProxyError::Transport("no servers in upstream".into()));
                }
                let lb_type = pool.lb_name();
                let key = Self::resolve_lb_request_key(
                    lb_type,
                    pool.lb_key(),
                    method,
                    path,
                    authority,
                    cid_key,
                    header_lookup,
                );
                let fast_selected = if pool.pool.readmit_due() {
                    None
                } else {
                    pool.pick_readonly(key.as_str())
                        .and_then(|idx| pool.pool.address(idx).map(|addr| (idx, addr.to_string())))
                };
                (lb_type, fast_selected)
            };

            if let Some((idx, addr)) = read_fast_selected {
                (idx, read_lb_type, addr)
            } else {
                let mut pool = upstream_pool
                    .write()
                    .map_err(|_| ProxyError::Transport("upstream pool lock poisoned".into()))?;
                if pool.pool.is_empty() {
                    return Err(ProxyError::Transport("no servers in upstream".into()));
                }
                let lb_type = pool.lb_name();
                let key = Self::resolve_lb_request_key(
                    lb_type,
                    pool.lb_key(),
                    method,
                    path,
                    authority,
                    cid_key,
                    header_lookup,
                );
                let idx = pool.pick_without_begin(key.as_str()).ok_or_else(|| {
                    let total = pool.pool.len();
                    let healthy = pool.pool.healthy_len();
                    error!(
                        "no healthy backends available: {}/{} backends healthy",
                        healthy, total
                    );
                    ProxyError::Transport("no healthy servers".into())
                })?;
                let backend_addr = pool
                    .pool
                    .address(idx)
                    .map(str::to_string)
                    .ok_or_else(|| ProxyError::Transport("invalid server address".into()))?;
                (idx, lb_type, backend_addr)
            }
        };

        debug!(
            "Selected backend {} via {} route={} path_len={} host_specific={} reason={:?}",
            backend_addr,
            lb_type,
            upstream_name,
            route_decision.matched_path_len,
            route_decision.host_specific,
            route_decision.reason
        );
        Ok(ResolvedBackend {
            upstream_name: upstream_name.to_string(),
            backend_addr,
            backend_index,
            upstream_pool,
            backend_lb: lb_type.to_string(),
            route_path_len: route_decision.matched_path_len,
            route_host_specific: route_decision.host_specific,
            route_reason: route_decision.reason,
        })
    }

    /// Resolve routing + LB for a request, returning `(backend_addr, backend_index, pool)`.
    pub(super) fn resolve_backend(
        method: &str,
        path: &str,
        authority: Option<&str>,
        cid_key: Option<&str>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        routing_index: &RouteIndex,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> Result<ResolvedBackend, ProxyError> {
        if method.is_empty() || path.is_empty() {
            return Err(ProxyError::Transport("empty method or path".into()));
        }

        let route_decision = routing_index
            .lookup_with_decision_for_method(path, authority, Some(method))
            .ok_or_else(|| ProxyError::Transport(format!("no route for {path}")))?;
        let upstream_name = route_decision.upstream;

        let upstream_pool = upstream_pools
            .get(upstream_name)
            .ok_or_else(|| ProxyError::Transport(format!("pool not found: {upstream_name}")))?
            .clone();

        let (backend_index, lb_type, backend_addr) = {
            let (read_lb_type, read_fast_selected) = {
                let pool = upstream_pool
                    .read()
                    .map_err(|_| ProxyError::Transport("upstream pool lock poisoned".into()))?;
                if pool.pool.is_empty() {
                    return Err(ProxyError::Transport("no servers in upstream".into()));
                }
                let lb_type = pool.lb_name();
                let key = Self::resolve_lb_request_key(
                    lb_type,
                    pool.lb_key(),
                    method,
                    path,
                    authority,
                    cid_key,
                    header_lookup,
                );
                // When a passively-ejected backend is pending re-admission, skip
                // the read-only fast path so the write-locked slow path can
                // reconcile it back into rotation.
                let fast_selected = if pool.pool.readmit_due() {
                    None
                } else {
                    pool.pick_readonly(key.as_str())
                        .and_then(|idx| pool.pool.address(idx).map(|addr| (idx, addr.to_string())))
                        .and_then(|(idx, addr)| {
                            pool.begin_request_if_healthy(idx).then_some((idx, addr))
                        })
                };
                (lb_type, fast_selected)
            };

            if let Some((idx, addr)) = read_fast_selected {
                (idx, read_lb_type, addr)
            } else {
                let mut pool = upstream_pool
                    .write()
                    .map_err(|_| ProxyError::Transport("upstream pool lock poisoned".into()))?;
                if pool.pool.is_empty() {
                    return Err(ProxyError::Transport("no servers in upstream".into()));
                }
                let lb_type = pool.lb_name();
                let key = Self::resolve_lb_request_key(
                    lb_type,
                    pool.lb_key(),
                    method,
                    path,
                    authority,
                    cid_key,
                    header_lookup,
                );

                let idx = pool.pick(key.as_str()).ok_or_else(|| {
                    let total = pool.pool.len();
                    let healthy = pool.pool.healthy_len();
                    error!(
                        "no healthy backends available: {}/{} backends healthy",
                        healthy, total
                    );
                    ProxyError::Transport("no healthy servers".into())
                })?;
                let backend_addr = pool
                    .pool
                    .address(idx)
                    .map(str::to_string)
                    .ok_or_else(|| ProxyError::Transport("invalid server address".into()))?;
                (idx, lb_type, backend_addr)
            }
        };

        debug!(
            "Selected backend {} via {} route={} path_len={} host_specific={} reason={:?}",
            backend_addr,
            lb_type,
            upstream_name,
            route_decision.matched_path_len,
            route_decision.host_specific,
            route_decision.reason
        );
        Ok(ResolvedBackend {
            upstream_name: upstream_name.to_string(),
            backend_addr,
            backend_index,
            upstream_pool,
            backend_lb: lb_type.to_string(),
            route_path_len: route_decision.matched_path_len,
            route_host_specific: route_decision.host_specific,
            route_reason: route_decision.reason,
        })
    }

    fn resolve_lb_key_from_spec(
        lb_key_spec: &str,
        method: &str,
        path: &str,
        authority: Option<&str>,
        cid_key: Option<&str>,
        client_addr: Option<SocketAddr>,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> Option<String> {
        let spec = lb_key_spec.trim();
        if spec.is_empty() {
            return None;
        }

        if spec.eq_ignore_ascii_case("path") {
            let path_only = path.split_once('?').map(|(p, _)| p).unwrap_or(path);
            return Some(path_only.to_string());
        }
        if spec.eq_ignore_ascii_case("authority") {
            return authority.map(str::to_string);
        }
        if spec.eq_ignore_ascii_case("method") {
            return Some(method.to_string());
        }
        if spec.eq_ignore_ascii_case("cid") || spec.eq_ignore_ascii_case("sticky-cid") {
            return cid_key.map(str::to_string);
        }
        if spec.eq_ignore_ascii_case("peer_ip") || spec.eq_ignore_ascii_case("client_ip") {
            return client_addr.map(|addr| addr.ip().to_string());
        }
        if spec.eq_ignore_ascii_case("bearer_token") {
            let raw =
                header_lookup.and_then(|lookup| lookup(http::header::AUTHORIZATION.as_str()))?;
            return Self::bearer_token_from_authorization_value(&raw);
        }

        let (source, key_name) = spec.split_once(':')?;
        let key_name = key_name.trim();
        if key_name.is_empty() {
            return None;
        }

        if source.eq_ignore_ascii_case("header") {
            return header_lookup.and_then(|lookup| lookup(key_name));
        }

        if source.eq_ignore_ascii_case("cookie") {
            let cookie_header =
                header_lookup.and_then(|lookup| lookup(http::header::COOKIE.as_str()))?;
            return extract_cookie_value(cookie_header.as_str(), key_name);
        }

        if source.eq_ignore_ascii_case("query") {
            return extract_query_param(path, key_name);
        }

        None
    }

    fn default_lb_request_key(method: &str, path: &str, authority: Option<&str>) -> String {
        authority
            .unwrap_or(if !path.is_empty() { path } else { method })
            .to_string()
    }

    fn resolve_lb_request_key(
        lb_type: &str,
        lb_key_spec: Option<&str>,
        method: &str,
        path: &str,
        authority: Option<&str>,
        cid_key: Option<&str>,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> String {
        let default_key = Self::default_lb_request_key(method, path, authority);

        if let Some(spec) = lb_key_spec
            && let Some(value) = Self::resolve_lb_key_from_spec(
                spec,
                method,
                path,
                authority,
                cid_key,
                None,
                header_lookup,
            )
            && !value.is_empty()
        {
            return value;
        }

        if lb_type == "sticky-cid"
            && let Some(cid_key) = cid_key
        {
            return cid_key.to_string();
        }

        default_key
    }

    fn bearer_token_from_authorization_value(raw: &str) -> Option<String> {
        let raw = raw.trim();
        let split = raw.find(char::is_whitespace)?;
        let (scheme, rest) = raw.split_at(split);
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        let token = rest.trim_start();
        if token.is_empty() {
            return None;
        }
        Some(token.to_string())
    }

    pub(super) fn api_key_is_authorized(
        policy: &RuntimeUpstreamPolicy,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> bool {
        let Some(api_key) = policy.upstream_auth.api_key.as_ref() else {
            return true;
        };
        let Some(provided) = header_lookup.and_then(|lookup| lookup(api_key.header_name.as_str()))
        else {
            return false;
        };
        let provided = provided.trim();
        !provided.is_empty()
            && api_key
                .keys
                .iter()
                .any(|expected| bool::from(provided.as_bytes().ct_eq(expected.as_bytes())))
    }

    pub(super) fn jwt_is_authorized(
        policy: &RuntimeUpstreamPolicy,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> bool {
        let Some(jwt) = policy.upstream_auth.jwt.as_ref() else {
            return true;
        };
        let Some(raw) =
            header_lookup.and_then(|lookup| lookup(http::header::AUTHORIZATION.as_str()))
        else {
            return false;
        };
        let Some(token) = Self::bearer_token_from_authorization_value(&raw) else {
            return false;
        };
        let Some(claims) = Self::validated_hs256_jwt_claims(token.as_str(), jwt, SystemTime::now())
        else {
            return false;
        };
        Self::jwt_claims_satisfy_rbac(policy, &claims)
    }

    fn validated_hs256_jwt_claims(
        token: &str,
        jwt: &spooky_config::runtime::RuntimeJwtAuth,
        now: SystemTime,
    ) -> Option<Value> {
        let mut parts = token.split('.');
        let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        let Ok(header_bytes) = URL_SAFE_NO_PAD.decode(header_b64) else {
            return None;
        };
        let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(payload_b64) else {
            return None;
        };
        let Ok(signature) = URL_SAFE_NO_PAD.decode(signature_b64) else {
            return None;
        };
        let Ok(header) = serde_json::from_slice::<Value>(&header_bytes) else {
            return None;
        };
        if header.get("alg").and_then(Value::as_str) != Some("HS256") {
            return None;
        }

        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(jwt.secret.as_bytes()) else {
            return None;
        };
        mac.update(format!("{header_b64}.{payload_b64}").as_bytes());
        let expected = mac.finalize().into_bytes();
        if expected.len() != signature.len()
            || !bool::from(expected.as_slice().ct_eq(signature.as_slice()))
        {
            return None;
        }

        let Ok(claims) = serde_json::from_slice::<Value>(&payload_bytes) else {
            return None;
        };
        let Ok(now_secs) = now.duration_since(UNIX_EPOCH).map(|value| value.as_secs()) else {
            return None;
        };
        let exp = claims.get("exp").and_then(Value::as_u64)?;
        if now_secs > exp.saturating_add(jwt.clock_skew_secs) {
            return None;
        }
        if claims
            .get("nbf")
            .and_then(Value::as_u64)
            .is_some_and(|nbf| now_secs.saturating_add(jwt.clock_skew_secs) < nbf)
        {
            return None;
        }
        if claims
            .get("iat")
            .and_then(Value::as_u64)
            .is_some_and(|iat| now_secs.saturating_add(jwt.clock_skew_secs) < iat)
        {
            return None;
        }
        if jwt
            .issuer
            .as_deref()
            .is_some_and(|issuer| claims.get("iss").and_then(Value::as_str) != Some(issuer))
        {
            return None;
        }
        if let Some(audience) = jwt.audience.as_deref() {
            let claim_aud = claims.get("aud")?;
            match claim_aud {
                Value::String(value) if value == audience => {}
                Value::Array(values)
                    if values
                        .iter()
                        .any(|value| value.as_str().is_some_and(|value| value == audience)) => {}
                _ => return None,
            }
        }

        Some(claims)
    }

    fn jwt_claims_satisfy_rbac(policy: &RuntimeUpstreamPolicy, claims: &Value) -> bool {
        let scopes = Self::jwt_string_claim_values(claims, &["scope", "scp"]);
        let roles = Self::jwt_string_claim_values(claims, &["roles", "role"]);
        policy
            .upstream_auth
            .required_scopes
            .iter()
            .all(|required| scopes.contains(required))
            && policy
                .upstream_auth
                .required_roles
                .iter()
                .all(|required| roles.contains(required))
    }

    fn jwt_string_claim_values(
        claims: &Value,
        claim_names: &[&str],
    ) -> std::collections::HashSet<String> {
        let mut values = std::collections::HashSet::new();
        for claim_name in claim_names {
            let Some(value) = claims.get(*claim_name) else {
                continue;
            };
            match value {
                Value::String(value) => {
                    for item in value.split_whitespace() {
                        if !item.is_empty() {
                            values.insert(item.to_string());
                        }
                    }
                }
                Value::Array(items) => {
                    for item in items {
                        if let Some(item) = item.as_str()
                            && !item.is_empty()
                        {
                            values.insert(item.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        values
    }

    pub(super) fn resolve_scoped_rate_limit_key(
        rule: &crate::resilience::ScopedRateLimitRule,
        route: &str,
        method: &str,
        path: &str,
        authority: Option<&str>,
        client_addr: SocketAddr,
        header_lookup: Option<&LbHeaderLookup<'_>>,
    ) -> Option<String> {
        match rule.scope() {
            ScopedRateLimitScope::Route => Some(route.to_string()),
            ScopedRateLimitScope::Client => Self::resolve_lb_key_from_spec(
                rule.key_spec().unwrap_or("peer_ip"),
                method,
                path,
                authority,
                None,
                Some(client_addr),
                header_lookup,
            ),
            ScopedRateLimitScope::Tenant => rule.key_spec().and_then(|key_spec| {
                Self::resolve_lb_key_from_spec(
                    key_spec,
                    method,
                    path,
                    authority,
                    None,
                    Some(client_addr),
                    header_lookup,
                )
            }),
            ScopedRateLimitScope::Token => Self::resolve_lb_key_from_spec(
                rule.key_spec().unwrap_or("bearer_token"),
                method,
                path,
                authority,
                None,
                Some(client_addr),
                header_lookup,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spooky_config::config::{ScopedRateLimit, ScopedRateLimitScope};
    use spooky_config::runtime::{
        RuntimeApiKeyAuth, RuntimeAuthPolicy, RuntimeExternalAuth, RuntimeExternalAuthFailureMode,
        RuntimeJwtAuth, RuntimeUpstreamPolicy,
    };

    fn test_hs256_jwt(secret: &str, claims: serde_json::Value, alg: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({ "alg": alg, "typ": "JWT" }))
                .expect("serialize header"),
        );
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("serialize claims"));
        let signing_input = format!("{header}.{payload}");
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("mac");
        mac.update(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{signing_input}.{signature}")
    }

    #[test]
    fn internal_pool_errors_are_classified_as_control_plane_only() {
        assert!(QUICListener::is_internal_pool_control_error(
            &PoolError::InflightLimiterClosed
        ));
        assert!(QUICListener::is_internal_pool_control_error(
            &PoolError::UnknownBackend("missing".to_string())
        ));
    }

    #[test]
    fn backend_overload_is_not_classified_as_internal_pool_error() {
        assert!(!QUICListener::is_internal_pool_control_error(
            &PoolError::BackendOverloaded("busy".to_string())
        ));
    }

    #[test]
    fn circuit_open_is_not_classified_as_internal_pool_error() {
        assert!(!QUICListener::is_internal_pool_control_error(
            &PoolError::CircuitOpen("open".to_string())
        ));
    }

    #[test]
    fn send_connect_error_with_tls_details_maps_to_tls_health_failure() {
        assert_eq!(
            QUICListener::classify_upstream_failure_reason(
                true,
                "client error (Connect): tls handshake failed: invalid certificate"
            ),
            (HealthFailureReason::Tls, "handshake")
        );
    }

    #[test]
    fn send_connect_error_without_tls_details_maps_to_transport_health_failure() {
        assert_eq!(
            QUICListener::classify_upstream_failure_reason(
                true,
                "client error (Connect): connection refused"
            ),
            (HealthFailureReason::Transport, "transport")
        );
    }

    #[test]
    fn send_error_with_timeout_detail_maps_to_timeout_health_failure() {
        assert_eq!(
            QUICListener::classify_upstream_failure_reason(false, "request timed out"),
            (HealthFailureReason::Timeout, "timeout")
        );
    }

    #[test]
    fn request_metrics_treat_server_error_as_failure() {
        let (is_success, route_outcome) =
            QUICListener::request_metrics_outcome_for_status(StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!is_success);
        match route_outcome {
            RouteOutcome::Failure => {}
            _ => panic!("unexpected route outcome"),
        }
    }

    #[test]
    fn request_metrics_treat_success_response_as_success() {
        let (is_success, route_outcome) =
            QUICListener::request_metrics_outcome_for_status(StatusCode::OK);
        assert!(is_success);
        match route_outcome {
            RouteOutcome::Success => {}
            _ => panic!("unexpected route outcome"),
        }
    }

    #[derive(Debug)]
    struct OuterErr(InnerErr);

    #[derive(Debug)]
    struct InnerErr;

    impl std::fmt::Display for OuterErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "outer")
        }
    }

    impl std::fmt::Display for InnerErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "inner")
        }
    }

    impl StdError for OuterErr {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(&self.0)
        }
    }

    impl StdError for InnerErr {}

    #[test]
    fn format_error_chain_includes_nested_causes() {
        let msg = QUICListener::format_error_chain(&OuterErr(InnerErr));
        assert_eq!(msg, "outer: inner");
    }

    #[test]
    fn api_key_authorization_requires_exact_configured_match() {
        let policy = RuntimeUpstreamPolicy {
            upstream_auth: RuntimeAuthPolicy {
                api_key: Some(RuntimeApiKeyAuth {
                    header_name: "x-api-key".to_string(),
                    keys: vec!["secret-key".to_string()],
                }),
                jwt: None,
                external_auth: None,
                required_scopes: Vec::new(),
                required_roles: Vec::new(),
            },
            host: Default::default(),
            forwarded_headers: Default::default(),
            protocol: Default::default(),
        };
        let headers = [("x-api-key".to_string(), "secret-key".to_string())]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();
        let wrong_lookup = |_: &str| Some("wrong-key".to_string());

        assert!(QUICListener::api_key_is_authorized(&policy, Some(&lookup)));
        assert!(!QUICListener::api_key_is_authorized(
            &policy,
            Some(&wrong_lookup)
        ));
        assert!(!QUICListener::api_key_is_authorized(&policy, None));
    }

    #[test]
    fn hs256_jwt_validation_enforces_signature_and_claims() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let token = test_hs256_jwt(
            "jwt-secret",
            serde_json::json!({
                "sub": "user-1",
                "iss": "issuer-1",
                "aud": "aud-1",
                "exp": 4_000_000_000u64,
                "nbf": 1_699_999_900u64,
            }),
            "HS256",
        );
        let policy = RuntimeUpstreamPolicy {
            upstream_auth: RuntimeAuthPolicy {
                api_key: None,
                jwt: Some(RuntimeJwtAuth {
                    secret: "jwt-secret".to_string(),
                    issuer: Some("issuer-1".to_string()),
                    audience: Some("aud-1".to_string()),
                    clock_skew_secs: 30,
                }),
                external_auth: None,
                required_scopes: Vec::new(),
                required_roles: Vec::new(),
            },
            host: Default::default(),
            forwarded_headers: Default::default(),
            protocol: Default::default(),
        };
        let headers = [("authorization".to_string(), format!("Bearer {token}"))]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();

        assert!(QUICListener::jwt_is_authorized(&policy, Some(&lookup)));
        assert!(
            QUICListener::validated_hs256_jwt_claims(
                token.as_str(),
                policy.upstream_auth.jwt.as_ref().expect("jwt policy"),
                now
            )
            .is_some()
        );

        let wrong_secret = RuntimeJwtAuth {
            secret: "wrong".to_string(),
            issuer: Some("issuer-1".to_string()),
            audience: Some("aud-1".to_string()),
            clock_skew_secs: 30,
        };
        assert!(
            QUICListener::validated_hs256_jwt_claims(token.as_str(), &wrong_secret, now).is_none()
        );

        let expired = test_hs256_jwt(
            "jwt-secret",
            serde_json::json!({ "exp": 1_699_999_900u64 }),
            "HS256",
        );
        assert!(
            QUICListener::validated_hs256_jwt_claims(
                expired.as_str(),
                &RuntimeJwtAuth {
                    secret: "jwt-secret".to_string(),
                    issuer: None,
                    audience: None,
                    clock_skew_secs: 0,
                },
                now
            )
            .is_none()
        );
    }

    #[test]
    fn jwt_rbac_requires_configured_scopes_and_roles() {
        let policy = RuntimeUpstreamPolicy {
            upstream_auth: RuntimeAuthPolicy {
                api_key: None,
                jwt: None,
                external_auth: None,
                required_scopes: vec!["read:fast".to_string()],
                required_roles: vec!["admin".to_string()],
            },
            host: Default::default(),
            forwarded_headers: Default::default(),
            protocol: Default::default(),
        };
        let allowed_claims = serde_json::json!({
            "scope": "read:fast write:slow",
            "roles": ["admin", "operator"]
        });
        let denied_claims = serde_json::json!({
            "scope": "write:slow",
            "roles": ["operator"]
        });

        assert!(QUICListener::jwt_claims_satisfy_rbac(
            &policy,
            &allowed_claims
        ));
        assert!(!QUICListener::jwt_claims_satisfy_rbac(
            &policy,
            &denied_claims
        ));
    }

    #[test]
    fn resolve_lb_key_from_spec_supports_peer_ip_and_bearer_token() {
        let headers = [("authorization".to_string(), "Bearer token-1".to_string())]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();
        let client_addr = "203.0.113.9:443".parse().expect("client addr");

        assert_eq!(
            QUICListener::resolve_lb_key_from_spec(
                "peer_ip",
                "GET",
                "/",
                Some("api.example.com"),
                None,
                Some(client_addr),
                Some(&lookup),
            )
            .as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(
            QUICListener::resolve_lb_key_from_spec(
                "bearer_token",
                "GET",
                "/",
                Some("api.example.com"),
                None,
                Some(client_addr),
                Some(&lookup),
            )
            .as_deref(),
            Some("token-1")
        );
    }

    #[test]
    fn resolve_scoped_rate_limit_key_defaults_match_scope() {
        let client_rule = crate::resilience::ScopedRateLimitRule::from_config(&ScopedRateLimit {
            name: "client".to_string(),
            scope: ScopedRateLimitScope::Client,
            requests_per_sec: 10,
            burst: 10,
            key: None,
            route_allowlist: Vec::new(),
            idle_ttl_secs: 300,
        });
        let token_rule = crate::resilience::ScopedRateLimitRule::from_config(&ScopedRateLimit {
            name: "token".to_string(),
            scope: ScopedRateLimitScope::Token,
            requests_per_sec: 10,
            burst: 10,
            key: None,
            route_allowlist: Vec::new(),
            idle_ttl_secs: 300,
        });
        let headers = [("authorization".to_string(), "Bearer token-2".to_string())]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let lookup = |name: &str| headers.get(&name.to_ascii_lowercase()).cloned();
        let client_addr = "198.51.100.10:443".parse().expect("client addr");

        assert_eq!(
            QUICListener::resolve_scoped_rate_limit_key(
                &client_rule,
                "api",
                "GET",
                "/resource",
                Some("api.example.com"),
                client_addr,
                Some(&lookup),
            )
            .as_deref(),
            Some("198.51.100.10")
        );
        assert_eq!(
            QUICListener::resolve_scoped_rate_limit_key(
                &token_rule,
                "api",
                "GET",
                "/resource",
                Some("api.example.com"),
                client_addr,
                Some(&lookup),
            )
            .as_deref(),
            Some("token-2")
        );
    }

    #[test]
    fn pending_forward_request_headers_apply_auth_mutations() {
        let pending_forward = PendingForward {
            method: Arc::<str>::from("GET"),
            path: Arc::<str>::from("/"),
            authority: Some(Arc::<str>::from("example.com")),
            headers: Arc::new(vec![
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b"x-user-id", b"stale"),
                quiche::h3::Header::new(b"x-remove-me", b"1"),
            ]),
            upstream_name: Arc::<str>::from("api"),
            route_reason: Arc::<str>::from("path_prefix"),
            route_path_len: 1,
            route_host_specific: false,
            backend_addr: Arc::<str>::from("http://127.0.0.1:8080"),
            backend_index: 0,
            backend_lb: None,
            client_addr: "127.0.0.1:443".parse().expect("client addr"),
            request_id: 7,
            trace_id: None,
            span_id: None,
            traceparent: None,
            host_policy: Default::default(),
            forwarded_header_policy: Default::default(),
            auth_header_mutations: vec![
                PendingHeaderMutation::Upsert {
                    name: b"x-user-id".to_vec(),
                    value: b"fresh".to_vec(),
                },
                PendingHeaderMutation::Remove {
                    name: b"x-remove-me".to_vec(),
                },
            ],
        };

        let headers = pending_forward.request_headers();
        assert!(headers.iter().any(|header| header.name() == b":method"));
        assert!(
            headers
                .iter()
                .any(|header| header.name() == b"x-user-id" && header.value() == b"fresh")
        );
        assert!(
            !headers
                .iter()
                .any(|header| header.name() == b"x-user-id" && header.value() == b"stale")
        );
        assert!(!headers.iter().any(|header| header.name() == b"x-remove-me"));
    }

    #[test]
    fn auth_header_allowlist_is_case_insensitive() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-auth-user", http::HeaderValue::from_static("alice"));
        headers.insert("x-ignore", http::HeaderValue::from_static("nope"));

        assert_eq!(
            allowed_auth_headers(&headers, &["X-Auth-User".to_string()]),
            vec![("x-auth-user".to_string(), "alice".to_string())]
        );

        assert_eq!(
            auth_allow_mutations(&headers, &["x-auth-user".to_string()]),
            vec![PendingHeaderMutation::Upsert {
                name: b"x-auth-user".to_vec(),
                value: b"alice".to_vec(),
            }]
        );
    }

    #[test]
    fn oidc_helper_predicates_match_expected_scope_and_audience_shapes() {
        assert!(oidc_scope_satisfied(
            &["read".to_string(), "write".to_string()],
            "read write admin"
        ));
        assert!(!oidc_scope_satisfied(
            &["read".to_string(), "write".to_string()],
            "read"
        ));

        assert!(oidc_audience_matches(
            Some("api://edge"),
            Some(&serde_json::Value::String("api://edge".to_string()))
        ));
        assert!(oidc_audience_matches(
            Some("api://edge"),
            Some(&serde_json::json!(["other", "api://edge"]))
        ));
        assert!(!oidc_audience_matches(
            Some("api://edge"),
            Some(&serde_json::Value::String("api://other".to_string()))
        ));
        assert!(oidc_audience_matches(None, None));
    }

    #[test]
    fn external_auth_failure_mode_helpers_track_fail_open() {
        let auth = RuntimeExternalAuth::Http {
            endpoint: "http://127.0.0.1:9000/auth".to_string(),
            request_headers: Vec::new(),
            response_header_allowlist: Vec::new(),
            timeout_ms: 250,
            failure_mode: RuntimeExternalAuthFailureMode::FailOpen,
        };

        assert_eq!(auth_timeout_ms(&auth), 250);
        assert!(fail_open(auth_failure_mode(&auth)));
    }
}
