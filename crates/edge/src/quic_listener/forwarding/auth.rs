use std::convert::Infallible;

use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use serde_json::Value;
use spooky_config::runtime::RuntimeExternalAuth;
use tokio::task::AbortHandle;

use super::*;
use crate::runtime::connection::{
    auth::{
        ExternalAuthCompletion, ExternalAuthDecision, ExternalAuthDenyResponse,
        ExternalAuthExecutionPolicy, ExternalAuthFailureDisposition, ExternalAuthResponseMetadata,
        ExternalAuthResult, ExternalAuthTaskConfig, OidcAuthorizationCheck,
        evaluate_external_auth_completion, merge_auth_request_mutations, oidc_audience_matches,
        oidc_authorization_check, oidc_discovery_target, oidc_scope_satisfied,
        validate_oidc_provider_metadata,
    },
    request::PendingForward,
    stream::StreamAdmissionState,
};

const MAX_AUTH_BODY_BYTES: usize = 64 * 1024;

pub(super) struct AuthStart {
    pub(super) rx: oneshot::Receiver<ExternalAuthResult>,
    pub(super) abort: AbortHandle,
    pub(super) deadline: Instant,
    pub(super) fail_open: bool,
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

fn is_unsafe_forwarded_auth_request_header(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(http::header::HOST.as_str().as_bytes())
        || name.eq_ignore_ascii_case(http::header::CONNECTION.as_str().as_bytes())
        || name.eq_ignore_ascii_case(http::header::CONTENT_LENGTH.as_str().as_bytes())
        || name.eq_ignore_ascii_case(http::header::TRANSFER_ENCODING.as_str().as_bytes())
        || name.eq_ignore_ascii_case(http::header::UPGRADE.as_str().as_bytes())
        || name.eq_ignore_ascii_case(http::header::TE.as_str().as_bytes())
        || name.eq_ignore_ascii_case(http::header::TRAILER.as_str().as_bytes())
        || name.eq_ignore_ascii_case(http::header::EXPECT.as_str().as_bytes())
        || name.eq_ignore_ascii_case(b"keep-alive")
        || name.eq_ignore_ascii_case(b"proxy-connection")
}

pub(super) fn append_auth_request_headers(
    builder: &mut http::request::Builder,
    pending_forward: &PendingForward,
    configured_headers: &[spooky_config::runtime::RuntimeExternalAuthRequestHeader],
) {
    for header in pending_forward.request_headers() {
        if header.name().starts_with(b":") || is_unsafe_forwarded_auth_request_header(header.name())
        {
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

async fn collect_auth_body(mut body: Incoming) -> Result<Vec<u8>, ProxyError> {
    use http_body_util::BodyExt as _;

    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|err| ProxyError::Transport(err.to_string()))?;
        let Ok(chunk) = frame.into_data() else {
            continue;
        };
        let next_len = bytes.len().saturating_add(chunk.len());
        if next_len > MAX_AUTH_BODY_BYTES {
            return Err(ProxyError::Transport(format!(
                "external auth body exceeded {MAX_AUTH_BODY_BYTES} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
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

async fn run_external_auth_with_timeout(
    pending_forward: Arc<PendingForward>,
    external_auth: RuntimeExternalAuth,
    timeout: Duration,
) -> ExternalAuthResult {
    tokio::time::timeout(timeout, run_external_auth(pending_forward, external_auth))
        .await
        .map_err(|_| ProxyError::Timeout)?
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
    let headers = response.headers().clone();
    let body = if status.is_success() || status.is_redirection() {
        Vec::new()
    } else {
        collect_auth_body(response.into_body()).await?
    };
    crate::runtime::connection::auth::map_http_external_auth_response(
        ExternalAuthResponseMetadata {
            status,
            headers: &headers,
            body: &body,
        },
        &response_header_allowlist,
    )
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

#[allow(clippy::too_many_arguments)]
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
    let token = match oidc_authorization_check(
        authorization_header_from_pending_forward(&pending_forward).as_deref(),
    ) {
        OidcAuthorizationCheck::Token(token) => token,
        OidcAuthorizationCheck::Challenge(response) => {
            return Ok(ExternalAuthDecision::Challenge(response));
        }
    };
    let discovery = oidc_discovery_target(discovery_url.as_deref(), issuer_url.as_deref())?;
    let document = fetch_json_document(discovery.url, timeout).await?;
    let metadata = validate_oidc_provider_metadata(&document)?;

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
        .uri(metadata.introspection_endpoint)
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
                body: b"missing oidc scopes\n".to_vec(),
            }));
        };
        if !oidc_scope_satisfied(&scopes, scope_value) {
            return Ok(ExternalAuthDecision::Deny(ExternalAuthDenyResponse {
                status: http::StatusCode::FORBIDDEN,
                headers: Vec::new(),
                body: b"missing oidc scopes\n".to_vec(),
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
    let timeout = ExternalAuthExecutionPolicy::from_external_auth(&external_auth).timeout;
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

pub(super) fn start_external_auth_task(
    pending_forward: Arc<PendingForward>,
    external_auth: RuntimeExternalAuth,
) -> Result<AuthStart, ProxyError> {
    let task_config = ExternalAuthTaskConfig::from_external_auth(&external_auth);
    let (tx, rx) = oneshot::channel();
    let fut = async move {
        let result =
            run_external_auth_with_timeout(pending_forward, external_auth, task_config.timeout)
                .await;
        let _ = tx.send(result);
    };
    let Some(handle) = runtime_handle() else {
        return Err(ProxyError::Transport(
            "dropping external auth task: no runtime available".into(),
        ));
    };
    let join = handle.spawn(fut);
    Ok(AuthStart {
        rx,
        abort: join.abort_handle(),
        deadline: Instant::now() + task_config.timeout,
        fail_open: task_config.disposition.fail_open(),
    })
}

impl QUICListener {
    pub(super) fn complete_auth_result(
        stream_id: u64,
        req: &mut RequestEnvelope,
        result: ExternalAuthResult,
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        exec_ctx: &ForwardingExecutionCtx<'_>,
        shared_ctx: &ForwardingSharedCtx<'_>,
    ) -> Result<bool, quiche::h3::Error> {
        let metrics = shared_ctx.metrics.as_ref();
        req.auth_result_rx = None;
        if let Some(abort) = req.auth_abort.take() {
            abort.abort();
        }
        req.auth_deadline = None;
        let completion = evaluate_external_auth_completion(
            result,
            ExternalAuthFailureDisposition::from_fail_open(req.auth_fail_open),
        );
        match completion {
            ExternalAuthCompletion::Allow {
                request_header_mutations,
            } => {
                metrics.inc_external_auth_allowed();
                if let Some(pending_forward) = req.pending_forward.as_mut() {
                    merge_auth_request_mutations(
                        &mut Arc::make_mut(pending_forward).auth_header_mutations,
                        request_header_mutations.into_iter().map(Into::into),
                    );
                }
                Self::materialize_forward_after_auth(stream_id, req, h3, quic, exec_ctx, shared_ctx)
            }
            ExternalAuthCompletion::Respond(decision) => {
                req.admission_state = StreamAdmissionState::Denied;
                req.response_status = Some(decision.status().as_u16());
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
            ExternalAuthCompletion::FailOpen { timed_out, error } => {
                if timed_out {
                    metrics.inc_external_auth_timeout();
                    warn!(
                        "request_id={} route={} external auth failed open: timeout",
                        req.request_id,
                        req.upstream_name.as_deref().unwrap_or("unrouted"),
                    );
                } else {
                    metrics.inc_external_auth_error();
                    if let Some(error) = error {
                        warn!(
                            "request_id={} route={} external auth failed open: {:?}",
                            req.request_id,
                            req.upstream_name.as_deref().unwrap_or("unrouted"),
                            error
                        );
                    }
                }
                Self::materialize_forward_after_auth(stream_id, req, h3, quic, exec_ctx, shared_ctx)
            }
            ExternalAuthCompletion::Reject {
                status,
                body,
                timed_out,
                error,
            } => {
                if timed_out {
                    metrics.inc_external_auth_timeout();
                } else {
                    metrics.inc_external_auth_error();
                    if let Some(error) = &error {
                        debug!(
                            "request_id={} route={} external auth rejected after error: {:?}",
                            req.request_id,
                            req.upstream_name.as_deref().unwrap_or("unrouted"),
                            error
                        );
                    }
                }
                metrics.inc_failure();
                let route_label = req.upstream_name.as_deref().unwrap_or("unrouted");
                let route_outcome = if timed_out {
                    RouteOutcome::Timeout
                } else {
                    RouteOutcome::Failure
                };
                req.admission_state = StreamAdmissionState::Denied;
                req.response_status = Some(status.as_u16());
                metrics.record_route(route_label, req.start.elapsed(), route_outcome);
                Self::send_simple_response(h3, quic, stream_id, status, body)?;
                Ok(false)
            }
        }
    }
}
