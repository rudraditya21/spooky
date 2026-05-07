use super::*;

pub(super) struct RequestValidationResult {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) authority: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RequestBufferError {
    StreamCap,
    GlobalCap,
}

pub(super) fn request_content_length(headers: &[quiche::h3::Header]) -> Option<usize> {
    for header in headers {
        if !header.name().eq_ignore_ascii_case(b"content-length") {
            continue;
        }
        let value = std::str::from_utf8(header.value()).ok()?;
        let parsed = value.trim().parse::<usize>().ok()?;
        return Some(parsed);
    }
    None
}

pub(super) fn validate_request_headers(
    list: &[quiche::h3::Header],
    resilience: &RuntimeResilience,
) -> Result<RequestValidationResult, (http::StatusCode, &'static [u8], bool)> {
    if list.len() > resilience.max_headers_count {
        return Err((
            http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            b"too many request headers\n",
            false,
        ));
    }

    let mut header_bytes = 0usize;
    let mut method = None::<String>;
    let mut path = None::<String>;
    let mut authority = None::<String>;
    let mut host = None::<String>;
    let mut scheme_seen = false;

    for header in list {
        header_bytes = header_bytes.saturating_add(header.name().len() + header.value().len());
        if header_bytes > resilience.max_headers_bytes {
            return Err((
                http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                b"request headers exceed size limit\n",
                false,
            ));
        }

        match header.name() {
            b":method" => {
                if method.is_some() {
                    return Err((
                        http::StatusCode::BAD_REQUEST,
                        b"duplicate :method header\n",
                        false,
                    ));
                }
                method = Some(String::from_utf8_lossy(header.value()).to_string());
            }
            b":path" => {
                if path.is_some() {
                    return Err((
                        http::StatusCode::BAD_REQUEST,
                        b"duplicate :path header\n",
                        false,
                    ));
                }
                path = Some(String::from_utf8_lossy(header.value()).to_string());
            }
            b":authority" => {
                if authority.is_some() {
                    return Err((
                        http::StatusCode::BAD_REQUEST,
                        b"duplicate :authority header\n",
                        false,
                    ));
                }
                authority = Some(String::from_utf8_lossy(header.value()).to_string());
            }
            b"host" => {
                if host.is_some() {
                    return Err((
                        http::StatusCode::BAD_REQUEST,
                        b"duplicate host header\n",
                        false,
                    ));
                }
                host = Some(String::from_utf8_lossy(header.value()).to_string());
            }
            b":scheme" => {
                if scheme_seen {
                    return Err((
                        http::StatusCode::BAD_REQUEST,
                        b"duplicate :scheme header\n",
                        false,
                    ));
                }
                scheme_seen = true;
            }
            name if name.starts_with(b":") => {
                return Err((
                    http::StatusCode::BAD_REQUEST,
                    b"unsupported pseudo-header\n",
                    false,
                ));
            }
            _ => {}
        }
    }

    let method = match method {
        Some(method) => method,
        None => {
            return Err((
                http::StatusCode::BAD_REQUEST,
                b"missing :method header\n",
                false,
            ));
        }
    };
    let path = match path {
        Some(path) => path,
        None => {
            return Err((
                http::StatusCode::BAD_REQUEST,
                b"missing :path header\n",
                false,
            ));
        }
    };

    validate_request_parts(
        method,
        path,
        authority,
        host,
        resilience,
        RequestPartErrors {
            invalid_method: b"invalid :method header\n",
            invalid_path: b"invalid :path header\n",
            authority_mismatch: b":authority and host headers must match\n",
        },
    )
}

pub(super) fn validate_http_request(
    req: &http::Request<Incoming>,
    resilience: &RuntimeResilience,
) -> Result<RequestValidationResult, (http::StatusCode, &'static [u8], bool)> {
    let header_count = req.headers().len().saturating_add(2);
    if header_count > resilience.max_headers_count {
        return Err((
            http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            b"too many request headers\n",
            false,
        ));
    }

    let mut header_bytes = req.method().as_str().len() + req.uri().path().len();
    let authority = req.uri().authority().map(|a| a.as_str().to_owned());
    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    if let Some(authority_value) = authority.as_deref() {
        header_bytes = header_bytes.saturating_add(authority_value.len());
    }
    if let Some(host_value) = host.as_deref() {
        header_bytes =
            header_bytes.saturating_add(http::header::HOST.as_str().len() + host_value.len());
    }

    for (name, value) in req.headers() {
        header_bytes = header_bytes.saturating_add(name.as_str().len() + value.as_bytes().len());
        if header_bytes > resilience.max_headers_bytes {
            return Err((
                http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                b"request headers exceed size limit\n",
                false,
            ));
        }
    }

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    validate_request_parts(
        req.method().as_str().to_string(),
        path.to_string(),
        authority,
        host,
        resilience,
        RequestPartErrors {
            invalid_method: b"invalid method header\n",
            invalid_path: b"invalid path header\n",
            authority_mismatch: b"authority and host headers must match\n",
        },
    )
}

struct RequestPartErrors {
    invalid_method: &'static [u8],
    invalid_path: &'static [u8],
    authority_mismatch: &'static [u8],
}

fn validate_request_parts(
    method: String,
    path: String,
    authority: Option<String>,
    host: Option<String>,
    resilience: &RuntimeResilience,
    errors: RequestPartErrors,
) -> Result<RequestValidationResult, (http::StatusCode, &'static [u8], bool)> {
    if method.trim().is_empty() || method.as_bytes().iter().any(|b| b.is_ascii_whitespace()) {
        return Err((http::StatusCode::BAD_REQUEST, errors.invalid_method, false));
    }

    if path.is_empty() || !path.starts_with('/') {
        return Err((http::StatusCode::BAD_REQUEST, errors.invalid_path, false));
    }

    if resilience.enforce_authority_host_match
        && let (Some(authority_value), Some(host_value)) = (authority.as_deref(), host.as_deref())
    {
        let normalized_authority = normalize_host_for_routing(authority_value)
            .unwrap_or_else(|| authority_value.to_ascii_lowercase());
        let normalized_host = normalize_host_for_routing(host_value)
            .unwrap_or_else(|| host_value.to_ascii_lowercase());
        if normalized_authority != normalized_host {
            return Err((
                http::StatusCode::BAD_REQUEST,
                errors.authority_mismatch,
                false,
            ));
        }
    }

    if !resilience.method_allowed(&method) {
        return Err((
            http::StatusCode::METHOD_NOT_ALLOWED,
            b"request method blocked by policy\n",
            true,
        ));
    }

    if resilience.path_denied(&path) {
        return Err((
            http::StatusCode::FORBIDDEN,
            b"request path blocked by policy\n",
            true,
        ));
    }

    Ok(RequestValidationResult {
        method,
        path,
        authority: authority.or(host),
    })
}

pub(super) fn extract_header_value<'a>(
    headers: &'a [quiche::h3::Header],
    name: &[u8],
) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name().eq_ignore_ascii_case(name))
        .and_then(|header| std::str::from_utf8(header.value()).ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(super) fn parse_traceparent(value: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() != 4 || parts[0] != "00" {
        return None;
    }
    let trace_id = parts[1];
    let parent_span_id = parts[2];
    let flags = parts[3];

    let trace_valid = trace_id.len() == 32
        && trace_id.chars().all(|c| c.is_ascii_hexdigit())
        && trace_id != "00000000000000000000000000000000";
    let span_valid = parent_span_id.len() == 16
        && parent_span_id.chars().all(|c| c.is_ascii_hexdigit())
        && parent_span_id != "0000000000000000";
    let flags_valid = flags.len() == 2 && flags.chars().all(|c| c.is_ascii_hexdigit());

    if !(trace_valid && span_valid && flags_valid) {
        return None;
    }

    Some((
        trace_id.to_ascii_lowercase(),
        parent_span_id.to_ascii_lowercase(),
    ))
}

pub(super) fn generated_trace_id(conn_trace_id: &str, request_id: u64) -> String {
    let mut seed = conn_trace_id.as_bytes().to_vec();
    seed.extend_from_slice(&request_id.to_be_bytes());
    let lo = crate::stable_hash64(&seed);
    seed.extend_from_slice(b"trace-hi");
    let hi = crate::stable_hash64(&seed);
    format!("{hi:016x}{lo:016x}")
}

pub(super) fn generated_span_id(request_id: u64) -> String {
    format!("{:016x}", crate::stable_hash64(&request_id.to_be_bytes()))
}
