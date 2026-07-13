use std::collections::HashSet;

use http::HeaderName;

pub fn connection_header_tokens(headers: &[quiche::h3::Header]) -> HashSet<String> {
    use quiche::h3::NameValue;

    let mut tokens = HashSet::new();
    for header in headers {
        if !header.name().eq_ignore_ascii_case(b"connection") {
            continue;
        }
        let Ok(value) = std::str::from_utf8(header.value()) else {
            continue;
        };
        for token in value.split(',') {
            let normalized = token.trim().to_ascii_lowercase();
            if !normalized.is_empty() {
                tokens.insert(normalized);
            }
        }
    }
    tokens
}

pub fn should_strip_request_header(
    name: &HeaderName,
    connection_tokens: &HashSet<String>,
    preserve_upgrade: bool,
) -> bool {
    if preserve_upgrade && (name == http::header::CONNECTION || name == http::header::UPGRADE) {
        return false;
    }

    if connection_tokens.contains(name.as_str()) {
        return true;
    }

    if name == http::header::CONTENT_LENGTH {
        return true;
    }

    if name == http::header::CONNECTION
        || name == http::header::PROXY_AUTHENTICATE
        || name == http::header::PROXY_AUTHORIZATION
        || name == http::header::TE
        || name == http::header::TRAILER
        || name == http::header::TRANSFER_ENCODING
        || name == http::header::UPGRADE
        || name.as_str().eq_ignore_ascii_case("keep-alive")
        || name.as_str().eq_ignore_ascii_case("proxy-connection")
        || name.as_str().eq_ignore_ascii_case("forwarded")
        || name.as_str().eq_ignore_ascii_case("x-forwarded-for")
        || name.as_str().eq_ignore_ascii_case("x-forwarded-proto")
        || name.as_str().eq_ignore_ascii_case("x-forwarded-host")
    {
        return true;
    }

    false
}
