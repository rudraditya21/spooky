use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendScheme {
    Http,
    Https,
}

impl BackendScheme {
    /// Returns the lowercase URI scheme token used in origins and absolute URIs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

impl fmt::Display for BackendScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendEndpoint {
    scheme: BackendScheme,
    authority: String,
}

impl BackendEndpoint {
    /// Parse backend endpoint policy from config.
    ///
    /// Accepted forms:
    /// - `host:port` => defaults to `https://host:port`
    /// - `https://host:port`
    /// - `http://host:port` (explicit insecure opt-out)
    ///
    /// Returns a normalized endpoint whose authority always includes an explicit port.
    /// Host-only inputs inherit the scheme default port: `443` for HTTPS and `80` for HTTP.
    ///
    /// Returns an error when the input is empty, uses an unsupported scheme, includes a
    /// path/query/fragment, or does not form a valid `host:port` authority.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err("backend address is empty".to_string());
        }

        let lower = raw.to_ascii_lowercase();
        let (scheme, authority) = if lower.starts_with("http://") {
            (BackendScheme::Http, &raw[7..])
        } else if lower.starts_with("https://") {
            (BackendScheme::Https, &raw[8..])
        } else if raw.contains("://") {
            return Err("unsupported URL scheme; use http:// or https://".to_string());
        } else {
            (BackendScheme::Https, raw)
        };

        if authority.is_empty() {
            return Err("backend authority is empty".to_string());
        }

        if authority.contains('/') || authority.contains('?') || authority.contains('#') {
            return Err("backend address must not include path, query, or fragment".to_string());
        }

        let authority = normalize_authority(authority, scheme);

        validate_authority(&authority)?;

        Ok(Self { scheme, authority })
    }

    /// Returns the effective backend transport scheme.
    pub fn scheme(&self) -> BackendScheme {
        self.scheme
    }

    /// Returns the normalized authority in `host:port` form.
    ///
    /// IPv6 literals are returned in bracketed form, for example `[::1]:443`.
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Returns just the host portion of the normalized authority.
    ///
    /// For bracketed IPv6 authorities, the surrounding `[` and `]` are removed.
    pub fn authority_host(&self) -> &str {
        split_authority(&self.authority)
            .map(|(host, _)| host)
            .unwrap_or_default()
    }

    /// Returns the parsed port portion of the normalized authority.
    ///
    /// Because [`BackendEndpoint::parse`] validates the authority, successful endpoints always
    /// return a non-zero port here.
    pub fn authority_port(&self) -> u16 {
        split_authority(&self.authority)
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .unwrap_or_default()
    }

    /// Returns `true` when the authority host is an IPv4 or IPv6 literal.
    pub fn authority_is_ip_literal(&self) -> bool {
        self.authority_host().parse::<IpAddr>().is_ok()
    }

    /// Returns the backend origin in `<scheme>://<authority>` form.
    ///
    /// Example: `https://api.example.com:443`.
    pub fn origin(&self) -> String {
        format!("{}://{}", self.scheme.as_str(), self.authority)
    }

    /// Builds an absolute backend URI for the provided request path.
    ///
    /// Behavior:
    /// - empty input becomes `/`
    /// - inputs starting with `/` are appended as-is
    /// - other inputs are treated as relative path text and joined with a single `/`
    pub fn uri_for_path(&self, path: &str) -> String {
        let normalized = if path.is_empty() {
            "/"
        } else if path.starts_with('/') {
            path
        } else {
            return format!("{}/{}", self.origin(), path);
        };
        format!("{}{}", self.origin(), normalized)
    }
}

fn normalize_authority(authority: &str, scheme: BackendScheme) -> String {
    if authority.starts_with('[') {
        // IPv6: always requires explicit port per validate_authority rules
        return authority.to_string();
    }
    if authority.rsplit_once(':').is_none() {
        // No port — append the scheme default
        let default_port = match scheme {
            BackendScheme::Https => 443,
            BackendScheme::Http => 80,
        };
        return format!("{}:{}", authority, default_port);
    }
    authority.to_string()
}

fn split_authority(authority: &str) -> Option<(&str, &str)> {
    if authority.starts_with('[') {
        let bracket_end = authority.find(']')?;
        let host = authority.get(1..bracket_end)?;
        let suffix = authority.get(bracket_end + 1..)?;
        let port = suffix.strip_prefix(':')?;
        Some((host, port))
    } else {
        authority.rsplit_once(':')
    }
}

fn validate_dns_hostname(host: &str) -> Result<(), String> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err("backend host is empty".to_string());
    }

    // Fast-path valid IP literals and localhost aliases.
    if trimmed.eq_ignore_ascii_case("localhost") || trimmed.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    let without_trailing_dot = trimmed.trim_end_matches('.');
    if without_trailing_dot.is_empty() {
        return Err("backend host is invalid".to_string());
    }

    // Enforce IDNA/UTS#46 conversion and reject malformed Unicode hostnames.
    let ascii = idna::domain_to_ascii(without_trailing_dot)
        .map_err(|_| "backend host is not a valid IDNA/DNS hostname".to_string())?;

    if ascii.len() > 253 {
        return Err("backend host exceeds maximum length (253)".to_string());
    }

    for label in ascii.split('.') {
        if label.is_empty() {
            return Err("backend host contains empty DNS label".to_string());
        }
        if label.len() > 63 {
            return Err("backend host contains DNS label longer than 63 characters".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("backend host DNS labels must not start or end with '-'".to_string());
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("backend host contains invalid DNS label characters".to_string());
        }
    }

    Ok(())
}

fn validate_authority(authority: &str) -> Result<(), String> {
    if authority.chars().any(|ch| ch.is_ascii_whitespace()) {
        return Err("backend authority must not contain whitespace".to_string());
    }

    let (host, port_str) = if authority.starts_with('[') {
        let bracket_end = authority
            .find(']')
            .ok_or_else(|| "invalid IPv6 authority; missing closing ']'".to_string())?;
        let host = &authority[1..bracket_end];
        if host.is_empty() {
            return Err("backend host is empty".to_string());
        }

        let suffix = &authority[bracket_end + 1..];
        if !suffix.starts_with(':') {
            return Err("backend authority must include ':port'".to_string());
        }
        (host, &suffix[1..])
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| "backend authority must be host:port".to_string())?;
        if host.is_empty() {
            return Err("backend host is empty".to_string());
        }
        if host.contains(':') {
            return Err("IPv6 authorities must use brackets, e.g. [::1]:443".to_string());
        }
        (host, port)
    };

    if host.is_empty() {
        return Err("backend host is empty".to_string());
    }

    validate_dns_hostname(host)?;

    if port_str.is_empty() {
        return Err("backend port is empty".to_string());
    }
    if !port_str.chars().all(|c| c.is_ascii_digit()) {
        return Err("backend port must be numeric".to_string());
    }
    let port = port_str
        .parse::<u16>()
        .map_err(|_| "backend port must be in range 1-65535".to_string())?;
    if port == 0 {
        return Err("backend port must be in range 1-65535".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BackendEndpoint, BackendScheme};

    #[test]
    fn display_formats_backend_scheme() {
        assert_eq!(BackendScheme::Http.to_string(), "http");
        assert_eq!(format!("{}", BackendScheme::Https), "https");
    }

    #[test]
    fn parse_host_port_defaults_to_https() {
        let endpoint = BackendEndpoint::parse("example.com:443").expect("endpoint");
        assert_eq!(endpoint.scheme(), BackendScheme::Https);
        assert_eq!(endpoint.authority(), "example.com:443");
        assert_eq!(endpoint.origin(), "https://example.com:443");
    }

    #[test]
    fn parse_explicit_http_is_supported() {
        let endpoint = BackendEndpoint::parse("http://127.0.0.1:8080").expect("endpoint");
        assert_eq!(endpoint.scheme(), BackendScheme::Http);
        assert_eq!(endpoint.authority(), "127.0.0.1:8080");
    }

    #[test]
    fn parse_bracketed_ipv6() {
        let endpoint = BackendEndpoint::parse("https://[::1]:8443").expect("endpoint");
        assert_eq!(endpoint.scheme(), BackendScheme::Https);
        assert_eq!(endpoint.authority(), "[::1]:8443");
    }

    #[test]
    fn parse_rejects_path_query_and_fragment() {
        assert!(BackendEndpoint::parse("https://example.com:443/api").is_err());
        assert!(BackendEndpoint::parse("https://example.com:443?a=1").is_err());
        assert!(BackendEndpoint::parse("https://example.com:443#frag").is_err());
    }

    #[test]
    fn parse_rejects_invalid_authority() {
        assert!(BackendEndpoint::parse("127.0.0.1:abc").is_err());
        assert!(BackendEndpoint::parse("::1:443").is_err());
        assert!(BackendEndpoint::parse("https://:443").is_err());
    }

    #[test]
    fn parse_rejects_malformed_dns_hostnames() {
        assert!(BackendEndpoint::parse("bad_host:443").is_err());
        assert!(BackendEndpoint::parse("-bad.example.com:443").is_err());
        assert!(BackendEndpoint::parse("bad-.example.com:443").is_err());
        assert!(BackendEndpoint::parse("a..b.example.com:443").is_err());
    }

    #[test]
    fn parse_accepts_idna_hostname() {
        let endpoint = BackendEndpoint::parse("bücher.example:443").expect("idna host");
        assert_eq!(endpoint.scheme(), BackendScheme::Https);
        assert_eq!(endpoint.authority(), "bücher.example:443");
    }

    #[test]
    fn parse_defaults_port_from_scheme() {
        let ep = BackendEndpoint::parse("https://wearebackbenchers.info").expect("https no port");
        assert_eq!(ep.scheme(), BackendScheme::Https);
        assert_eq!(ep.authority(), "wearebackbenchers.info:443");
        assert_eq!(ep.origin(), "https://wearebackbenchers.info:443");

        let ep = BackendEndpoint::parse("http://localhost").expect("http no port");
        assert_eq!(ep.scheme(), BackendScheme::Http);
        assert_eq!(ep.authority(), "localhost:80");

        let ep = BackendEndpoint::parse("127.0.0.1").expect("bare host defaults https:443");
        assert_eq!(ep.scheme(), BackendScheme::Https);
        assert_eq!(ep.authority(), "127.0.0.1:443");
    }

    #[test]
    fn uri_for_path_normalizes_empty_and_relative_paths() {
        let endpoint = BackendEndpoint::parse("backend.local:443").expect("endpoint");
        assert_eq!(endpoint.uri_for_path(""), "https://backend.local:443/");
        assert_eq!(
            endpoint.uri_for_path("/health"),
            "https://backend.local:443/health"
        );
        assert_eq!(
            endpoint.uri_for_path("health"),
            "https://backend.local:443/health"
        );
    }

    #[test]
    fn authority_helpers_extract_hostname_and_port() {
        let endpoint = BackendEndpoint::parse("https://example.com").expect("endpoint");
        assert_eq!(endpoint.authority_host(), "example.com");
        assert_eq!(endpoint.authority_port(), 443);
        assert!(!endpoint.authority_is_ip_literal());
    }

    #[test]
    fn authority_helpers_extract_ipv6_literal_host_and_port() {
        let endpoint = BackendEndpoint::parse("https://[::1]:8443").expect("endpoint");
        assert_eq!(endpoint.authority_host(), "::1");
        assert_eq!(endpoint.authority_port(), 8443);
        assert!(endpoint.authority_is_ip_literal());
    }
}
