use std::net::IpAddr;

use http::HeaderValue;
use spooky_config::config::{ForwardedHeaderPolicy, ForwardedHeaderPolicyMode};

use crate::{
    BridgeError,
    context::{ForwardedHeaderChains, ForwardedHeaderValues},
};

pub fn build_forwarded_header_values(
    policy: &ForwardedHeaderPolicy,
    inbound: ForwardedHeaderChains<'_>,
    client_ip: IpAddr,
    host_value: &str,
) -> Result<ForwardedHeaderValues, BridgeError> {
    let forwarded_current = format!(
        "for={};proto=https;host=\"{}\"",
        forwarded_for_value(client_ip),
        escape_forwarded_host(host_value),
    );
    let x_forwarded_for_current = client_ip.to_string();
    let x_forwarded_proto_current = "https";
    let x_forwarded_host_current = host_value;

    Ok(ForwardedHeaderValues {
        forwarded: merge_forwarded_chain(
            policy.mode,
            inbound.forwarded,
            Some(forwarded_current.as_bytes()),
        )?,
        x_forwarded_for: merge_forwarded_chain(
            policy.mode,
            inbound.x_forwarded_for,
            Some(x_forwarded_for_current.as_bytes()),
        )?,
        x_forwarded_proto: merge_forwarded_chain(
            policy.mode,
            inbound.x_forwarded_proto,
            Some(x_forwarded_proto_current.as_bytes()),
        )?,
        x_forwarded_host: merge_forwarded_chain(
            policy.mode,
            inbound.x_forwarded_host,
            Some(x_forwarded_host_current.as_bytes()),
        )?,
    })
}

pub fn merge_forwarded_chain(
    mode: ForwardedHeaderPolicyMode,
    inbound: &[Vec<u8>],
    current: Option<&[u8]>,
) -> Result<Option<HeaderValue>, BridgeError> {
    match mode {
        ForwardedHeaderPolicyMode::Preserve => join_header_chain(inbound),
        ForwardedHeaderPolicyMode::Append => {
            let mut values = inbound.to_vec();
            if let Some(current) = current {
                values.push(current.to_vec());
            }
            join_header_chain(&values)
        }
        ForwardedHeaderPolicyMode::Overwrite => current
            .map(HeaderValue::from_bytes)
            .transpose()
            .map_err(|_| BridgeError::InvalidHeader),
    }
}

pub fn join_header_chain(values: &[Vec<u8>]) -> Result<Option<HeaderValue>, BridgeError> {
    if values.is_empty() {
        return Ok(None);
    }

    let mut joined = Vec::new();
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            joined.extend_from_slice(b", ");
        }
        joined.extend_from_slice(value);
    }

    HeaderValue::from_bytes(&joined)
        .map(Some)
        .map_err(|_| BridgeError::InvalidHeader)
}

pub fn forwarded_for_value(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("\"[{}]\"", v6),
    }
}

pub fn escape_forwarded_host(host: &str) -> String {
    host.replace('\\', "\\\\").replace('"', "\\\"")
}
