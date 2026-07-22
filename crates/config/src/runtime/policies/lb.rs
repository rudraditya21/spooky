use super::{config_invalid, normalize_optional_string};
use crate::{
    config::LoadBalancing,
    runtime::RuntimeConfigError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeLoadBalancingStrategy {
    RoundRobin,
    ConsistentHash,
    Random,
    LeastConnections,
    LatencyAware,
    StickyCid,
    Other,
}

impl RuntimeLoadBalancingStrategy {
    pub fn from_lb_type(lb_type: &str) -> Self {
        match lb_type.trim().to_ascii_lowercase().as_str() {
            "round-robin" | "round_robin" | "rr" => Self::RoundRobin,
            "consistent-hash" | "consistent_hash" | "ch" => Self::ConsistentHash,
            "random" => Self::Random,
            "least-connections" | "least_connections" | "lc" => Self::LeastConnections,
            "latency-aware" | "latency_aware" | "la" => Self::LatencyAware,
            "sticky-cid" | "sticky_cid" | "cid-sticky" | "cid_sticky" => Self::StickyCid,
            _ => Self::Other,
        }
    }

    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::RoundRobin => "round-robin",
            Self::ConsistentHash => "consistent-hash",
            Self::Random => "random",
            Self::LeastConnections => "least-connections",
            Self::LatencyAware => "latency-aware",
            Self::StickyCid => "sticky-cid",
            Self::Other => "unsupported",
        }
    }

    pub fn supports_readonly_alternate_pick(self) -> bool {
        !matches!(self, Self::ConsistentHash | Self::StickyCid | Self::Other)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeRequestKeySpec {
    Path,
    Authority,
    Method,
    Cid,
    StickyCid,
    PeerIp,
    ClientIp,
    BearerToken,
    Header(String),
    Cookie(String),
    Query(String),
}

impl RuntimeRequestKeySpec {
    pub(crate) fn normalize(raw: &str) -> Result<Self, RuntimeConfigError> {
        let normalized = raw.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "path" => Ok(Self::Path),
            "authority" => Ok(Self::Authority),
            "method" => Ok(Self::Method),
            "cid" => Ok(Self::Cid),
            "sticky-cid" => Ok(Self::StickyCid),
            "peer_ip" => Ok(Self::PeerIp),
            "client_ip" => Ok(Self::ClientIp),
            "bearer_token" => Ok(Self::BearerToken),
            _ => {
                let Some((source, key_name)) = normalized.split_once(':') else {
                    return Err(config_invalid(format!(
                        "unsupported request key spec '{}'",
                        raw
                    )));
                };
                if key_name.trim().is_empty() {
                    return Err(config_invalid(format!(
                        "unsupported request key spec '{}'",
                        raw
                    )));
                }
                match source {
                    "header" => Ok(Self::Header(key_name.to_string())),
                    "cookie" => Ok(Self::Cookie(key_name.to_string())),
                    "query" => Ok(Self::Query(key_name.to_string())),
                    _ => Err(config_invalid(format!(
                        "unsupported request key spec '{}'",
                        raw
                    ))),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeAlternateBackendPolicy {
    pub readonly_lb_pick: bool,
    pub healthy_fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLoadBalancingPolicy {
    pub strategy: RuntimeLoadBalancingStrategy,
    pub key: Option<String>,
    pub key_spec: Option<RuntimeRequestKeySpec>,
    pub alternate_backend: RuntimeAlternateBackendPolicy,
}

impl RuntimeLoadBalancingPolicy {
    pub(crate) fn normalize(load_balancing: &LoadBalancing) -> Result<Self, RuntimeConfigError> {
        let strategy = RuntimeLoadBalancingStrategy::from_lb_type(&load_balancing.lb_type);
        if matches!(strategy, RuntimeLoadBalancingStrategy::Other) {
            return Err(config_invalid(format!(
                "unsupported load balancing type '{}'",
                load_balancing.lb_type
            )));
        }

        Ok(Self {
            strategy,
            key: normalize_optional_string(load_balancing.key.as_deref()),
            key_spec: load_balancing
                .key
                .as_deref()
                .map(RuntimeRequestKeySpec::normalize)
                .transpose()?,
            alternate_backend: RuntimeAlternateBackendPolicy {
                readonly_lb_pick: strategy.supports_readonly_alternate_pick(),
                healthy_fallback: true,
            },
        })
    }

    #[cfg(test)]
    pub(crate) fn as_config(&self) -> LoadBalancing {
        LoadBalancing {
            lb_type: self.strategy.canonical_name().to_string(),
            key: self.key.clone(),
        }
    }
}
