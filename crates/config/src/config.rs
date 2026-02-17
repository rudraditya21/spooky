

use serde::{Deserialize, Serialize};

use crate::default::{
    get_default_address, get_default_cooldown_ms, get_default_failure_threshold,
    get_default_health_timeout, get_default_interval, get_default_load_balancing,
    get_default_log, get_default_log_level, get_default_path, get_default_port,
    get_default_protocol, get_default_success_threshold, get_default_weight,
};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub version: u32,

    pub listen: Listen,
    pub upstreams: Vec<Upstream>, // we can use HashMap<Route, pool>
    pub routing: Routing,

    #[serde(default = "get_default_log")]
    pub log: Log,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Listen {
    #[serde(default = "get_default_protocol")]
    pub protocol: String, // "http3"

    #[serde(default = "get_default_port")]
    pub port: u32, // 9889

    #[serde(default = "get_default_address")]
    pub address: String, // "0.0.0.0"
    pub tls: Tls,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Tls {
    pub cert: String, // "/path/to/cert"
    pub key: String,  // "/path/to/key"
}

#[derive(Debug, Deserialize, Clone)]
pub struct Upstream {
    pub name: String,

    #[serde(default = "get_default_load_balancing")]
    pub load_balancing: LoadBalancing,

    pub backends: Vec<Backend>
}

#[derive(Debug, Deserialize, Clone)]
pub struct Backend {
    pub id: String,      // "backend1"
    pub address: String, // "10.0.1.100:8080"

    #[serde(default = "get_default_weight")]
    pub weight: u32, // 100
    pub health_check: HealthCheck,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Routing {
    pub rules: Vec<RouteRule>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouteRule {
    #[serde(rename = "match")]
    pub matcher: RouteMatch,

    pub upstream: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouteMatch {
    #[serde(default)]
    pub host: Option<String>,

    #[serde(default)]
    pub path_prefix: Option<String>,

    #[serde(default)]
    pub method: Option<String>, // future-safe
}

#[derive(Debug, Deserialize, Clone)]
pub struct HealthCheck {
    #[serde(default = "get_default_path")]
    pub path: String, // "/health"

    #[serde(default = "get_default_interval")]
    pub interval: u64, // "5000" (write in number of milli seconds)

    #[serde(default = "get_default_health_timeout")]
    pub timeout_ms: u64,

    #[serde(default = "get_default_failure_threshold")]
    pub failure_threshold: u32,

    #[serde(default = "get_default_success_threshold")]
    pub success_threshold: u32,

    #[serde(default = "get_default_cooldown_ms")]
    pub cooldown_ms: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct LoadBalancing {
    #[serde(rename = "type")]
    pub lb_type: String, // "weight-based", "least_connection", etc.
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Log {
    // whisper -> trace
    // haunt -> debug
    // spooky -> info
    // scream -> warn
    // poltergeist -> error
    // silence -> off

    #[serde(default = "get_default_log_level")]
    pub level: String, // "info, warn, error"
}