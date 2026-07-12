use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BenchReport {
    #[serde(default)]
    pub suite: String,
    #[serde(default)]
    pub report_kind: String,
    #[serde(default)]
    pub profile: String,
    #[serde(default)]
    pub generated_unix_secs: u64,
    #[serde(default)]
    pub cpu_threshold: f64,
    #[serde(default)]
    pub mem_threshold: f64,
    #[serde(default)]
    pub cases: Vec<BenchCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchCase {
    #[serde(default = "default_case_kind")]
    pub kind: String,
    pub name: String,
    pub scale: usize,
    pub iterations: u64,
    pub duration_ns: u128,
    pub latency_ns_per_op: f64,
    #[serde(default)]
    pub throughput_ops_per_sec: f64,
    pub alloc_calls: u64,
    pub alloc_bytes: u64,
    pub rss_delta_kb: u64,
    #[serde(default)]
    pub cpu_pct: f64,
    #[serde(default)]
    pub latency_p50_ns: f64,
    #[serde(default)]
    pub latency_p95_ns: f64,
    #[serde(default)]
    pub latency_p99_ns: f64,
    #[serde(default)]
    pub latency_max_ns: f64,
    #[serde(default)]
    pub latency_sampled: bool,
}

fn default_case_kind() -> String {
    "micro".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReleaseBaselineIndex {
    #[serde(default)]
    pub current_release: String,
    #[serde(default)]
    pub releases: HashMap<String, ReleaseBaselineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseBaselineEntry {
    pub micro: String,
    #[serde(rename = "macro")]
    pub macro_report: String,
}
