use std::{collections::HashMap, fs, path::Path};

use serde::Deserialize;

use crate::utils::{
    default_macro_stream_chunk_bytes, default_macro_stream_chunks, default_macro_stream_iterations,
    default_macro_traffic_mix_iterations, default_true,
};

#[derive(Debug, Deserialize)]
pub struct BenchManifest {
    pub version: u32,
    pub profiles: HashMap<String, BenchProfile>,
    #[serde(default)]
    pub micro: MicroSuiteConfig,
    #[serde(rename = "macro", default)]
    pub macro_suite: MacroSuiteConfig,
    pub gates: GateConfig,
}

#[derive(Debug, Deserialize)]
pub struct BenchProfile {
    pub scales: Vec<usize>,
    #[serde(default)]
    pub macro_scales: Vec<usize>,
    #[serde(default = "default_macro_traffic_mix_iterations")]
    pub macro_traffic_mix_iterations: u64,
    #[serde(default = "default_macro_stream_iterations")]
    pub macro_long_lived_stream_iterations: u64,
    #[serde(default = "default_macro_stream_chunks")]
    pub macro_long_lived_stream_chunks: usize,
    #[serde(default = "default_macro_stream_chunk_bytes")]
    pub macro_long_lived_stream_chunk_bytes: usize,
}

#[derive(Debug, Deserialize)]
pub struct MicroSuiteConfig {
    #[serde(default = "default_true")]
    pub include_h3_header_collection: bool,
}

#[derive(Debug, Deserialize)]
pub struct MacroSuiteConfig {
    #[serde(default = "default_true")]
    pub include_traffic_mix: bool,
    #[serde(default = "default_true")]
    pub include_long_lived_stream: bool,
}

impl Default for MicroSuiteConfig {
    fn default() -> Self {
        Self {
            include_h3_header_collection: true,
        }
    }
}

impl Default for MacroSuiteConfig {
    fn default() -> Self {
        Self {
            include_traffic_mix: true,
            include_long_lived_stream: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct GateMetric {
    pub warn_pct: f64,
    pub severe_pct: f64,
    #[serde(default)]
    pub zero_baseline_limit: f64,
    #[serde(default)]
    pub min_delta_abs: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GateConfig {
    pub cpu: GateMetric,
    pub memory: GateMetric,
    pub alloc_calls: GateMetric,
    pub alloc_bytes: GateMetric,
    pub tail_p99: GateMetric,
}

pub fn load_manifest(path: &Path) -> Result<BenchManifest, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read manifest '{}': {err}", path.display()))?;
    let manifest: BenchManifest = serde_yaml::from_str(&text)
        .map_err(|err| format!("failed to parse manifest '{}': {err}", path.display()))?;

    if manifest.version != 1 {
        return Err(format!(
            "unsupported bench manifest version {} (expected 1)",
            manifest.version
        ));
    }
    Ok(manifest)
}
