use crate::cli::Args;
use crate::manifest::{GateConfig, GateMetric};
use crate::report::{BenchCase, BenchReport};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct RegressionIssue {
    pub severity: RegressionSeverity,
    pub metric: &'static str,
    pub case: String,
    pub scale: usize,
    pub kind: String,
    pub current: f64,
    pub baseline: f64,
    pub warn_limit: f64,
    pub severe_limit: f64,
    pub unit: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegressionSeverity {
    Warn,
    Severe,
}

pub fn classify_regression(
    current: f64,
    baseline: f64,
    gate: &GateMetric,
    zero_limit: f64,
) -> Option<(RegressionSeverity, f64, f64)> {
    let warn = gate.warn_pct.max(0.0);
    let severe = gate.severe_pct.max(warn);

    if baseline > 0.0 {
        // For tiny baselines (for example, allocation calls close to zero),
        // percent-only thresholds are too sensitive to allocator/runtime noise
        // across OS/toolchain environments. Apply a configurable floor so gates
        // remain stable while still catching meaningful growth.
        let effective_baseline = if gate.zero_baseline_limit > 0.0 {
            baseline.max(gate.zero_baseline_limit)
        } else {
            baseline
        };
        let warn_limit = effective_baseline * (1.0 + warn);
        let severe_limit = effective_baseline * (1.0 + severe);
        let delta = current - baseline;
        let min_delta_abs = gate.min_delta_abs.max(0.0);
        if delta < min_delta_abs {
            return None;
        }
        if current > severe_limit {
            return Some((RegressionSeverity::Severe, warn_limit, severe_limit));
        }
        if current > warn_limit {
            return Some((RegressionSeverity::Warn, warn_limit, severe_limit));
        }
        return None;
    }

    let base_limit = if gate.zero_baseline_limit > 0.0 {
        gate.zero_baseline_limit
    } else {
        zero_limit
    };
    let warn_limit = base_limit;
    let severe_limit = base_limit * (1.0 + severe);
    if current > severe_limit {
        return Some((RegressionSeverity::Severe, warn_limit, severe_limit));
    }
    if current > warn_limit {
        return Some((RegressionSeverity::Warn, warn_limit, severe_limit));
    }
    None
}

pub fn compare_reports(
    current: &BenchReport,
    baseline: &BenchReport,
    gates: &GateConfig,
) -> Vec<RegressionIssue> {
    let baseline_map: HashMap<(String, String, usize), &BenchCase> = baseline
        .cases
        .iter()
        .map(|case| ((case.kind.clone(), case.name.clone(), case.scale), case))
        .collect();

    let mut cpu_ratios = Vec::new();
    let mut tail_ratios = Vec::new();
    for case in &current.cases {
        let key = (case.kind.clone(), case.name.clone(), case.scale);
        let Some(base) = baseline_map.get(&key) else {
            continue;
        };
        if base.latency_ns_per_op > 0.0 {
            cpu_ratios.push(case.latency_ns_per_op / base.latency_ns_per_op);
        }
        if base.latency_sampled && case.latency_sampled && base.latency_p99_ns > 0.0 {
            tail_ratios.push(case.latency_p99_ns / base.latency_p99_ns);
        }
    }
    // Normalize only for slower environments. Faster runs should not tighten
    // baselines and create artificial regressions when a subset of cases
    // improves significantly.
    let cpu_factor = if cpu_ratios.len() >= 5 {
        median(&mut cpu_ratios).max(1.0)
    } else {
        1.0
    };
    let tail_factor = if tail_ratios.len() >= 5 {
        median(&mut tail_ratios).max(1.0)
    } else {
        1.0
    };

    let mut issues = Vec::new();

    for case in &current.cases {
        let key = (case.kind.clone(), case.name.clone(), case.scale);
        let Some(base) = baseline_map.get(&key) else {
            continue;
        };

        let normalized_cpu_baseline = if base.latency_ns_per_op > 0.0 {
            base.latency_ns_per_op * cpu_factor
        } else {
            base.latency_ns_per_op
        };
        if let Some((severity, warn_limit, severe_limit)) = classify_regression(
            case.latency_ns_per_op,
            normalized_cpu_baseline,
            &gates.cpu,
            0.0,
        ) {
            issues.push(RegressionIssue {
                severity,
                metric: "cpu_ns_per_op",
                case: case.name.clone(),
                scale: case.scale,
                kind: case.kind.clone(),
                current: case.latency_ns_per_op,
                baseline: normalized_cpu_baseline,
                warn_limit,
                severe_limit,
                unit: "ns/op",
            });
        }

        if let Some((severity, warn_limit, severe_limit)) = classify_regression(
            case.alloc_calls as f64,
            base.alloc_calls as f64,
            &gates.alloc_calls,
            32.0,
        ) {
            issues.push(RegressionIssue {
                severity,
                metric: "alloc_calls",
                case: case.name.clone(),
                scale: case.scale,
                kind: case.kind.clone(),
                current: case.alloc_calls as f64,
                baseline: base.alloc_calls as f64,
                warn_limit,
                severe_limit,
                unit: "calls",
            });
        }

        if let Some((severity, warn_limit, severe_limit)) = classify_regression(
            case.alloc_bytes as f64,
            base.alloc_bytes as f64,
            &gates.alloc_bytes,
            (16 * 1024) as f64,
        ) {
            issues.push(RegressionIssue {
                severity,
                metric: "alloc_bytes",
                case: case.name.clone(),
                scale: case.scale,
                kind: case.kind.clone(),
                current: case.alloc_bytes as f64,
                baseline: base.alloc_bytes as f64,
                warn_limit,
                severe_limit,
                unit: "bytes",
            });
        }

        if let Some((severity, warn_limit, severe_limit)) = classify_regression(
            case.rss_delta_kb as f64,
            base.rss_delta_kb as f64,
            &gates.memory,
            128.0,
        ) {
            issues.push(RegressionIssue {
                severity,
                metric: "rss_delta_kb",
                case: case.name.clone(),
                scale: case.scale,
                kind: case.kind.clone(),
                current: case.rss_delta_kb as f64,
                baseline: base.rss_delta_kb as f64,
                warn_limit,
                severe_limit,
                unit: "KB",
            });
        }

        // Legacy baseline reports may not have tail latency fields populated.
        // Skip tail-p99 regression checks when baseline p99 is unavailable.
        if base.latency_sampled && case.latency_sampled && base.latency_p99_ns > 0.0 {
            let normalized_tail_baseline = base.latency_p99_ns * tail_factor;
            if let Some((severity, warn_limit, severe_limit)) = classify_regression(
                case.latency_p99_ns,
                normalized_tail_baseline,
                &gates.tail_p99,
                0.0,
            ) {
                issues.push(RegressionIssue {
                    severity,
                    metric: "tail_p99_ns",
                    case: case.name.clone(),
                    scale: case.scale,
                    kind: case.kind.clone(),
                    current: case.latency_p99_ns,
                    baseline: normalized_tail_baseline,
                    warn_limit,
                    severe_limit,
                    unit: "ns",
                });
            }
        }
    }

    issues
}

fn median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 1.0;
    }
    values.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

pub fn format_issue(issue: &RegressionIssue) -> String {
    let severity = match issue.severity {
        RegressionSeverity::Warn => "WARN",
        RegressionSeverity::Severe => "SEVERE",
    };
    let delta_pct = if issue.baseline > 0.0 {
        ((issue.current / issue.baseline) - 1.0) * 100.0
    } else {
        0.0
    };

    format!(
        "[{severity}] {} in {}:{} [{}] => {:.2}{} (baseline {:.2}{}, warn>{:.2}{}, severe>{:.2}{}; delta {:.1}%)",
        issue.metric,
        issue.case,
        issue.scale,
        issue.kind,
        issue.current,
        issue.unit,
        issue.baseline,
        issue.unit,
        issue.warn_limit,
        issue.unit,
        issue.severe_limit,
        issue.unit,
        delta_pct
    )
}

pub fn resolve_gate_config(mut gates: GateConfig, args: &Args) -> GateConfig {
    if let Some(cpu_override) = args.cpu_threshold {
        gates.cpu.warn_pct = cpu_override;
        gates.cpu.severe_pct = cpu_override;
    }
    if let Some(mem_override) = args.mem_threshold {
        gates.memory.warn_pct = mem_override;
        gates.memory.severe_pct = mem_override;
        gates.alloc_calls.warn_pct = mem_override;
        gates.alloc_calls.severe_pct = mem_override;
        gates.alloc_bytes.warn_pct = mem_override;
        gates.alloc_bytes.severe_pct = mem_override;
    }
    gates
}
