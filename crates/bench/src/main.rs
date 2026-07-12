mod allocator;
mod benchmark;
mod cli;
mod io;
mod manifest;
mod markdown;
mod profiler;
mod promotion;
mod regression;
mod report;
mod utils;

use crate::benchmark::macro_bench::run_macro_suite;
use crate::benchmark::micro_bench::run_micro_suite;
use crate::cli::{Args, BenchSuite, FailOn};
use crate::io::{
    load_release_index, load_report, merge_reports, resolve_baseline_paths, write_report,
};
use crate::manifest::load_manifest;
use crate::markdown::write_markdown;
use crate::promotion::run_promotion;
use crate::regression::{RegressionSeverity, compare_reports, format_issue, resolve_gate_config};
use crate::report::BenchReport;
use crate::utils::{suite_label, unix_now};

use clap::Parser;

fn print_summary(report: &BenchReport) {
    println!(
        "{:<8} {:<30} {:>7} {:>12} {:>10} {:>12} {:>9}",
        "kind", "case", "scale", "ns/op", "cpu%", "ops/s", "p99(ns)"
    );
    for case in &report.cases {
        println!(
            "{:<8} {:<30} {:>7} {:>12.2} {:>10.2} {:>12.2} {:>9.0}",
            case.kind,
            case.name,
            case.scale,
            case.latency_ns_per_op,
            case.cpu_pct,
            case.throughput_ops_per_sec,
            case.latency_p99_ns
        );
    }
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    if args.promote_release.is_some() {
        return run_promotion(&args);
    }

    let manifest = load_manifest(&args.manifest)?;
    let profile = manifest
        .profiles
        .get(&args.profile)
        .ok_or_else(|| format!("profile '{}' missing in manifest", args.profile))?;

    let mut cases = Vec::new();
    match args.suite {
        BenchSuite::Micro => {
            cases.extend(run_micro_suite(profile, &manifest.micro)?);
        }
        BenchSuite::Macro => {
            cases.extend(run_macro_suite(profile, &manifest.macro_suite)?);
        }
        BenchSuite::All => {
            cases.extend(run_micro_suite(profile, &manifest.micro)?);
            cases.extend(run_macro_suite(profile, &manifest.macro_suite)?);
        }
    }

    cases.sort_by(|left, right| {
        (&left.kind, &left.name, left.scale).cmp(&(&right.kind, &right.name, right.scale))
    });

    let report = BenchReport {
        suite: "spooky-performance-regression".to_string(),
        report_kind: suite_label(args.suite).to_string(),
        profile: args.profile.clone(),
        generated_unix_secs: unix_now(),
        cpu_threshold: args.cpu_threshold.unwrap_or(manifest.gates.cpu.warn_pct),
        mem_threshold: args.mem_threshold.unwrap_or(manifest.gates.memory.warn_pct),
        cases,
    };

    print_summary(&report);
    write_report(&args.output, &report)?;

    let mut issues = Vec::new();
    if args.check_baseline {
        let release_index = load_release_index(&args.baseline_index)?;
        let baseline_paths = resolve_baseline_paths(&args, &release_index)?;
        let mut baseline_reports = Vec::with_capacity(baseline_paths.len());
        for path in &baseline_paths {
            baseline_reports.push(load_report(path)?);
        }
        let baseline = merge_reports(baseline_reports);

        let gates = resolve_gate_config(manifest.gates.clone(), &args);
        issues = compare_reports(&report, &baseline, &gates);
    }

    if let Some(markdown) = &args.markdown_out {
        write_markdown(markdown, &report, &issues, args.fail_on)?;
    }

    if !issues.is_empty() {
        let severe_count = issues
            .iter()
            .filter(|issue| issue.severity == RegressionSeverity::Severe)
            .count();
        let warn_count = issues.len().saturating_sub(severe_count);

        for issue in &issues {
            eprintln!("{}", format_issue(issue));
        }

        let fail = match args.fail_on {
            FailOn::Severe => severe_count > 0,
            FailOn::Any => !issues.is_empty(),
        };

        if fail {
            return Err(format!(
                "benchmark regression gate failed (severe={severe_count}, warn={warn_count}, mode={:?})",
                args.fail_on
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{GateMetric, RegressionSeverity, classify_regression};

    fn gate(
        warn_pct: f64,
        severe_pct: f64,
        zero_baseline_limit: f64,
        min_delta_abs: f64,
    ) -> GateMetric {
        GateMetric {
            warn_pct,
            severe_pct,
            zero_baseline_limit,
            min_delta_abs,
        }
    }

    #[test]
    fn min_delta_abs_suppresses_small_absolute_memory_drift() {
        let memory_gate = gate(0.20, 0.40, 128.0, 256.0);
        let regression = classify_regression(320.0, 200.0, &memory_gate, 128.0);
        assert!(regression.is_none());
    }

    #[test]
    fn min_delta_abs_still_allows_large_absolute_memory_regressions() {
        let memory_gate = gate(0.20, 0.40, 128.0, 256.0);
        let regression = classify_regression(520.0, 200.0, &memory_gate, 128.0);
        assert!(matches!(
            regression,
            Some((RegressionSeverity::Severe, _, _))
        ));
    }
}
