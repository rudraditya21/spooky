mod allocator;
mod benchmark;
mod cli;
mod manifest;
mod markdown;
mod profiler;
mod regression;
mod report;

use crate::benchmark::macro_bench::run_macro_suite;
use crate::benchmark::micro_bench::run_micro_suite;
use crate::cli::{Args, BenchSuite, FailOn};
use crate::manifest::{GateMetric, load_manifest};
use crate::markdown::write_markdown;
use crate::regression::{
    RegressionSeverity, classify_regression, compare_reports, format_issue, resolve_gate_config,
};
use crate::report::{BenchReport, ReleaseBaselineEntry, ReleaseBaselineIndex};

use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};

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

fn load_report(path: &Path) -> Result<BenchReport, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read baseline '{}': {err}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|err| format!("failed to parse baseline '{}': {err}", path.display()))
}

fn load_release_index(path: &Path) -> Result<ReleaseBaselineIndex, String> {
    if !path.exists() {
        return Ok(ReleaseBaselineIndex::default());
    }
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read baseline index '{}': {err}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|err| format!("failed to parse baseline index '{}': {err}", path.display()))
}

fn write_release_index(path: &Path, index: &ReleaseBaselineIndex) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create baseline index dir '{}': {err}",
                parent.display()
            )
        })?;
    }
    let text = serde_json::to_string_pretty(index)
        .map_err(|err| format!("failed to serialize baseline index: {err}"))?;
    fs::write(path, text)
        .map_err(|err| format!("failed to write baseline index '{}': {err}", path.display()))
}

fn write_report(path: &Path, report: &BenchReport) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create output dir '{}': {err}", parent.display()))?;
    }
    let json =
        serde_json::to_string_pretty(report).map_err(|err| format!("serialize report: {err}"))?;
    fs::write(path, json)
        .map_err(|err| format!("failed to write report '{}': {err}", path.display()))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn suite_label(suite: BenchSuite) -> &'static str {
    match suite {
        BenchSuite::Micro => "micro",
        BenchSuite::Macro => "macro",
        BenchSuite::All => "all",
    }
}

fn resolve_baseline_paths(
    args: &Args,
    release_index: &ReleaseBaselineIndex,
) -> Result<Vec<PathBuf>, String> {
    if let Some(path) = &args.baseline {
        return Ok(vec![path.clone()]);
    }

    let release = args
        .baseline_release
        .clone()
        .or_else(|| {
            (!release_index.current_release.is_empty()).then_some(release_index.current_release.clone())
        })
        .ok_or_else(|| {
            "baseline not specified; pass --baseline or configure --baseline-release / current_release in baseline index".to_string()
        })?;

    let entry = release_index
        .releases
        .get(&release)
        .ok_or_else(|| format!("release '{release}' missing from baseline index"))?;

    let paths = match args.suite {
        BenchSuite::Micro => vec![PathBuf::from(&entry.micro)],
        BenchSuite::Macro => vec![PathBuf::from(&entry.macro_report)],
        BenchSuite::All => vec![
            PathBuf::from(&entry.micro),
            PathBuf::from(&entry.macro_report),
        ],
    };

    Ok(paths)
}

fn merge_reports(reports: Vec<BenchReport>) -> BenchReport {
    let mut merged = BenchReport {
        suite: "spooky-performance-baseline".to_string(),
        report_kind: "merged".to_string(),
        profile: "baseline".to_string(),
        generated_unix_secs: unix_now(),
        ..BenchReport::default()
    };

    for report in reports {
        merged.cases.extend(report.cases);
    }

    merged.cases.sort_by(|left, right| {
        (&left.kind, &left.name, left.scale).cmp(&(&right.kind, &right.name, right.scale))
    });
    merged
}

fn run_promotion(args: &Args) -> Result<(), String> {
    let release = args
        .promote_release
        .as_ref()
        .ok_or_else(|| "internal error: promote_release missing".to_string())?;

    let mut index = load_release_index(&args.baseline_index)?;

    let release_dir = PathBuf::from("bench").join("baselines").join(release);
    fs::create_dir_all(&release_dir).map_err(|err| {
        format!(
            "failed to create release baseline directory '{}': {err}",
            release_dir.display()
        )
    })?;

    if !args.promote_micro_report.exists() {
        return Err(format!(
            "micro report '{}' does not exist",
            args.promote_micro_report.display()
        ));
    }
    if !args.promote_macro_report.exists() {
        return Err(format!(
            "macro report '{}' does not exist",
            args.promote_macro_report.display()
        ));
    }

    let micro_dest = release_dir.join("micro.json");
    let macro_dest = release_dir.join("macro.json");

    fs::copy(&args.promote_micro_report, &micro_dest).map_err(|err| {
        format!(
            "failed to copy micro report '{}' -> '{}': {err}",
            args.promote_micro_report.display(),
            micro_dest.display()
        )
    })?;
    fs::copy(&args.promote_macro_report, &macro_dest).map_err(|err| {
        format!(
            "failed to copy macro report '{}' -> '{}': {err}",
            args.promote_macro_report.display(),
            macro_dest.display()
        )
    })?;

    let entry = ReleaseBaselineEntry {
        micro: micro_dest.to_string_lossy().to_string(),
        macro_report: macro_dest.to_string_lossy().to_string(),
    };
    index.releases.insert(release.clone(), entry);
    if args.set_current_release {
        index.current_release = release.clone();
    }

    write_release_index(&args.baseline_index, &index)?;

    println!(
        "Promoted release baseline '{}' (micro='{}', macro='{}')",
        release,
        micro_dest.display(),
        macro_dest.display()
    );

    Ok(())
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
