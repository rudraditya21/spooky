use std::{hint::black_box, time::Instant};

use crate::{
    allocator::{alloc_snapshot, reset_alloc_counters},
    profiler::{cpu_pct, current_cpu_micros, current_rss_kb, percentile_from_sorted},
    report::BenchCase,
};

const BENCH_SAMPLES: usize = 3;

pub fn run_case_aggregate(
    kind: &str,
    name: &str,
    scale: usize,
    iterations: u64,
    mut op: impl FnMut() -> usize,
) -> BenchCase {
    let warmup_iters = (iterations / 10).clamp(100, 10_000);
    for _ in 0..warmup_iters {
        black_box(op());
    }

    let mut measurements = Vec::with_capacity(BENCH_SAMPLES);
    for _ in 0..BENCH_SAMPLES {
        reset_alloc_counters();
        let rss_before = current_rss_kb().unwrap_or(0);
        let cpu_before = current_cpu_micros();
        let start = Instant::now();
        let mut sink = 0usize;
        for _ in 0..iterations {
            sink ^= op();
        }
        black_box(sink);
        let elapsed = start.elapsed();
        let cpu_after = current_cpu_micros();
        let rss_after = current_rss_kb().unwrap_or(rss_before);
        let (alloc_calls, alloc_bytes) = alloc_snapshot();
        let mean_ns = elapsed.as_secs_f64() * 1e9 / iterations as f64;
        let throughput = if elapsed.as_secs_f64() > 0.0 {
            iterations as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        measurements.push(CaseMeasurement {
            duration_ns: elapsed.as_nanos(),
            mean_ns,
            throughput_ops_per_sec: throughput,
            alloc_calls,
            alloc_bytes,
            rss_delta_kb: rss_after.saturating_sub(rss_before),
            cpu_pct: cpu_pct(cpu_before, cpu_after, elapsed.as_nanos()),
            p50_ns: mean_ns,
            p95_ns: mean_ns,
            p99_ns: mean_ns,
            max_ns: mean_ns,
            latency_sampled: false,
        });
    }
    measurements.sort_by(|left, right| {
        left.mean_ns
            .partial_cmp(&right.mean_ns)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let selected = measurements[measurements.len() / 2];

    BenchCase {
        kind: kind.to_string(),
        name: name.to_string(),
        scale,
        iterations,
        duration_ns: selected.duration_ns,
        latency_ns_per_op: selected.mean_ns,
        throughput_ops_per_sec: selected.throughput_ops_per_sec,
        alloc_calls: selected.alloc_calls,
        alloc_bytes: selected.alloc_bytes,
        rss_delta_kb: selected.rss_delta_kb,
        cpu_pct: selected.cpu_pct,
        latency_p50_ns: selected.p50_ns,
        latency_p95_ns: selected.p95_ns,
        latency_p99_ns: selected.p99_ns,
        latency_max_ns: selected.max_ns,
        latency_sampled: selected.latency_sampled,
    }
}

pub fn run_case_with_latencies(
    kind: &str,
    name: &str,
    scale: usize,
    iterations: u64,
    mut op: impl FnMut() -> usize,
) -> BenchCase {
    let warmup_iters = (iterations / 10).clamp(50, 5_000);
    for _ in 0..warmup_iters {
        black_box(op());
    }

    let mut measurements = Vec::with_capacity(BENCH_SAMPLES);
    for _ in 0..BENCH_SAMPLES {
        reset_alloc_counters();
        let rss_before = current_rss_kb().unwrap_or(0);
        let cpu_before = current_cpu_micros();
        let mut latencies = Vec::with_capacity(iterations.min(200_000) as usize);

        let start = Instant::now();
        let mut sink = 0usize;
        for _ in 0..iterations {
            let op_start = Instant::now();
            sink ^= op();
            latencies.push(op_start.elapsed().as_nanos());
        }
        black_box(sink);
        let elapsed = start.elapsed();
        latencies.sort_unstable();

        let cpu_after = current_cpu_micros();
        let rss_after = current_rss_kb().unwrap_or(rss_before);
        let (alloc_calls, alloc_bytes) = alloc_snapshot();
        let mean_ns = elapsed.as_secs_f64() * 1e9 / iterations as f64;
        let throughput = if elapsed.as_secs_f64() > 0.0 {
            iterations as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        measurements.push(CaseMeasurement {
            duration_ns: elapsed.as_nanos(),
            mean_ns,
            throughput_ops_per_sec: throughput,
            alloc_calls,
            alloc_bytes,
            rss_delta_kb: rss_after.saturating_sub(rss_before),
            cpu_pct: cpu_pct(cpu_before, cpu_after, elapsed.as_nanos()),
            p50_ns: percentile_from_sorted(&latencies, 0.50),
            p95_ns: percentile_from_sorted(&latencies, 0.95),
            p99_ns: percentile_from_sorted(&latencies, 0.99),
            max_ns: latencies.last().copied().unwrap_or(0) as f64,
            latency_sampled: true,
        });
    }
    measurements.sort_by(|left, right| {
        left.mean_ns
            .partial_cmp(&right.mean_ns)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let selected = measurements[measurements.len() / 2];

    BenchCase {
        kind: kind.to_string(),
        name: name.to_string(),
        scale,
        iterations,
        duration_ns: selected.duration_ns,
        latency_ns_per_op: selected.mean_ns,
        throughput_ops_per_sec: selected.throughput_ops_per_sec,
        alloc_calls: selected.alloc_calls,
        alloc_bytes: selected.alloc_bytes,
        rss_delta_kb: selected.rss_delta_kb,
        cpu_pct: selected.cpu_pct,
        latency_p50_ns: selected.p50_ns,
        latency_p95_ns: selected.p95_ns,
        latency_p99_ns: selected.p99_ns,
        latency_max_ns: selected.max_ns,
        latency_sampled: selected.latency_sampled,
    }
}

#[derive(Clone, Copy)]
struct CaseMeasurement {
    duration_ns: u128,
    mean_ns: f64,
    throughput_ops_per_sec: f64,
    alloc_calls: u64,
    alloc_bytes: u64,
    rss_delta_kb: u64,
    cpu_pct: f64,
    p50_ns: f64,
    p95_ns: f64,
    p99_ns: f64,
    max_ns: f64,
    latency_sampled: bool,
}
