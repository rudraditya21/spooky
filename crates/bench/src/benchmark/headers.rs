use smallvec::SmallVec;

use crate::{benchmark::runner::run_case_aggregate, report::BenchCase};

pub fn benchmark_h3_header_collection(scale: usize) -> Vec<BenchCase> {
    const INLINE_HEADERS: usize = 16;
    let small_headers = synth_h3_headers(8);
    let large_headers = synth_h3_headers(24);

    vec![
        run_case_aggregate(
            "micro",
            "h3_headers_collect_vec_small",
            scale,
            header_collect_iterations(scale, false),
            || {
                let mut headers = Vec::with_capacity(small_headers.len());
                for (name, value) in &small_headers {
                    headers.push((name.as_slice().to_vec(), value.as_slice().to_vec()));
                }
                headers.len()
            },
        ),
        run_case_aggregate(
            "micro",
            "h3_headers_collect_smallvec_small",
            scale,
            header_collect_iterations(scale, false),
            || {
                let mut headers = SmallVec::<[(Vec<u8>, Vec<u8>); INLINE_HEADERS]>::with_capacity(
                    small_headers.len(),
                );
                for (name, value) in &small_headers {
                    headers.push((name.as_slice().to_vec(), value.as_slice().to_vec()));
                }
                headers.len()
            },
        ),
        run_case_aggregate(
            "micro",
            "h3_headers_collect_vec_large",
            scale,
            header_collect_iterations(scale, true),
            || {
                let mut headers = Vec::with_capacity(large_headers.len());
                for (name, value) in &large_headers {
                    headers.push((name.as_slice().to_vec(), value.as_slice().to_vec()));
                }
                headers.len()
            },
        ),
        run_case_aggregate(
            "micro",
            "h3_headers_collect_smallvec_large",
            scale,
            header_collect_iterations(scale, true),
            || {
                let mut headers = SmallVec::<[(Vec<u8>, Vec<u8>); INLINE_HEADERS]>::with_capacity(
                    large_headers.len(),
                );
                for (name, value) in &large_headers {
                    headers.push((name.as_slice().to_vec(), value.as_slice().to_vec()));
                }
                headers.len()
            },
        ),
    ]
}

fn header_collect_iterations(scale: usize, is_large_header_set: bool) -> u64 {
    match (scale, is_large_header_set) {
        (100, false) => 200_000,
        (1_000, false) => 120_000,
        (10_000, false) => 60_000,
        (100, true) => 120_000,
        (1_000, true) => 80_000,
        (10_000, true) => 40_000,
        _ => 50_000,
    }
}

pub fn synth_h3_headers(count: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let name = match i {
            0 => b":method".to_vec(),
            1 => b":path".to_vec(),
            2 => b":authority".to_vec(),
            3 => b"user-agent".to_vec(),
            _ => format!("x-bench-{i}").into_bytes(),
        };
        let value = match i {
            0 => b"GET".to_vec(),
            1 => b"/bench".to_vec(),
            2 => b"example.test".to_vec(),
            _ => format!("value-{i}").into_bytes(),
        };
        out.push((name, value));
    }
    out
}
