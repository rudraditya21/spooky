use crate::{
    benchmark::{
        connection::benchmark_connection_lookup, headers::benchmark_h3_header_collection,
        lb::benchmark_lb, route::benchmark_route_lookup,
    },
    manifest::{BenchProfile, MicroSuiteConfig},
    report::BenchCase,
};

pub fn run_micro_suite(
    profile: &BenchProfile,
    config: &MicroSuiteConfig,
) -> Result<Vec<BenchCase>, String> {
    let mut cases = Vec::new();
    for &scale in &profile.scales {
        cases.extend(benchmark_route_lookup(scale));
        cases.extend(benchmark_lb(scale)?);
        cases.extend(benchmark_connection_lookup(scale));
        if config.include_h3_header_collection {
            cases.extend(benchmark_h3_header_collection(scale));
        }
    }
    Ok(cases)
}
