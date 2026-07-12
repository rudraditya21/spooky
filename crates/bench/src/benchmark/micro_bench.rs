use crate::benchmark::connection::benchmark_connection_lookup;
use crate::benchmark::headers::benchmark_h3_header_collection;
use crate::benchmark::lb::benchmark_lb;
use crate::benchmark::route::benchmark_route_lookup;
use crate::manifest::{BenchProfile, MicroSuiteConfig};
use crate::report::BenchCase;

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
