use crate::telemetry::init::DEFAULT_OTLP_ENDPOINT;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtlpEndpointSource {
    Config,
    EnvTraces,
    EnvGeneric,
    Default,
}

pub fn resolve_otlp_endpoint<F>(
    otlp_endpoint: Option<&str>,
    mut lookup_env: F,
) -> (String, OtlpEndpointSource)
where
    F: FnMut(&str) -> Option<String>,
{
    if let Some(endpoint) = otlp_endpoint
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return (endpoint.to_string(), OtlpEndpointSource::Config);
    }

    if let Some(endpoint) = lookup_env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return (endpoint, OtlpEndpointSource::EnvTraces);
    }

    if let Some(endpoint) = lookup_env("OTEL_EXPORTER_OTLP_ENDPOINT")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return (endpoint, OtlpEndpointSource::EnvGeneric);
    }

    (
        DEFAULT_OTLP_ENDPOINT.to_string(),
        OtlpEndpointSource::Default,
    )
}
