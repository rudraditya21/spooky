use std::sync::OnceLock;

use log::{info, warn};
use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use tracing_subscriber::Registry;
use tracing_subscriber::layer::SubscriberExt;

const DEFAULT_OTLP_ENDPOINT: &str = "http://127.0.0.1:4317";

static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OtlpEndpointSource {
    Config,
    EnvTraces,
    EnvGeneric,
    Default,
}

pub fn init_tracing(
    enabled: bool,
    service_name: &str,
    otlp_endpoint: Option<&str>,
    sample_ratio: f64,
) {
    if !enabled {
        return;
    }

    let ratio = sample_ratio.clamp(0.0, 1.0);
    let (endpoint, endpoint_source) =
        resolve_otlp_endpoint(otlp_endpoint, |key| std::env::var(key).ok());

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.as_str())
        .build()
    {
        Ok(exporter) => exporter,
        Err(err) => {
            warn!(
                "OpenTelemetry tracing enabled but exporter initialization failed (endpoint={}): {}",
                endpoint, err
            );
            return;
        }
    };

    let provider = SdkTracerProvider::builder()
        .with_sampler(Sampler::TraceIdRatioBased(ratio))
        .with_batch_exporter(exporter)
        .with_resource(
            Resource::builder_empty()
                .with_attributes([KeyValue::new("service.name", service_name.to_string())])
                .build(),
        )
        .build();

    let tracer = provider.tracer("spooky");
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let subscriber = Registry::default().with(otel_layer);
    if let Err(err) = tracing::subscriber::set_global_default(subscriber) {
        warn!(
            "OpenTelemetry tracing setup failed to install tracing subscriber: {}",
            err
        );
        let _ = provider.shutdown();
        return;
    }

    if TRACER_PROVIDER.set(provider).is_err() {
        warn!("OpenTelemetry tracing already initialized; reusing existing tracer provider");
        return;
    }

    info!(
        "OpenTelemetry tracing enabled (service_name={}, endpoint={}, endpoint_source={:?}, sample_ratio={})",
        service_name, endpoint, endpoint_source, ratio
    );
}

pub fn shutdown_tracing() {
    if let Some(provider) = TRACER_PROVIDER.get() {
        let _ = provider.shutdown();
    }
}

fn resolve_otlp_endpoint<F>(
    otlp_endpoint: Option<&str>,
    mut lookup_env: F,
) -> (String, OtlpEndpointSource)
where
    F: FnMut(&str) -> Option<String>,
{
    if let Some(endpoint) = otlp_endpoint.map(str::trim).filter(|value| !value.is_empty()) {
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

#[cfg(test)]
mod tests {
    use super::{DEFAULT_OTLP_ENDPOINT, OtlpEndpointSource, resolve_otlp_endpoint};

    #[test]
    fn config_endpoint_overrides_environment() {
        let (endpoint, source) =
            resolve_otlp_endpoint(Some(" http://cfg-collector:4317 "), |key| match key {
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT" => {
                    Some("http://env-traces:4317".to_string())
                }
                "OTEL_EXPORTER_OTLP_ENDPOINT" => Some("http://env-generic:4317".to_string()),
                _ => None,
            });

        assert_eq!(endpoint, "http://cfg-collector:4317");
        assert_eq!(source, OtlpEndpointSource::Config);
    }

    #[test]
    fn traces_environment_overrides_generic_environment() {
        let (endpoint, source) = resolve_otlp_endpoint(None, |key| match key {
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT" => Some("http://env-traces:4317".to_string()),
            "OTEL_EXPORTER_OTLP_ENDPOINT" => Some("http://env-generic:4317".to_string()),
            _ => None,
        });

        assert_eq!(endpoint, "http://env-traces:4317");
        assert_eq!(source, OtlpEndpointSource::EnvTraces);
    }

    #[test]
    fn generic_environment_is_used_when_traces_endpoint_is_absent() {
        let (endpoint, source) = resolve_otlp_endpoint(None, |key| match key {
            "OTEL_EXPORTER_OTLP_ENDPOINT" => Some(" http://env-generic:4317 ".to_string()),
            _ => None,
        });

        assert_eq!(endpoint, "http://env-generic:4317");
        assert_eq!(source, OtlpEndpointSource::EnvGeneric);
    }

    #[test]
    fn default_endpoint_is_used_when_config_and_environment_are_absent() {
        let (endpoint, source) = resolve_otlp_endpoint(None, |_| None);

        assert_eq!(endpoint, DEFAULT_OTLP_ENDPOINT);
        assert_eq!(source, OtlpEndpointSource::Default);
    }
}
