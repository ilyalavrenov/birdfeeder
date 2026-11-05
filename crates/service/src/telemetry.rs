//! OTel providers configured from the standard `OTEL_*` environment, and the tracing subscriber that feeds them.

use std::{env, thread, time::Duration};

use anyhow::{Context as _, bail};
use opentelemetry::{Key, global, trace::TracerProvider as _};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{
    LogExporter, MetricExporter, Protocol, SpanExporter, WithExportConfig as _, WithHttpConfig, WithTonicConfig,
    tonic_types::transport::ClientTlsConfig,
};
use opentelemetry_resource_detectors::{HostResourceDetector, OsResourceDetector, ProcessResourceDetector};
use opentelemetry_sdk::{
    Resource,
    logs::SdkLoggerProvider,
    metrics::{Aggregation, InstrumentKind, SdkMeterProvider, Stream},
    propagation::{BaggagePropagator, TraceContextPropagator},
    trace::SdkTracerProvider,
};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{Layer as _, filter::Targets, layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::logging;

mod guest;

pub use guest::GuestLogs;

const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);
const HISTOGRAM_MAX_SIZE: u32 = 160;
const HISTOGRAM_MAX_SCALE: i8 = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Signal {
    Traces,
    Metrics,
    Logs,
}

impl Signal {
    fn name(self) -> &'static str {
        match self {
            Self::Traces => "TRACES",
            Self::Metrics => "METRICS",
            Self::Logs => "LOGS",
        }
    }
}

/// Whether a signal exports, and over which OTLP protocol. `None` means it doesn't.
fn protocol(signal: Signal, var: &impl Fn(&str) -> Option<String>) -> anyhow::Result<Option<Protocol>> {
    if var("OTEL_SDK_DISABLED").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        return Ok(None);
    }
    let name = signal.name();
    let exporter = var(&format!("OTEL_{name}_EXPORTER"));
    match exporter.as_deref() {
        Some("none") => return Ok(None),
        None | Some("otlp") => {}
        Some(_) => bail!("OTEL_{name}_EXPORTER must be otlp or none"),
    }
    // the SDK's default endpoint would have every service exporting to localhost without being asked.
    let configured =
        exporter.is_some() || var("OTEL_EXPORTER_OTLP_ENDPOINT").is_some() || var(&format!("OTEL_EXPORTER_OTLP_{name}_ENDPOINT")).is_some();
    if !configured {
        return Ok(None);
    }
    let protocol = var(&format!("OTEL_EXPORTER_OTLP_{name}_PROTOCOL")).or_else(|| var("OTEL_EXPORTER_OTLP_PROTOCOL"));
    match protocol.as_deref() {
        None | Some("grpc") => Ok(Some(Protocol::Grpc)),
        Some("http/protobuf") => Ok(Some(Protocol::HttpBinary)),
        Some(other) => bail!("unsupported OTLP {name} protocol {other:?}"),
    }
}

fn env_var(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.is_empty())
}

/// The process's OTel providers. Drop it without [`Telemetry::shutdown`] and you lose whatever's still batched.
#[must_use = "shut telemetry down to flush it"]
pub struct Telemetry {
    tracer: SdkTracerProvider,
    meter: Option<SdkMeterProvider>,
    logger: Option<SdkLoggerProvider>,
    guest_logs: Option<GuestLogs>,
}

/// Installs the global providers, W3C propagation, and a subscriber that logs JSON to stdout and, when OTLP logs are
/// on, exports the same events. `service_name` is used unless `OTEL_SERVICE_NAME` or `OTEL_RESOURCE_ATTRIBUTES` names
/// the service. gRPC exporters need a Tokio runtime entered.
pub(crate) fn init(service_name: &'static str) -> anyhow::Result<Telemetry> {
    let exports = [Signal::Traces, Signal::Metrics, Signal::Logs].map(|s| Export::from_env(s, env_var));
    let [span_export, metric_export, log_export] = exports;
    let (span_export, metric_export, log_export) = (span_export?, metric_export?, log_export?);
    let resource = resource(service_name);

    global::set_text_map_propagator(opentelemetry::propagation::TextMapCompositePropagator::new(vec![
        Box::new(TraceContextPropagator::new()),
        Box::new(BaggagePropagator::new()),
    ]));

    // a tracer provider runs even without an exporter, so incoming trace context still makes it to outgoing calls.
    let mut tracer = SdkTracerProvider::builder().with_resource(resource.clone());
    if let Some(export) = &span_export {
        tracer = tracer.with_batch_exporter(export.spans()?);
    }
    let tracer = tracer.build();
    global::set_tracer_provider(tracer.clone());

    let meter = metric_export
        .map(|export| -> anyhow::Result<_> {
            let provider = SdkMeterProvider::builder()
                .with_resource(resource.clone())
                .with_periodic_exporter(export.metrics()?)
                .with_view(exponential_histograms)
                .build();
            global::set_meter_provider(provider.clone());
            Ok(provider)
        })
        .transpose()?;

    let logger = log_export
        .map(|export| -> anyhow::Result<_> {
            let exporter = guest::Routed::new(export.logs()?);
            Ok(SdkLoggerProvider::builder().with_resource(resource.clone()).with_batch_exporter(exporter).build())
        })
        .transpose()?;
    let guest_logs = logger.as_ref().map(|provider| GuestLogs::new(provider.clone(), &resource));

    // exporters log their own failures. exporting those would feed the very queue that's failing.
    let exported = Targets::new()
        .with_default(LevelFilter::INFO)
        .with_targets(["opentelemetry", "h2", "hyper", "hyper_util", "reqwest", "tonic", "tower"].map(|t| (t, LevelFilter::OFF)));
    let stdout = Targets::new().with_default(LevelFilter::INFO).with_target("opentelemetry", LevelFilter::WARN);
    tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(tracer.tracer(service_name)).with_filter(LevelFilter::INFO))
        .with(logging::layer().with_filter(stdout))
        .with(logger.as_ref().map(|provider| OpenTelemetryTracingBridge::new(provider).with_filter(exported)))
        .try_init()
        .context("install the tracing subscriber")?;

    Ok(Telemetry { tracer, meter, logger, guest_logs })
}

impl Telemetry {
    /// Loggers for guest workloads, when OTLP logs export.
    #[must_use]
    pub fn guest_logs(&self) -> Option<&GuestLogs> {
        self.guest_logs.as_ref()
    }

    /// Flushes and stops every provider in parallel. Call it outside `block_on`: it blocks, and gRPC exporters need the
    /// runtime's worker threads.
    pub(crate) fn shutdown(self) {
        thread::scope(|scope| {
            scope.spawn(|| report("traces", self.tracer.shutdown_with_timeout(FLUSH_TIMEOUT)));
            if let Some(meter) = &self.meter {
                scope.spawn(|| report("metrics", meter.shutdown_with_timeout(FLUSH_TIMEOUT)));
            }
            if let Some(logger) = &self.logger {
                scope.spawn(|| report("logs", logger.shutdown_with_timeout(FLUSH_TIMEOUT)));
            }
        });
    }
}

fn report(signal: &str, result: opentelemetry_sdk::error::OTelSdkResult) {
    if let Err(err) = result {
        tracing::warn!(signal, error = %err, "otel shutdown");
    }
}

fn resource(service_name: &'static str) -> Resource {
    // the SDK falls back to unknown_service:<executable>, and only an explicit setting should replace that.
    let named = Resource::builder()
        .build()
        .get(&Key::from_static_str("service.name"))
        .is_some_and(|name| !name.as_str().starts_with("unknown_service"));
    let mut builder = Resource::builder().with_detectors(&[
        Box::new(HostResourceDetector::default()),
        Box::new(OsResourceDetector),
        Box::new(ProcessResourceDetector),
    ]);
    if !named {
        builder = builder.with_service_name(service_name);
    }
    builder.build()
}

fn exponential_histograms(instrument: &opentelemetry_sdk::metrics::Instrument) -> Option<Stream> {
    if instrument.kind() != InstrumentKind::Histogram {
        return None;
    }
    Stream::builder()
        .with_aggregation(Aggregation::Base2ExponentialHistogram {
            max_size: HISTOGRAM_MAX_SIZE,
            max_scale: HISTOGRAM_MAX_SCALE,
            record_min_max: true,
        })
        .build()
        .ok()
}

/// How one signal exports: its OTLP protocol, plus the TLS settings the exporter crate leaves up to us.
struct Export {
    protocol: Protocol,
    https: bool,
    /// replaces the system roots, same as the spec's `OTEL_EXPORTER_OTLP_CERTIFICATE`.
    ca: Option<Vec<u8>>,
    /// certificate and key PEMs for mutual TLS.
    client: Option<(Vec<u8>, Vec<u8>)>,
    timeout: Duration,
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

impl Export {
    /// `None` when the signal doesn't export.
    fn from_env(signal: Signal, var: impl Fn(&str) -> Option<String>) -> anyhow::Result<Option<Self>> {
        let Some(protocol) = protocol(signal, &var)? else { return Ok(None) };
        let name = signal.name();
        // the signal's own setting beats the shared one, like every OTLP variable.
        let setting =
            |suffix: &str| var(&format!("OTEL_EXPORTER_OTLP_{name}_{suffix}")).or_else(|| var(&format!("OTEL_EXPORTER_OTLP_{suffix}")));
        let read = |suffix: &str| -> anyhow::Result<Option<Vec<u8>>> {
            setting(suffix).map(|path| std::fs::read(&path).with_context(|| format!("OTLP {name} {suffix}: read {path}"))).transpose()
        };
        let client = match (read("CLIENT_CERTIFICATE")?, read("CLIENT_KEY")?) {
            (Some(certificate), Some(key)) => Some((certificate, key)),
            (None, None) => None,
            _ => bail!("OTLP {name}: set both the client certificate and its key, or neither"),
        };
        let timeout = setting("TIMEOUT").map_or(Ok(DEFAULT_TIMEOUT), |ms| {
            ms.parse().map(Duration::from_millis).with_context(|| format!("OTLP {name} timeout {ms:?} is not milliseconds"))
        })?;
        let https = setting("ENDPOINT").is_some_and(|endpoint| endpoint.starts_with("https://"));
        Ok(Some(Self { protocol, https, ca: read("CERTIFICATE")?, client, timeout }))
    }

    fn spans(&self) -> anyhow::Result<SpanExporter> {
        let exporter = match self.protocol {
            Protocol::Grpc => self.grpc(SpanExporter::builder().with_tonic()).build(),
            protocol => self.http(SpanExporter::builder().with_http().with_protocol(protocol))?.build(),
        };
        exporter.context("otlp traces")
    }

    fn metrics(&self) -> anyhow::Result<MetricExporter> {
        let exporter = match self.protocol {
            Protocol::Grpc => self.grpc(MetricExporter::builder().with_tonic()).build(),
            protocol => self.http(MetricExporter::builder().with_http().with_protocol(protocol))?.build(),
        };
        exporter.context("otlp metrics")
    }

    fn logs(&self) -> anyhow::Result<LogExporter> {
        let exporter = match self.protocol {
            Protocol::Grpc => self.grpc(LogExporter::builder().with_tonic()).build(),
            protocol => self.http(LogExporter::builder().with_http().with_protocol(protocol))?.build(),
        };
        exporter.context("otlp logs")
    }

    /// The exporter's own HTTPS setup trusts no roots, so an `https` endpoint always gets one from us.
    fn grpc<B: WithTonicConfig>(&self, builder: B) -> B {
        if !self.https {
            return builder;
        }
        let mut tls = ClientTlsConfig::new();
        tls = match &self.ca {
            Some(ca) => tls.ca_certificate(tonic::transport::Certificate::from_pem(ca)),
            None => tls.with_native_roots(),
        };
        if let Some((certificate, key)) = &self.client {
            tls = tls.identity(tonic::transport::Identity::from_pem(certificate, key));
        }
        builder.with_tls_config(tls)
    }

    /// The exporter's default client already verifies against the platform's roots. Only custom certs need a client of
    /// ours, and then it also has to carry the timeout the default one would've had.
    fn http<B: WithHttpConfig>(&self, builder: B) -> anyhow::Result<B> {
        if self.ca.is_none() && self.client.is_none() {
            return Ok(builder);
        }
        let mut client = reqwest::blocking::Client::builder().timeout(self.timeout);
        if let Some(ca) = &self.ca {
            client = client.tls_certs_only(reqwest::Certificate::from_pem_bundle(ca).context("OTLP CA certificate")?);
        }
        if let Some((certificate, key)) = &self.client {
            let pem = [certificate.as_slice(), b"\n", key.as_slice()].concat();
            client = client.identity(reqwest::Identity::from_pem(&pem).context("OTLP client certificate")?);
        }
        // the blocking client spins up its own runtime, and it can't do that from inside ours.
        let client = thread::scope(|scope| scope.spawn(|| client.build()).join())
            .map_err(|_| anyhow::anyhow!("building the OTLP HTTP client panicked"))?
            .context("OTLP HTTP client")?;
        Ok(builder.with_http_client(client))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const ENDPOINT: (&str, &str) = ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317");
    const HTTP: (&str, &str) = ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf");
    const GRPC_TRACES: (&str, &str) = ("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "grpc");

    fn protocol_with(signal: Signal, vars: &[(&str, &str)]) -> anyhow::Result<Option<Protocol>> {
        let vars: HashMap<_, _> = vars.iter().map(|&(k, v)| (k.to_owned(), v.to_owned())).collect();
        protocol(signal, &|key| vars.get(key).cloned())
    }

    #[test]
    fn protocol_from_env() {
        type Vars = &'static [(&'static str, &'static str)];
        let cases: [(Signal, Vars, Option<Protocol>); 9] = [
            (Signal::Traces, &[], None),
            (Signal::Traces, &[ENDPOINT], Some(Protocol::Grpc)),
            (Signal::Logs, &[("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "http://c:4318/v1/logs")], Some(Protocol::Grpc)),
            (Signal::Metrics, &[("OTEL_METRICS_EXPORTER", "otlp")], Some(Protocol::Grpc)),
            (Signal::Metrics, &[ENDPOINT, ("OTEL_METRICS_EXPORTER", "none")], None),
            (Signal::Traces, &[ENDPOINT, ("OTEL_SDK_DISABLED", "TRUE")], None),
            (Signal::Traces, &[ENDPOINT, HTTP], Some(Protocol::HttpBinary)),
            (Signal::Traces, &[ENDPOINT, HTTP, GRPC_TRACES], Some(Protocol::Grpc)),
            (Signal::Logs, &[ENDPOINT, HTTP, GRPC_TRACES], Some(Protocol::HttpBinary)),
        ];
        for (signal, vars, want) in cases {
            assert_eq!(protocol_with(signal, vars).unwrap(), want, "{signal:?} {vars:?}");
        }
    }

    #[test]
    fn unsupported_settings_fail() {
        assert!(protocol_with(Signal::Traces, &[ENDPOINT, ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json")]).is_err());
        assert!(protocol_with(Signal::Logs, &[("OTEL_LOGS_EXPORTER", "console")]).is_err());
    }

    fn export_with(signal: Signal, vars: &[(&str, &str)]) -> anyhow::Result<Option<Export>> {
        let vars: HashMap<_, _> = vars.iter().map(|&(k, v)| (k.to_owned(), v.to_owned())).collect();
        Export::from_env(signal, |key| vars.get(key).cloned())
    }

    #[test]
    fn tls_settings_prefer_the_signals_own() {
        let dir = tempfile::tempdir().unwrap();
        let pem = |name: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, name).unwrap();
            path.to_str().unwrap().to_owned()
        };
        let (shared, traces) = (pem("shared.pem"), pem("traces.pem"));
        let endpoint = ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4317");
        let vars = [endpoint, ("OTEL_EXPORTER_OTLP_CERTIFICATE", &shared), ("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", &traces)];
        let spans = export_with(Signal::Traces, &vars).unwrap().unwrap();
        assert!(spans.https);
        assert_eq!(spans.ca.as_deref(), Some(b"traces.pem".as_slice()));
        assert_eq!(spans.timeout, DEFAULT_TIMEOUT);
        let logs = export_with(Signal::Logs, &vars).unwrap().unwrap();
        assert_eq!(logs.ca.as_deref(), Some(b"shared.pem".as_slice()));
        let plain = export_with(Signal::Logs, &[("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "http://c:4318/v1/logs"), endpoint]).unwrap().unwrap();
        assert!(!plain.https, "the signal's endpoint decides");
        assert!(plain.ca.is_none() && plain.client.is_none());
        let timed = export_with(Signal::Metrics, &[endpoint, ("OTEL_EXPORTER_OTLP_TIMEOUT", "1500")]).unwrap().unwrap();
        assert_eq!(timed.timeout, Duration::from_millis(1500));
    }

    #[test]
    fn bad_tls_settings_fail() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("client.pem");
        std::fs::write(&cert, "cert").unwrap();
        let endpoint = ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4317");
        let half = export_with(Signal::Traces, &[endpoint, ("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", cert.to_str().unwrap())]);
        assert!(half.is_err_and(|e| e.to_string().contains("both")));
        let missing = export_with(Signal::Traces, &[endpoint, ("OTEL_EXPORTER_OTLP_CERTIFICATE", "/nonexistent/ca.pem")]);
        assert!(missing.is_err_and(|e| e.to_string().contains("/nonexistent/ca.pem")));
        assert!(export_with(Signal::Traces, &[endpoint, ("OTEL_EXPORTER_OTLP_TIMEOUT", "10s")]).is_err());
    }
}
