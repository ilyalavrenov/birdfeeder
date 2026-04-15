//! An OTLP collector that writes whatever the services and guests export as JSON lines in the state directory,
//! plus the checks that read them back.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::contract::{Saved, guest_stats};
use crate::harness::{REPO, Service, TRACE_ID, eventually, listening};

const METRICS: [&str; 8] = [
    "birdfeeder.vm.mem.current",
    "birdfeeder.guest.mem.available",
    "birdfeeder.guest.disk.used",
    "birdfeeder.guest.container.mem.current",
    "birdfeeder.guest.container.cpu.usage",
    "birdfeeder.guest.container.pids",
    "birdfeeder.guest.stats.requests",
    "birdfeeder.roost.boot.duration",
];

pub struct Telemetry {
    dir: PathBuf,
    pub collector: Option<Service>,
}

impl Telemetry {
    pub async fn start(dir: &Path) -> Self {
        let mut cmd = Command::new("otelcol");
        cmd.arg("--config").arg(Path::new(REPO).join("dev/collector/config.yaml"));
        cmd.env("BIRDFEEDER_TELEMETRY_DIR", dir).env("GOMEMLIMIT", "128MiB");
        let collector = Service::start("otelcol", &dir.join("collector.log"), cmd);
        eventually("OTLP collector", async || Ok(listening("127.0.0.1:4317").await? && listening("127.0.0.1:4318").await?)).await;
        Self { dir: dir.to_owned(), collector: Some(collector) }
    }

    /// Exports roost over gRPC and the dispatcher over HTTP, so both protocols are covered.
    pub fn env(kind: &str) -> [(&'static str, &'static str); 7] {
        let (endpoint, protocol) =
            if kind == "dispatcher" { ("http://127.0.0.1:4318", "http/protobuf") } else { ("http://127.0.0.1:4317", "grpc") };
        [
            ("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment.name=test"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint),
            ("OTEL_EXPORTER_OTLP_PROTOCOL", protocol),
            ("OTEL_METRIC_EXPORT_INTERVAL", "1000"),
            ("OTEL_BSP_SCHEDULE_DELAY", "100"),
            ("OTEL_BLRP_SCHEDULE_DELAY", "100"),
            ("OTEL_EXPORTER_OTLP_TIMEOUT", "1000"),
        ]
    }

    fn records<T: DeserializeOwned>(&self, file: &str) -> Vec<T> {
        let path = self.dir.join(file);
        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Vec::new(),
            Err(e) => panic!("read {}: {e}", path.display()),
        };
        // the file exporter might still be writing its last line.
        let complete = data.iter().rposition(|&b| b == b'\n').map_or(&data[..0], |end| &data[..=end]);
        let lines = complete.split(|&b| b == b'\n').filter(|line| !line.trim_ascii().is_empty());
        lines.map(|line| serde_json::from_slice(line).unwrap_or_else(|e| panic!("decode {}: {e}", path.display()))).collect()
    }

    fn logs(&self) -> Vec<(Attributes, LogRecord)> {
        let mut logs = Vec::new();
        for batch in self.records::<LogBatch>("logs.jsonl") {
            for r in batch.resource_logs {
                let resource = attributes(&r.resource.attributes);
                logs.extend(r.scope_logs.into_iter().flat_map(|s| s.log_records).map(|record| (resource.clone(), record)));
            }
        }
        logs
    }

    fn spans(&self) -> Vec<(Attributes, Span)> {
        let mut spans = Vec::new();
        for batch in self.records::<TraceBatch>("traces.jsonl") {
            for r in batch.resource_spans {
                let resource = attributes(&r.resource.attributes);
                spans.extend(r.scope_spans.into_iter().flat_map(|s| s.spans).map(|span| (resource.clone(), span)));
            }
        }
        spans
    }

    fn metric_names(&self) -> BTreeSet<String> {
        let batches = self.records::<MetricBatch>("metrics.jsonl");
        let scopes = batches.into_iter().flat_map(|b| b.resource_metrics).flat_map(|r| r.scope_metrics);
        scopes.flat_map(|s| s.metrics).map(|m| m.name).collect()
    }

    /// The shared example's writer announcing itself, one per guest.
    fn guest_logs(&self) -> Vec<(Attributes, LogRecord)> {
        let mut logs = self.logs();
        logs.retain(|(r, record)| attr(r, "service.name") == "birdfeeder.guest" && record.body.string_value == "shared volume initialized");
        logs
    }

    pub fn guest_log_uids(&self) -> Vec<String> {
        self.guest_logs().iter().map(|(_, record)| attr(&attributes(&record.attributes), "log.record.uid").to_owned()).collect()
    }

    pub fn cursors(&self) -> Vec<PathBuf> {
        let Ok(entries) = fs::read_dir(self.dir.join("log-cursors")) else { return Vec::new() };
        entries.flatten().map(|e| e.path()).filter(|p| p.extension() == Some(OsStr::new("cursor"))).collect()
    }

    /// Checks the guest logs, the services' logs over both protocols, trace propagation, metrics, guest stats and
    /// log cursors of the shared example's guests, and returns the guest logs' uids.
    pub async fn verify_initial(&self, saved: &BTreeMap<String, Saved>) -> Vec<String> {
        eventually("guest OTLP logs", async || Ok(self.guest_logs().len() >= 2)).await;
        let guests = self.guest_logs();
        assert_eq!(guests.len(), 2, "guest logs");
        let mut uids = Vec::new();
        for (r, record) in &guests {
            assert_eq!(attr(r, "container.name"), "writer");
            assert_ne!(attr(r, "container.id"), "");
            assert_eq!(attr(r, "container.id"), attr(r, "service.instance.id"));
            assert_eq!(attr(r, "deployment.environment.name"), "test");
            assert!(!r.keys().any(|k| k.starts_with("process.")), "{r:?}");
            let attrs = attributes(&record.attributes);
            assert_eq!(attr(&attrs, "log.iostream"), "stdout");
            for stamp in [&record.time_unix_nano, &record.observed_time_unix_nano] {
                assert!(stamp.parse::<u64>().is_ok_and(|t| t > 0), "timestamp {stamp:?}");
            }
            assert_eq!(record.severity_number, 0);
            let uid = attr(&attrs, "log.record.uid");
            assert_ne!(uid, "");
            uids.push(uid.to_owned());
        }
        eventually("host OTLP logs over both protocols", async || {
            let services: BTreeSet<String> = self.logs().iter().map(|(r, _)| attr(r, "service.name").to_owned()).collect();
            Ok(services.contains("roost") && services.contains("dispatcher"))
        })
        .await;
        eventually("W3C trace propagation through dispatcher and host", async || {
            let spans = self.spans();
            let services: BTreeSet<&str> =
                spans.iter().filter(|(_, s)| s.trace_id == TRACE_ID).map(|(r, _)| attr(r, "service.name")).collect();
            Ok(services.contains("roost") && services.contains("dispatcher"))
        })
        .await;
        eventually("VM metrics", async || {
            let names = self.metric_names();
            Ok(METRICS.iter().all(|m| names.contains(*m)))
        })
        .await;
        for session in saved.values() {
            let group = fs::read_to_string(format!("/proc/{}/cgroup", session.pid())).expect("read VMM cgroup");
            assert!(group.contains("/birdfeeder/") && !group.contains(".service"), "VMM cgroup: {group}");
            let stats = guest_stats(&session.vsock_path).await.expect("guest stats");
            let memory = stats.memory.expect("memory stats");
            assert!(0 < memory.available_bytes && memory.available_bytes < memory.total_bytes);
            let disk = stats.disk.expect("disk stats");
            assert!(0 < disk.free_bytes && disk.free_bytes < disk.total_bytes);
            assert_eq!(stats.containers.keys().map(String::as_str).collect::<Vec<_>>(), ["web", "writer"]);
            for counters in stats.containers.values() {
                for value in [counters.cpu_usec, counters.memory_bytes, counters.pids] {
                    assert!(value.is_some_and(|v| v > 0), "container counter {value:?}");
                }
                assert_eq!(counters.oom_kill, Some(0));
            }
        }
        eventually("durable log cursors", async || Ok(self.cursors().len() >= 2)).await;
        uids
    }

    /// Waits for the template's first `n` boot spans and returns them in the order they started.
    pub async fn boots(&self, template: &str, n: usize) -> Vec<Boot> {
        let mut found = Vec::new();
        eventually(&format!("{n} boot spans"), async || {
            found = self.boot_spans(template)?;
            Ok(found.len() >= n)
        })
        .await;
        found.truncate(n);
        found
    }

    /// The template's boot spans exported so far, in the order they started.
    pub fn boot_spans(&self, template: &str) -> anyhow::Result<Vec<Boot>> {
        let mut found = Vec::new();
        for (_, span) in self.spans() {
            let attrs = attributes(&span.attributes);
            if span.name != "birdfeeder.session.boot" || attr(&attrs, "birdfeeder.template.id") != template {
                continue;
            }
            let (start, end): (u64, u64) = (span.start_time_unix_nano.parse()?, span.end_time_unix_nano.parse()?);
            found.push(Boot { mode: attr(&attrs, "birdfeeder.boot.mode").to_owned(), start, duration: Duration::from_nanos(end - start) });
        }
        found.sort_by_key(|b| b.start);
        Ok(found)
    }
}

pub struct Boot {
    pub mode: String,
    start: u64,
    pub duration: Duration,
}

pub fn modes(boots: &[Boot]) -> Vec<&str> {
    boots.iter().map(|b| b.mode.as_str()).collect()
}

type Attributes = BTreeMap<String, String>;

/// The string-valued attributes. The checks don't read any others.
fn attributes(attrs: &[Attribute]) -> Attributes {
    attrs.iter().map(|a| (a.key.clone(), a.value.string_value.clone())).collect()
}

fn attr<'a>(attrs: &'a Attributes, key: &str) -> &'a str {
    attrs.get(key).map_or("", String::as_str)
}

// OTLP's JSON encoding, as the collector's file exporter writes it.

#[derive(Default, Deserialize)]
#[serde(default)]
struct Attribute {
    key: String,
    value: AnyValue,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct AnyValue {
    string_value: String,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Resource {
    attributes: Vec<Attribute>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct LogBatch {
    resource_logs: Vec<ResourceLogs>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct ResourceLogs {
    resource: Resource,
    scope_logs: Vec<ScopeLogs>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct ScopeLogs {
    log_records: Vec<LogRecord>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct LogRecord {
    attributes: Vec<Attribute>,
    body: AnyValue,
    time_unix_nano: String,
    observed_time_unix_nano: String,
    severity_number: i32,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct TraceBatch {
    resource_spans: Vec<ResourceSpans>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct ResourceSpans {
    resource: Resource,
    scope_spans: Vec<ScopeSpans>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct ScopeSpans {
    spans: Vec<Span>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Span {
    trace_id: String,
    name: String,
    start_time_unix_nano: String,
    end_time_unix_nano: String,
    attributes: Vec<Attribute>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct MetricBatch {
    resource_metrics: Vec<ResourceMetrics>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct ResourceMetrics {
    scope_metrics: Vec<ScopeMetrics>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct ScopeMetrics {
    metrics: Vec<Metric>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Metric {
    name: String,
}
