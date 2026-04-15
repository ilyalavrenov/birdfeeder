//! Counters from Firecracker's metrics blobs. Firecracker reports deltas and resets them after each flush, even when
//! the write fails.

use std::collections::HashMap;

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Meter};

use super::telemetry::Blob;

const PREFIX: &str = "birdfeeder.firecracker.";
const HOST_PREFIX: &str = "birdfeeder.firecracker.host.";
const BYTES: &str = "By";
const SECCOMP: &str = "firecracker seccomp violation, vmm exiting";
const SIGNAL: &str = "firecracker fatal signal, vmm exiting";
const PANIC: &str = "firecracker panic, vmm exiting";

/// A metric Firecracker reports per group (block, net, vcpu...). `rollup` adds a host-wide sum, and `alert` logs any
/// count as an error.
struct Field {
    name: &'static str,
    unit: &'static str,
    rollup: bool,
    alert: Option<&'static str>,
}

const fn field(name: &'static str) -> Field {
    Field { name, unit: "", rollup: false, alert: None }
}

const fn bytes(name: &'static str) -> Field {
    Field { unit: BYTES, ..field(name) }
}

const fn rollup(name: &'static str) -> Field {
    Field { rollup: true, ..field(name) }
}

const fn alert(name: &'static str, alert: &'static str) -> Field {
    Field { alert: Some(alert), ..rollup(name) }
}

/// The fields kept from Firecracker's logger and device metrics.
const ALLOWLIST: &[(&str, &[Field])] = &[
    ("seccomp", &[alert("num_faults", SECCOMP)]),
    ("signals", &[alert("sigbus", SIGNAL), alert("sigsegv", SIGNAL), alert("sigxfsz", SIGNAL)]),
    ("vmm", &[alert("panic_count", PANIC)]),
    ("vcpu", &[rollup("failures")]),
    ("logger", &[rollup("missed_metrics_count"), field("missed_log_count"), field("rate_limited_log_count")]),
    ("mmds", &[field("rx_accepted_err"), field("rx_bad_eth"), field("tx_errors")]),
    ("uart", &[field("flush_count"), field("error_count"), field("missed_write_count"), bytes("rate_limiter_dropped_bytes")]),
    (
        "vsock",
        &[field("rx_read_fails"), field("tx_write_fails"), field("tx_flush_fails"), field("conn_event_fails"), field("muxer_event_fails")],
    ),
    (
        "block",
        &[
            rollup("rate_limiter_throttled_events"),
            rollup("io_engine_throttled_events"),
            bytes("read_bytes"),
            bytes("write_bytes"),
            field("execute_fails"),
            field("invalid_reqs_count"),
            field("event_fails"),
        ],
    ),
    (
        "net",
        &[
            rollup("rx_rate_limiter_throttled"),
            rollup("tx_rate_limiter_throttled"),
            bytes("rx_bytes_count"),
            bytes("tx_bytes_count"),
            field("no_rx_avail_buffer"),
            field("rx_fails"),
            field("tx_fails"),
            field("tap_read_fails"),
            field("tap_write_fails"),
            field("tx_malformed_frames"),
            field("tx_spoofed_mac_count"),
        ],
    ),
];

struct Instrument {
    field: &'static Field,
    per_session: Counter<u64>,
    host: Option<Counter<u64>>,
}

pub struct Metrics {
    groups: HashMap<&'static str, Vec<Instrument>>,
}

impl Metrics {
    pub fn new(meter: &Meter) -> Self {
        let groups = ALLOWLIST
            .iter()
            .map(|(group, fields)| {
                let instruments = fields
                    .iter()
                    .map(|field| {
                        let key = format!("{group}.{}", field.name);
                        let per_session = meter
                            .u64_counter(format!("{PREFIX}{key}"))
                            .with_unit(field.unit)
                            .with_description(format!("firecracker {key} per session"))
                            .build();
                        let host = field.rollup.then(|| {
                            meter
                                .u64_counter(format!("{HOST_PREFIX}{key}"))
                                .with_unit(field.unit)
                                .with_description(format!("firecracker {key} summed over the host's sessions"))
                                .build()
                        });
                        Instrument { field, per_session, host }
                    })
                    .collect();
                (*group, instruments)
            })
            .collect();
        Self { groups }
    }

    pub fn record(&self, session: &str, blob: &Blob) {
        for (key, fields) in blob {
            let Some((group, device)) = group_of(key) else { continue };
            let (Some(instruments), Some(fields)) = (self.groups.get(group), fields.as_object()) else { continue };
            let mut attributes = vec![KeyValue::new("birdfeeder.session.id", session.to_owned())];
            if let Some(device) = device {
                attributes.push(KeyValue::new("birdfeeder.device.id", device.to_owned()));
            }
            for instrument in instruments {
                let Some(n) = fields.get(instrument.field.name).and_then(serde_json::Value::as_u64).filter(|&n| n > 0) else { continue };
                instrument.per_session.add(n, &attributes);
                if let Some(host) = &instrument.host {
                    host.add(n, &[]);
                }
                if let Some(alert) = instrument.field.alert {
                    tracing::error!(
                        session,
                        component = "firecracker",
                        metric = format!("{key}.{}", instrument.field.name),
                        count = n,
                        "{alert}"
                    );
                }
            }
        }
    }
}

/// Splits a blob key like `block_rootfs` into group and device. Skips the aggregate `block` and `net` keys, or every
/// device would count twice.
fn group_of(key: &str) -> Option<(&str, Option<&str>)> {
    for device_group in ["block", "net"] {
        if key == device_group {
            return None;
        }
        if let Some(id) = key.strip_prefix(device_group).and_then(|rest| rest.strip_prefix('_')) {
            return Some((device_group, Some(id)));
        }
    }
    Some((key, None))
}

#[cfg(test)]
mod tests {
    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
    use serde_json::json;

    use super::*;

    fn blob(faults: u64, throttled: u64, rx_bytes: u64) -> Blob {
        let blob = json!({
            "utc_timestamp_ms": 1_757_188_000_000_u64,
            "seccomp": {"num_faults": faults},
            "block_rootfs": {"rate_limiter_throttled_events": throttled, "read_bytes": 4096},
            "block": {"rate_limiter_throttled_events": throttled, "read_bytes": 4096},
            "net_net1": {"rx_bytes_count": rx_bytes, "tx_rate_limiter_throttled": 0},
            "vcpu": {"exit_io_in_agg": {"min_us": 1}, "failures": 0},
        });
        blob.as_object().unwrap().clone()
    }

    /// A sum's points as (sorted attributes, value).
    type Points = Vec<(Vec<(String, String)>, u64)>;

    fn sums(exporter: &InMemoryMetricExporter) -> HashMap<String, Points> {
        let mut out = HashMap::new();
        for batch in exporter.get_finished_metrics().unwrap() {
            for scope in batch.scope_metrics() {
                for metric in scope.metrics() {
                    let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() else { panic!("{} isn't a u64 sum", metric.name()) };
                    let points = sum
                        .data_points()
                        .map(|p| {
                            let mut attributes: Vec<_> = p.attributes().map(|kv| (kv.key.to_string(), kv.value.to_string())).collect();
                            attributes.sort();
                            (attributes, p.value())
                        })
                        .collect();
                    out.insert(metric.name().to_owned(), points);
                }
            }
        }
        out
    }

    #[test]
    fn records_allowlisted_deltas() {
        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder().with_reader(PeriodicReader::builder(exporter.clone()).build()).build();
        let metrics = Metrics::new(&provider.meter("test"));
        metrics.record("sess-a", &blob(0, 5, 100));
        metrics.record("sess-a", &blob(1, 9, 100));
        provider.force_flush().unwrap();
        let sums = sums(&exporter);

        let value = |name: &str| sums[name].iter().map(|(_, v)| v).sum::<u64>();
        assert_eq!(value("birdfeeder.firecracker.seccomp.num_faults"), 1);
        assert_eq!(value("birdfeeder.firecracker.host.seccomp.num_faults"), 1);
        assert_eq!(value("birdfeeder.firecracker.block.read_bytes"), 8192, "the aggregate block twin isn't counted");
        assert_eq!(
            sums["birdfeeder.firecracker.block.rate_limiter_throttled_events"],
            [(vec![("birdfeeder.device.id".into(), "rootfs".into()), ("birdfeeder.session.id".into(), "sess-a".into())], 14)]
        );
        assert_eq!(sums["birdfeeder.firecracker.host.block.rate_limiter_throttled_events"], [(vec![], 14)]);
        assert_eq!(value("birdfeeder.firecracker.net.rx_bytes_count"), 200);
        assert!(!sums.contains_key("birdfeeder.firecracker.net.tx_rate_limiter_throttled"), "zeros aren't recorded");
        assert!(!sums.contains_key("birdfeeder.firecracker.vcpu.failures"));
    }

    #[test]
    fn device_keys_split_into_group_and_device() {
        assert_eq!(group_of("block_rootfs"), Some(("block", Some("rootfs"))));
        assert_eq!(group_of("net"), None);
        assert_eq!(group_of("seccomp"), Some(("seccomp", None)));
        assert_eq!(group_of("blocked"), Some(("blocked", None)));
    }
}
