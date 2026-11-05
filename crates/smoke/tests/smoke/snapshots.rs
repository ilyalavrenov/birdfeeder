//! Restores guests every way roost's config can ask for. Modes roost never picks on its own, like a lazy restore
//! without a recorded working set, are covered by the vmm crate's KVM test.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region, RequestChecksumCalculation};
use aws_sdk_s3::primitives::ByteStream;
use aws_smithy_http_client::tls;
use nix::sys::signal::Signal;
use roost_api::v1;
use serde::{Serialize, Serializer};
use serde_json::json;

use crate::contract::{Snapshot, StoreConfig};
use crate::harness::{Harness, REPO, Service, claim, claim_request, eventually, get, release};
use crate::telemetry::{Telemetry, modes};
use crate::workloads::Example;

const ACCESS_KEY: &str = "birdfeeder";
const SECRET_KEY: &str = "birdfeeder-secret";
const BUCKET: &str = "snapshots";
const REGION: &str = "us-east-1";
const S3_PORT: u16 = 18333;

/// Restores two clones of an eager or lazy template from a snapshot store. Checks they don't inherit the golden
/// guest's clock or randomness, and that their vsock agent still answers.
pub async fn run(snapshot: Snapshot) {
    let mut h = snapshot_harness(Some(snapshot), true).await;
    let template = h.config.templates[0].id.clone();
    h.start_roost();
    eventually("golden guest", async || h.pooled().await).await;
    // clones wake up with the snapshot's wall clock unless roost fixes it.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let golden = claim(h.host(), claim_request(&template)).await;
    assert_eq!(get(&golden, "/", 200).await, Example::Http.body().as_bytes());
    // the host only fits two guests, so the second clone needs the golden one's slot.
    release(h.host(), &golden).await;
    let mut clones = Vec::new();
    let mut handler_logs = Vec::new();
    for _ in 0..2 {
        eventually("restored guest", async || h.pooled().await).await;
        let clone = claim(h.host(), claim_request(&template)).await;
        h.check_clone(&clone).await;
        handler_logs.push(h.uffd_log(&clone));
        clones.push(clone);
    }
    assert_ne!(
        get(&clones[0], "/test/random", 200).await,
        get(&clones[1], "/test/random", 200).await,
        "clones share the golden guest's random stream"
    );

    let want = match snapshot {
        Snapshot::Lazy => ["golden", "record", "prefetch"],
        Snapshot::Eager => ["golden", "restore", "restore"],
    };
    let tm = h.telemetry.as_ref().expect("telemetry");
    assert_eq!(modes(&tm.boots(&template, want.len()).await), want);
    // the golden boot exports memory before any restore, so restores read it remotely. the exception is a recording,
    // which reads the local file it records against.
    for (log, mode) in handler_logs.iter().zip(&want[1..]) {
        let remote = *mode != "record";
        assert!(log.contains(&format!(r#""remote":{remote}"#)), "{mode} restore:\n{log}");
    }
    if snapshot == Snapshot::Lazy {
        assert!(handler_logs[1].contains(r#""packed":true"#), "the prefetch didn't fetch the exported working set:\n{}", handler_logs[1]);
    }
    for clone in &clones {
        release(h.host(), clone).await;
    }
}

#[derive(Serialize)]
struct Sample {
    #[serde(rename = "ready_ns", serialize_with = "nanos")]
    ready: Duration,
    #[serde(rename = "first_request_ns", serialize_with = "nanos")]
    first_request: Duration,
    vmm_rss_kib: u64,
}

#[derive(Serialize)]
struct Phase {
    mode: &'static str,
    samples: Vec<Sample>,
}

/// Times each boot path to a ready guest (from roost's boot spans), plus the first request and VMM memory after a
/// claim, over `BENCH_RUNS` claims per mode. One guest boots at a time, so this doesn't measure contention. Results
/// go to bin/bench.json.
pub async fn bench() {
    let runs: usize = std::env::var("BENCH_RUNS").map_or(10, |r| r.parse().expect("BENCH_RUNS is a count"));
    // the last field counts the boots before the measured ones: the golden guest, plus a lazy template's recording.
    let phases = [
        ("cold", None, false, 0),
        ("eager", Some(Snapshot::Eager), false, 1),
        ("prefetch", Some(Snapshot::Lazy), false, 2),
        ("eager_s3", Some(Snapshot::Eager), true, 1),
        ("prefetch_s3", Some(Snapshot::Lazy), true, 2),
    ];
    let mut results = Vec::new();
    for (mode, snapshot, store, warm) in phases {
        let mut h = snapshot_harness(snapshot, store).await;
        let template = h.config.templates[0].id.clone();
        h.start_roost();
        let mut samples = Vec::new();
        for i in 0..warm + runs {
            eventually("pooled guest", async || h.pooled().await).await;
            let session = claim(h.host(), claim_request(&template)).await;
            let start = Instant::now();
            assert_eq!(get(&session, "/", 200).await, Example::Http.body().as_bytes());
            if i >= warm {
                let first_request = start.elapsed();
                samples.push(Sample { ready: Duration::ZERO, first_request, vmm_rss_kib: vm_rss_kib(h.saved(&session).pid()) });
            }
            release(h.host(), &session).await;
        }
        let boots = h.telemetry.as_ref().expect("telemetry").boots(&template, warm + runs).await;
        for (sample, boot) in samples.iter_mut().zip(&boots[warm..]) {
            sample.ready = boot.duration;
        }
        results.push(Phase { mode, samples });
    }
    eprintln!("{runs} claims per mode, 1 vCPU / 512 MiB guest\n{}", table(&results));
    let out = Path::new(REPO).join("bin/bench.json");
    fs::write(&out, serde_json::to_vec_pretty(&results).unwrap()).expect("write bench results");
}

/// A harness for a one-guest pool of the HTTP example with its test endpoints. Exports traces so the test can see
/// how each guest booted.
async fn snapshot_harness(snapshot: Option<Snapshot>, store: bool) -> Harness {
    let mut h = Harness::new();
    let mut manifest = Example::Http.manifest();
    manifest["containers"][0]["args"] = json!(["/usr/local/bin/serve", "--test-control"]);
    let template = h.example_template(Example::Http, manifest, snapshot);
    h.config.templates = vec![template];
    h.telemetry = Some(Telemetry::start(&h.state).await);
    if store {
        let store = SnapshotStore::start(&h.state.join("weed")).await;
        h.config.snapshot_store = Some(SnapshotStore::config());
        h.store = Some(store);
    }
    h
}

impl Harness {
    /// Checks what a restore could break: the workload, the wall clock, and the vsock agent, whose connections reset
    /// on restore.
    async fn check_clone(&self, session: &v1::Session) {
        assert_eq!(get(session, "/", 200).await, Example::Http.body().as_bytes());
        let guest_time = String::from_utf8(get(session, "/test/time", 200).await).unwrap();
        let guest_ns: u128 = guest_time.trim().parse().expect("guest time in nanoseconds");
        let skew = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().abs_diff(guest_ns);
        assert!(skew < Duration::from_secs(1).as_nanos(), "guest clock is {skew}ns off");
        let vsock = self.saved(session).vsock_path;
        let stats = crate::contract::guest_stats(&vsock).await.expect("guest stats");
        assert!(stats.memory.is_some(), "no memory stats");
        let record: crate::contract::LogLine = crate::contract::ask_guest(&vsock, "LOGS web 0").await.expect("web's first log line");
        assert!(record.line.contains("serving /srv"), "{}", record.line);
    }

    /// The restored session's page-fault handler log, which roost keeps in the session's run directory.
    fn uffd_log(&self, session: &v1::Session) -> String {
        let path = self.run.join(format!("{}.{}", session.name, session.generation)).join("uffd-handler.log");
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }
}

/// A single-node `SeaweedFS`, which `mise.toml` pins, serving the snapshot bucket.
pub struct SnapshotStore {
    pub weed: Option<Service>,
    started: SystemTime,
}

impl SnapshotStore {
    async fn start(dir: &Path) -> Self {
        fs::create_dir(dir).expect("create weed dir");
        let identities = json!({"identities": [{
            "name": "roost",
            "credentials": [{"accessKey": ACCESS_KEY, "secretKey": SECRET_KEY}],
            "actions": ["Admin", "Read", "Write", "List"],
        }]});
        let s3_config = dir.join("s3.json");
        fs::write(&s3_config, identities.to_string()).expect("write weed identities");
        let mut cmd = Command::new("weed");
        cmd.args(["mini", "-ip", "127.0.0.1", "-ip.bind", "127.0.0.1", "-bucket", BUCKET, "-admin.ui=false"])
            .args(["-master.port", "19333", "-volume.port", "18089", "-filer.port", "18888"])
            .arg(format!("-s3.port={S3_PORT}"))
            .arg(format!("-dir={}", dir.display()))
            .arg(format!("-s3.config={}", s3_config.display()));
        let started = SystemTime::now();
        // weed mini stops its servers one at a time, and the filer alone has taken 15s, past a service's 20s to stop.
        // nothing reads the store afterwards, so just kill it.
        let weed = Service::start_stopped_by(Signal::SIGKILL, "weed", &dir.join("weed.log"), cmd);
        let store = Self { weed: Some(weed), started };
        let client = s3_client(&Self::config().endpoint);
        // the bucket shows up a bit after the S3 port opens, and roost's first export mustn't race it.
        eventually("seaweedfs accepting uploads", async || {
            client.put_object().bucket(BUCKET).key("probe").body(ByteStream::from_static(b"probe")).send().await?;
            Ok(true)
        })
        .await;
        store
    }

    fn config() -> StoreConfig {
        StoreConfig { endpoint: format!("http://127.0.0.1:{S3_PORT}"), region: REGION, bucket: BUCKET, path_style: true }
    }

    /// The credentials roost signs its uploads with.
    pub fn env() -> [(&'static str, &'static str); 2] {
        [("AWS_ACCESS_KEY_ID", ACCESS_KEY), ("AWS_SECRET_ACCESS_KEY", SECRET_KEY)]
    }
}

impl Drop for SnapshotStore {
    /// weed leaves fixed-name sockets in /tmp and ignores TMPDIR. Root-owned ones would block another user's weed
    /// run later.
    fn drop(&mut self) {
        drop(self.weed.take());
        let socks = fs::read_dir("/tmp").into_iter().flatten().flatten().map(|e| e.path()).filter(|p: &PathBuf| {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            name.starts_with("seaweedfs-") && name.ends_with(".sock")
        });
        for sock in socks {
            if fs::metadata(&sock).and_then(|m| m.modified()).is_ok_and(|m| m >= self.started) {
                let _ = fs::remove_file(sock);
            }
        }
    }
}

fn s3_client(endpoint: &str) -> aws_sdk_s3::Client {
    let http =
        aws_smithy_http_client::Builder::new().tls_provider(tls::Provider::Rustls(tls::rustls_provider::CryptoMode::Ring)).build_https();
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(REGION))
        .endpoint_url(endpoint)
        .force_path_style(true)
        .credentials_provider(Credentials::new(ACCESS_KEY, SECRET_KEY, None, None, "smoke"))
        // same as roost's uploads: not every compatible store accepts aws-chunked bodies.
        .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
        .http_client(http)
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

fn vm_rss_kib(pid: u32) -> u64 {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).expect("read VMM status");
    let line = status.lines().find_map(|l| l.strip_prefix("VmRSS:")).unwrap_or_else(|| panic!("no VmRSS for pid {pid}"));
    line.trim().trim_end_matches(" kB").parse().expect("VmRSS in kB")
}

fn table(phases: &[Phase]) -> String {
    let mut out = String::from("| mode | ready p50 | ready p90 | first request p50 | vmm RSS p50 |\n|---|---|---|---|---|\n");
    for phase in phases {
        let ready: Vec<Duration> = phase.samples.iter().map(|s| s.ready).collect();
        let first: Vec<Duration> = phase.samples.iter().map(|s| s.first_request).collect();
        let rss: Vec<u64> = phase.samples.iter().map(|s| s.vmm_rss_kib).collect();
        let ms = |d: Duration| Duration::from_millis(d.as_millis() as u64);
        let tenth_ms = |d: Duration| Duration::from_micros(d.as_micros() as u64 / 100 * 100);
        writeln!(
            out,
            "| {} | {:?} | {:?} | {:?} | {} MiB |",
            phase.mode,
            ms(percentile(&ready, 50)),
            ms(percentile(&ready, 90)),
            tenth_ms(percentile(&first, 50)),
            percentile(&rss, 50) / 1024
        )
        .unwrap();
    }
    out
}

/// Nearest-rank percentile, so it doesn't interpolate across a handful of samples.
fn percentile<T: Ord + Copy>(values: &[T], p: usize) -> T {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = (p * sorted.len() + 50) / 100;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn nanos<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u128(d.as_nanos())
}
