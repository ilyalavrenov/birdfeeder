//! roost's config, its session files, and the guest agent's protocol, in the suite's own types so a format change
//! breaks here instead of quietly changing both sides. Fields the suite doesn't use are left out.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, ensure};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::UnixStream;

#[derive(Serialize)]
pub struct RoostConfig {
    pub listen_addr: &'static str,
    pub state_dir: PathBuf,
    pub run_dir: PathBuf,
    pub host_id: &'static str,
    pub max_sessions: u32,
    pub max_vcpus: u32,
    pub max_memory_mib: u32,
    pub dnsgate_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_upstream: Option<SocketAddr>,
    pub ready_timeout_sec: u32,
    pub reap_interval_sec: u32,
    pub metrics_interval_sec: u32,
    pub firecracker_bin: &'static str,
    pub kernel_image_path: String,
    pub kernel_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_store: Option<StoreConfig>,
    pub templates: Vec<Template>,
}

impl RoostConfig {
    pub fn use_kernel(&mut self, kernel: &Artifact) {
        self.kernel_image_path.clone_from(&kernel.path);
        self.kernel_sha256.clone_from(&kernel.sha256);
    }
}

/// An S3 bucket; roost takes its credentials from the `AWS_*` environment.
#[derive(Serialize)]
pub struct StoreConfig {
    pub endpoint: String,
    pub region: &'static str,
    pub bucket: &'static str,
    pub path_style: bool,
}

#[derive(Serialize)]
pub struct Template {
    #[serde(rename = "template_id")]
    pub id: String,
    pub base_disk: String,
    pub base_disk_sha256: String,
    pub scratch_disk: String,
    pub scratch_disk_sha256: String,
    pub blobs: BTreeMap<String, String>,
    pub blob_sha256: BTreeMap<String, String>,
    /// as examples/*.json has it, so fields the suite doesn't know about pass through.
    pub manifest: Value,
    pub endpoints: BTreeMap<&'static str, u16>,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub pool_target: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<Snapshot>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub snapshot_warmup: Vec<Warmup>,
}

impl Template {
    /// A one-guest pool of 1 vCPU and 512 MiB guests serving `http` on port 8080.
    pub fn new(id: String, base: &Artifact, scratch: &Artifact, blobs: &[(&str, &Artifact)], manifest: Value) -> Self {
        Self {
            id,
            base_disk: base.path.clone(),
            base_disk_sha256: base.sha256.clone(),
            scratch_disk: scratch.path.clone(),
            scratch_disk_sha256: scratch.sha256.clone(),
            blobs: blobs.iter().map(|(name, a)| ((*name).to_owned(), a.path.clone())).collect(),
            blob_sha256: blobs.iter().map(|(name, a)| ((*name).to_owned(), a.sha256.clone())).collect(),
            manifest,
            endpoints: BTreeMap::from([("http", 8080)]),
            vcpus: 1,
            mem_mib: 512,
            pool_target: 1,
            snapshot: None,
            snapshot_warmup: Vec::new(),
        }
    }
}

/// How a template's clones restore from its snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Snapshot {
    /// all memory before the guest resumes.
    Eager,
    /// memory on fault, after prefetching a recorded working set.
    Lazy,
}

#[derive(Serialize)]
pub struct Warmup {
    pub endpoint: &'static str,
    pub path: &'static str,
}

/// An entry of the artifacts.json that scripts/build-artifacts.sh writes.
#[derive(Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
}

/// roost's record of a session, in `<state>/sessions/<name>.json`.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Saved {
    pub pid: Option<u32>,
    pub uffd_pid: Option<u32>,
    pub nest_id: Option<String>,
    pub vsock_path: PathBuf,
    pub guest_ip: String,
    pub netns: String,
    pub endpoints: BTreeMap<String, SavedEndpoint>,
}

impl Saved {
    pub fn pid(&self) -> u32 {
        self.pid.filter(|&p| p != 0).expect("session record has a VMM pid")
    }

    pub fn host_port(&self, endpoint: &str) -> u16 {
        self.endpoints.get(endpoint).unwrap_or_else(|| panic!("session record has no {endpoint} endpoint")).host_port
    }
}

#[derive(Default, Deserialize)]
pub struct SavedEndpoint {
    pub host_port: u16,
}

/// the guest agent's vsock port.
const GUEST_PORT: u32 = 5000;

/// Connects through Firecracker's hybrid vsock: `CONNECT <port>` on the unix socket, answered by `OK <port>`. The
/// reader keeps anything that came in after the reply.
async fn dial_guest(vsock: &Path) -> anyhow::Result<BufReader<UnixStream>> {
    let mut conn = BufReader::new(UnixStream::connect(vsock).await.context("dial guest socket")?);
    conn.get_mut().write_all(format!("CONNECT {GUEST_PORT}\n").as_bytes()).await?;
    let mut reply = String::new();
    conn.read_line(&mut reply).await.context("vsock handshake")?;
    ensure!(reply.starts_with("OK "), "vsock handshake answered {reply:?}");
    Ok(conn)
}

/// Sends one request line to the guest agent and decodes the first JSON line it answers with.
pub async fn ask_guest<T: DeserializeOwned>(vsock: &Path, request: &str) -> anyhow::Result<T> {
    let answer = async {
        let mut conn = dial_guest(vsock).await?;
        conn.get_mut().write_all(format!("{request}\n").as_bytes()).await?;
        let mut line = String::new();
        conn.read_line(&mut line).await?;
        serde_json::from_str(&line).with_context(|| format!("decode the answer to {request}: {line:?}"))
    };
    tokio::time::timeout(Duration::from_secs(5), answer).await.with_context(|| format!("guest didn't answer {request}"))?
}

/// A line of a container's output, as `LOGS <container> <seq>` streams them.
#[derive(Deserialize)]
pub struct LogLine {
    pub container: String,
    pub seq: u64,
    pub line: String,
}

#[derive(Deserialize)]
pub struct GuestStats {
    pub memory: Option<MemoryStats>,
    pub disk: Option<DiskStats>,
    #[serde(default)]
    pub containers: BTreeMap<String, ContainerStats>,
}

#[derive(Deserialize)]
pub struct MemoryStats {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Deserialize)]
pub struct DiskStats {
    pub total_bytes: u64,
    pub free_bytes: u64,
}

#[derive(Deserialize)]
pub struct ContainerStats {
    pub cpu_usec: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub oom_kill: Option<u64>,
    pub pids: Option<u64>,
}

/// Asks for version 1 stats.
pub async fn guest_stats(vsock: &Path) -> anyhow::Result<GuestStats> {
    #[derive(Deserialize)]
    struct Versioned {
        version: u32,
        #[serde(flatten)]
        stats: GuestStats,
    }
    let answer: Versioned = ask_guest(vsock, "STATS 1").await?;
    ensure!(answer.version == 1, "guest answered stats version {}", answer.version);
    Ok(answer.stats)
}
