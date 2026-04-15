//! Fakes for the vmm and host kernel, plus a config with real artifact files, so the manager runs without root.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use guestnet::Slot;
use serde_json::{Value, json};
use vmm::{Boot, Failures, Guest, Instance, RestoreSource};

use crate::config::Config;
use crate::host::{Host, Uplink};

/// The SHA-256 of nothing, which every test artifact hashes to.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// A one-template config under `dir`, whose artifacts are empty files there.
pub fn config_json(dir: &Path) -> Value {
    let artifacts = dir.join("artifacts");
    std::fs::create_dir_all(&artifacts).unwrap();
    for name in ["vmlinux", "base.ext4", "scratch.ext4", "web.squashfs"] {
        std::fs::write(artifacts.join(name), "").unwrap();
    }
    json!({
        "state_dir": dir.join("state"),
        "run_dir": dir.join("run"),
        "host_id": "test-host",
        "host_iface": "eth0",
        "endpoint_ip": "10.0.0.1",
        "dns_upstream": "127.0.0.1:53",
        // tests run in parallel, so each gate takes whatever port is free.
        "dnsgate_port": 0,
        "conntrack_sizing_disabled": true,
        "firecracker_bin": "/bin/firecracker",
        "kernel_image_path": artifacts.join("vmlinux"),
        "kernel_sha256": EMPTY_SHA256,
        "ready_timeout_sec": 5,
        "reap_interval_sec": 3600,
        "metrics_interval_sec": 3600,
        "templates": [{
            "template_id": "web-v1",
            "base_disk": artifacts.join("base.ext4"),
            "base_disk_sha256": EMPTY_SHA256,
            "scratch_disk": artifacts.join("scratch.ext4"),
            "scratch_disk_sha256": EMPTY_SHA256,
            "blobs": {"web": artifacts.join("web.squashfs")},
            "blob_sha256": {"web": EMPTY_SHA256},
            "endpoints": {"http": 8080},
            "manifest": {
                "containers": [{"name": "web", "blob": "web"}],
                "readiness": [{"name": "http", "tcp_port": 8080}],
            },
        }],
    })
}

pub fn config(dir: &Path) -> Config {
    serde_json::from_value(config_json(dir)).unwrap()
}

/// A fake vmm whose processes are just pids it hands out. They stay alive until killed.
#[derive(Default)]
pub struct FakeDriver {
    next_pid: AtomicU32,
    killed: Mutex<BTreeSet<u32>>,
    pub kill_fails: AtomicBool,
    pub starts: AtomicU32,
    pub restores: Mutex<Vec<RestoreSource>>,
}

impl FakeDriver {
    fn spawn(&self, inst: &mut Instance) {
        inst.pid = Some(1_000_000 + self.next_pid.fetch_add(1, Ordering::Relaxed));
    }

    /// Kills the vmm as if it crashed.
    pub fn crash(&self, inst: &Instance) {
        self.killed.lock().unwrap().extend(inst.pid);
    }
}

impl vmm::Driver for FakeDriver {
    fn setup(&self) -> Result<()> {
        Ok(())
    }

    fn allocate(&self, inst: &mut Instance, guest: &Guest) {
        inst.api_sock = guest.run_dir.join("fc.sock");
        inst.vsock_path = guest.run_dir.join("v.sock");
    }

    fn uid(&self, _: &Instance) -> u32 {
        0
    }

    fn prepare(&self, _: &Instance, _: &Guest) -> Result<()> {
        Ok(())
    }

    async fn start(&self, inst: &mut Instance, _: &Boot) -> Result<()> {
        self.starts.fetch_add(1, Ordering::Relaxed);
        self.spawn(inst);
        fake_guest(&inst.vsock_path);
        Ok(())
    }

    fn adopt(&self, _: &Instance) -> Result<()> {
        Ok(())
    }

    fn alive(&self, inst: &Instance) -> bool {
        inst.pid.is_some_and(|pid| !self.killed.lock().unwrap().contains(&pid))
    }

    async fn kill(&self, inst: &Instance) -> Result<()> {
        if self.kill_fails.load(Ordering::Relaxed) {
            bail!("vmm won't die");
        }
        self.crash(inst);
        Ok(())
    }

    async fn cleanup(&self, _: &Instance) -> Result<(), Failures> {
        Ok(())
    }

    fn cgroup(&self, _: &Instance) -> Option<PathBuf> {
        None
    }

    async fn sweep(&self, _: &[&Instance]) -> Result<(), Failures> {
        Ok(())
    }

    async fn snapshot(&self, _: &Instance, dir: &Path, _: bool) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join(vmm::SNAPSHOT_DISK), "")?;
        Ok(())
    }

    async fn restore(&self, inst: &mut Instance, _: &Boot, src: &RestoreSource) -> Result<()> {
        self.restores.lock().unwrap().push(src.clone());
        self.spawn(inst);
        fake_guest(&inst.vsock_path);
        Ok(())
    }

    async fn export_memory(&self, dir: &Path) -> Result<PathBuf> {
        Ok(dir.join("mem"))
    }

    async fn finish_recording(&self, _: &Instance, _: &Path) -> Result<()> {
        Ok(())
    }
}

/// A host where networks always build and guests answer once `ready` is set.
pub struct FakeHost {
    pub ready: AtomicBool,
    pub apply_fails: AtomicBool,
    pub rulesets: Mutex<Vec<String>>,
    pub deleted: Mutex<Vec<u32>>,
}

impl Default for FakeHost {
    fn default() -> Self {
        Self { ready: AtomicBool::new(true), apply_fails: AtomicBool::new(false), rulesets: Mutex::default(), deleted: Mutex::default() }
    }
}

impl FakeHost {
    pub fn last_ruleset(&self) -> String {
        self.rulesets.lock().unwrap().last().cloned().unwrap_or_default()
    }
}

impl Host for FakeHost {
    fn enable_forwarding(&self) -> Result<()> {
        Ok(())
    }

    async fn uplink(&self) -> Result<Uplink> {
        Ok(Uplink { iface: "eth0".into(), source: Some(Ipv4Addr::new(10, 0, 0, 1)) })
    }

    async fn apply_ruleset(&self, ruleset: String) -> Result<()> {
        if self.apply_fails.load(Ordering::Relaxed) {
            bail!("nft says no");
        }
        self.rulesets.lock().unwrap().push(ruleset);
        Ok(())
    }

    async fn create_session(&self, _: Slot, _: u32) -> Result<()> {
        Ok(())
    }

    async fn delete_session(&self, slot: Slot) -> Result<()> {
        self.deleted.lock().unwrap().push(slot.index);
        Ok(())
    }

    fn attach_netns(&self, _: Slot, _: u32) -> Result<()> {
        Ok(())
    }

    async fn sweep_networks(&self, _: &[Slot]) {}

    fn kill_stray_vmms(&self, _: &Path, _: &Path, _: &[u32]) {}

    async fn accepts(&self, _: SocketAddr, within: Duration) -> bool {
        if self.ready.load(Ordering::Relaxed) {
            return true;
        }
        tokio::time::sleep(within).await;
        false
    }
}

/// Serves the guest API at `path` behind Firecracker's hybrid vsock handshake. `CLOCK` succeeds and `STATS` reports a
/// guest with no containers.
fn fake_guest(path: &Path) {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path).unwrap();
    tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut conn = BufReader::new(conn);
                let mut line = String::new();
                conn.read_line(&mut line).await?;
                conn.get_mut().write_all(b"OK 1\n").await?;
                line.clear();
                conn.read_line(&mut line).await?;
                let reply: &[u8] = if line.starts_with("CLOCK 1 ") {
                    b"OK\n"
                } else if line == "STATS 1\n" {
                    b"{\"version\":1,\"memory\":{\"total_bytes\":100,\"available_bytes\":50},\"containers\":{}}\n"
                } else {
                    return Ok(());
                };
                conn.get_mut().write_all(reply).await?;
                std::io::Result::Ok(())
            });
        }
    });
}
