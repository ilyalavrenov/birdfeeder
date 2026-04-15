//! roost's JSON config: the host's limits and paths, plus the templates its pools boot. Missing fields get defaults,
//! and a rate or limit of -1 turns it off.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use guestapi::workload::{Manifest, is_identifier};
use ipnet::Ipv4Net;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

/// Each session's endpoints get a block of this many host ports.
pub const MAX_ENDPOINTS: usize = 16;
/// [`MAX_ENDPOINTS`] as a port count.
pub const ENDPOINT_BLOCK: u32 = MAX_ENDPOINTS as u32;
const MAX_TEMPLATES: usize = 128;
const MAX_BLOBS: usize = 16;
const MAX_WARMUP_REQUESTS: usize = 16;
const MAX_SESSIONS_PER_HOST: u32 = 1024;
const KIB: u64 = 1 << 10;
const MIB: u64 = 1 << 20;

/// A checked config. Deserializing one checks it, so there's no such thing as an unchecked `Config`.
#[derive(Debug, Clone, Deserialize)]
// `remote = "Self"` turns the derive into an inherent `Config::deserialize`, and the checking `Deserialize` impl below
// wraps it.
#[serde(deny_unknown_fields, remote = "Self")]
pub struct Config {
    pub kernel_sha256: Sha256Hex,
    #[serde(default = "defaults::listen_addr")]
    pub listen_addr: SocketAddr,
    #[serde(default = "defaults::state_dir")]
    pub state_dir: PathBuf,
    /// Holds the session, generation and template records that every claim fsyncs. Put it on its own filesystem and
    /// claims stop waiting on journal commits that flush guest disk writes. Defaults to `state_dir`.
    #[serde(default)]
    session_state_dir: Option<PathBuf>,
    #[serde(default = "defaults::run_dir")]
    pub run_dir: PathBuf,
    /// Defaults to the hostname.
    #[serde(default = "defaults::host_id")]
    pub host_id: String,
    /// Where clients reach endpoints. Falls back to the default route's source address.
    #[serde(default)]
    pub endpoint_ip: Option<Ipv4Addr>,
    /// Where guest traffic leaves the host. Falls back to the default route's interface.
    #[serde(default)]
    pub host_iface: Option<String>,
    /// Carved into one /30 per session.
    #[serde(default = "defaults::subnet")]
    pub subnet: Ipv4Net,
    #[serde(default = "defaults::dnat_port_start")]
    pub dnat_port_start: u16,
    #[serde(default = "defaults::max_sessions")]
    pub max_sessions: u32,
    #[serde(default = "defaults::guest_log_max_streams")]
    pub guest_log_max_streams: u32,
    #[serde(default = "defaults::max_vcpus")]
    pub max_vcpus: u32,
    #[serde(default = "defaults::max_memory_mib")]
    pub max_memory_mib: u32,
    /// Skips raising `nf_conntrack_max` to cover every guest's connection cap.
    #[serde(default)]
    pub conntrack_sizing_disabled: bool,

    pub firecracker_bin: PathBuf,
    pub kernel_image_path: PathBuf,
    #[serde(default = "defaults::boot_args")]
    pub boot_args: String,
    #[serde(default)]
    pub hugepages_2m: bool,
    /// `None` when `jailer.disabled` runs the vmms as roost.
    #[serde(default = "defaults::jailer", deserialize_with = "jailer")]
    jailer: Option<Jailer>,
    /// Caps guest serial output, since the guest controls it.
    #[serde(default = "defaults::serial_bytes_per_sec", deserialize_with = "rate")]
    pub serial_bytes_per_sec: Option<NonZeroU64>,
    /// Defaults to `uffd-handler` next to `firecracker_bin`.
    #[serde(default)]
    uffd_handler_bin: Option<PathBuf>,

    /// Keeps a copy of each template's snapshot memory. Restores after the first one read it by range, but the
    /// recording restore sticks with the local file.
    #[serde(default)]
    pub snapshot_store: Option<snapstore::Config>,
    /// Rotates a guest's console.log above this size.
    #[serde(default = "defaults::console_max_bytes", deserialize_with = "rate")]
    pub console_max_bytes: Option<NonZeroU64>,
    #[serde(default = "defaults::one")]
    pub max_concurrent_boots: u32,
    #[serde(rename = "ready_timeout_sec", default = "defaults::ready_timeout", deserialize_with = "secs")]
    pub ready_timeout: Duration,
    /// How long a pooled guest can wait for a claim. Negative means forever.
    #[serde(rename = "max_unregistered_sec", default = "defaults::max_unregistered", deserialize_with = "optional_secs")]
    pub max_unregistered: Option<Duration>,
    #[serde(rename = "reap_interval_sec", default = "defaults::reap_interval", deserialize_with = "secs")]
    pub reap_interval: Duration,
    /// How long we keep a deleted session's idempotency key, so a late retry of its claim can't claim a second session.
    #[serde(rename = "claim_key_retention_sec", default = "defaults::claim_key_retention", deserialize_with = "secs")]
    pub claim_key_retention: Duration,
    #[serde(rename = "metrics_interval_sec", default = "defaults::metrics_interval", deserialize_with = "secs")]
    pub metrics_interval: Duration,

    /// Port allowlisted guest DNS gets redirected to. 0 picks a free one.
    #[serde(default = "defaults::dnsgate_port")]
    pub dnsgate_port: u16,
    /// Defaults to the first nameserver in /etc/resolv.conf.
    #[serde(default)]
    pub dns_upstream: Option<SocketAddr>,
    // DNS TTLs are whole seconds on the wire. The gate clamps answers' u32 TTLs to these.
    #[serde(default = "defaults::fqdn_min_ttl_sec")]
    pub fqdn_min_ttl_sec: u32,
    #[serde(default = "defaults::fqdn_max_ttl_sec")]
    pub fqdn_max_ttl_sec: u32,
    #[serde(default = "defaults::fqdn_max_ips")]
    pub fqdn_max_ips: u32,
    pub templates: Vec<Arc<Template>>,
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let cfg = Self::deserialize(d)?;
        cfg.validate().map_err(|err| serde::de::Error::custom(format!("{err:#}")))?;
        Ok(cfg)
    }
}

/// Runs each vmm in a chroot, as its own uid.
#[derive(Debug, Clone)]
struct Jailer {
    /// Defaults to `jailer` next to `firecracker_bin`.
    bin: Option<PathBuf>,
    /// Defaults to `<state_dir>/nest`.
    chroot_base: Option<PathBuf>,
    uid_base: u32,
    cgroup_limits: bool,
}

/// The config file's `jailer` object. Once `disabled` is set, the other fields don't mean anything.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawJailer {
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    bin: Option<PathBuf>,
    #[serde(default)]
    chroot_base: Option<PathBuf>,
    #[serde(default = "defaults::uid_base")]
    uid_base: u32,
    #[serde(default)]
    cgroup_limits: bool,
}

fn jailer<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Jailer>, D::Error> {
    let RawJailer { disabled, bin, chroot_base, uid_base, cgroup_limits } = RawJailer::deserialize(d)?;
    Ok((!disabled).then_some(Jailer { bin, chroot_base, uid_base, cgroup_limits }))
}

/// A SHA-256 digest in lowercase hex, as `sha256sum` prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Sha256Hex(String);

#[derive(Debug, thiserror::Error)]
#[error("not a lowercase hex SHA-256 digest")]
pub struct NotSha256;

impl TryFrom<String> for Sha256Hex {
    type Error = NotSha256;

    fn try_from(s: String) -> Result<Self, NotSha256> {
        if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) { Ok(Self(s)) } else { Err(NotSha256) }
    }
}

impl Sha256Hex {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    pub template_id: String,
    pub base_disk: PathBuf,
    pub base_disk_sha256: Sha256Hex,
    /// An empty filesystem. Each guest gets its own copy for writable state.
    pub scratch_disk: PathBuf,
    pub scratch_disk_sha256: Sha256Hex,
    pub blobs: BTreeMap<String, PathBuf>,
    pub blob_sha256: BTreeMap<String, Sha256Hex>,
    pub manifest: Manifest,
    /// Named guest ports, published at a claim.
    #[serde(default)]
    endpoints: BTreeMap<String, u16>,
    #[serde(default = "defaults::vcpus")]
    pub vcpus: NonZeroU32,
    #[serde(default = "defaults::mem_mib")]
    pub mem_mib: u32,
    #[serde(default)]
    pub pool_target: u32,
    #[serde(default = "defaults::disk_bytes_per_sec", deserialize_with = "rate")]
    pub disk_bytes_per_sec: Option<NonZeroU64>,
    // Firecracker's virtio-blk has max_segments=1, so ops are just 4k bandwidth.
    #[serde(default, deserialize_with = "rate")]
    pub disk_ops_per_sec: Option<NonZeroU64>,
    #[serde(default = "defaults::net_bytes_per_sec", deserialize_with = "rate")]
    pub net_bytes_per_sec: Option<NonZeroU64>,
    #[serde(default = "defaults::net_packets_per_sec", deserialize_with = "rate")]
    pub net_packets_per_sec: Option<NonZeroU64>,
    /// Caps each guest's concurrent connections, and the burst for its new connections per second.
    #[serde(default = "defaults::conn_limit", deserialize_with = "conn_limit")]
    pub conn_limit: Option<NonZeroU32>,
    /// Restores pool guests from one booted guest's memory. Leave it out to cold-boot every guest.
    #[serde(default)]
    pub snapshot: Option<Snapshot>,
    /// Hit on a lazy template's first restored guest while its handler records which pages they touch. Later restores
    /// load those pages up front. Startup and readiness always get recorded.
    #[serde(default)]
    pub snapshot_warmup: Vec<Warmup>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Snapshot {
    /// Pages are served on fault.
    Lazy,
    /// Every page loads before the guest resumes.
    Eager,
}

/// An HTTP GET of `path` on a named endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Warmup {
    pub endpoint: String,
    pub path: String,
}

mod defaults {
    use super::*;

    pub fn listen_addr() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 7443))
    }
    pub fn state_dir() -> PathBuf {
        "/var/lib/birdfeeder".into()
    }
    pub fn run_dir() -> PathBuf {
        "/run/birdfeeder".into()
    }
    pub fn host_id() -> String {
        nix::unistd::gethostname().ok().and_then(|h| h.into_string().ok()).unwrap_or_default()
    }
    pub fn subnet() -> Ipv4Net {
        Ipv4Net::new_assert(Ipv4Addr::new(172, 20, 0, 0), 24)
    }
    pub fn boot_args() -> String {
        // firecracker appends root= and ro from the read-only root drive.
        "init=/sbin/init birdfeeder.guest=1 reboot=k panic=-1 nomodule transparent_hugepage=always console=ttyS0 i8042.noaux \
         i8042.nomux i8042.dumbkbd swiotlb=noforce pci=off"
            .into()
    }
    pub fn dnat_port_start() -> u16 {
        31000
    }
    pub fn max_sessions() -> u32 {
        2
    }
    pub fn guest_log_max_streams() -> u32 {
        32
    }
    pub fn max_vcpus() -> u32 {
        2
    }
    pub fn max_memory_mib() -> u32 {
        1024
    }
    pub fn one() -> u32 {
        1
    }
    pub fn serial_bytes_per_sec() -> Option<NonZeroU64> {
        NonZeroU64::new(64 * KIB)
    }
    pub fn console_max_bytes() -> Option<NonZeroU64> {
        NonZeroU64::new(8 * MIB)
    }
    pub fn ready_timeout() -> Duration {
        Duration::from_mins(5)
    }
    #[expect(clippy::unnecessary_wraps, reason = "a serde default has the field's type")]
    pub fn max_unregistered() -> Option<Duration> {
        Some(Duration::from_mins(15))
    }
    pub fn reap_interval() -> Duration {
        Duration::from_secs(5)
    }
    pub fn claim_key_retention() -> Duration {
        Duration::from_hours(24)
    }
    pub fn metrics_interval() -> Duration {
        Duration::from_secs(10)
    }
    pub fn dnsgate_port() -> u16 {
        15353
    }
    pub fn fqdn_min_ttl_sec() -> u32 {
        15
    }
    pub fn fqdn_max_ttl_sec() -> u32 {
        300
    }
    pub fn fqdn_max_ips() -> u32 {
        1024
    }
    pub fn uid_base() -> u32 {
        10000
    }
    #[expect(clippy::unnecessary_wraps, reason = "a serde default has the field's type")]
    pub fn jailer() -> Option<Jailer> {
        Some(Jailer { bin: None, chroot_base: None, uid_base: uid_base(), cgroup_limits: false })
    }
    pub fn vcpus() -> NonZeroU32 {
        NonZeroU32::MIN
    }
    pub fn mem_mib() -> u32 {
        512
    }
    pub fn disk_bytes_per_sec() -> Option<NonZeroU64> {
        NonZeroU64::new(64 * MIB)
    }
    pub fn net_bytes_per_sec() -> Option<NonZeroU64> {
        NonZeroU64::new(250 * MIB)
    }
    pub fn net_packets_per_sec() -> Option<NonZeroU64> {
        NonZeroU64::new(250_000)
    }
    pub fn conn_limit() -> Option<NonZeroU32> {
        NonZeroU32::new(4096)
    }
}

/// A positive rate, or -1 for none.
fn rate<'de, D: Deserializer<'de>>(d: D) -> Result<Option<NonZeroU64>, D::Error> {
    match i64::deserialize(d)? {
        -1 => Ok(None),
        n => u64::try_from(n)
            .ok()
            .and_then(NonZeroU64::new)
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom("rates and limits must be positive or -1")),
    }
}

fn conn_limit<'de, D: Deserializer<'de>>(d: D) -> Result<Option<NonZeroU32>, D::Error> {
    rate(d)?
        .map(|n| u32::try_from(n.get()).ok().and_then(NonZeroU32::new).ok_or_else(|| serde::de::Error::custom("conn_limit out of range")))
        .transpose()
}

fn secs<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    u64::deserialize(d).map(Duration::from_secs)
}

/// Positive seconds, or a negative number for none.
fn optional_secs<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
    match i64::deserialize(d)? {
        n if n < 0 => Ok(None),
        0 => Err(serde::de::Error::custom("must be positive, or negative for none")),
        n => Ok(Some(Duration::from_secs(n.unsigned_abs()))),
    }
}

impl Config {
    /// Reads and checks the config at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).with_context(|| format!("read config {}", path.display()))?;
        serde_json::from_slice(&data).context("parse config")
    }

    #[must_use]
    pub fn session_state_dir(&self) -> &Path {
        self.session_state_dir.as_deref().unwrap_or(&self.state_dir)
    }

    #[must_use]
    pub fn uffd_handler_bin(&self) -> PathBuf {
        self.uffd_handler_bin.clone().unwrap_or_else(|| self.beside_firecracker("uffd-handler"))
    }

    fn beside_firecracker(&self, name: &str) -> PathBuf {
        self.firecracker_bin.parent().unwrap_or(Path::new("")).join(name)
    }

    /// Where jailed vms' chroots live, `None` when the jailer is off.
    #[must_use]
    pub fn chroot_base(&self) -> Option<PathBuf> {
        let j = self.jailer.as_ref()?;
        Some(j.chroot_base.clone().unwrap_or_else(|| self.state_dir.join("nest")))
    }

    #[must_use]
    pub fn driver(&self) -> vmm::firecracker::Config {
        vmm::firecracker::Config {
            firecracker_bin: self.firecracker_bin.clone(),
            kernel_image_path: self.kernel_image_path.clone(),
            boot_args: self.boot_args.clone(),
            hugepages_2m: self.hugepages_2m,
            jailer: self.jailer.as_ref().zip(self.chroot_base()).map(|(j, chroot_base)| vmm::firecracker::Jailer {
                bin: j.bin.clone().unwrap_or_else(|| self.beside_firecracker("jailer")),
                chroot_base,
                uid_base: j.uid_base,
                cgroup_limits: j.cgroup_limits,
            }),
            serial_bytes_per_sec: self.serial_bytes_per_sec,
            uffd_handler_bin: self.uffd_handler_bin(),
        }
    }

    /// How many sessions the subnet and limits leave room for.
    #[must_use]
    pub fn slots(&self) -> u32 {
        guestnet::slot_count(self.subnet).min(self.max_sessions)
    }

    #[must_use]
    pub fn template(&self, id: &str) -> Option<&Template> {
        self.templates.iter().map(Arc::as_ref).find(|t| t.template_id == id)
    }

    #[must_use]
    pub fn snapshots_enabled(&self) -> bool {
        self.templates.iter().any(|t| t.snapshot.is_some())
    }

    fn validate(&self) -> Result<()> {
        ensure!((1..=1024).contains(&self.guest_log_max_streams), "guest_log_max_streams must be between 1 and 1024");
        let subnet = self.subnet;
        ensure!(
            (16..=30).contains(&subnet.prefix_len()) && subnet.addr() == subnet.network(),
            "subnet must be a canonical IPv4 /16 through /30"
        );
        ensure!(!subnet.contains(&guestnet::GUEST_NET) && !guestnet::GUEST_NET.contains(&subnet), "subnet {subnet} overlaps guest network");
        ensure!(
            (1..=MAX_SESSIONS_PER_HOST.min(guestnet::slot_count(subnet))).contains(&self.max_sessions)
                && (1..=65536).contains(&self.max_vcpus)
                && (128..=1 << 30).contains(&self.max_memory_mib),
            "invalid host resource limits"
        );
        let last_port = u32::from(self.dnat_port_start) + self.max_sessions * ENDPOINT_BLOCK - 1;
        ensure!(self.dnat_port_start >= 1024 && u16::try_from(last_port).is_ok(), "DNAT port range exceeds 1024..65535");
        self.validate_paths()?;
        ensure!(
            (1..=self.max_sessions).contains(&self.max_concurrent_boots)
                && (Duration::from_secs(1)..=Duration::from_hours(1)).contains(&self.ready_timeout)
                && !self.reap_interval.is_zero()
                && !self.metrics_interval.is_zero(),
            "invalid concurrency or intervals"
        );
        ensure!(
            self.fqdn_min_ttl_sec >= 1 && self.fqdn_max_ttl_sec >= self.fqdn_min_ttl_sec && (1..=65536).contains(&self.fqdn_max_ips),
            "invalid DNS limits"
        );
        self.validate_templates()?;
        if let Some(store) = &self.snapshot_store {
            store.validate()?;
        }
        ensure!(
            !self.firecracker_bin.as_os_str().is_empty() && !self.kernel_image_path.as_os_str().is_empty(),
            "firecracker_bin and kernel_image_path required"
        );
        Ok(())
    }

    fn validate_templates(&self) -> Result<()> {
        ensure!((1..=MAX_TEMPLATES).contains(&self.templates.len()), "configure 1..{MAX_TEMPLATES} templates");
        let (mut sessions, mut cpus, mut memory) = (0_u64, 0_u64, 0_u64);
        let mut seen = BTreeSet::new();
        for t in &self.templates {
            ensure!(seen.insert(t.template_id.as_str()), "duplicate template {:?}", t.template_id);
            t.validate().with_context(|| format!("template {:?}", t.template_id))?;
            ensure!(
                t.pool_target <= self.max_sessions && t.vcpus.get() <= self.max_vcpus && t.mem_mib <= self.max_memory_mib,
                "template {:?} exceeds host budget",
                t.template_id
            );
            sessions += u64::from(t.pool_target);
            cpus += u64::from(t.pool_target) * u64::from(t.vcpus.get());
            memory += u64::from(t.pool_target) * u64::from(t.mem_mib);
        }
        ensure!(
            sessions <= u64::from(self.max_sessions) && cpus <= u64::from(self.max_vcpus) && memory <= u64::from(self.max_memory_mib),
            "warm pool targets exceed host budget"
        );
        Ok(())
    }

    /// Cleanup deletes what roost owns under these roots, so none of them can hold state, another root, or a runtime
    /// input.
    fn validate_paths(&self) -> Result<()> {
        let state = managed_root(&self.state_dir)?;
        let run = managed_root(&self.run_dir)?;
        let sessions = managed_root(self.session_state_dir())?;
        let chroots = self.chroot_base().map(|p| managed_root(&p)).transpose()?;
        let mut owned = vec![sessions.join("sessions"), state.join("disks"), state.join("snapshots"), run];
        owned.extend(chroots.map(|c| c.join("firecracker")));
        // a subdirectory might itself be a symlink to somewhere else.
        let owned = owned.iter().map(|p| resolve(p)).collect::<Result<Vec<_>>>()?;
        let inputs = self.runtime_inputs().iter().map(|p| resolve(p)).collect::<Result<Vec<_>>>()?;
        let mut rest = owned.as_slice();
        while let [dir, others @ ..] = rest {
            rest = others;
            for state in [&state, &sessions] {
                ensure!(!state.starts_with(dir), "managed directory {} contains state directory {}", dir.display(), state.display());
            }
            for other in others {
                ensure!(
                    !other.starts_with(dir) && !dir.starts_with(other),
                    "managed directories {} and {} overlap",
                    dir.display(),
                    other.display()
                );
            }
            for input in &inputs {
                ensure!(!input.starts_with(dir), "runtime input {} is inside managed directory {}", input.display(), dir.display());
            }
        }
        Ok(())
    }

    fn runtime_inputs(&self) -> Vec<PathBuf> {
        let mut inputs = vec![self.kernel_image_path.clone(), self.firecracker_bin.clone(), self.uffd_handler_bin()];
        if let Some(jailer) = self.driver().jailer {
            inputs.push(jailer.bin);
        }
        for t in &self.templates {
            inputs.extend([t.base_disk.clone(), t.scratch_disk.clone()]);
            inputs.extend(t.blobs.values().cloned());
        }
        inputs
    }
}

/// A managed directory's real path. Can't be `/`, or a symlink that ends up there.
fn managed_root(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute() && path != Path::new("/") && is_clean(path),
        "managed directory {} must be a clean absolute path other than /",
        path.display()
    );
    let real = resolve(path)?;
    ensure!(real != Path::new("/"), "managed directory {} resolves to /", path.display());
    Ok(real)
}

/// Whether `path` is already clean: no `.`, `..`, empty or trailing components.
fn is_clean(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s == "/" || (!s.ends_with('/') && s.split('/').skip(1).all(|c| !c.is_empty() && c != "." && c != ".."))
}

/// Also resolves symlinks in `path`'s existing ancestors, since managed directories don't have to exist at startup.
fn resolve(path: &Path) -> Result<PathBuf> {
    let abs = std::path::absolute(path).with_context(|| format!("resolve {}", path.display()))?;
    match abs.canonicalize() {
        Ok(real) => Ok(real),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // a dangling symlink is ambiguous.
            if abs.symlink_metadata().is_ok() {
                bail!("resolve {}: {err}", abs.display());
            }
            match (abs.parent(), abs.file_name()) {
                (Some(parent), Some(name)) => Ok(resolve(parent)?.join(name)),
                _ => Ok(abs),
            }
        }
        Err(err) => Err(err).with_context(|| format!("resolve {}", abs.display())),
    }
}

impl Template {
    pub fn endpoints(&self) -> impl Iterator<Item = (&String, u16)> {
        self.endpoints.iter().map(|(name, port)| (name, *port))
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            is_identifier(&self.template_id) && self.base_disk.is_absolute() && self.scratch_disk.is_absolute(),
            "template_id must be a short identifier and base_disk and scratch_disk must be absolute"
        );
        ensure!(self.vcpus.get() <= 32 && (128..=1 << 20).contains(&self.mem_mib), "invalid guest resources");
        ensure!(self.blob_sha256.len() == self.blobs.len(), "artifact SHA-256 digests are required");
        ensure!(self.blobs.len() <= MAX_BLOBS && self.endpoints.len() <= MAX_ENDPOINTS, "too many blobs or endpoints");
        for (name, path) in &self.blobs {
            ensure!(is_identifier(name) && path.is_absolute() && self.blob_sha256.contains_key(name), "invalid blob name or path");
        }
        for (name, port) in self.endpoints() {
            ensure!(is_identifier(name) && port != 0, "invalid endpoint name or port");
        }
        self.manifest.validate()?;
        ensure!(self.manifest.containers.iter().all(|c| self.blobs.contains_key(c.blob.as_str())), "container refers to unknown blob");
        ensure!(self.snapshot_warmup.is_empty() || self.snapshot == Some(Snapshot::Lazy), r#"snapshot_warmup needs snapshot "lazy""#);
        ensure!(self.snapshot_warmup.len() <= MAX_WARMUP_REQUESTS, "too many snapshot_warmup requests");
        for w in &self.snapshot_warmup {
            ensure!(
                self.endpoints().any(|(name, _)| *name == w.endpoint) && w.path.starts_with('/') && w.path.len() <= 1024,
                "snapshot_warmup needs a known endpoint and an absolute path"
            );
        }
        Ok(())
    }

    /// The template's identity, which has to stay the same for a given template id. That's everything that shapes its
    /// guests, but not where its artifacts live (their digests do count), its pool target, or its boot strategy.
    #[must_use]
    pub fn fingerprint(&self, kernel_sha256: &Sha256Hex, boot_args: &str) -> String {
        #[derive(Serialize)]
        struct Identity<'a> {
            template_id: &'a str,
            base_disk_sha256: &'a Sha256Hex,
            scratch_disk_sha256: &'a Sha256Hex,
            blob_sha256: &'a BTreeMap<String, Sha256Hex>,
            manifest: &'a Manifest,
            endpoints: &'a BTreeMap<String, u16>,
            vcpus: NonZeroU32,
            mem_mib: u32,
            disk_bytes_per_sec: Option<NonZeroU64>,
            disk_ops_per_sec: Option<NonZeroU64>,
            net_bytes_per_sec: Option<NonZeroU64>,
            net_packets_per_sec: Option<NonZeroU64>,
            conn_limit: Option<NonZeroU32>,
            kernel_sha256: &'a Sha256Hex,
            boot_args: &'a str,
        }
        let identity = Identity {
            template_id: &self.template_id,
            base_disk_sha256: &self.base_disk_sha256,
            scratch_disk_sha256: &self.scratch_disk_sha256,
            blob_sha256: &self.blob_sha256,
            manifest: &self.manifest,
            endpoints: &self.endpoints,
            vcpus: self.vcpus,
            mem_mib: self.mem_mib,
            disk_bytes_per_sec: self.disk_bytes_per_sec,
            disk_ops_per_sec: self.disk_ops_per_sec,
            net_bytes_per_sec: self.net_bytes_per_sec,
            net_packets_per_sec: self.net_packets_per_sec,
            conn_limit: self.conn_limit,
            kernel_sha256,
            boot_args,
        };
        hex::encode(Sha256::digest(serde_json::to_vec(&identity).expect("strings, integers and string-keyed maps always serialize")))
    }
}

#[cfg(test)]
mod tests;
