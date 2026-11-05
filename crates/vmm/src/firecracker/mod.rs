//! A [`Driver`](crate::Driver) that runs each guest in Firecracker, sandboxed by its jailer unless that's disabled.

use std::borrow::Cow;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::{self, Read as _};
use std::num::NonZeroU64;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use fcapi::{
    BootSource, Drive, DriveCacheType, DriveIoEngine, InstanceActionInfo, InstanceActionInfoActionType, MachineConfiguration,
    MachineConfigurationHugePages, MmdsConfig, MmdsConfigVersion, NetworkInterface, RateLimiter, SerialDevice, TokenBucket, Vsock,
};
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use opentelemetry::metrics::Meter;
use serde::Serialize;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};
use tracing::field::Empty;
use tracing::{Instrument, Span};

use crate::{Boot, Failures, Guest, Instance, Limits, NestId, RestoreSource, Sandbox, Stage, staged};

mod api;
mod metrics;
mod nest;
mod snapshot;
mod telemetry;
#[cfg(test)]
mod tests;

use api::{Api, Endpoint, Mmds};

pub struct Config {
    pub firecracker_bin: PathBuf,
    pub kernel_image_path: PathBuf,
    pub boot_args: String,
    pub hugepages_2m: bool,
    /// `None` runs Firecracker unsandboxed, as roost's uid.
    pub jailer: Option<Jailer>,
    /// Caps guest serial output since the guest controls it. `None` means no cap.
    pub serial_bytes_per_sec: Option<NonZeroU64>,
    /// The page fault handler for restored vms.
    pub uffd_handler_bin: PathBuf,
}

pub struct Jailer {
    pub bin: PathBuf,
    /// Chroots are `<chroot_base>/firecracker/<nest id>/root`.
    pub chroot_base: PathBuf,
    /// Each vm runs as uid = gid = `uid_base` + slot.
    pub uid_base: u32,
    /// Caps each vm's cgroup at its guest ram (memory.max, hugetlb.2MB.max). Off until we've measured the headroom.
    pub cgroup_limits: bool,
}

pub struct Driver {
    cfg: Config,
    metrics: Arc<metrics::Metrics>,
    cgroup_root: PathBuf,
}

impl Driver {
    #[must_use]
    pub fn new(cfg: Config, meter: &Meter) -> Self {
        Self { cfg, metrics: Arc::new(metrics::Metrics::new(meter)), cgroup_root: CGROUP_ROOT.into() }
    }
}

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SOCK_WAIT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
// sockets show up within milliseconds of the process starting, and every boot waits on two of them
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(5);
const KILL_WAIT: Duration = Duration::from_secs(10);
const CONSOLE_HEAD_BYTES: u64 = 512;
const FILE_MODE: u32 = 0o600;
const MIB: u64 = 1 << 20;

const API_SOCK_NAME: &str = "fc.sock";
const MMDS_IP: &str = "169.254.169.254";
// lowest cid Firecracker accepts. one vm per device, so every vm can just use it
const VSOCK_GUEST_CID: i64 = 3;
const VSOCK_SOCK_NAME: &str = "v.sock";
const REFILL_TIME_MS: i64 = 1000;
// boot reads go full speed off a one-time burst, then the sustained cap kicks in
const DISK_BOOT_BURST_SECS: u64 = 16;
const SERIAL_BURST_SECS: u64 = 64;

impl crate::Driver for Driver {
    fn setup(&self) -> Result<()> {
        if self.cfg.jailer.is_none() {
            return Ok(());
        }
        self.ensure_vm_cgroup()
    }

    fn allocate(&self, inst: &mut Instance, guest: &Guest) {
        inst.api_sock = guest.run_dir.join(API_SOCK_NAME);
        inst.vsock_path = guest.run_dir.join(VSOCK_SOCK_NAME);
        let Some(jailer) = &self.cfg.jailer else { return };
        let id = NestId::new(inst.slot, inst.generation);
        let root = nest::root(&jailer.chroot_base, &id);
        inst.disk = root.join(nest::SCRATCH);
        inst.api_sock = root.join("run/firecracker.socket");
        inst.vsock_path = root.join("run").join(VSOCK_SOCK_NAME);
        inst.sandbox = Sandbox::Jailed(id);
    }

    fn uid(&self, inst: &Instance) -> u32 {
        self.nest(inst).map_or(0, |(jailer, _)| jailer.uid_base + inst.slot)
    }

    fn prepare(&self, inst: &Instance, guest: &Guest) -> Result<()> {
        let Some((jailer, id)) = self.nest(inst) else { return Ok(()) };
        self.prepare_nest(jailer, id, inst, guest)
    }

    async fn start(&self, inst: &mut Instance, boot: &Boot) -> Result<()> {
        self.spawn(inst, boot).await?;
        let api = Api::new(&inst.api_sock);
        self.attach_telemetry(&api, inst).await?;
        for req in self.config_requests(inst, boot) {
            api.send(&req).await?;
        }
        Ok(())
    }

    fn adopt(&self, inst: &Instance) -> Result<()> {
        self.adopt_fifos(inst)
    }

    fn alive(&self, inst: &Instance) -> bool {
        inst.pid.is_some_and(|pid| alive(pid, &marker(inst))) && inst.uffd_pid.is_none_or(|pid| alive(pid, &snapshot::uffd_marker(inst)))
    }

    async fn kill(&self, inst: &Instance) -> Result<()> {
        self.flush_metrics(inst).await;
        if let Some(pid) = inst.pid {
            kill_vmm(pid, &marker(inst)).await?;
        }
        // the handler exits on its own once the vmm's end of the handshake socket closes. this is just the backstop
        if let Some(pid) = inst.uffd_pid {
            kill_vmm(pid, &snapshot::uffd_marker(inst)).await?;
        }
        Ok(())
    }

    async fn cleanup(&self, inst: &Instance) -> Result<(), Failures> {
        match (&inst.sandbox, &self.cfg.jailer) {
            (Sandbox::Jailed(id), Some(jailer)) => return self.remove_nest(jailer, id).await,
            // the instance survived a config change, and without the chroot base we can't find its nest
            (Sandbox::Jailed(id), None) => {
                let err = anyhow::anyhow!("jailed instance but jailer not configured; nest {id} left behind");
                return Err(Failures(vec![staged(Stage::Nest, err)]));
            }
            (Sandbox::Host, _) => {}
        }
        // the stage outlives the restore: the handler doesn't open its files until Firecracker's handshake shows up
        let mut failures = Failures::default();
        for (stage, removed) in [
            (Stage::Disk, tokio::fs::remove_file(&inst.disk).await),
            (Stage::SnapshotStage, tokio::fs::remove_dir_all(snapshot::stage_dir(inst)).await),
        ] {
            if let Err(err) = removed.or_else(|err| if err.kind() == io::ErrorKind::NotFound { Ok(()) } else { Err(err) }) {
                failures.push(staged(stage, anyhow::Error::new(err).context(format!("remove {stage}"))));
            }
        }
        failures.into_result()
    }

    fn cgroup(&self, inst: &Instance) -> Option<PathBuf> {
        inst.sandbox.nest_id().map(|id| self.cgroup_leaf(id))
    }

    async fn sweep(&self, live: &[&Instance]) -> Result<(), Failures> {
        self.sweep_nests(live).await
    }

    async fn snapshot(&self, inst: &Instance, dir: &Path, resume: bool) -> Result<()> {
        self.snapshot_to(inst, dir, resume).await
    }

    async fn restore(&self, inst: &mut Instance, boot: &Boot, src: &RestoreSource) -> Result<()> {
        self.restore_from(inst, boot, src).await
    }

    async fn export_memory(&self, dir: &Path) -> Result<PathBuf> {
        snapshot::export_memory(dir).await
    }

    async fn finish_recording(&self, inst: &Instance, dir: &Path) -> Result<()> {
        snapshot::finish_recording(inst, dir).await
    }
}

impl Sandbox {
    /// The path the vmm should open for a file. Either `host` as is, or `in_nest` relative to the chroot, where the
    /// file gets linked or created.
    fn path_in_vm(&self, host: &Path, in_nest: &str) -> String {
        match self {
            Self::Host => path_str(host),
            Self::Jailed(_) => format!("/{in_nest}"),
        }
    }
}

/// Something a live vmm's cmdline contains, so we don't mistake a reused pid for it.
fn marker(inst: &Instance) -> Vec<u8> {
    match &inst.sandbox {
        Sandbox::Host => inst.api_sock.as_os_str().as_encoded_bytes().to_vec(),
        Sandbox::Jailed(id) => nest::marker(id),
    }
}

/// One call of a fresh guest's configuration.
#[derive(Debug, PartialEq, Serialize)]
#[serde(untagged)]
enum ConfigRequest<'a> {
    Machine(MachineConfiguration),
    BootSource(BootSource),
    Drive(Drive),
    Network(NetworkInterface),
    Vsock(Vsock),
    MmdsConfig(MmdsConfig),
    Mmds(Mmds<'a>),
    Serial(SerialDevice),
    Action(InstanceActionInfo),
}

impl Endpoint for ConfigRequest<'_> {
    fn path(&self) -> Cow<'static, str> {
        match self {
            Self::Machine(r) => r.path(),
            Self::BootSource(r) => r.path(),
            Self::Drive(r) => r.path(),
            Self::Network(r) => r.path(),
            Self::Vsock(r) => r.path(),
            Self::MmdsConfig(r) => r.path(),
            Self::Mmds(r) => r.path(),
            Self::Serial(r) => r.path(),
            Self::Action(r) => r.path(),
        }
    }
}

impl Driver {
    /// The jailer and nest of an instance that runs jailed.
    fn nest<'a>(&'a self, inst: &'a Instance) -> Option<(&'a Jailer, &'a NestId)> {
        Some((self.cfg.jailer.as_ref()?, inst.sandbox.nest_id()?))
    }

    /// Starts the vmm and waits for its API. The process isn't tied to roost. We only reap its exit here, and the
    /// maintenance loop spots the death through [`crate::Driver::alive`].
    async fn spawn(&self, inst: &mut Instance, boot: &Boot) -> Result<()> {
        tokio::fs::create_dir_all(&boot.guest.run_dir).await.context("mkdir run dir")?;
        let console = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_APPEND)
            .mode(FILE_MODE)
            .open(&boot.console)
            .context("create console log")?;
        let mut cmd = Command::from(self.command(inst, &boot.guest)?);
        cmd.stdin(Stdio::null()).stdout(console.try_clone().context("dup console log")?).stderr(console);
        detach(&mut cmd);
        let child = traced("exec_vmm", async { cmd.spawn().context("start vmm") }).await?;
        inst.pid = child.id();
        let reaped = reap(child, inst.name.clone(), "vmm process exited");

        if self.nest(inst).is_some() {
            // --new-pid-ns: the jailer clones firecracker, writes its host pid, and exits
            let pid_file = inst.disk.with_file_name("firecracker.pid");
            inst.pid = Some(traced("wait_pid", jailed_pid(reaped, &pid_file)).await.map_err(|err| with_console(err, &boot.console))?);
        }
        traced("wait_api_socket", wait_for_listener(&inst.api_sock)).await.map_err(|err| with_console(err, &boot.console))
    }

    fn command(&self, inst: &Instance, guest: &Guest) -> Result<std::process::Command> {
        if let Some((jailer, id)) = self.nest(inst) {
            return self.jailer_command(jailer, id, inst, guest);
        }
        let mut cmd = match &guest.netns {
            // firecracker has no --netns flag. ip execs it in place, so the pid and cmdline marker stay firecracker's
            Some(netns) => {
                let mut cmd = std::process::Command::new("ip");
                cmd.args(["netns", "exec"]).arg(netns.file_name().context("netns path has no name")?).arg(&self.cfg.firecracker_bin);
                cmd
            }
            None => std::process::Command::new(&self.cfg.firecracker_bin),
        };
        cmd.arg("--api-sock").arg(&inst.api_sock).args(["--id", &inst.name]);
        Ok(cmd)
    }

    /// The API calls that configure and start a fresh guest, in order.
    fn config_requests<'a>(&self, inst: &Instance, boot: &'a Boot) -> Vec<ConfigRequest<'a>> {
        let g = &boot.guest;
        let sandbox = &inst.sandbox;
        let Limits { disk_bytes_per_sec, disk_ops_per_sec, net_bytes_per_sec, net_packets_per_sec } = boot.limits;
        let disk_limits = rate_limiter(disk_bytes_per_sec, disk_ops_per_sec, DISK_BOOT_BURST_SECS);
        let net_limits = rate_limiter(net_bytes_per_sec, net_packets_per_sec, 0);
        let drive = |id: &str, path: String, root: bool, read_only: bool| {
            ConfigRequest::Drive(Drive {
                blk_size: 512,
                cache_type: DriveCacheType::Unsafe,
                discard: false,
                drive_id: id.into(),
                io_engine: DriveIoEngine::Sync,
                is_read_only: Some(read_only),
                is_root_device: root,
                partuuid: None,
                path_on_host: Some(path),
                rate_limiter: disk_limits.clone(),
                socket: None,
                topology: None,
            })
        };

        let mut requests = vec![
            ConfigRequest::Machine(MachineConfiguration {
                cpu_template: None,
                huge_pages: if self.cfg.hugepages_2m { MachineConfigurationHugePages::X2m } else { MachineConfigurationHugePages::None },
                mem_size_mib: g.mem_mib.into(),
                smt: false,
                track_dirty_pages: false,
                vcpu_count: g.vcpus.into(),
            }),
            ConfigRequest::BootSource(BootSource {
                boot_args: Some(self.cfg.boot_args.clone()),
                initrd_path: None,
                kernel_image_path: sandbox.path_in_vm(&self.cfg.kernel_image_path, "vmlinux"),
            }),
            drive("rootfs", sandbox.path_in_vm(&g.base_disk, nest::BASE), true, true),
            drive("scratch", sandbox.path_in_vm(&inst.disk, nest::SCRATCH), false, false),
        ];
        for (index, (name, path)) in g.blobs.iter().enumerate() {
            requests.push(drive(&format!("blob_{index:02}"), sandbox.path_in_vm(path, &format!("{name}.squashfs")), false, true));
        }
        requests.extend([
            ConfigRequest::Network(NetworkInterface {
                guest_mac: Some(g.mac.clone()),
                host_dev_name: g.tap.clone(),
                iface_id: "net1".into(),
                mtu: None,
                rx_rate_limiter: net_limits.clone(),
                tx_rate_limiter: net_limits,
            }),
            ConfigRequest::Vsock(Vsock {
                guest_cid: VSOCK_GUEST_CID,
                uds_path: sandbox.path_in_vm(&inst.vsock_path, &format!("run/{VSOCK_SOCK_NAME}")),
                vsock_id: None,
            }),
            ConfigRequest::MmdsConfig(MmdsConfig {
                imds_compat: false,
                ipv4_address: MMDS_IP.into(),
                network_interfaces: vec!["net1".into()],
                version: MmdsConfigVersion::V2,
            }),
            ConfigRequest::Mmds(Mmds(&boot.metadata)),
        ]);
        if let Some(rate) = self.cfg.serial_bytes_per_sec {
            requests.push(ConfigRequest::Serial(SerialDevice {
                rate_limiter: Some(token_bucket(rate, SERIAL_BURST_SECS)),
                ..SerialDevice::default()
            }));
        }
        requests.push(ConfigRequest::Action(InstanceActionInfo { action_type: InstanceActionInfoActionType::InstanceStart }));
        requests
    }
}

fn path_str(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn api_int(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn token_bucket(per_sec: NonZeroU64, burst_secs: u64) -> TokenBucket {
    let per_sec = per_sec.get();
    TokenBucket {
        one_time_burst: (burst_secs > 0).then(|| api_int(per_sec.saturating_mul(burst_secs))),
        refill_time: REFILL_TIME_MS,
        size: api_int(per_sec),
    }
}

fn rate_limiter(bytes_per_sec: Option<NonZeroU64>, ops_per_sec: Option<NonZeroU64>, burst_secs: u64) -> Option<RateLimiter> {
    let bandwidth = bytes_per_sec.map(|rate| token_bucket(rate, burst_secs));
    let ops = ops_per_sec.map(|rate| token_bucket(rate, burst_secs));
    (bandwidth.is_some() || ops.is_some()).then_some(RateLimiter { bandwidth, ops })
}

/// Puts the child in its own session like the vmm, so roost's signals and terminal don't reach it.
fn detach(cmd: &mut Command) {
    // SAFETY: setsid is async-signal-safe and touches no memory the forked child shares.
    unsafe {
        cmd.pre_exec(|| nix::unistd::setsid().map(drop).map_err(io::Error::from));
    }
}

/// Waits on a detached child so it doesn't hang around as a zombie. The handle reports its exit to whoever cares.
fn reap(mut child: tokio::process::Child, name: String, what: &'static str) -> JoinHandle<io::Result<ExitStatus>> {
    tokio::spawn(async move {
        let status = child.wait().await;
        tracing::debug!(name, ?status, "{what}");
        status
    })
}

/// Runs `step` as a span of the caller's trace, marked failed if it fails.
async fn traced<T>(name: &'static str, step: impl Future<Output = Result<T>>) -> Result<T> {
    let span = tracing::info_span!("step", otel.name = name, otel.status_code = Empty, otel.status_description = Empty);
    let result = step.instrument(span.clone()).await;
    record_error(&span, &result);
    result
}

fn record_error<T>(span: &Span, result: &Result<T>) {
    if let Err(err) = result {
        span.record("otel.status_code", "error");
        span.record("otel.status_description", format!("{err:#}"));
    }
}

fn with_console(err: anyhow::Error, console: &Path) -> anyhow::Error {
    let mut head = Vec::new();
    // the console is just extra context for `err`, so if we can't read it `err` stays as is
    match std::fs::File::open(console).and_then(|f| f.take(CONSOLE_HEAD_BYTES).read_to_end(&mut head)) {
        Ok(n) if n > 0 => err.context(format!("console: {}", String::from_utf8_lossy(&head).trim())),
        _ => err,
    }
}

async fn wait_until(limit: Duration, what: &str, mut ok: impl FnMut() -> bool) -> Result<()> {
    let deadline = Instant::now() + limit;
    while !ok() {
        ensure!(Instant::now() < deadline, "{what} never appeared");
        sleep(SOCKET_POLL_INTERVAL).await;
    }
    Ok(())
}

/// Dials instead of stat'ing: Firecracker binds its API socket (which creates the path) before it listens, and a
/// request in that window gets refused.
async fn wait_for_listener(sock: &Path) -> Result<()> {
    wait_until(SOCK_WAIT, &format!("api socket {}", sock.display()), || std::os::unix::net::UnixStream::connect(sock).is_ok()).await
}

/// Reads Firecracker's pid once the jailer that wrote it has exited.
async fn jailed_pid(jailer: JoinHandle<io::Result<ExitStatus>>, pid_file: &Path) -> Result<u32> {
    let status =
        timeout(SOCK_WAIT, jailer).await.context("jailer didn't exit")?.context("jailer wasn't reaped")?.context("wait for jailer")?;
    ensure!(status.success(), "jailer: {status}");
    read_pid(pid_file).with_context(|| format!("jailer exited without writing {}", pid_file.display()))
}

fn read_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok().filter(|&pid| pid != 0)
}

fn alive(pid: u32, marker: &[u8]) -> bool {
    std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|cmdline| has_marker(&cmdline, marker))
}

fn has_marker(cmdline: &[u8], marker: &[u8]) -> bool {
    cmdline.windows(marker.len()).any(|w| w == marker)
}

/// SIGKILLs the process if it's still the one `marker` names, and waits for it to go.
async fn kill_vmm(pid: u32, marker: &[u8]) -> Result<()> {
    if !alive(pid, marker) {
        return Ok(());
    }
    match kill(Pid::from_raw(pid.cast_signed()), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(err) => return Err(err).with_context(|| format!("kill vmm {pid}")),
    }
    let deadline = Instant::now() + KILL_WAIT;
    while Instant::now() < deadline {
        if exited(pid, marker) {
            return Ok(());
        }
        sleep(POLL_INTERVAL).await;
    }
    bail!("vmm {pid} still alive after SIGKILL")
}

/// Whether the process has let go of everything it held, mainly the guest's tap. An exiting process loses its
/// cmdline before it closes its files, so only a zombie, a gone pid, or a pid reused by something else counts.
fn exited(pid: u32, marker: &[u8]) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { return true };
    // the state comes after the parenthesized command, and the command can have parens in it too
    if stat.rsplit_once(") ").is_some_and(|(_, rest)| rest.starts_with(['Z', 'X'])) {
        return true;
    }
    std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|cmdline| !cmdline.is_empty() && !has_marker(&cmdline, marker))
}
