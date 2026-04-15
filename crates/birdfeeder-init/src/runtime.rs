//! Boots the workload. Reads it from MMDS, mounts its images, writes each container's bundle,
//! starts runc for each one, then serves telemetry until the first container exits.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fs::{self, DirBuilder, File};
use std::io::{BufReader, Read};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use nix::errno::Errno;
use nix::mount::{MsFlags, mount};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use signal_hook::consts::{SIGINT, SIGTERM};
use tracing::{error, info, warn};

use crate::bundle::{self, ImageSpec, ROOTFS};
use crate::logs::{self, DEFAULT_LOG_CAP, FramedLog, Tailer};
use crate::server::{self, Telemetry};
use crate::stats::{Disk, Stats, StatsProvider};
use crate::{mmds, sys};
use guestapi::workload::{Container, Identifier, Metadata};

const GUEST_STATE: &str = "/var/lib/birdfeeder";
const LOGS_DIR: &str = "/var/lib/birdfeeder/logs";
const IMAGES_DIR: &str = "/var/lib/birdfeeder/images";
const CONTAINERS_DIR: &str = "/var/lib/birdfeeder/containers";
const VOLUMES_DIR: &str = "/var/lib/birdfeeder/volumes";
const RUNC: &str = "/usr/local/bin/runc";
const MMDS: &str = "http://169.254.169.254";
const GUEST_MARKER: &str = " birdfeeder.guest=1 ";
const DIR_MODE: u32 = 0o755;
const MAX_IMAGE_CONFIG_BYTES: u64 = 1 << 20;
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// How long a stopping guest gives log followers to read the last records.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Only returns with the reason the guest is stopping.
pub fn run() -> Result<Infallible> {
    let signals = signal_pipe()?;
    let cmdline = fs::read_to_string("/proc/cmdline").context("read kernel cmdline")?;
    ensure!(format!(" {} ", cmdline.trim()).contains(GUEST_MARKER), "kernel cmdline lacks the guest marker");
    let md = mmds::fetch(MMDS)?;
    info!(template_id = %md.template_id, "workload received");
    prepare(&md)?;

    let containers = &md.manifest.containers;
    let mut logs = BTreeMap::new();
    let mut stdio = Vec::with_capacity(containers.len());
    // declared before `running` on purpose. on any return the containers get killed and reaped first,
    // then the tailers frame everything they wrote, then followers get to send it.
    let mut tails = Tails(Vec::with_capacity(containers.len()));
    for c in containers {
        let tailer = Tailer::open(Path::new(LOGS_DIR), c.name.as_str(), DEFAULT_LOG_CAP)?;
        logs.insert(c.name.to_string(), tailer.log());
        stdio.push(tailer.stdio().context("clone log descriptors")?);
        tails.spawn(tailer);
    }
    let listener = server::listen(guestapi::PORT)?;
    let stats = StatsProvider::new("/proc", "/sys/fs/cgroup/birdfeeder", containers.iter().map(|c| c.name.to_string()).collect(), || {
        sys::disk_stats(Path::new(GUEST_STATE))
    });
    let telemetry = Arc::new(Telemetry { logs, system: Guest(stats) });
    thread::spawn(move || server::serve(&listener, &telemetry));

    let mut running = Running(Vec::with_capacity(containers.len()));
    for (c, (stdout, stderr)) in containers.iter().zip(stdio) {
        let mut child = Command::new(RUNC)
            .args(["run", "--bundle"])
            .arg(Path::new(CONTAINERS_DIR).join(&c.name))
            .arg(&c.name)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .with_context(|| format!("start container {}", c.name))?;
        let pidfd = match sys::pidfd_open(child.id()) {
            Ok(pidfd) => pidfd,
            Err(e) => {
                // not in `running` yet, so nothing else will kill and reap it.
                let _ = child.kill();
                let _ = child.wait();
                return Err(e).with_context(|| format!("watch container {}", c.name));
            }
        };
        running.0.push(Started { name: c.name.clone(), child, pidfd });
    }
    info!(count = containers.len(), "containers started");
    Err(running.wait_first(&signals)?.into())
}

struct Guest<D>(StatsProvider<D>);

impl<D: Fn() -> Option<Disk> + Send + Sync> server::System for Guest<D> {
    fn stats(&self) -> Stats {
        self.0.get()
    }

    fn set_clock(&self, since_epoch: Duration) -> std::io::Result<()> {
        sys::set_realtime(since_epoch)
    }
}

/// The containers' tail loops. Dropping it lets each one finish and waits for it, then gives
/// connected followers up to [`DRAIN_TIMEOUT`] to read the last record. The guest reboots once
/// init returns, and anything they haven't sent goes with it.
struct Tails(Vec<Tail>);

struct Tail {
    log: Arc<FramedLog>,
    stop: Sender<()>,
    thread: JoinHandle<()>,
}

impl Tails {
    fn spawn(&mut self, tailer: Tailer) {
        let (stop, stopped) = mpsc::channel();
        let log = tailer.log();
        self.0.push(Tail { log, stop, thread: thread::spawn(move || tail(tailer, &stopped)) });
    }
}

impl Drop for Tails {
    fn drop(&mut self) {
        // drop all the senders before the first join so the loops wind down in parallel.
        let tails: Vec<_> = self
            .0
            .drain(..)
            .map(|Tail { log, stop, thread }| {
                drop(stop);
                (log, thread)
            })
            .collect();
        let mut logs = Vec::with_capacity(tails.len());
        for (log, thread) in tails {
            // a tail loop that panicked already reported it, and it only cost that container's last lines.
            let _ = thread.join();
            log.close();
            logs.push(log);
        }
        let deadline = Instant::now() + DRAIN_TIMEOUT;
        for log in logs {
            if !log.followers.wait_gone(deadline) {
                warn!(container = log.name, "log followers still reading at stop");
            }
        }
    }
}

/// Polls until its sender drops, then wraps up.
fn tail(mut tailer: Tailer, stopped: &Receiver<()>) {
    loop {
        if let Err(err) = tailer.poll() {
            error!(container = tailer.log().name, err = format!("{err:#}"), "tail");
        }
        if stopped.recv_timeout(POLL_INTERVAL) != Err(RecvTimeoutError::Timeout) {
            break;
        }
    }
    if let Err(err) = tailer.finish() {
        error!(container = tailer.log().name, err = format!("{err:#}"), "tail");
    }
}

/// SIGINT and SIGTERM as an fd, so we can poll it next to the containers'.
fn signal_pipe() -> Result<UnixStream> {
    let (read, write) = UnixStream::pair().context("signal pipe")?;
    for sig in [SIGINT, SIGTERM] {
        signal_hook::low_level::pipe::register(sig, write.try_clone()?).context("register signal")?;
    }
    Ok(read)
}

/// The started containers. Dropping it kills and reaps them all.
struct Running(Vec<Started>);

struct Started {
    name: Identifier,
    /// The container's runc.
    child: Child,
    /// Polls readable once `child` exits.
    pidfd: OwnedFd,
}

/// Why a guest stops after its containers ran. Any container exit ends the guest, so even a clean one counts.
#[derive(Debug, thiserror::Error)]
enum StopReason {
    #[error("stopped by signal")]
    Signal,
    #[error("container {0} exited")]
    Exited(Identifier),
    #[error("container {0} exited: {1}")]
    Failed(Identifier, ExitStatus),
}

impl Running {
    fn wait_first(&mut self, signals: &UnixStream) -> Result<StopReason> {
        loop {
            let mut fds: Vec<PollFd<'_>> = self.0.iter().map(|c| PollFd::new(c.pidfd.as_fd(), PollFlags::POLLIN)).collect();
            fds.push(PollFd::new(signals.as_fd(), PollFlags::POLLIN));
            match poll(&mut fds, PollTimeout::NONE) {
                Ok(_) | Err(Errno::EINTR) => {}
                Err(e) => return Err(e).context("wait for containers"),
            }
            let readable = |fd: &PollFd<'_>| fd.revents().is_some_and(|r| !r.is_empty());
            let (signal, exits) = fds.split_last().expect("the signal pipe is polled last");
            if readable(signal) {
                return Ok(StopReason::Signal);
            }
            let exited: Vec<bool> = exits.iter().map(readable).collect();
            if let Some(c) = self.0.iter_mut().zip(exited).find_map(|(c, exited)| exited.then_some(c)) {
                let status = c.child.wait().with_context(|| format!("wait for container {}", c.name))?;
                let name = c.name.clone();
                return Ok(if status.success() { StopReason::Exited(name) } else { StopReason::Failed(name, status) });
            }
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        for Started { child, .. } in &mut self.0 {
            // an unreaped child's pid can't get reused, so this only ever signals the container's runc.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn prepare(md: &Metadata) -> Result<()> {
    for d in [LOGS_DIR, IMAGES_DIR, CONTAINERS_DIR, VOLUMES_DIR] {
        mkdir(Path::new(d)).context("mkdir guest state")?;
    }
    for v in &md.manifest.volumes {
        mkdir(&Path::new(VOLUMES_DIR).join(v)).with_context(|| format!("mkdir volume {v}"))?;
    }
    for (i, blob) in md.blobs.iter().enumerate() {
        let dir = Path::new(IMAGES_DIR).join(blob);
        mkdir(&dir).with_context(|| format!("mkdir image {blob}"))?;
        // blobs attach after the root and scratch disks, so the first one is vdc.
        let device = format!("/dev/vd{}", char::from(b'c' + u8::try_from(i)?));
        mount(Some(device.as_str()), &dir, Some("squashfs"), MsFlags::MS_RDONLY | MsFlags::MS_NODEV, None::<&str>)
            .with_context(|| format!("mount image {blob} from {device}"))?;
    }
    for c in &md.manifest.containers {
        prepare_container(c)?;
    }
    Ok(())
}

fn prepare_container(c: &Container) -> Result<()> {
    let dir = Path::new(CONTAINERS_DIR).join(&c.name);
    for d in ["upper", "work", ROOTFS] {
        mkdir(&dir.join(d)).with_context(|| format!("mkdir container {}", c.name))?;
    }
    let image = Path::new(IMAGES_DIR).join(&c.blob);
    let opts = format!("lowerdir={}/{ROOTFS},upperdir={}/upper,workdir={}/work", image.display(), dir.display(), dir.display());
    mount(Some("overlay"), &dir.join(ROOTFS), Some("overlay"), MsFlags::MS_NODEV, Some(opts.as_str()))
        .with_context(|| format!("mount container {} rootfs", c.name))?;
    let spec = bundle::bundle_spec(&load_image_spec(&image.join("config.json"))?, c, VOLUMES_DIR)?;
    logs::write_private(&dir.join("config.json"), &serde_json::to_vec(&spec)?)
}

fn load_image_spec(path: &Path) -> Result<ImageSpec> {
    let f = File::open(path).context("open image config")?;
    if f.metadata().context("stat image config")?.len() > MAX_IMAGE_CONFIG_BYTES {
        bail!("image config exceeds 1 MiB");
    }
    serde_json::from_reader(BufReader::new(f.take(MAX_IMAGE_CONFIG_BYTES))).with_context(|| format!("decode {}", path.display()))
}

fn mkdir(path: &Path) -> std::io::Result<()> {
    DirBuilder::new().recursive(true).mode(DIR_MODE).create(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::Stream;

    #[test]
    fn dropping_tails_frames_unpolled_output() {
        let dir = tempfile::tempdir().unwrap();
        let tailer = Tailer::open(dir.path(), "app", DEFAULT_LOG_CAP).unwrap();
        tailer.write_raw(Stream::Stderr, "fatal: no newline before exit");
        let mut tails = Tails(Vec::new());
        tails.spawn(tailer);
        drop(tails);
        let framed = fs::read_to_string(dir.path().join("app.jsonl")).unwrap();
        let record: logs::Record = serde_json::from_str(framed.trim_end()).unwrap();
        assert_eq!((record.stream, record.line.as_str()), (Stream::Stderr, "fatal: no newline before exit"));
    }
}
