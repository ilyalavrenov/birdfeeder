//! Where roost's session manager hands off to the vmm. The manager handles the guest side (disks, taps, nft, ready
//! probes). A [`Driver`] handles the vmm process and the devices it exposes.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

mod copy_disk;
pub mod firecracker;

use copy_disk::CopyDiskError;
pub use copy_disk::copy_disk;

/// A vmm implementation. Every method takes the session's [`Instance`], and anything a driver needs after a roost
/// restart has to live in there.
pub trait Driver: Send + Sync {
    /// One-time host setup before anything starts (the cgroup tree).
    fn setup(&self) -> anyhow::Result<()>;
    /// Fills in the driver's paths on a fresh instance. `disk` comes in at the manager's default spot, and a sandboxing
    /// driver moves it.
    fn allocate(&self, inst: &mut Instance, guest: &Guest);
    /// The uid the vmm runs as, so we can hand it the tap (0 means it runs as roost). Only depends on the allocated
    /// instance, so the tap doesn't have to wait for [`Driver::prepare`].
    fn uid(&self, inst: &Instance) -> u32;
    /// Finishes setting up the sandbox once the disk is copied.
    fn prepare(&self, inst: &Instance, guest: &Guest) -> anyhow::Result<()>;
    /// Spawns the vmm, configures the guest and starts it. The process outlives roost on purpose so [`Driver::adopt`]
    /// can pick it back up later. Its pids go into `inst` even if a later step fails.
    fn start(&self, inst: &mut Instance, boot: &Boot) -> impl Future<Output = anyhow::Result<()>> + Send;
    /// Hooks per-vmm telemetry back up to an instance that's still running after a roost restart.
    fn adopt(&self, inst: &Instance) -> anyhow::Result<()>;
    /// Whether the recorded pids still belong to this instance (guards against pid reuse).
    fn alive(&self, inst: &Instance) -> bool;
    /// Flushes what it can, SIGKILLs the vmm, and waits for the pid to go away.
    fn kill(&self, inst: &Instance) -> impl Future<Output = anyhow::Result<()>> + Send;
    /// Removes the instance's sandbox and disk. Best effort: every step runs, and each failure comes back staged.
    fn cleanup(&self, inst: &Instance) -> impl Future<Output = Result<(), Failures>> + Send;
    /// The host cgroup the vmm runs in; `None` when it shares roost's.
    fn cgroup(&self, inst: &Instance) -> Option<PathBuf>;
    /// Kills and removes sandboxes no live instance owns. A crash between spawn and state save leaves these behind.
    fn sweep(&self, live: &[&Instance]) -> impl Future<Output = Result<(), Failures>> + Send;
    /// Pauses the vm and writes vmstate, guest memory and a disk copy into `dir` (on the sandbox's filesystem). With
    /// `resume` the guest starts back up afterwards.
    fn snapshot(&self, inst: &Instance, dir: &Path, resume: bool) -> impl Future<Output = anyhow::Result<()>> + Send;
    /// Spawns a vmm for a prepared instance (disk in place, sandbox and tap ready) from a snapshot dir and resumes it.
    fn restore(&self, inst: &mut Instance, boot: &Boot, src: &RestoreSource) -> impl Future<Output = anyhow::Result<()>> + Send;
    /// Writes the manifest a remote copy of the snapshot's memory needs into the dir. Returns the memory file to copy.
    fn export_memory(&self, dir: &Path) -> impl Future<Output = anyhow::Result<PathBuf>> + Send;
    /// Stops a [`RestoreMode::Record`] restore's recording and saves the pages the guest touched as `dir`'s working set.
    fn finish_recording(&self, inst: &Instance, dir: &Path) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// The vmm half of a session's saved state. `name`, `generation` and `slot` are how the manager identifies it. The
/// rest belongs to the driver.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instance {
    pub name: String,
    pub generation: u64,
    pub slot: u32,
    pub disk: PathBuf,
    pub api_sock: PathBuf,
    /// Host end of the guest's vsock. Roost's log relay and guest calls connect here.
    #[serde(default)]
    pub vsock_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Where the vmm runs. Stays under the `nest_id` key because the smoke tests read it.
    #[serde(rename = "nest_id", default, skip_serializing_if = "Sandbox::is_host")]
    pub sandbox: Sandbox,
    /// Page fault handler for a lazily restored vm. The guest hangs without it, so [`Driver::alive`] checks it too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uffd_pid: Option<u32>,
}

/// Whether a vmm runs as roost or inside a jailer's nest.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "Option<NestId>", into = "Option<NestId>")]
pub enum Sandbox {
    #[default]
    Host,
    Jailed(NestId),
}

impl Sandbox {
    fn is_host(&self) -> bool {
        matches!(self, Self::Host)
    }

    pub(crate) fn nest_id(&self) -> Option<&NestId> {
        match self {
            Self::Host => None,
            Self::Jailed(id) => Some(id),
        }
    }
}

impl From<Option<NestId>> for Sandbox {
    fn from(id: Option<NestId>) -> Self {
        id.map_or(Self::Host, Self::Jailed)
    }
}

impl From<Sandbox> for Option<NestId> {
    fn from(sandbox: Sandbox) -> Self {
        match sandbox {
            Sandbox::Host => None,
            Sandbox::Jailed(id) => Some(id),
        }
    }
}

/// A nest's id, which also names its chroot dir and cgroup.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NestId(pub(crate) String);

impl NestId {
    pub(crate) fn new(slot: u32, generation: u64) -> Self {
        Self(format!("s{slot}-g{generation}"))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The machine the manager wants: sizes, nic, and the per-session scratch dir (console, unsandboxed sockets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Guest {
    pub vcpus: NonZeroU32,
    pub mem_mib: u32,
    pub tap: String,
    /// Netns the vmm joins before opening `tap`. `None` stays in the host's.
    pub netns: Option<PathBuf>,
    pub mac: String,
    pub run_dir: PathBuf,
    /// The shared read-only rootfs. The instance's own `disk` is its private scratch disk.
    pub base_disk: PathBuf,
    /// Read-only disk images attached after the scratch disk, in name order.
    pub blobs: BTreeMap<String, PathBuf>,
}

/// What a boot needs on top of [`Guest`].
#[derive(Clone, Debug, PartialEq)]
pub struct Boot {
    pub guest: Guest,
    pub limits: Limits,
    /// Passed to the guest (via mmds on Firecracker). The guest's runtime reads the workload out of it.
    pub metadata: serde_json::Value,
    /// Gets the vmm's stdout and stderr. If the spawn fails, the start of it gets tacked onto the error.
    pub console: PathBuf,
}

/// Sustained rate per device. `None` means that device isn't throttled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    pub disk_bytes_per_sec: Option<NonZeroU64>,
    pub disk_ops_per_sec: Option<NonZeroU64>,
    pub net_bytes_per_sec: Option<NonZeroU64>,
    pub net_packets_per_sec: Option<NonZeroU64>,
}

/// The snapshot dir a restore reads, and how its memory arrives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreSource {
    pub dir: PathBuf,
    pub mode: RestoreMode,
    /// Read the dir's exported memory from here instead of the local file. [`RestoreMode::Record`] ignores this.
    pub remote: Option<RemoteMemory>,
}

/// URLs that serve an exported snapshot's files by range, such as presigned GETs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteMemory {
    pub mem_url: String,
    /// The dir's packed working set. [`RestoreMode::Prefetch`] reads this instead of every memory file chunk the
    /// working set touches.
    pub working_set_url: Option<String>,
}

/// How a restored guest's memory arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreMode {
    /// Each page gets served the first time it's touched.
    Lazy,
    /// Loads all guest memory before the restore returns.
    Eager,
    /// Lazy, and tracks which pages the guest touches until [`Driver::finish_recording`].
    Record,
    /// Loads the dir's working set before serving the first fault, then the rest lazily.
    Prefetch,
}

/// The scratch disk copy a snapshot leaves in its dir. The manager copies restored instances' disks from it.
pub const SNAPSHOT_DISK: &str = "scratch.ext4";
/// What [`Driver::finish_recording`] leaves in a snapshot dir.
pub const SNAPSHOT_WORKING_SET: &str = "working-set";
/// The working set's pages, in working set order. [`Driver::finish_recording`] leaves it next to the working set.
pub const SNAPSHOT_WORKING_SET_PACK: &str = "working-set.pack";
/// What [`Driver::export_memory`] leaves in a snapshot dir.
pub const SNAPSHOT_MANIFEST: &str = "mem.manifest";

/// A boot or teardown step, as failure counters label it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stage {
    // the manager's boot steps
    VerifyArtifacts,
    Hugepages,
    CopyDisk,
    Nest,
    Tap,
    Nft,
    StartVmm,
    Persist,
    WaitReady,
    SyncClock,
    Snapshot,
    ExportMemory,
    RecordWorkingSet,
    ExportWorkingSet,
    // teardown
    KillVmm,
    DeleteTap,
    RunDir,
    Disk,
    SnapshotStage,
    Cgroup,
}

impl Stage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifyArtifacts => "verify_artifacts",
            Self::Hugepages => "hugepages",
            Self::CopyDisk => "copy_disk",
            Self::Nest => "nest",
            Self::Tap => "tap",
            Self::Nft => "nft",
            Self::StartVmm => "start_vmm",
            Self::Persist => "persist",
            Self::WaitReady => "wait_ready",
            Self::SyncClock => "sync_clock",
            Self::Snapshot => "snapshot",
            Self::ExportMemory => "export_memory",
            Self::RecordWorkingSet => "record_working_set",
            Self::ExportWorkingSet => "export_working_set",
            Self::KillVmm => "kill_vmm",
            Self::DeleteTap => "delete_tap",
            Self::RunDir => "run_dir",
            Self::Disk => "disk",
            Self::SnapshotStage => "snapshot_stage",
            Self::Cgroup => "cgroup",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error tagged with the boot or teardown step that failed, so failure counters can attribute it. Display only
/// shows the stage. Use `{:#}` to see the cause.
#[derive(Debug, thiserror::Error)]
#[error("{stage}")]
pub struct Staged {
    pub stage: Stage,
    #[source]
    pub source: anyhow::Error,
}

pub fn staged(stage: Stage, source: impl Into<anyhow::Error>) -> Staged {
    Staged { stage, source: source.into() }
}

/// The steps that failed in a best-effort operation, which keeps going past each failure.
#[derive(Debug, Default)]
pub struct Failures(pub Vec<Staged>);

impl Failures {
    fn push(&mut self, failure: Staged) {
        self.0.push(failure);
    }

    fn extend(&mut self, other: Result<(), Self>) {
        if let Err(other) = other {
            self.0.extend(other.0);
        }
    }

    fn into_result(self) -> Result<(), Self> {
        if self.0.is_empty() { Ok(()) } else { Err(self) }
    }
}

// an error only gets one source, so each step's cause goes inline
impl fmt::Display for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, failure) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{}: {:#}", failure.stage, failure.source)?;
        }
        Ok(())
    }
}

impl std::error::Error for Failures {}

/// The step `err` names. A joined error is attributed to its first step.
#[must_use]
pub fn stage_of(err: &anyhow::Error) -> Option<Stage> {
    err.chain()
        .find_map(|e| e.downcast_ref::<Staged>().map(|s| s.stage).or_else(|| e.downcast_ref::<Failures>()?.0.first().map(|s| s.stage)))
}

/// Whether `err` failed because a [`copy_disk`] base couldn't be read.
#[must_use]
pub fn base_unreadable(err: &anyhow::Error) -> bool {
    err.chain().any(|e| matches!(e.downcast_ref(), Some(CopyDiskError::UnreadableBase { .. })))
}

#[cfg(test)]
mod tests {
    use anyhow::Context as _;
    use serde_json::json;

    use super::*;

    #[test]
    fn instances_round_trip_through_the_state_file() {
        let unsandboxed: Instance = serde_json::from_value(json!({
            "name": "h-web-0", "generation": 2, "slot": 1, "disk": "/d/h-web-0.2.ext4", "api_sock": "/r/fc.sock",
        }))
        .unwrap();
        assert_eq!((unsandboxed.pid, unsandboxed.uffd_pid, &unsandboxed.sandbox), (None, None, &Sandbox::Host));
        assert_eq!(unsandboxed.vsock_path, PathBuf::new());
        assert!(serde_json::to_value(&unsandboxed).unwrap().get("nest_id").is_none());

        let jailed = Instance {
            name: "h-web-0".into(),
            generation: 2,
            slot: 1,
            disk: "/n/scratch.ext4".into(),
            api_sock: "/n/run/firecracker.socket".into(),
            vsock_path: "/n/run/v.sock".into(),
            pid: Some(41),
            sandbox: Sandbox::Jailed(NestId::new(1, 2)),
            uffd_pid: Some(42),
        };
        let wire = serde_json::to_value(&jailed).unwrap();
        assert_eq!(
            wire,
            json!({"name": "h-web-0", "generation": 2, "slot": 1, "disk": "/n/scratch.ext4", "api_sock": "/n/run/firecracker.socket",
                "vsock_path": "/n/run/v.sock", "pid": 41, "nest_id": "s1-g2", "uffd_pid": 42})
        );
        assert_eq!(serde_json::from_value::<Instance>(wire).unwrap(), jailed);
    }

    #[test]
    fn stages_survive_context() {
        let err = anyhow::Error::new(staged(Stage::Tap, anyhow::anyhow!("no such device"))).context("boot h-web-0");
        assert_eq!(stage_of(&err), Some(Stage::Tap));
        assert_eq!(format!("{err:#}"), "boot h-web-0: tap: no such device");
        assert_eq!(stage_of(&anyhow::anyhow!("plain")), None);

        let failures = Failures(vec![staged(Stage::Nest, anyhow::anyhow!("busy")), staged(Stage::Cgroup, anyhow::anyhow!("busy"))]);
        assert_eq!(failures.to_string(), "nest: busy; cgroup: busy");
        let err = Err::<(), _>(failures).context("teardown").unwrap_err();
        assert_eq!(stage_of(&err), Some(Stage::Nest), "a joined error is attributed to its first step");
    }
}
