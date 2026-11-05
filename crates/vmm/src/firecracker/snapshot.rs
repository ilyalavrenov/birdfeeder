//! Snapshots and restores. Restores always go through the uffd handler: a hugetlb guest can't restore from a file
//! backend, and this way one path handles both page sizes.

use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, BufReader, Read};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, chown};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use fcapi::{
    MemoryBackend, MemoryBackendBackendType, SnapshotCreateParams, SnapshotCreateParamsSnapshotType, SnapshotLoadParams, Vm, VmState,
};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tokio::process::Command;
use tokio::task::JoinHandle;

use super::api::{Api, Mmds};
use super::telemetry::{run_file, run_file_in_vm};
use super::{Driver, FILE_MODE, SOCK_WAIT, alive, detach, nest, reap, traced, wait_until};
use crate::{
    Boot, Instance, RestoreMode, RestoreSource, SNAPSHOT_DISK, SNAPSHOT_MANIFEST, SNAPSHOT_WORKING_SET, SNAPSHOT_WORKING_SET_PACK, Sandbox,
    copy_disk,
};

const STAGE_DIR: &str = "snapshot";
const VMSTATE: &str = "vmstate";
const MEM: &str = "mem";
// restores and the handler run as other vm uids
const SHARED_MODE: u32 = 0o644;
pub const UFFD_SOCK_NAME: &str = "uffd.sock";
pub const UFFD_PID_NAME: &str = "uffd-handler.pid";
const UFFD_LOG_NAME: &str = "uffd-handler.log";
/// The handler writes the pack before the working set shows up, and with hugepages the pack can be several GiB.
const RECORD_WAIT: Duration = Duration::from_secs(60);

/// Where Firecracker reads and writes snapshot files. It's next to the disk so hardlinks and renames stay on the
/// snapshots' filesystem. Unjailed disks all share one dir that concurrent restores stage in, so their stage is
/// named after the disk. A nest already has its own.
pub(super) fn stage_dir(inst: &Instance) -> PathBuf {
    match inst.sandbox {
        Sandbox::Host => inst.disk.with_extension(STAGE_DIR),
        Sandbox::Jailed(_) => inst.disk.with_file_name(STAGE_DIR),
    }
}

fn stage_in_vm(inst: &Instance, name: &str) -> String {
    inst.sandbox.path_in_vm(&stage_dir(inst).join(name), &format!("{STAGE_DIR}/{name}"))
}

/// Moves files Firecracker or the handler wrote in the sandbox into `dir`, and makes them readable to other vm uids.
async fn move_out(from: impl Fn(&str) -> PathBuf, dir: &Path, names: &[&str]) -> Result<()> {
    for name in names {
        let dst = dir.join(name);
        tokio::fs::rename(from(name), &dst).await.with_context(|| format!("move {name} out of the sandbox"))?;
        tokio::fs::set_permissions(&dst, Permissions::from_mode(SHARED_MODE)).await.with_context(|| format!("chmod {name}"))?;
    }
    Ok(())
}

pub fn uffd_marker(inst: &Instance) -> Vec<u8> {
    run_file(inst, UFFD_SOCK_NAME).into_os_string().into_encoded_bytes()
}

impl Driver {
    pub(super) async fn snapshot_to(&self, inst: &Instance, dir: &Path, resume: bool) -> Result<()> {
        let stage = stage_dir(inst);
        tokio::fs::create_dir_all(&stage).await.context("mkdir snapshot stage")?;
        let uid = crate::Driver::uid(self, inst);
        if uid != 0 {
            chown(&stage, Some(uid), Some(uid)).context("chown snapshot stage")?;
        }
        tokio::fs::create_dir_all(dir).await.context("mkdir snapshot dir")?;

        let api = Api::new(&inst.api_sock);
        api.send(&Vm { state: VmState::Paused }).await?;
        let mut result = async {
            api.send(&SnapshotCreateParams {
                mem_file_path: stage_in_vm(inst, MEM),
                snapshot_path: stage_in_vm(inst, VMSTATE),
                snapshot_type: Some(SnapshotCreateParamsSnapshotType::Full),
                sync_snapshot_files: true,
            })
            .await?;
            // still paused, so the disk matches the memory image
            copy_disk(&inst.disk, &dir.join(SNAPSHOT_DISK)).await
        }
        .await;
        if resume && let Err(err) = api.send(&Vm { state: VmState::Resumed }).await {
            result = Err(match result {
                Ok(()) => err,
                Err(first) => first.context(format!("then resume: {err:#}")),
            });
        }
        result?;

        move_out(|name| stage.join(name), dir, &[VMSTATE, MEM]).await?;
        tokio::fs::remove_dir(&stage).await.context("remove snapshot stage")
    }

    pub(super) async fn restore_from(&self, inst: &mut Instance, boot: &Boot, src: &RestoreSource) -> Result<()> {
        let stage = stage_dir(inst);
        tokio::fs::create_dir_all(&stage).await.context("mkdir snapshot stage")?;
        // the handler can't record what a remote chunk fills in without a fault
        let remote = src.remote.as_ref().filter(|_| src.mode != RestoreMode::Record);
        let mut files = if remote.is_some() { vec![VMSTATE, SNAPSHOT_MANIFEST] } else { vec![VMSTATE, MEM] };
        if src.mode == RestoreMode::Prefetch {
            files.push(SNAPSHOT_WORKING_SET);
        }
        traced("stage_snapshot", async {
            for name in files {
                tokio::fs::hard_link(src.dir.join(name), stage.join(name))
                    .await
                    .with_context(|| format!("hardlink {name} into the sandbox"))?;
            }
            Ok(())
        })
        .await?;

        self.spawn(inst, boot).await?;
        let api = Api::new(&inst.api_sock);
        self.attach_telemetry(&api, inst).await?;
        let handler_exit = self.start_handler(inst, boot, src.mode, remote).await?;
        api.send(&SnapshotLoadParams {
            clock_realtime: None,
            // deprecated alias for track_dirty_pages. dirty tracking would drop hugetlb down to 4k ept mappings
            enable_diff_snapshots: Some(false),
            huge_pages: None,
            mem_backend: Some(MemoryBackend {
                backend_path: run_file_in_vm(inst, UFFD_SOCK_NAME),
                backend_type: MemoryBackendBackendType::Uffd,
            }),
            mem_file_path: None,
            network_overrides: Vec::new(),
            resume_vm: Some(true),
            snapshot_path: stage_in_vm(inst, VMSTATE),
            track_dirty_pages: None,
            vsock_override: None,
        })
        .await?;
        // the snapshot has the mmds config but not its data store
        api.send(&Mmds(&boot.metadata)).await?;

        if src.mode != RestoreMode::Eager {
            return Ok(());
        }
        let status = handler_exit.await.context("uffd handler wasn't reaped")?.context("wait for the fault-all uffd handler")?;
        inst.uffd_pid = None;
        ensure!(status.success(), "uffd handler (fault-all): {status}");
        Ok(())
    }

    /// Starts the detached handler before Firecracker connects to it. It shares the vm's uid and cgroup.
    async fn start_handler(
        &self,
        inst: &mut Instance,
        boot: &Boot,
        mode: RestoreMode,
        remote: Option<&crate::RemoteMemory>,
    ) -> Result<JoinHandle<io::Result<ExitStatus>>> {
        let log_path = boot.console.with_file_name(UFFD_LOG_NAME);
        let log = OpenOptions::new().append(true).create(true).mode(FILE_MODE).open(&log_path).context("create uffd handler log")?;
        let sock = run_file(inst, UFFD_SOCK_NAME);
        let stage = stage_dir(inst);

        let mut cmd = Command::new(&self.cfg.uffd_handler_bin);
        cmd.arg("--socket").arg(&sock);
        match remote {
            Some(remote) => cmd.args(["--mem-url", &remote.mem_url]).arg("--manifest").arg(stage.join(SNAPSHOT_MANIFEST)),
            None => cmd.arg("--mem").arg(stage.join(MEM)),
        };
        match mode {
            RestoreMode::Lazy => {}
            RestoreMode::Eager => {
                cmd.arg("--fault-all");
            }
            RestoreMode::Record => {
                // the handler runs as the vm's uid, which can write the run dir but not the snapshot dir
                cmd.arg("--record")
                    .arg(run_file(inst, SNAPSHOT_WORKING_SET))
                    .arg("--record-pack")
                    .arg(run_file(inst, SNAPSHOT_WORKING_SET_PACK));
            }
            RestoreMode::Prefetch => {
                cmd.arg("--prefetch").arg(stage.join(SNAPSHOT_WORKING_SET));
                if let Some(url) = remote.and_then(|r| r.working_set_url.as_deref()) {
                    cmd.args(["--prefetch-url", url]);
                }
            }
        }
        cmd.stdin(Stdio::null()).stdout(log.try_clone().context("dup uffd handler log")?).stderr(log);
        let uid = crate::Driver::uid(self, inst);
        if uid != 0 {
            cmd.uid(uid).gid(uid);
        }
        detach(&mut cmd);

        let child = traced("exec_uffd_handler", async { cmd.spawn().context("start uffd handler") }).await?;
        let pid = child.id().expect("a just-spawned child has a pid");
        inst.uffd_pid = Some(pid);
        let exit = reap(child, inst.name.clone(), "uffd handler exited");

        if let Some(id) = inst.sandbox.nest_id() {
            nest::write_cgroup_file(&self.cgroup_leaf(id).join("cgroup.procs"), &pid.to_string())
                .context("move uffd handler into the vm cgroup")?;
        }
        tokio::fs::write(run_file(inst, UFFD_PID_NAME), pid.to_string()).await.context("write uffd handler pid")?;
        // just a stat: the handler's socket shows up once it listens, and a probe connection would eat its only accept
        traced("wait_uffd_socket", wait_until(SOCK_WAIT, &format!("uffd socket {}", sock.display()), || sock.exists())).await?;
        Ok(exit)
    }
}

pub async fn export_memory(dir: &Path) -> Result<PathBuf> {
    let mem = dir.join(MEM);
    let manifest = {
        let mem = mem.clone();
        tokio::task::spawn_blocking(move || manifest(&mem)).await??
    };
    let path = dir.join(SNAPSHOT_MANIFEST);
    tokio::fs::write(&path, manifest).await.context("write memory manifest")?;
    tokio::fs::set_permissions(&path, Permissions::from_mode(SHARED_MODE)).await.context("chmod memory manifest")?;
    Ok(mem)
}

// the granularity we look for zeros at. hugetlb guests' 2 MiB pages are whole multiples of it
const MANIFEST_PAGE: usize = 4096;
const MANIFEST_READ_BUF: usize = 1 << 20;

/// Describes the memory file so it can be served from somewhere that can't report holes. It's little-endian u64s:
/// the size, then the start and end of each extent (crates/uffd-handler decodes it). The extents are the non-zero
/// pages. Firecracker writes untouched guest memory as zeros, not holes, and zero pages don't need fetching.
fn manifest(path: &Path) -> Result<Vec<u8>> {
    let mut r = BufReader::with_capacity(MANIFEST_READ_BUF, fs::File::open(path).context("open memory file")?);
    let mut page = vec![0; MANIFEST_PAGE];
    let mut extents: Vec<(u64, u64)> = Vec::new();
    let mut off = 0;
    loop {
        let n = read_full(&mut r, &mut page).context("read memory file")?;
        if page[..n].iter().any(|&b| b != 0) {
            let end = off + n as u64;
            match extents.last_mut() {
                Some((_, last)) if *last == off => *last = end,
                _ => extents.push((off, end)),
            }
        }
        off += n as u64;
        if n < MANIFEST_PAGE {
            return Ok(std::iter::once(off).chain(extents.into_iter().flat_map(|(s, e)| [s, e])).flat_map(u64::to_le_bytes).collect());
        }
    }
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            read => n += read,
        }
    }
    Ok(n)
}

pub async fn finish_recording(inst: &Instance, dir: &Path) -> Result<()> {
    let Some(pid) = inst.uffd_pid.filter(|&pid| alive(pid, &uffd_marker(inst))) else { bail!("uffd handler isn't running") };
    let recorded = run_file(inst, SNAPSHOT_WORKING_SET);
    kill(Pid::from_raw(pid.cast_signed()), Signal::SIGUSR1).context("signal uffd handler")?;
    wait_until(RECORD_WAIT, &format!("working set {}", recorded.display()), || recorded.exists()).await?;
    // the handler writes the pack before the working set, so both are there
    move_out(|name| run_file(inst, name), dir, &[SNAPSHOT_WORKING_SET_PACK, SNAPSHOT_WORKING_SET]).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifests_skip_zero_pages() {
        const PAGE: u64 = MANIFEST_PAGE as u64;
        let mut mem = vec![0; 5 * MANIFEST_PAGE + 100];
        mem[MANIFEST_PAGE] = 1;
        mem[2 * MANIFEST_PAGE + 10] = 1;
        *mem.last_mut().unwrap() = 1;
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("mem"), &mem).unwrap();

        let words: Vec<u64> =
            manifest(&dir.path().join("mem")).unwrap().as_chunks::<8>().0.iter().map(|w| u64::from_le_bytes(*w)).collect();
        let len = mem.len() as u64;
        assert_eq!(words, [len, PAGE, 3 * PAGE, 5 * PAGE, len], "the size, then adjacent non-zero pages merged, and a short last page");
    }

    #[test]
    fn empty_memory_has_only_a_size() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("mem"), vec![0; 3 * MANIFEST_PAGE]).unwrap();
        assert_eq!(manifest(&dir.path().join("mem")).unwrap(), (3 * MANIFEST_PAGE as u64).to_le_bytes());
    }

    #[test]
    fn snapshot_files_live_beside_the_disk() {
        let jailed = Instance {
            disk: "/n/firecracker/s0-g1/root/scratch.ext4".into(),
            api_sock: "/n/firecracker/s0-g1/root/run/firecracker.socket".into(),
            sandbox: Sandbox::Jailed(crate::NestId::new(0, 1)),
            ..Instance::default()
        };
        assert_eq!(stage_in_vm(&jailed, VMSTATE), "/snapshot/vmstate", "jailed: chroot-relative");
        assert_eq!(stage_dir(&jailed), Path::new("/n/firecracker/s0-g1/root/snapshot"));
        assert_eq!(uffd_marker(&jailed), b"/n/firecracker/s0-g1/root/run/uffd.sock");
        assert_eq!(run_file_in_vm(&jailed, UFFD_SOCK_NAME), "/run/uffd.sock");

        let unjailed =
            Instance { disk: "/var/lib/roost/disks/x.1.ext4".into(), api_sock: "/run/roost/x.1/fc.sock".into(), ..Instance::default() };
        assert_eq!(stage_in_vm(&unjailed, MEM), "/var/lib/roost/disks/x.1.snapshot/mem");
        assert_eq!(run_file_in_vm(&unjailed, UFFD_SOCK_NAME), "/run/roost/x.1/uffd.sock");
        let sibling = Instance { disk: "/var/lib/roost/disks/x.2.ext4".into(), ..unjailed.clone() };
        assert_ne!(stage_dir(&unjailed), stage_dir(&sibling), "unjailed disks share a dir but not a stage");
    }
}
