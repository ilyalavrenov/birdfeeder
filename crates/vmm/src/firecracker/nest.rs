//! The jailer's sandbox ("nest"): a chroot holding hardlinks of the guest's artifacts, and a cgroup outside roost's.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::chown;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::time::{Instant, sleep};

use super::{Driver, Jailer, KILL_WAIT, MIB, POLL_INTERVAL, kill_vmm, read_pid, snapshot};
use crate::{Failures, Guest, Instance, NestId, Stage, staged};

pub const BASE: &str = "base.ext4";
pub const SCRATCH: &str = "scratch.ext4";
const NO_FILE: u32 = 1024;
// the host cgroup sits outside roost's service so vmms survive roost restarts
const VM_CGROUP: &str = "birdfeeder";
// memory.max headroom over guest ram for the vmm itself (guest ram counts too on memory_hugetlb_accounting mounts)
const VMM_OVERHEAD_MIB: u64 = 256;

fn dir(chroot_base: &Path, id: &NestId) -> PathBuf {
    chroot_base.join("firecracker").join(id.as_str())
}

pub fn root(chroot_base: &Path, id: &NestId) -> PathBuf {
    dir(chroot_base, id).join("root")
}

pub fn marker(id: &NestId) -> Vec<u8> {
    format!("--id\0{id}\0").into_bytes()
}

/// Writes a cgroup control file but never creates one. A missing file means the controller isn't available or the
/// path is wrong.
pub fn write_cgroup_file(path: &Path, value: &str) -> io::Result<()> {
    OpenOptions::new().write(true).open(path)?.write_all(value.as_bytes())
}

impl Driver {
    /// With no --cgroup flags, the jailer joins this parent directly and doesn't make a child.
    pub(super) fn cgroup_leaf(&self, id: &NestId) -> PathBuf {
        self.cgroup_root.join(VM_CGROUP).join(id.as_str())
    }

    pub(super) fn ensure_vm_cgroup(&self) -> Result<()> {
        let dir = self.cgroup_root.join(VM_CGROUP);
        fs::create_dir_all(&dir).context("mkdir vm cgroup")?;
        let hugetlb = self.cfg.hugepages_2m.then_some("hugetlb");
        for controller in ["cpu", "memory", "pids"].into_iter().chain(hugetlb) {
            for cgroup in [&self.cgroup_root, &dir] {
                write_cgroup_file(&cgroup.join("cgroup.subtree_control"), &format!("+{controller}"))
                    .with_context(|| format!("enable {controller} on {}", cgroup.display()))?;
            }
        }
        Ok(())
    }

    /// The kernel, base disk and blob hardlinks need the chroot and artifacts on the same filesystem. Linking instead of
    /// copying is what lets every guest share one host page cache for them.
    pub(super) fn prepare_nest(&self, jailer: &Jailer, id: &NestId, inst: &Instance, guest: &Guest) -> Result<()> {
        let uid = crate::Driver::uid(self, inst);
        chown(&inst.disk, Some(uid), Some(uid)).context("chown disk")?;
        let dir = inst.disk.parent().expect("a nest's disk is inside its root");
        fs::hard_link(&self.cfg.kernel_image_path, dir.join("vmlinux")).context("hardlink kernel into nest")?;
        fs::hard_link(&guest.base_disk, dir.join(BASE)).context("hardlink base disk into nest")?;
        for (name, path) in &guest.blobs {
            fs::hard_link(path, dir.join(format!("{name}.squashfs"))).with_context(|| format!("hardlink {name} blob into nest"))?;
        }

        let leaf = self.cgroup_leaf(id);
        fs::create_dir_all(&leaf).context("mkdir cgroup leaf")?;
        if !jailer.cgroup_limits {
            return Ok(());
        }
        let mem = u64::from(guest.mem_mib) * MIB;
        write_cgroup_file(&leaf.join("memory.max"), &(mem + VMM_OVERHEAD_MIB * MIB).to_string()).context("write memory.max")?;
        if self.cfg.hugepages_2m {
            write_cgroup_file(&leaf.join("hugetlb.2MB.max"), &mem.to_string()).context("write hugetlb.2MB.max")?;
        }
        Ok(())
    }

    pub(super) fn jailer_command(&self, jailer: &Jailer, id: &NestId, inst: &Instance, guest: &Guest) -> Result<std::process::Command> {
        let disk = fs::metadata(&inst.disk).context("stat disk")?;
        // RLIMIT_FSIZE also gates the hugetlb memfd ftruncate, so it has to cover guest memory
        let fsize = disk.len().max(u64::from(guest.mem_mib) * MIB);
        let uid = crate::Driver::uid(self, inst).to_string();
        let mut cmd = std::process::Command::new(&jailer.bin);
        cmd.args(["--id", id.as_str(), "--exec-file"])
            .arg(&self.cfg.firecracker_bin)
            .args(["--uid", &uid, "--gid", &uid, "--chroot-base-dir"])
            .arg(&jailer.chroot_base)
            .args(["--cgroup-version", "2", "--parent-cgroup", &format!("{VM_CGROUP}/{id}"), "--new-pid-ns"])
            .args(["--resource-limit", &format!("no-file={NO_FILE}"), "--resource-limit", &format!("fsize={fsize}")]);
        if let Some(netns) = &guest.netns {
            cmd.arg("--netns").arg(netns);
        }
        Ok(cmd)
    }

    pub(super) async fn remove_nest(&self, jailer: &Jailer, id: &NestId) -> Result<(), Failures> {
        let mut failures = Failures::default();
        if let Err(err) = tokio::fs::remove_dir_all(dir(&jailer.chroot_base, id)).await
            && err.kind() != io::ErrorKind::NotFound
        {
            failures.push(staged(Stage::Nest, anyhow::Error::new(err).context(format!("remove nest {id}"))));
        }
        if let Err(err) = remove_cgroup(&self.cgroup_leaf(id)).await {
            failures.push(staged(Stage::Cgroup, err.context(format!("remove cgroup leaf {id}"))));
        }
        failures.into_result()
    }

    pub(super) async fn sweep_nests(&self, live: &[&Instance]) -> Result<(), Failures> {
        let Some(jailer) = &self.cfg.jailer else { return Ok(()) };
        let owned: HashSet<&NestId> = live.iter().filter_map(|inst| inst.sandbox.nest_id()).collect();
        let mut failures = Failures::default();

        for id in list_dir(&jailer.chroot_base.join("firecracker")) {
            if owned.contains(&id) {
                continue;
            }
            let root = root(&jailer.chroot_base, &id);
            let pid = read_pid(&root.join("firecracker.pid"));
            if let Some(pid) = pid
                && let Err(err) = kill_vmm(pid, &marker(&id)).await
            {
                failures.push(staged(Stage::KillVmm, err.context(format!("orphan nest {id} pid {pid}"))));
                continue;
            }
            let run = root.join("run");
            let handler = read_pid(&run.join(snapshot::UFFD_PID_NAME));
            if let Some(handler) = handler
                && let Err(err) = kill_vmm(handler, run.join(snapshot::UFFD_SOCK_NAME).as_os_str().as_encoded_bytes()).await
            {
                failures.push(staged(Stage::KillVmm, err.context(format!("orphan nest {id} uffd handler pid {handler}"))));
                continue;
            }
            tracing::info!(nest_id = %id, "removing orphan nest");
            failures.extend(self.remove_nest(jailer, &id).await);
        }

        for id in list_dir(&self.cgroup_root.join(VM_CGROUP)) {
            let leaf = self.cgroup_leaf(&id);
            if owned.contains(&id) || !leaf.is_dir() {
                continue;
            }
            tracing::info!(nest_id = %id, "removing orphan cgroup leaf");
            if let Err(err) = remove_cgroup(&leaf).await {
                failures.push(staged(Stage::Cgroup, err.context(format!("remove orphan cgroup leaf {id}"))));
            }
        }
        failures.into_result()
    }
}

/// The nests a dir holds, by entry name.
fn list_dir(dir: &Path) -> Vec<NestId> {
    match fs::read_dir(dir) {
        Ok(entries) => entries.filter_map(|e| e.ok()?.file_name().into_string().ok().map(NestId)).collect(),
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
                tracing::error!(path = %dir.display(), error = %err, "read dir");
            }
            Vec::new()
        }
    }
}

/// Kills whatever is left in the cgroup and removes it once the kernel lets go.
async fn remove_cgroup(leaf: &Path) -> Result<()> {
    let kill = leaf.join("cgroup.kill");
    if let Err(err) = write_cgroup_file(&kill, "1")
        && err.kind() != io::ErrorKind::NotFound
    {
        return Err(err).with_context(|| format!("write {}", kill.display()));
    }
    let deadline = Instant::now() + KILL_WAIT;
    loop {
        match tokio::fs::remove_dir(leaf).await {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) if Instant::now() >= deadline => return Err(anyhow::Error::new(err).context("rmdir cgroup")),
            Err(_) => sleep(POLL_INTERVAL).await,
        }
    }
}
