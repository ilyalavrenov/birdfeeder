//! Each snapshotting template's golden snapshot, kept for the life of the process. We clear them on start since an old
//! one might not match the firecracker binary or host CPU. Restored guests keep their own hardlinks.

use std::collections::HashMap;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context as _, Result, bail, ensure};

use crate::config::{Config, Snapshot, Template};

/// Consecutive failures before a template gives up on snapshots for this process.
const MAX_FAILURES: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    Cold,
    /// Boots cold, then snapshots itself for later guests.
    Golden,
    Restore,
    /// A lazy template's first restore, which records the pages its guest touches.
    Record,
    /// A lazy restore that loads the recorded pages before the guest resumes.
    Prefetch,
}

impl BootMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Golden => "golden",
            Self::Restore => "restore",
            Self::Record => "record",
            Self::Prefetch => "prefetch",
        }
    }
}

/// What a boot showed about the snapshot it used or built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Sound,
    /// Tells us nothing about the snapshot, except that an unfinished golden boot didn't build one.
    Inconclusive,
    Broken,
}

pub struct Cache {
    root: PathBuf,
    /// Shared with removals that a dropped [`Lease`] leaves running in the background.
    templates: Arc<Mutex<HashMap<String, TemplateSnapshot>>>,
}

#[derive(Debug, Default)]
struct TemplateSnapshot {
    phase: Phase,
    /// Consecutive broken snapshots. At [`MAX_FAILURES`] the template boots cold for good.
    failures: u32,
    /// Consecutive failed recordings. Keeps counting across rebuilt snapshots.
    working_set_failures: u32,
}

#[derive(Debug, Default)]
enum Phase {
    #[default]
    Absent,
    /// A golden boot is building it.
    Building {
        /// The memory's object key, once it's in the snapshot store.
        mem_key: Option<String>,
    },
    Ready {
        /// Restores planned against it that haven't finished yet. They read its directory until they're done.
        restoring: u32,
        mem_key: Option<String>,
        working_set: WorkingSet,
    },
    /// Dropped, but its directory sticks around until the last restore reading it is done.
    Stale { restoring: u32 },
}

#[derive(Debug)]
enum WorkingSet {
    Unrecorded,
    Recording,
    Recorded {
        /// The packed pages' object key, once they're in the snapshot store.
        pack_key: Option<String>,
    },
}

impl TemplateSnapshot {
    fn plan(&mut self, snapshot: Snapshot) -> BootMode {
        match &mut self.phase {
            Phase::Absent if self.failures < MAX_FAILURES => {
                self.phase = Phase::Building { mem_key: None };
                BootMode::Golden
            }
            // a golden boot would write over the directory a dropped snapshot's restores are still reading.
            Phase::Absent | Phase::Building { .. } | Phase::Stale { .. } => BootMode::Cold,
            Phase::Ready { restoring, working_set, .. } => {
                *restoring += 1;
                if snapshot != Snapshot::Lazy {
                    return BootMode::Restore;
                }
                match working_set {
                    WorkingSet::Recorded { .. } => BootMode::Prefetch,
                    WorkingSet::Recording => BootMode::Restore,
                    WorkingSet::Unrecorded if self.working_set_failures >= MAX_FAILURES => BootMode::Restore,
                    WorkingSet::Unrecorded => {
                        *working_set = WorkingSet::Recording;
                        BootMode::Record
                    }
                }
            }
        }
    }

    /// Releases a `mode` boot's hold with what it showed, and says whether the snapshot's directory is now unused and
    /// should go. Only a golden boot holds a building snapshot, and only restores hold a ready or stale one.
    fn release(&mut self, mode: BootMode, verdict: Verdict) -> bool {
        if mode == BootMode::Cold {
            return false;
        }
        match &mut self.phase {
            Phase::Building { mem_key } => match verdict {
                Verdict::Sound => {
                    self.failures = 0;
                    let mem_key = mem_key.take();
                    self.phase = Phase::Ready { restoring: 0, mem_key, working_set: WorkingSet::Unrecorded };
                }
                Verdict::Broken => {
                    self.failures += 1;
                    self.phase = Phase::Stale { restoring: 0 };
                }
                Verdict::Inconclusive => self.phase = Phase::Stale { restoring: 0 },
            },
            Phase::Ready { restoring, working_set, .. } => {
                *restoring -= 1;
                if mode == BootMode::Record && matches!(working_set, WorkingSet::Recording) {
                    *working_set = WorkingSet::Unrecorded;
                }
                match verdict {
                    Verdict::Sound => self.failures = 0,
                    Verdict::Broken => {
                        self.failures += 1;
                        self.phase = Phase::Stale { restoring: *restoring };
                    }
                    Verdict::Inconclusive => {}
                }
            }
            // a restore that began before a sibling dropped the snapshot reports on one that's already gone.
            Phase::Stale { restoring } => *restoring -= 1,
            Phase::Absent => unreachable!("a snapshot is absent only once every lease on it is released"),
        }
        matches!(self.phase, Phase::Stale { restoring: 0 })
    }
}

impl Cache {
    pub fn new(state_dir: &Path) -> Self {
        Self { root: state_dir.join("snapshots"), templates: Arc::default() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn dir(&self, template_id: &str) -> PathBuf {
        self.root.join(template_id)
    }

    pub async fn reset(&self) -> Result<()> {
        match tokio::fs::remove_dir_all(&self.root).await {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err).context("clear snapshots"),
            _ => {}
        }
        tokio::fs::create_dir_all(&self.root).await.context("mkdir snapshots")
    }

    fn templates(&self) -> MutexGuard<'_, HashMap<String, TemplateSnapshot>> {
        lock(&self.templates)
    }

    fn with<R>(&self, template_id: &str, f: impl FnOnce(&mut TemplateSnapshot) -> R) -> R {
        f(self.templates().entry(template_id.to_owned()).or_default())
    }

    /// Picks how the next guest of `t` boots. The lease holds the snapshot until it's finished or dropped.
    pub fn plan(&self, t: &Template) -> Lease<'_> {
        let mode = t.snapshot.map_or(BootMode::Cold, |snapshot| self.with(&t.template_id, |s| s.plan(snapshot)));
        Lease { cache: self, template_id: t.template_id.clone(), mode, released: false }
    }

    pub fn mem_key(&self, template_id: &str) -> Option<String> {
        match &self.templates().get(template_id)?.phase {
            Phase::Ready { mem_key, .. } => mem_key.clone(),
            Phase::Absent | Phase::Building { .. } | Phase::Stale { .. } => None,
        }
    }

    pub fn pack_key(&self, template_id: &str) -> Option<String> {
        match &self.templates().get(template_id)?.phase {
            Phase::Ready { working_set: WorkingSet::Recorded { pack_key }, .. } => pack_key.clone(),
            _ => None,
        }
    }

    /// Removes a stale snapshot's directory so a golden boot can write it again. Blocks for a while, since a snapshot's
    /// memory file can be gigabytes.
    fn removal(&self, template_id: &str) -> impl FnOnce() -> Result<()> + Send + 'static {
        let (templates, dir, template_id) = (Arc::clone(&self.templates), self.dir(template_id), template_id.to_owned());
        move || {
            let removed = match std::fs::remove_dir_all(dir) {
                Err(err) if err.kind() != std::io::ErrorKind::NotFound => Err(err).context("remove snapshot"),
                _ => Ok(()),
            };
            lock(&templates).entry(template_id).or_default().phase = Phase::Absent;
            removed
        }
    }
}

fn lock(templates: &Mutex<HashMap<String, TemplateSnapshot>>) -> MutexGuard<'_, HashMap<String, TemplateSnapshot>> {
    templates.lock().expect("snapshot bookkeeping never panics")
}

/// One boot's hold on its template's snapshot: either a golden boot's claim to build it, or a restore reading its
/// directory. Dropping it unfinished (a panicked or abandoned boot) releases it as inconclusive.
#[must_use = "dropping a lease releases it as an inconclusive boot"]
pub struct Lease<'a> {
    cache: &'a Cache,
    template_id: String,
    mode: BootMode,
    released: bool,
}

impl Lease<'_> {
    pub fn mode(&self) -> BootMode {
        self.mode
    }

    /// Notes a golden boot's memory is in the snapshot store under `key`.
    pub fn exported(&self, key: String) {
        self.cache.with(&self.template_id, |s| {
            if let Phase::Building { mem_key } = &mut s.phase {
                *mem_key = Some(key);
            }
        });
    }

    /// Notes a record boot's guest left a working set, packed in the snapshot store under `pack_key` if it got there.
    pub fn recorded(&self, pack_key: Option<String>) {
        self.cache.with(&self.template_id, |s| {
            s.working_set_failures = 0;
            // a sibling may have dropped the snapshot, and its working set with it, since this boot began.
            if let Phase::Ready { working_set, .. } = &mut s.phase {
                *working_set = WorkingSet::Recorded { pack_key };
            }
        });
    }

    /// Notes a record boot's guest left no working set. The boot itself worked either way.
    pub fn recording_failed(&self) {
        self.cache.with(&self.template_id, |s| s.working_set_failures += 1);
    }

    /// Records what the boot showed. A broken snapshot gets dropped so a later boot rebuilds it, and its directory goes
    /// once no restore is reading it.
    pub async fn finish(mut self, verdict: Verdict) -> Result<()> {
        match self.release(verdict) {
            Some(remove) => tokio::task::spawn_blocking(remove).await.context("remove snapshot")?,
            None => Ok(()),
        }
    }

    /// Settles the hold under the lock, and hands back the directory removal for the caller to run afterwards.
    fn release(&mut self, verdict: Verdict) -> Option<impl FnOnce() -> Result<()> + Send + 'static> {
        self.released = true;
        let unused = self.cache.with(&self.template_id, |s| s.release(self.mode, verdict));
        unused.then(|| self.cache.removal(&self.template_id))
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let Some(remove) = self.release(Verdict::Inconclusive) else { return };
        let template = self.template_id.clone();
        let remove = move || {
            if let Err(err) = remove() {
                tracing::error!(template, error = format!("{err:#}"), "drop snapshot");
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => drop(runtime.spawn_blocking(remove)),
            Err(_) => remove(),
        }
    }
}

/// Fails startup on hosts where every restore would fail.
pub fn check_paths(cfg: &Config, snapshots: &Path) -> Result<()> {
    let Some(chroot_base) = cfg.chroot_base().filter(|_| cfg.snapshots_enabled()) else { return Ok(()) };
    std::fs::create_dir_all(&chroot_base).context("mkdir chroot base")?;
    let nest = std::fs::metadata(&chroot_base).context("stat chroot base")?;
    let snap = std::fs::metadata(snapshots).context("stat snapshots")?;
    ensure!(nest.dev() == snap.dev(), "snapshots hardlink into nests, so state_dir and jailer.chroot_base must share a filesystem");
    // the uffd handler runs outside the chroot as the vm's uid, so it execs from a host path and opens its socket by
    // host path too.
    for path in [cfg.uffd_handler_bin(), chroot_base] {
        others_can_reach(&path).context("snapshot restores run the uffd handler as vm uids")?;
    }
    Ok(())
}

/// Fails on the first of `path` or its ancestors that's missing o+x.
fn others_can_reach(path: &Path) -> Result<()> {
    for p in path.ancestors() {
        let mode = std::fs::metadata(p).with_context(|| format!("stat {}", p.display()))?.permissions().mode();
        if mode & 0o001 == 0 {
            bail!("{} isn't o+x", p.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    fn template(snapshot: Option<Snapshot>) -> Template {
        let dir = tempfile::tempdir().unwrap();
        let mut t = Arc::unwrap_or_clone(testing::config(dir.path()).templates.remove(0));
        t.snapshot = snapshot;
        t
    }

    /// Boots one guest per verdict in turn. A record boot's recording goes the same way as its boot.
    async fn plans(c: &Cache, t: &Template, verdicts: &[Verdict]) -> Vec<BootMode> {
        let mut modes = Vec::new();
        for &verdict in verdicts {
            let lease = c.plan(t);
            modes.push(lease.mode());
            match (lease.mode(), verdict) {
                (BootMode::Record, Verdict::Sound) => lease.recorded(None),
                (BootMode::Record, _) => lease.recording_failed(),
                _ => {}
            }
            lease.finish(verdict).await.unwrap();
        }
        modes
    }

    #[tokio::test]
    async fn builds_once_then_records_then_prefetches() {
        let dir = tempfile::tempdir().unwrap();
        let c = Cache::new(dir.path());
        let lazy = template(Some(Snapshot::Lazy));
        let golden = c.plan(&lazy);
        assert_eq!(golden.mode(), BootMode::Golden);
        assert_eq!(c.plan(&lazy).mode(), BootMode::Cold, "a second boot doesn't wait for the snapshot");
        golden.exported("mem".into());
        golden.finish(Verdict::Sound).await.unwrap();
        assert_eq!(c.mem_key(&lazy.template_id).as_deref(), Some("mem"));
        let record = c.plan(&lazy);
        assert_eq!(record.mode(), BootMode::Record);
        assert_eq!(c.plan(&lazy).mode(), BootMode::Restore, "one recording at a time");
        record.recorded(Some("pack".into()));
        record.finish(Verdict::Sound).await.unwrap();
        assert_eq!(c.pack_key(&lazy.template_id).as_deref(), Some("pack"));
        assert_eq!(plans(&c, &lazy, &[Verdict::Sound]).await, [BootMode::Prefetch]);
        assert_eq!(c.plan(&template(None)).mode(), BootMode::Cold);
    }

    #[tokio::test]
    async fn stops_recording_after_repeated_failures() {
        let dir = tempfile::tempdir().unwrap();
        let c = Cache::new(dir.path());
        let lazy = template(Some(Snapshot::Lazy));
        assert_eq!(plans(&c, &lazy, &[Verdict::Sound]).await, [BootMode::Golden]);
        // the guests boot fine; only their recordings fail.
        for _ in 0..MAX_FAILURES {
            let record = c.plan(&lazy);
            assert_eq!(record.mode(), BootMode::Record);
            record.recording_failed();
            record.finish(Verdict::Sound).await.unwrap();
        }
        assert_eq!(c.plan(&lazy).mode(), BootMode::Restore);
    }

    #[tokio::test]
    async fn drops_failed_snapshots_and_gives_up() {
        let dir = tempfile::tempdir().unwrap();
        let c = Cache::new(dir.path());
        let eager = template(Some(Snapshot::Eager));
        let id = &eager.template_id;
        std::fs::create_dir_all(c.dir(id)).unwrap();
        let golden = c.plan(&eager);
        golden.exported("mem".into());
        golden.finish(Verdict::Inconclusive).await.unwrap();
        assert!(!c.dir(id).exists());
        assert_eq!(c.mem_key(id), None);
        let modes = plans(&c, &eager, &[Verdict::Broken, Verdict::Broken, Verdict::Broken, Verdict::Sound]).await;
        assert_eq!(modes, [BootMode::Golden, BootMode::Golden, BootMode::Golden, BootMode::Cold]);
    }

    /// Eager templates never record, and an inconclusive restore keeps the snapshot.
    #[tokio::test]
    async fn eager_restores_survive_inconclusive() {
        let dir = tempfile::tempdir().unwrap();
        let c = Cache::new(dir.path());
        let eager = template(Some(Snapshot::Eager));
        assert_eq!(
            plans(&c, &eager, &[Verdict::Sound, Verdict::Inconclusive, Verdict::Sound]).await,
            [BootMode::Golden, BootMode::Restore, BootMode::Restore]
        );
    }

    #[tokio::test]
    async fn broken_snapshot_outlives_its_restores() {
        let dir = tempfile::tempdir().unwrap();
        let c = Cache::new(dir.path());
        let eager = template(Some(Snapshot::Eager));
        let id = &eager.template_id;
        assert_eq!(plans(&c, &eager, &[Verdict::Sound]).await, [BootMode::Golden]);
        std::fs::create_dir_all(c.dir(id)).unwrap();
        let [first, second, third] = [c.plan(&eager), c.plan(&eager), c.plan(&eager)];
        assert_eq!([first.mode(), second.mode(), third.mode()], [BootMode::Restore; 3]);

        first.finish(Verdict::Broken).await.unwrap();
        assert!(c.dir(id).exists(), "two restores still read it");
        assert_eq!(c.plan(&eager).mode(), BootMode::Cold, "no golden boot over a directory in use");
        second.finish(Verdict::Broken).await.unwrap();
        third.finish(Verdict::Sound).await.unwrap();
        assert!(!c.dir(id).exists());
        assert_eq!(c.templates()[id].failures, 1, "one broken snapshot, however many restores reported it");

        assert_eq!(plans(&c, &eager, &[Verdict::Sound]).await, [BootMode::Golden]);
        assert_eq!(c.plan(&eager).mode(), BootMode::Restore);
    }

    /// Outside a runtime, so a dropped lease removes the directory before the drop returns.
    #[test]
    fn dropped_lease_releases() {
        let dir = tempfile::tempdir().unwrap();
        let c = Cache::new(dir.path());
        let lazy = template(Some(Snapshot::Lazy));
        let id = &lazy.template_id;
        std::fs::create_dir_all(c.dir(id)).unwrap();
        drop(c.plan(&lazy));
        assert!(!c.dir(id).exists(), "an abandoned golden boot built nothing");
        assert_eq!(c.plan(&lazy).mode(), BootMode::Golden, "nor holds the template building");

        c.templates().get_mut(id).unwrap().phase = Phase::Ready { restoring: 0, mem_key: None, working_set: WorkingSet::Unrecorded };
        drop(c.plan(&lazy));
        assert!(
            matches!(c.templates()[id].phase, Phase::Ready { restoring: 0, working_set: WorkingSet::Unrecorded, .. }),
            "an abandoned record boot neither reads the snapshot nor records it"
        );
        assert_eq!(c.plan(&lazy).mode(), BootMode::Record);
    }

    #[test]
    fn names_dir_blocking_vm_uids() {
        others_can_reach(Path::new("/")).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(private.join("uffd-handler"), "").unwrap();
        std::fs::set_permissions(private.join("uffd-handler"), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(others_can_reach(&private.join("uffd-handler")).unwrap_err().to_string(), format!("{} isn't o+x", private.display()));
    }
}
