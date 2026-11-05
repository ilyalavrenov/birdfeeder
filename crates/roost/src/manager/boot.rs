//! Booting a pool guest: cold, or restored from its template's snapshot, through to its readiness probes.

use std::io::Read as _;
use std::net::SocketAddr;
use std::time::UNIX_EPOCH;

use anyhow::bail;
use guestapi::workload::{Metadata, Probe, ProbeTarget};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;
use vmm::{RestoreMode, Stage};

use super::*;
use crate::config::{Sha256Hex, Snapshot};
use crate::snapshots::{BootMode, Lease, Verdict};

const READY_POLL: Duration = Duration::from_millis(250);
const WARMUP_TIMEOUT: Duration = Duration::from_secs(10);
const TRIGGER_POOL: &str = "pool";

#[derive(Debug)]
enum BootOutcome {
    Ready,
    Canceled,
    Failed(anyhow::Error),
}

/// Why a boot stopped short of ready.
#[derive(Debug)]
enum Halt {
    Canceled,
    Failed(anyhow::Error),
}

impl From<anyhow::Error> for Halt {
    fn from(err: anyhow::Error) -> Self {
        Self::Failed(err)
    }
}

impl BootOutcome {
    fn of(result: Result<(), Halt>, cancel: &CancellationToken) -> Self {
        match result {
            Ok(()) => Self::Ready,
            // a delete or shutdown can break a step that isn't a cancellation point, like killing the vmm under
            // start_vmm. Blaming the boot would back off the refill, and for a restore it'd drop a good snapshot.
            Err(Halt::Failed(err)) if !cancel.is_cancelled() => Self::Failed(err),
            Err(Halt::Canceled | Halt::Failed(_)) => Self::Canceled,
        }
    }
}

/// An artifact as we last hashed it, by identity and metadata. Rebuilds publish artifacts by rename, so a replacement
/// is a new inode, and an in-place write changes size or mtime. Root rewriting one and resetting its mtime would slip
/// past this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Seen {
    dev: u64,
    ino: u64,
    len: u64,
    modified: SystemTime,
    sha256: Sha256Hex,
}

/// Whether an artifact, as last seen, hashed to the digest it was checked against.
#[derive(Debug)]
pub(super) struct Hashed {
    seen: Seen,
    matched: bool,
}

async fn cancellable<T>(cancel: &CancellationToken, fut: impl Future<Output = Result<T>>) -> Result<T, Halt> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(Halt::Canceled),
        result = fut => Ok(result?),
    }
}

impl<D: Driver + 'static, H: Host> Manager<D, H> {
    /// Makes an allocated session's generation durable, then its record, and only then shows it to clients.
    pub(super) async fn record(&self, id: &SessionRef) -> Result<()> {
        let (gens, rec) = {
            let sessions = self.sessions();
            let s = sessions.get(id).context("an allocated session vanished")?;
            (self.store.stage_gens(&sessions.gens), self.store.stage(&s.rec))
        };
        // recovery refuses a record newer than the generation file
        gens.write().await.context("persist generation")?;
        rec.write().await.context("persist session")?;
        if let Some(s) = self.sessions().get_mut(id) {
            s.recorded = true;
        }
        Ok(())
    }

    /// Boots the allocated session `id` into its template's pool.
    pub(super) async fn boot_pooled(&self, pool: &Pool, id: SessionRef, handle: BootHandle) {
        let _done = handle.done.clone().drop_guard();
        let t = &pool.template;
        let name = id.name.as_str();
        if let Err(err) = self.record(&id).await {
            tracing::error!(name, error = format!("{err:#}"), "record allocated session");
            if let Err(err) = self.destroy(&id).await {
                tracing::error!(name, error = format!("{err:#}"), "cleanup after failed record");
            }
            return;
        }
        let queued = Instant::now();
        let permit = tokio::select! {
            permit = self.boots.acquire() => permit.expect("the boot semaphore is never closed"),
            // a delete finishes the cleanup once the boot's done. A shutdown leaves it to the next roost.
            () = handle.cancel.cancelled() => return,
        };
        self.metrics.boot_queue.record(queued.elapsed().as_secs_f64(), &[KeyValue::new("birdfeeder.boot.trigger", TRIGGER_POOL)]);
        tracing::info!(name, generation = id.generation, "booting pool session");
        let start = Instant::now();
        let (mode, outcome) = self.boot(t, &id, &handle.cancel).await;
        drop(permit);
        self.record_boot(t, mode, start, &outcome);
        count_for_refill(pool, &outcome);
        match outcome {
            BootOutcome::Canceled => {}
            BootOutcome::Failed(err) => {
                tracing::error!(name, error = format!("{err:#}"), "pool boot failed");
                if let Err(err) = self.destroy(&id).await {
                    tracing::error!(name, error = format!("{err:#}"), "cleanup after failed boot");
                }
            }
            BootOutcome::Ready => {
                let (guest_ip, pooled) = {
                    let mut sessions = self.sessions();
                    let Some(s) = sessions.get_mut(&id).filter(|s| s.rec.state == State::Booting) else { return };
                    s.rec.state = State::Pooled;
                    s.rec.pooled_at = Some(SystemTime::now());
                    (s.rec.guest_ip, self.store.stage(&s.rec))
                };
                persist_logged(pooled, name, "persist pooled session").await;
                tracing::info!(name, mode = mode.as_str(), boot_ms = start.elapsed().as_millis(), %guest_ip, "session pooled");
            }
        }
    }

    fn record_boot(&self, t: &Template, mode: BootMode, start: Instant, outcome: &BootOutcome) {
        let outcome = match outcome {
            BootOutcome::Ready => "ok",
            BootOutcome::Canceled => "canceled",
            BootOutcome::Failed(err) => {
                self.metrics.boot_failures.add(
                    1,
                    &[
                        KeyValue::new("birdfeeder.boot.trigger", TRIGGER_POOL),
                        KeyValue::new("birdfeeder.boot.mode", mode.as_str()),
                        KeyValue::new("birdfeeder.operation.stage", stage_label(vmm::stage_of(err))),
                        KeyValue::new("birdfeeder.template.id", t.template_id.clone()),
                    ],
                );
                "error"
            }
        };
        self.metrics.boot_duration.record(
            start.elapsed().as_secs_f64(),
            &[
                KeyValue::new("birdfeeder.boot.trigger", TRIGGER_POOL),
                KeyValue::new("birdfeeder.boot.mode", mode.as_str()),
                KeyValue::new("birdfeeder.operation.outcome", outcome),
                KeyValue::new("birdfeeder.template.id", t.template_id.clone()),
            ],
        );
    }

    async fn boot(&self, t: &Template, id: &SessionRef, cancel: &CancellationToken) -> (BootMode, BootOutcome) {
        let lease = self.snapshots.plan(t);
        let mode = lease.mode();
        let span = tracing::info_span!(
            "birdfeeder.session.boot",
            birdfeeder.session.id = id.name,
            birdfeeder.template.id = t.template_id,
            birdfeeder.boot.mode = mode.as_str(),
            otel.status_code = Empty,
            otel.status_description = Empty
        );
        let outcome = BootOutcome::of(self.boot_as(t, id, &lease, cancel).instrument(span.clone()).await, cancel);
        let failure = match &outcome {
            BootOutcome::Ready => None,
            BootOutcome::Canceled => Some("boot canceled".to_owned()),
            BootOutcome::Failed(err) => Some(format!("{err:#}")),
        };
        if let Some(failure) = failure {
            span.record("otel.status_code", "error");
            span.record("otel.status_description", failure);
        }
        if let Err(err) = lease.finish(verdict(mode, &outcome)).await {
            tracing::error!(template = t.template_id, error = format!("{err:#}"), "drop snapshot");
        }
        (mode, outcome)
    }

    async fn boot_as(&self, t: &Template, id: &SessionRef, lease: &Lease<'_>, cancel: &CancellationToken) -> Result<(), Halt> {
        let restore = match lease.mode() {
            BootMode::Restore if t.snapshot == Some(Snapshot::Eager) => Some(RestoreMode::Eager),
            BootMode::Restore => Some(RestoreMode::Lazy),
            BootMode::Record => Some(RestoreMode::Record),
            BootMode::Prefetch => Some(RestoreMode::Prefetch),
            BootMode::Cold | BootMode::Golden => None,
        };
        let dir = self.snapshots.dir(&t.template_id);
        let scratch = if restore.is_some() { dir.join(vmm::SNAPSHOT_DISK) } else { t.scratch_disk.clone() };
        self.boot_steps(t, id, &scratch, restore, cancel).await?;
        match lease.mode() {
            BootMode::Golden => {
                // the guest is ready, so every restore starts out ready. Resuming keeps it in the pool.
                let inst = self.instance(id)?;
                step(Stage::Snapshot, self.driver.snapshot(&inst, &dir, true)).await?;
                self.export_memory(t, lease).await;
            }
            BootMode::Record => self.record_working_set(t, id, lease).await,
            _ => {}
        }
        Ok(())
    }

    fn instance(&self, id: &SessionRef) -> Result<vmm::Instance> {
        Ok(self.sessions().get(id).context("a booting session vanished")?.rec.instance.clone())
    }

    async fn boot_steps(
        &self,
        t: &Template,
        id: &SessionRef,
        scratch: &Path,
        restore: Option<RestoreMode>,
        cancel: &CancellationToken,
    ) -> Result<(), Halt> {
        let (rec, slot) = {
            let sessions = self.sessions();
            let s = sessions.get(id).context("a booting session vanished")?;
            (s.rec.clone(), s.slot)
        };
        cancellable(cancel, step(Stage::VerifyArtifacts, self.verify_artifacts(t))).await?;
        if self.cfg.hugepages_2m {
            let committed = self.sessions().reserved().memory_mib;
            sysctl::ensure_hugepages(committed).await.map_err(|err| anyhow::Error::from(vmm::staged(Stage::Hugepages, err)))?;
        }
        // disk, namespace and host rules don't depend on each other. Only the vmm needs all three.
        let guest = self.guest(&rec.instance, &rec.mac, t, &slot);
        let disk = async {
            step(Stage::CopyDisk, async {
                if let Some(dir) = rec.instance.disk.parent() {
                    tokio::fs::create_dir_all(dir).await.context("mkdir disk dir")?;
                }
                vmm::copy_disk(scratch, &rec.instance.disk).await
            })
            .await?;
            step(Stage::Nest, async { self.driver.prepare(&rec.instance, &guest) }).await
        };
        let tap = step(Stage::Tap, self.host.create_session(slot, self.driver.uid(&rec.instance)));
        // rules match interfaces by name, so they can land before the tap exists.
        let nft = step(Stage::Nft, self.apply_net());
        cancellable(cancel, async { tokio::try_join!(disk, tap, nft).map(drop) }).await?;
        // not cancellable: the vmm it spawns has to get recorded so teardown can kill it.
        step(Stage::StartVmm, self.start_vmm(id, &rec, t, &slot, restore)).await?;
        if cancel.is_cancelled() {
            return Err(Halt::Canceled);
        }
        let started = {
            let sessions = self.sessions();
            self.store.stage(&sessions.get(id).context("a booting session vanished")?.rec)
        };
        step(Stage::Persist, started.write()).await?;
        cancellable(cancel, step(Stage::WaitReady, self.wait_ready(&rec, self.cfg.ready_timeout))).await
    }

    async fn start_vmm(&self, id: &SessionRef, rec: &Record, t: &Template, slot: &Slot, restore: Option<RestoreMode>) -> Result<()> {
        let boot = vmm::Boot {
            guest: self.guest(&rec.instance, &rec.mac, t, slot),
            limits: vmm::Limits {
                disk_bytes_per_sec: t.disk_bytes_per_sec,
                disk_ops_per_sec: t.disk_ops_per_sec,
                net_bytes_per_sec: t.net_bytes_per_sec,
                net_packets_per_sec: t.net_packets_per_sec,
            },
            metadata: serde_json::to_value(Metadata {
                version: 1,
                template_id: t.template_id.parse()?,
                blobs: t.blobs.keys().map(|b| b.parse()).collect::<Result<_, _>>()?,
                manifest: rec.manifest.clone(),
            })?,
            console: self.console_path(rec),
        };
        let mut inst = rec.instance.clone();
        let started = match restore {
            None => self.driver.start(&mut inst, &boot).await,
            Some(mode) => {
                let src = self.restore_source(t, mode).await?;
                self.driver.restore(&mut inst, &boot, &src).await
            }
        };
        // published even on failure, so teardown after a canceled or failed boot kills whatever did start.
        if let Some(s) = self.sessions().get_mut(id) {
            s.rec.instance = inst.clone();
        }
        started?;
        if restore.is_some() {
            step(Stage::SyncClock, guestapi::set_clock(&inst.vsock_path, SystemTime::now())).await?;
        }
        Ok(())
    }

    /// Where a restore reads its memory from. That's the snapshot store once the memory's there, except for a
    /// recording, which records against the local file.
    async fn restore_source(&self, t: &Template, mode: RestoreMode) -> Result<vmm::RestoreSource> {
        let dir = self.snapshots.dir(&t.template_id);
        let mut remote = None;
        if let (Some(store), Some(mem_key)) = (&self.snapstore, self.snapshots.mem_key(&t.template_id))
            && mode != RestoreMode::Record
        {
            let working_set_url = match self.snapshots.pack_key(&t.template_id) {
                Some(key) if mode == RestoreMode::Prefetch => Some(store.url(&key).await?),
                _ => None,
            };
            remote = Some(vmm::RemoteMemory { mem_url: store.url(&mem_key).await?, working_set_url });
        }
        Ok(vmm::RestoreSource { dir, mode, remote })
    }

    /// Copies a fresh snapshot's memory to the snapshot store. Restores read the local file until it lands, so if this
    /// fails we only lose the copy.
    async fn export_memory(&self, t: &Template, lease: &Lease<'_>) {
        let Some(store) = &self.snapstore else { return };
        // a rebuilt snapshot gets a new key, so guests still pulling the old memory keep reading it.
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        let key = store.key(&[&self.cfg.host_id, &t.template_id, &base36(nanos), "mem"]);
        let dir = self.snapshots.dir(&t.template_id);
        let exported = step(Stage::ExportMemory, async {
            let mem = self.driver.export_memory(&dir).await?;
            Box::pin(store.put(&key, &mem)).await
        })
        .await;
        match exported {
            Ok(()) => lease.exported(key),
            Err(err) => tracing::error!(template = t.template_id, error = format!("{err:#}"), "export snapshot memory"),
        }
    }

    /// Runs the template's warm-up against a recording guest, then saves the pages it touched. The guest is already
    /// ready, so a failure just means later restores don't get a prefetch.
    async fn record_working_set(&self, t: &Template, id: &SessionRef, lease: &Lease<'_>) {
        let dir = self.snapshots.dir(&t.template_id);
        let recorded = step(Stage::RecordWorkingSet, async {
            let (inst, guest_ip, endpoints) = {
                let sessions = self.sessions();
                let s = sessions.get(id).context("a recording session vanished")?;
                (s.rec.instance.clone(), s.rec.guest_ip, s.rec.endpoints.clone())
            };
            for w in &t.snapshot_warmup {
                let port = endpoints.get(&w.endpoint).map_or(0, |e| e.guest_port);
                if let Err(err) = warmup(SocketAddr::from((guest_ip, port)), &w.path).await {
                    tracing::warn!(template = t.template_id, path = w.path, error = format!("{err:#}"), "snapshot warm-up");
                }
            }
            self.driver.finish_recording(&inst, &dir).await
        })
        .await;
        match recorded {
            Ok(()) => lease.recorded(Box::pin(self.export_working_set(t)).await),
            Err(err) => {
                tracing::error!(template = t.template_id, error = format!("{err:#}"), "record working set");
                lease.recording_failed();
            }
        }
    }

    /// Copies a fresh working set's packed pages next to the snapshot memory, so remote prefetches pull just those
    /// pages. Without it they pull the whole chunks the pages fall in. Returns the pack's key once it's uploaded.
    async fn export_working_set(&self, t: &Template) -> Option<String> {
        let (Some(store), Some(mem_key)) = (&self.snapstore, self.snapshots.mem_key(&t.template_id)) else { return None };
        let key = match mem_key.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/{}", vmm::SNAPSHOT_WORKING_SET_PACK),
            None => vmm::SNAPSHOT_WORKING_SET_PACK.to_owned(),
        };
        let pack = self.snapshots.dir(&t.template_id).join(vmm::SNAPSHOT_WORKING_SET_PACK);
        // the SDK's futures are huge, and this one would otherwise end up inside every boot's.
        match step(Stage::ExportWorkingSet, Box::pin(store.put(&key, &pack))).await {
            Ok(()) => Some(key),
            Err(err) => {
                tracing::error!(template = t.template_id, error = format!("{err:#}"), "export working set");
                None
            }
        }
    }

    async fn verify_artifacts(&self, t: &Template) -> Result<()> {
        self.verify(&self.cfg.kernel_image_path, &self.cfg.kernel_sha256).await?;
        self.verify(&t.base_disk, &t.base_disk_sha256).await?;
        self.verify(&t.scratch_disk, &t.scratch_disk_sha256).await?;
        for (name, path) in &t.blobs {
            self.verify(path, &t.blob_sha256[name]).await?;
        }
        Ok(())
    }

    /// Checks `path` hashes to `want`. Skips hashing if it's the same file we hashed last time.
    pub(super) async fn verify(&self, path: &Path, want: &Sha256Hex) -> Result<()> {
        use std::os::unix::fs::MetadataExt as _;

        let (mut file, meta) = {
            let path = path.to_owned();
            tokio::task::spawn_blocking(move || {
                let file = File::open(&path).with_context(|| format!("verify artifact {}", path.display()))?;
                let meta = file.metadata().with_context(|| format!("stat artifact {}", path.display()))?;
                anyhow::Ok((file, meta))
            })
            .await??
        };
        let seen = Seen { dev: meta.dev(), ino: meta.ino(), len: meta.len(), modified: meta.modified()?, sha256: want.clone() };
        let cached = self.verified.lock().expect("never poisoned").get(path).filter(|h| h.seen == seen).map(|h| h.matched);
        match cached {
            Some(true) => return Ok(()),
            Some(false) => bail!("artifact {}: SHA-256 mismatch", path.display()),
            None => {}
        }
        let digest = tokio::task::spawn_blocking(move || {
            let mut hash = Sha256::new();
            let mut buf = vec![0; 1 << 20];
            loop {
                match file.read(&mut buf)? {
                    0 => return std::io::Result::Ok(hex::encode(hash.finalize())),
                    n => hash.update(&buf[..n]),
                }
            }
        })
        .await?
        .context("hash artifact")?;
        let matched = digest == want.as_str();
        self.verified.lock().expect("never poisoned").insert(path.to_owned(), Hashed { seen, matched });
        if !matched {
            bail!("artifact {}: SHA-256 mismatch", path.display());
        }
        Ok(())
    }

    /// Waits on all the readiness probes at once, up to `timeout`.
    pub(super) async fn wait_ready(&self, rec: &Record, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        let deadline = start + timeout;
        let probes = rec.manifest.readiness.iter().map(|p| {
            let span = tracing::info_span!(
                "probe",
                otel.name = p.name.as_str(),
                birdfeeder.readiness.probe.count = Empty,
                otel.status_code = Empty,
                otel.status_description = Empty
            );
            let counted = span.clone();
            traced(span, async move {
                let (tries, result) = self.wait_for(rec, p, deadline).await;
                counted.record("birdfeeder.readiness.probe.count", tries);
                result.map(|()| start.elapsed())
            })
        });
        let ready = futures_util::future::try_join_all(probes).await?;
        let phases: Vec<String> =
            rec.manifest.readiness.iter().zip(ready).map(|(p, d)| format!("{}={}ms", p.name, d.as_millis())).collect();
        tracing::info!(name = rec.name(), phases = phases.join(" "), "guest ready");
        Ok(())
    }

    /// Polls `p` until it answers or `deadline` passes. Each try is capped so a guest eating SYNs can't stall it.
    async fn wait_for(&self, rec: &Record, p: &Probe, deadline: Instant) -> (u32, Result<()>) {
        for tries in 1.. {
            let ok = match p.target {
                ProbeTarget::Vsock(port) => {
                    let connect = guestapi::connect(&rec.instance.vsock_path, u32::from(port.get()));
                    tokio::time::timeout(READY_POLL, connect).await.is_ok_and(|c| c.is_ok())
                }
                ProbeTarget::Tcp(port) => self.host.accepts(SocketAddr::from((rec.guest_ip, port.get())), READY_POLL).await,
            };
            if ok {
                return (tries, Ok(()));
            }
            if Instant::now() > deadline {
                return (tries, Err(anyhow::anyhow!("{} on guest {} never appeared", p.name, rec.guest_ip)));
            }
            tokio::time::sleep(READY_POLL).await;
        }
        unreachable!("the probe loop only returns")
    }
}

fn count_for_refill(pool: &Pool, outcome: &BootOutcome) {
    let mut backoff = pool.backoff.lock().expect("never poisoned");
    match outcome {
        BootOutcome::Ready => backoff.succeeded(),
        BootOutcome::Failed(_) => {
            if let Some(retry_in) = backoff.failed(Instant::now()) {
                tracing::warn!(template = pool.template.template_id, retry_in_ms = retry_in.as_millis(), "pool refill backing off");
            }
        }
        BootOutcome::Canceled => {}
    }
}

/// Only blames the snapshot for steps that use it. A full disk or missing tap doesn't tell us anything about it.
fn verdict(mode: BootMode, outcome: &BootOutcome) -> Verdict {
    let err = match outcome {
        BootOutcome::Ready => return Verdict::Sound,
        BootOutcome::Canceled => return Verdict::Inconclusive,
        BootOutcome::Failed(err) => err,
    };
    let Some(stage) = vmm::stage_of(err) else { return Verdict::Inconclusive };
    let restored = match mode {
        BootMode::Cold | BootMode::Golden => false,
        BootMode::Restore | BootMode::Record | BootMode::Prefetch => true,
    };
    let blamed = match stage {
        Stage::Snapshot => mode == BootMode::Golden,
        // a restore copies its disk from the snapshot, so a base it can't open means a snapshot file went missing
        Stage::CopyDisk => restored && vmm::base_unreadable(err),
        // start_vmm loads the snapshot and syncs the restored clock. If a guest snapshotted ready doesn't come back
        // ready, it most likely came back broken.
        Stage::StartVmm | Stage::WaitReady => restored,
        Stage::VerifyArtifacts
        | Stage::Hugepages
        | Stage::Nest
        | Stage::Tap
        | Stage::Nft
        | Stage::Persist
        | Stage::SyncClock
        | Stage::ExportMemory
        | Stage::RecordWorkingSet
        | Stage::ExportWorkingSet
        | Stage::KillVmm
        | Stage::DeleteTap
        | Stage::RunDir
        | Stage::Disk
        | Stage::SnapshotStage
        | Stage::Cgroup => false,
    };
    if blamed { Verdict::Broken } else { Verdict::Inconclusive }
}

/// An HTTP GET that reads the whole response, so every page the guest touches to produce it gets counted.
async fn warmup(addr: SocketAddr, path: &str) -> Result<()> {
    tokio::time::timeout(WARMUP_TIMEOUT, async {
        let mut conn = tokio::net::TcpStream::connect(addr).await.context("connect")?;
        conn.write_all(format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
        tokio::io::copy(&mut conn, &mut tokio::io::sink()).await.context("read warm-up response")?;
        anyhow::Ok(())
    })
    .await
    .context("warm-up timed out")?
}

fn base36(mut n: u128) -> String {
    let mut digits = Vec::new();
    loop {
        digits.push(char::from_digit((n % 36) as u32, 36).expect("below 36"));
        n /= 36;
        if n == 0 {
            return digits.into_iter().rev().collect();
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn failed_at(stage: Stage) -> BootOutcome {
        BootOutcome::Failed(vmm::staged(stage, anyhow::anyhow!("boom")).into())
    }

    #[rstest]
    #[case::ready(BootMode::Restore, BootOutcome::Ready, Verdict::Sound)]
    #[case::canceled(BootMode::Restore, BootOutcome::Canceled, Verdict::Inconclusive)]
    #[case::restore_start(BootMode::Restore, failed_at(Stage::StartVmm), Verdict::Broken)]
    #[case::prefetch_ready(BootMode::Prefetch, failed_at(Stage::WaitReady), Verdict::Broken)]
    #[case::restore_copy(BootMode::Restore, failed_at(Stage::CopyDisk), Verdict::Inconclusive)]
    #[case::golden_copy(BootMode::Golden, failed_at(Stage::CopyDisk), Verdict::Inconclusive)]
    #[case::record_tap(BootMode::Record, failed_at(Stage::Tap), Verdict::Inconclusive)]
    #[case::restore_nft(BootMode::Restore, failed_at(Stage::Nft), Verdict::Inconclusive)]
    #[case::golden_ready(BootMode::Golden, failed_at(Stage::WaitReady), Verdict::Inconclusive)]
    #[case::golden_snapshot(BootMode::Golden, failed_at(Stage::Snapshot), Verdict::Broken)]
    #[case::restore_snapshot(BootMode::Restore, failed_at(Stage::Snapshot), Verdict::Inconclusive)]
    fn verdicts(#[case] mode: BootMode, #[case] outcome: BootOutcome, #[case] want: Verdict) {
        assert_eq!(verdict(mode, &outcome), want);
    }

    #[rstest]
    #[case::restore(BootMode::Restore)]
    #[case::record(BootMode::Record)]
    #[case::prefetch(BootMode::Prefetch)]
    #[case::golden(BootMode::Golden)]
    fn cancellation_blames_nothing(#[case] mode: BootMode) {
        let canceled = CancellationToken::new();
        canceled.cancel();
        for stage in [Stage::StartVmm, Stage::WaitReady, Stage::Snapshot] {
            let outcome = BootOutcome::of(Err(Halt::Failed(vmm::staged(stage, anyhow::anyhow!("boom")).into())), &canceled);
            assert!(matches!(outcome, BootOutcome::Canceled), "{mode:?} failing at {stage}: {outcome:?}");
            assert_eq!(verdict(mode, &outcome), Verdict::Inconclusive, "{mode:?} failing at {stage}");
        }
    }

    /// The disk copy a restore starts with is the first read of the snapshot's files.
    #[tokio::test]
    async fn restore_blames_unreadable_snapshot_disk() {
        let dir = tempfile::tempdir().unwrap();
        let copy = |base: PathBuf, dst: PathBuf| async move {
            let copied = step(Stage::CopyDisk, async move { vmm::copy_disk(&base, &dst).await }).await;
            BootOutcome::Failed(copied.unwrap_err())
        };

        let missing = copy(dir.path().join("snapshot/disk.ext4"), dir.path().join("dst")).await;
        assert_eq!(verdict(BootMode::Restore, &missing), Verdict::Broken, "{missing:?}");
        assert_eq!(verdict(BootMode::Golden, &missing), Verdict::Inconclusive, "a template's own disk isn't a snapshot");

        let base = dir.path().join("disk.ext4");
        fs::write(&base, "disk").unwrap();
        let unwritable = copy(base, dir.path().join("no-such-dir/dst")).await;
        assert_eq!(verdict(BootMode::Prefetch, &unwritable), Verdict::Inconclusive, "{unwritable:?}");
    }
}
