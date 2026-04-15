//! The session manager: one host's warm pools of guests, their claims, and their teardown. It's all persisted so a
//! restarted roost can adopt the guests that are still running.
//!
//! Every session holds a slot, which fixes its name, addresses and ports. A session name's generation goes up on each
//! reuse, and callers fence their requests with it. The state lock is never held across an await. Network changes take
//! turns on their own lock and render whatever the sessions look like when their turn comes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::NonZeroU64;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context as _, Result};
use guestnet::{Egress, Endpoint, Slot};
use nix::fcntl::{Flock, FlockArg};
use opentelemetry::KeyValue;
use opentelemetry::metrics::Meter;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::field::Empty;
use tracing::{Instrument as _, Span};
use vmm::{Driver, Stage};

use crate::config::{Config, ENDPOINT_BLOCK, Template};
use crate::host::Host;
use crate::metrics::Metrics;
use crate::snapshots;
use crate::state::{ClaimKey, Pending, Record, Released, State, Store};

mod boot;
mod dnsgate;
mod recovery;
mod sampling;
mod sysctl;
#[cfg(test)]
mod tests;

/// Long host ids get hashed so nftables names stay under the kernel's limit without colliding.
const MAX_NAME_PREFIX: usize = 48;
/// "-" and eight hex digits of a 32-bit FNV-1a hash.
const HOST_HASH_SUFFIX: usize = 9;
/// The wait before refilling a pool after a failed boot, doubling per failure up to [`MAX_REFILL_BACKOFF`].
const REFILL_BACKOFF: Duration = Duration::from_secs(5);
const MAX_REFILL_BACKOFF: Duration = Duration::from_mins(5);

/// Backs off refilling a template that keeps failing to boot, so we don't re-hash and re-boot a bad artifact every reap
/// tick.
#[derive(Debug, Default)]
struct Backoff {
    failures: u32,
    until: Option<Instant>,
}

impl Backoff {
    fn blocks(&self, now: Instant) -> bool {
        self.until.is_some_and(|until| now < until)
    }

    /// Counts a failed boot and returns the new wait, once per round. Siblings that started before the backoff kicked
    /// in fail into it without stretching it.
    fn failed(&mut self, now: Instant) -> Option<Duration> {
        if self.blocks(now) {
            return None;
        }
        self.failures = self.failures.saturating_add(1);
        let delay = REFILL_BACKOFF.saturating_mul(1 << (self.failures - 1).min(16)).min(MAX_REFILL_BACKOFF);
        self.until = Some(now + delay);
        Some(delay)
    }

    fn succeeded(&mut self) {
        *self = Self::default();
    }
}

/// A template's warm pool.
struct Pool {
    template: Arc<Template>,
    /// The template's identity, as [`Template::fingerprint`] computes it.
    fingerprint: String,
    backoff: Mutex<Backoff>,
}

/// Why a session request was refused.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("session not found")]
    NotFound,
    #[error("no ready session for template")]
    PoolEmpty,
    #[error("unknown template")]
    UnknownTemplate,
    #[error("session generation mismatch")]
    GenerationMismatch,
    #[error("no free slots")]
    SlotsExhausted,
    /// The session is mid-teardown and will be done shortly, so the caller should retry.
    #[error("session teardown is waiting for boot cancellation")]
    Busy,
    #[error("idempotency key was used for a different claim")]
    KeyReused,
    #[error("the session this idempotency key claimed was deleted")]
    KeyDeleted,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// What a claim asks of its guest on top of the template.
#[derive(Debug, Clone, Default)]
pub struct Claim {
    pub template_id: String,
    pub labels: BTreeMap<String, String>,
    pub egress: Option<Egress>,
    /// Expires the claim after this long unless it's extended.
    pub idle_timeout: Option<Duration>,
    pub key: Option<ClaimKey>,
}

/// A session name at one of its generations. Names get reused at the next generation, so anything acting on a session
/// later holds one of these, not the bare name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRef {
    pub name: String,
    pub generation: NonZeroU64,
}

/// What a claim handed out.
enum Claimed {
    /// A pooled guest, claimed now.
    Fresh(Info),
    /// The session this claim's idempotency key already claimed.
    Replayed(Info),
}

/// A session as callers see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub name: String,
    /// Each endpoint's `ip:port` on the host.
    pub endpoints: BTreeMap<String, String>,
    pub template_id: String,
    pub generation: u64,
    pub state: State,
    pub host_id: String,
    pub labels: BTreeMap<String, String>,
}

/// The session an idempotency key claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Keyed {
    Live(Info),
    /// Deleted within the key's retention.
    Deleted(Released),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolFill {
    pub template_id: String,
    /// Pooled guests, which a claim can take now.
    pub ready: u32,
    pub target: u32,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub capacity: u32,
    pub running: u32,
    pub pools: Vec<PoolFill>,
    pub max_vcpus: u32,
    pub reserved_vcpus: u32,
    pub max_memory_mib: u32,
    pub reserved_memory_mib: u32,
}

pub struct Manager<D, H> {
    cfg: Config,
    driver: D,
    host: H,
    store: Store,
    /// Held for the manager's life, so a second roost can't share the state directories.
    _lock: Vec<Flock<File>>,
    /// Keeps session names unique across the fleet.
    name_prefix: String,
    /// The DNS gate's bound port. Guest lookups get redirected here.
    dns_port: u16,
    iface: String,
    endpoint_ip: Ipv4Addr,
    capacity: u32,
    /// Each template's pool, in config order.
    pools: Vec<Arc<Pool>>,
    sessions: Mutex<Sessions>,
    /// Orders ruleset applies. Each one renders the sessions only once it has the turn, so an older ruleset never lands
    /// after a newer one.
    net: tokio::sync::Mutex<()>,
    /// Keyed claims and key lookups take turns, so a retry waits for the original attempt to finish and hit disk.
    keyed: tokio::sync::Mutex<()>,
    boots: Semaphore,
    verified: Mutex<HashMap<PathBuf, boot::Hashed>>,
    snapshots: snapshots::Cache,
    snapstore: Option<snapstore::Store>,
    metrics: Metrics,
    /// Stops the background loops and cancels in-flight boots. The next roost resumes or cleans those up.
    stop: CancellationToken,
    /// Every task the manager spawns, so shutdown can wait for them to stop.
    tasks: TaskTracker,
}

#[derive(Default)]
struct Sessions {
    by_name: BTreeMap<String, Session>,
    /// The last generation of each session name.
    gens: BTreeMap<String, u64>,
    /// Deleted sessions' idempotency keys, until their retention ends.
    released: BTreeMap<String, Released>,
    slots: BTreeSet<u32>,
    /// Teardowns that already took their session out of `by_name` but still hold its slot. A concurrent teardown of the
    /// same session waits for the slot to free up, instead of finding nothing to do.
    leaving: BTreeMap<String, Arc<tokio::sync::Mutex<()>>>,
}

struct Session {
    /// The record's name and generation, which never change.
    id: SessionRef,
    rec: Record,
    slot: Slot,
    /// The boot task, if this process has or had one.
    boot: Option<BootHandle>,
    /// Makes teardowns take turns, since their steps aren't idempotent if they overlap.
    teardown: Arc<tokio::sync::Mutex<()>>,
    /// Whether its record and generation are on disk. Clients can't see it until then, because a restart would reuse a
    /// generation they'd seen and fencing with it would hit the wrong session.
    recorded: bool,
}

#[derive(Clone)]
struct BootHandle {
    cancel: CancellationToken,
    /// Cancelled once the boot task returns.
    done: CancellationToken,
}

impl BootHandle {
    fn new(stop: &CancellationToken) -> Self {
        Self { cancel: stop.child_token(), done: CancellationToken::new() }
    }
}

impl Session {
    fn booting(&self) -> bool {
        self.boot.as_ref().is_some_and(|b| !b.done.is_cancelled())
    }
}

/// The resources the sessions hold between them.
#[derive(Debug, Clone, Copy, Default)]
struct Reserved {
    vcpus: u32,
    memory_mib: u32,
}

impl Sessions {
    /// The session `id` names, if that generation is still current.
    fn get(&self, id: &SessionRef) -> Option<&Session> {
        self.by_name.get(&id.name).filter(|s| s.id == *id)
    }

    fn get_mut(&mut self, id: &SessionRef) -> Option<&mut Session> {
        self.by_name.get_mut(&id.name).filter(|s| s.id == *id)
    }

    fn keyed(&self, key: &str) -> Option<&Session> {
        self.by_name.values().find(|s| s.rec.claim_key.as_ref().is_some_and(|k| k.key == key))
    }

    fn reserved(&self) -> Reserved {
        self.by_name
            .values()
            .fold(Reserved::default(), |r, s| Reserved { vcpus: r.vcpus + s.rec.vcpus, memory_mib: r.memory_mib + s.rec.mem_mib })
    }
}

impl<D: Driver + 'static, H: Host> Manager<D, H> {
    /// Takes the state directories, adopts the guests a previous roost left running, and starts the pools. Fails if
    /// another roost has the state directories.
    pub async fn start(cfg: Config, driver: D, host: H, meter: &Meter) -> Result<Arc<Self>> {
        let store = Store::new(cfg.session_state_dir(), &cfg.state_dir)?;
        fs::create_dir_all(&cfg.run_dir).context("mkdir run dir")?;
        let lock = lock_state(&cfg)?;
        let gens = store.load_gens()?;
        let released = store.load_keys()?;
        store.pin_templates(&cfg.templates, &cfg.kernel_sha256, &cfg.boot_args)?;
        let (iface, endpoint_ip) = match (&cfg.host_iface, cfg.endpoint_ip) {
            (Some(iface), Some(ip)) => (iface.clone(), ip),
            (iface, ip) => {
                let uplink = host.uplink().await?;
                let ip = ip.or(uplink.source).context("could not detect endpoint ip; set endpoint_ip")?;
                (iface.clone().unwrap_or(uplink.iface), ip)
            }
        };
        host.enable_forwarding()?;
        driver.setup()?;
        let snapshots = snapshots::Cache::new(&cfg.state_dir);
        snapshots.reset().await?;
        snapshots::check_paths(&cfg, snapshots.root())?;
        let snapstore = match &cfg.snapshot_store {
            // only resolves config here. Credentials get fetched on first use.
            Some(store) => Some(snapstore::Store::new(store).await?),
            None => None,
        };
        let (gate, gate_cfg) = dnsgate::bind_dns_gate(&cfg, meter).await?;
        let manager = Arc::new(Self {
            dns_port: gate.local_addr().context("dnsgate address")?.port(),
            name_prefix: name_prefix(&cfg.host_id),
            capacity: cfg.slots(),
            pools: cfg
                .templates
                .iter()
                .map(|t| {
                    let fingerprint = t.fingerprint(&cfg.kernel_sha256, &cfg.boot_args);
                    Arc::new(Pool { template: Arc::clone(t), fingerprint, backoff: Mutex::default() })
                })
                .collect(),
            sessions: Mutex::new(Sessions { gens, released, ..Sessions::default() }),
            boots: Semaphore::new(cfg.max_concurrent_boots as usize),
            net: tokio::sync::Mutex::new(()),
            keyed: tokio::sync::Mutex::new(()),
            verified: Mutex::default(),
            metrics: Metrics::new(meter),
            stop: CancellationToken::new(),
            tasks: TaskTracker::new(),
            snapshots,
            snapstore,
            iface,
            endpoint_ip,
            store,
            _lock: lock,
            driver,
            host,
            cfg,
        });
        manager.register_gauges(meter);
        manager.reconcile().await?;
        manager.apply_net().await?;
        manager.ensure_conntrack(true);
        manager.spawn(gate.serve(gate_cfg, dnsgate::Gate(Arc::clone(&manager))));
        // before serving, so the first requests can't race the first round.
        manager.maintain().await;
        manager.spawn_loops();
        Ok(manager)
    }

    /// Stops the background loops and boots, waits for them to wind down, and leaves every guest running for the next
    /// roost to adopt.
    pub async fn shutdown(&self) {
        self.stop.cancel();
        self.tasks.close();
        self.tasks.wait().await;
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Most containers any session here runs, counting adopted sessions whose template isn't configured anymore.
    pub fn max_containers(&self) -> u32 {
        let configured = self.cfg.templates.iter().map(|t| t.manifest.containers.len());
        let sessions = self.sessions();
        let adopted = sessions.by_name.values().map(|s| s.rec.manifest.containers.len());
        configured.chain(adopted).max().unwrap_or(0) as u32
    }

    /// A log stream for each container of every pooled and claimed guest.
    pub fn log_targets(&self) -> Vec<relay::Target> {
        let sessions = self.sessions();
        let live = sessions.by_name.values().filter(|s| matches!(s.rec.state, State::Pooled | State::Claimed));
        live.filter(|s| !s.rec.instance.vsock_path.as_os_str().is_empty())
            .flat_map(|s| {
                s.rec.manifest.containers.iter().map(|c| relay::Target {
                    host_id: self.cfg.host_id.clone(),
                    session_id: s.rec.name().to_owned(),
                    template_id: s.rec.template_id.clone(),
                    container: c.name.to_string(),
                    socket: s.rec.instance.vsock_path.clone(),
                    generation: s.rec.generation(),
                })
            })
            .collect()
    }

    fn sessions(&self) -> MutexGuard<'_, Sessions> {
        self.sessions.lock().expect("the session table's holders don't panic")
    }

    /// Hands a pooled guest of the template to the caller.
    pub async fn claim(&self, c: Claim) -> Result<Info, Error> {
        let span = tracing::info_span!(
            "birdfeeder.session.claim",
            birdfeeder.template.id = c.template_id,
            birdfeeder.operation.outcome = Empty,
            otel.status_code = Empty,
            otel.status_description = Empty
        );
        let start = Instant::now();
        let template_id = c.template_id.clone();
        let result = self.claim_once(c).instrument(span.clone()).await;
        let outcome = match &result {
            Ok(Claimed::Replayed(_)) => "replayed",
            Ok(Claimed::Fresh(_)) => "pooled",
            Err(Error::UnknownTemplate) => "unknown_template",
            Err(Error::PoolEmpty) => "pool_empty",
            Err(Error::KeyReused | Error::KeyDeleted) => "key_conflict",
            Err(err) => {
                span.record("otel.status_code", "error");
                span.record("otel.status_description", format!("{err:#}"));
                "error"
            }
        };
        span.record("birdfeeder.operation.outcome", outcome);
        self.metrics.claim_duration.record(
            start.elapsed().as_secs_f64(),
            &[KeyValue::new("birdfeeder.operation.outcome", outcome), KeyValue::new("birdfeeder.template.id", template_id)],
        );
        result.map(|(Claimed::Fresh(info) | Claimed::Replayed(info))| info)
    }

    /// Claims a pooled guest, unless the claim's key already claimed one. Then it returns that one instead.
    async fn claim_once(&self, c: Claim) -> Result<Claimed, Error> {
        let Some(key) = &c.key else { return self.claim_pooled(c).await.map(Claimed::Fresh) };
        let _turn = self.keyed.lock().await;
        {
            let sessions = self.sessions();
            if let Some(s) = sessions.keyed(&key.key) {
                let same = s.rec.claim_key.as_ref().is_some_and(|k| k.digest == key.digest);
                return if same { Ok(Claimed::Replayed(self.info(s))) } else { Err(Error::KeyReused) };
            }
            if let Some(r) = sessions.released.get(&key.key) {
                return Err(if r.digest == key.digest { Error::KeyDeleted } else { Error::KeyReused });
            }
        }
        self.claim_pooled(c).await.map(Claimed::Fresh)
    }

    async fn claim_pooled(&self, c: Claim) -> Result<Info, Error> {
        if self.cfg.template(&c.template_id).is_none() {
            return Err(Error::UnknownTemplate);
        }
        let (id, saved) = {
            let mut sessions = self.sessions();
            let pooled = sessions.by_name.values_mut().find(|s| s.rec.state == State::Pooled && s.rec.template_id == c.template_id);
            let s = pooled.ok_or(Error::PoolEmpty)?;
            s.rec.state = State::Claimed;
            s.rec.labels = c.labels;
            s.rec.claim_key = c.key;
            s.rec.egress = c.egress;
            s.rec.expires_at = c.idle_timeout.map(|t| SystemTime::now() + t);
            (s.id.clone(), self.store.stage(&s.rec))
        };
        // don't hand out a claim until it's on disk, or a restart would put the guest back in the pool
        if let Err(err) = step(Stage::Persist, saved.write()).await {
            self.abandon_claim(&id).await;
            return Err(err.into());
        }
        if let Err(err) = traced(step_span("apply_network"), self.apply_net()).await {
            // the guest can't serve its claim. The reaper retires it.
            self.abandon_claim(&id).await;
            return Err(err.into());
        }
        let sessions = self.sessions();
        let s = sessions.get(&id).ok_or(Error::NotFound)?;
        Ok(self.info(s))
    }

    /// Marks the session stopping, and stages the change for the caller to write once the session table's unlocked.
    fn quarantine(&self, s: &mut Session) -> Pending {
        s.rec.state = State::Stopping;
        self.store.stage(&s.rec)
    }

    /// Quarantines a failed claim and frees its key. No caller holds the session, so a retry can claim a different one.
    async fn abandon_claim(&self, id: &SessionRef) {
        let stopping = self.sessions().get_mut(id).map(|s| {
            s.rec.claim_key = None;
            self.quarantine(s)
        });
        let Some(stopping) = stopping else { return };
        persist_logged(stopping, &id.name, "persist stopping state").await;
    }

    pub fn get(&self, name: &str) -> Result<Info, Error> {
        let sessions = self.sessions();
        sessions.by_name.get(name).filter(|s| s.recorded).map(|s| self.info(s)).ok_or(Error::NotFound)
    }

    /// The session `key` claimed, once its claim (or one still in flight) finishes.
    pub async fn get_keyed(&self, key: &str) -> Result<Keyed, Error> {
        let _turn = self.keyed.lock().await;
        let sessions = self.sessions();
        if let Some(s) = sessions.keyed(key) {
            return Ok(Keyed::Live(self.info(s)));
        }
        sessions.released.get(key).cloned().map(Keyed::Deleted).ok_or(Error::NotFound)
    }

    /// Keeps a deleted session's key, and stages the change for the caller to write before it removes the record.
    fn release_key(&self, sessions: &mut Sessions, rec: &Record) -> Option<Pending> {
        let key = rec.claim_key.as_ref()?;
        let released = Released {
            name: rec.name().to_owned(),
            generation: rec.generation(),
            template_id: rec.template_id.clone(),
            labels: rec.labels.clone(),
            digest: key.digest.clone(),
            deleted_at: SystemTime::now(),
        };
        sessions.released.insert(key.key.clone(), released);
        Some(self.store.stage_keys(&sessions.released))
    }

    /// Every session carrying all of `labels`, by name.
    pub fn list(&self, labels: &BTreeMap<String, String>) -> Vec<Info> {
        let sessions = self.sessions();
        let matching = sessions.by_name.values().filter(|s| s.recorded && labels.iter().all(|(k, v)| s.rec.labels.get(k) == Some(v)));
        matching.map(|s| self.info(s)).collect()
    }

    fn info(&self, s: &Session) -> Info {
        let endpoints =
            s.rec.endpoints.iter().map(|(name, e)| (name.clone(), SocketAddrV4::new(self.endpoint_ip, e.host_port).to_string())).collect();
        Info {
            name: s.rec.name().to_owned(),
            endpoints,
            template_id: s.rec.template_id.clone(),
            generation: s.rec.generation(),
            state: s.rec.state,
            host_id: self.cfg.host_id.clone(),
            labels: s.rec.labels.clone(),
        }
    }

    /// Moves a claim's expiry. `None` keeps it until it's deleted.
    pub async fn set_expiry(&self, name: &str, generation: u64, expires_at: Option<SystemTime>) -> Result<(), Error> {
        let (id, old, saved) = {
            let mut sessions = self.sessions();
            let s = fenced(&mut sessions, name, generation)?;
            (s.id.clone(), std::mem::replace(&mut s.rec.expires_at, expires_at), self.store.stage(&s.rec))
        };
        if let Err(err) = saved.write().await {
            // put the expiry back to what's on disk, unless another change has moved it since
            if let Some(s) = self.sessions().get_mut(&id).filter(|s| s.rec.expires_at == expires_at) {
                s.rec.expires_at = old;
            }
            return Err(err.into());
        }
        Ok(())
    }

    pub fn status(&self) -> Status {
        let sessions = self.sessions();
        let reserved = sessions.reserved();
        Status {
            capacity: self.capacity,
            running: sessions.by_name.len() as u32,
            pools: self.pool_fills(&sessions),
            max_vcpus: self.cfg.max_vcpus,
            reserved_vcpus: reserved.vcpus,
            max_memory_mib: self.cfg.max_memory_mib,
            reserved_memory_mib: reserved.memory_mib,
        }
    }

    fn pool_fills(&self, sessions: &Sessions) -> Vec<PoolFill> {
        self.pools
            .iter()
            .map(|pool| PoolFill {
                template_id: pool.template.template_id.clone(),
                ready: sessions
                    .by_name
                    .values()
                    .filter(|s| s.rec.state == State::Pooled && s.rec.template_id == pool.template.template_id)
                    .count() as u32,
                target: pool.template.pool_target,
                fingerprint: pool.fingerprint.clone(),
            })
            .collect()
    }

    /// Tears the session down, canceling its boot first if it's still booting.
    pub async fn delete(&self, name: &str, generation: u64) -> Result<(), Error> {
        let (id, boot, stopping) = {
            let mut sessions = self.sessions();
            let s = fenced(&mut sessions, name, generation)?;
            let (boot, stopping) = match s.rec.state {
                State::Stopping if s.booting() => {
                    return Err(Error::Busy);
                }
                State::Stopping => (None, None),
                state => (s.boot.clone().filter(|_| state == State::Booting), Some(self.quarantine(s))),
            };
            (s.id.clone(), boot, stopping)
        };
        if let Some(stopping) = stopping {
            persist_logged(stopping, name, "persist stopping state").await;
        }
        if let Some(boot) = boot {
            boot.cancel.cancel();
            boot.done.cancelled().await;
        }
        Ok(self.destroy(&id).await?)
    }

    /// Kills the vmm and removes the session's network, disk and record. Its filtering and reservations stick around
    /// until all of that works. If anything fails, the session stays stopping and the reaper retries.
    async fn destroy(&self, id: &SessionRef) -> Result<()> {
        let span = tracing::info_span!(
            "birdfeeder.session.destroy",
            birdfeeder.session.id = id.name,
            otel.status_code = Empty,
            otel.status_description = Empty
        );
        traced(span, self.destroy_steps(id)).await
    }

    async fn destroy_steps(&self, id: &SessionRef) -> Result<()> {
        let name = id.name.as_str();
        let teardown = {
            let sessions = self.sessions();
            sessions.get(id).map(|s| &s.teardown).or_else(|| sessions.leaving.get(name)).map(Arc::clone)
        };
        let Some(teardown) = teardown else { return Ok(()) };
        let _turn = teardown.lock().await;
        let (rec, slot, stopping) = {
            let mut sessions = self.sessions();
            let Some(s) = sessions.get_mut(id) else { return Ok(()) };
            let stopping = (s.rec.state != State::Stopping).then(|| self.quarantine(s));
            (s.rec.clone(), s.slot, stopping)
        };
        if let Some(stopping) = stopping {
            persist_logged(stopping, name, "persist stopping state").await;
        }
        if let Err(err) = self.teardown(&rec, slot).await {
            self.teardown_failed(vmm::stage_of(&err));
            return Err(err.context(format!("teardown {name}")));
        }
        // staged along with taking the session out of the table, so no later change can bring its record back
        let (removed, released, gone) = {
            let mut sessions = self.sessions();
            let removed = sessions.by_name.remove(name).context("a torn-down session vanished")?;
            sessions.leaving.insert(name.to_owned(), Arc::clone(&removed.teardown));
            let released = self.release_key(&mut sessions, &removed.rec);
            (removed, released, self.store.stage_remove(name))
        };
        // keep the key before the record goes, so a crash in between can't free it
        let written = async {
            if let Some(released) = released {
                released.write().await?;
            }
            gone.write().await
        };
        if let Err(err) = written.await {
            let mut sessions = self.sessions();
            sessions.leaving.remove(name);
            sessions.by_name.insert(name.to_owned(), removed);
            return Err(err);
        }
        if let Err(err) = self.apply_net().await {
            let saved = {
                let mut sessions = self.sessions();
                let saved = self.store.stage(&removed.rec);
                sessions.leaving.remove(name);
                sessions.by_name.insert(name.to_owned(), removed);
                saved
            };
            // two failures can't share one error chain, so the caller gets the one that failed the teardown.
            persist_logged(saved, name, "restore record after failed network apply").await;
            return Err(err);
        }
        let mut sessions = self.sessions();
        sessions.leaving.remove(name);
        sessions.slots.remove(&slot.index);
        Ok(())
    }

    /// Kill and network failures block reusing the slot. The rest is generation-specific and later sweeps retry it.
    async fn teardown(&self, rec: &Record, slot: Slot) -> Result<()> {
        self.driver.kill(&rec.instance).await.map_err(|err| vmm::staged(Stage::KillVmm, err))?;
        self.host.delete_session(slot).await.map_err(|err| vmm::staged(Stage::DeleteTap, err))?;
        if let Err(failures) = self.driver.cleanup(&rec.instance).await {
            self.teardown_errors("cleanup vmm", &failures);
        }
        let run_dir = self.run_dir(&rec.instance);
        if let Err(err) = tokio::fs::remove_dir_all(&run_dir).await
            && err.kind() != std::io::ErrorKind::NotFound
        {
            tracing::error!(name = rec.name(), error = %err, "remove run dir");
            self.teardown_failed(Some(Stage::RunDir));
        }
        Ok(())
    }

    fn teardown_failed(&self, stage: Option<Stage>) {
        self.metrics.teardown_failures.add(1, &[KeyValue::new("birdfeeder.operation.stage", stage_label(stage))]);
    }

    fn teardown_errors(&self, what: &str, failures: &vmm::Failures) {
        for f in &failures.0 {
            tracing::error!(stage = f.stage.as_str(), error = format!("{:#}", f.source), "{what}");
            self.teardown_failed(Some(f.stage));
        }
    }

    fn run_dir(&self, inst: &vmm::Instance) -> PathBuf {
        self.cfg.run_dir.join(format!("{}.{}", inst.name, inst.generation))
    }

    fn console_path(&self, rec: &Record) -> PathBuf {
        self.run_dir(&rec.instance).join("console.log")
    }

    /// Applies the host ruleset for the sessions as they are when this call's turn comes.
    async fn apply_net(&self) -> Result<()> {
        let _turn = self.net.lock().await;
        let ruleset = self.ruleset(&self.sessions());
        self.host.apply_ruleset(ruleset).await
    }

    fn ruleset(&self, sessions: &Sessions) -> String {
        let views: Vec<_> = sessions
            .by_name
            .values()
            .map(|s| guestnet::Session {
                name: s.rec.name(),
                slot: s.slot,
                conn_limit: s.rec.conn_limit,
                claim: (s.rec.state == State::Claimed).then_some(guestnet::Claim {
                    endpoints: &s.rec.endpoints,
                    egress: s.rec.egress.as_ref(),
                    fqdn_addrs: &s.rec.fqdn_addrs,
                }),
            })
            .collect();
        let host = guestnet::Host { iface: &self.iface, subnet: self.cfg.subnet, dns_port: self.dns_port, slots: self.capacity };
        guestnet::host_ruleset(&host, &views, SystemTime::now())
    }

    fn spawn_loops(self: &Arc<Self>) {
        let reap = self.cfg.reap_interval;
        let maintained = Arc::clone(self);
        self.spawn(async move {
            let mut ticks = ticker(reap);
            // start already ran the round this first tick would
            ticks.tick().await;
            loop {
                ticks.tick().await;
                maintained.maintain().await;
            }
        });
        let sampled = Arc::clone(self);
        self.spawn(async move { sampled.sample_loop().await });
    }

    /// Runs `task` until shutdown.
    fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        let stop = self.stop.clone();
        self.tasks.spawn(async move { stop.run_until_cancelled(task).await });
    }

    /// Reaps dead, expired and unclaimed guests, rotates consoles, and refills the pools.
    async fn maintain(self: &Arc<Self>) {
        let now = SystemTime::now();
        let (doomed, consoles, pruned) = {
            let mut sessions = self.sessions();
            let mut doomed = Vec::new();
            let mut consoles = Vec::with_capacity(sessions.by_name.len());
            for s in sessions.by_name.values_mut() {
                consoles.push(self.console_path(&s.rec));
                let reason = match s.rec.state {
                    // the boot task owns it. Its pid isn't set until the vmm starts.
                    State::Booting => None,
                    State::Pooled | State::Claimed if !self.driver.alive(&s.rec.instance) => Some("vmm_died"),
                    State::Pooled => self
                        .cfg
                        .max_unregistered
                        .zip(s.rec.pooled_at)
                        .is_some_and(|(max, pooled)| now.duration_since(pooled).is_ok_and(|age| age > max))
                        .then_some("unclaimed_age_exceeded"),
                    State::Claimed => s.rec.expires_at.is_some_and(|at| now > at).then_some("expired"),
                    State::Stopping => (!s.booting()).then_some("teardown_retry"),
                };
                if let Some(reason) = reason {
                    tracing::info!(name = s.rec.name(), reason, "reaping session");
                    self.metrics.reaps.add(1, &[KeyValue::new("birdfeeder.reap.reason", reason)]);
                    // persisted, so if a reaped guest's teardown fails a restart won't adopt it as claimable
                    let stopping = (s.rec.state != State::Stopping).then(|| self.quarantine(s));
                    doomed.push((s.id.clone(), stopping));
                }
            }
            let retention = self.cfg.claim_key_retention;
            let kept = sessions.released.len();
            sessions.released.retain(|_, r| !now.duration_since(r.deleted_at).is_ok_and(|age| age > retention));
            let pruned = (sessions.released.len() != kept).then(|| self.store.stage_keys(&sessions.released));
            (doomed, consoles, pruned)
        };
        if let Some(pruned) = pruned {
            persist_logged(pruned, "keys.json", "persist pruned idempotency keys").await;
        }
        for (id, stopping) in doomed {
            if let Some(stopping) = stopping {
                persist_logged(stopping, &id.name, "persist stopping state").await;
            }
            if let Err(err) = self.destroy(&id).await {
                tracing::error!(name = id.name, error = format!("{err:#}"), "destroy failed");
            }
        }
        if let Some(max) = self.cfg.console_max_bytes {
            // rotating copies up to a cap's worth per console, so keep it off the runtime.
            let capped = tokio::task::spawn_blocking(move || {
                for path in consoles {
                    if let Err(err) = sysctl::cap_console(&path, max.get()) {
                        tracing::error!(path = %path.display(), error = format!("{err:#}"), "cap console");
                    }
                }
            });
            if let Err(err) = capped.await {
                tracing::error!(error = %err, "cap consoles");
            }
        }
        self.refill();
        self.ensure_conntrack(false);
    }

    /// Boots guests until each pool (counting ones still booting) hits its target or the host runs out of budget. A
    /// pool whose last boot failed waits out its backoff first.
    fn refill(self: &Arc<Self>) {
        let now = Instant::now();
        let ready: Vec<_> = self.pools.iter().filter(|p| !p.backoff.lock().expect("never poisoned").blocks(now)).collect();
        let mut boots = Vec::new();
        {
            let mut sessions = self.sessions();
            for pool in ready {
                let t = &pool.template;
                let have = sessions
                    .by_name
                    .values()
                    .filter(|s| matches!(s.rec.state, State::Booting | State::Pooled) && s.rec.template_id == t.template_id)
                    .count();
                for _ in have..t.pool_target as usize {
                    match self.allocate(&mut sessions, t) {
                        Ok(boot) => boots.push((Arc::clone(pool), boot)),
                        Err(err) => {
                            tracing::warn!(template = t.template_id, error = format!("{err:#}"), "pool refill blocked");
                            break;
                        }
                    }
                }
            }
        }
        for (pool, (id, handle)) in boots {
            let manager = Arc::clone(self);
            self.tasks.spawn(async move { manager.boot_pooled(&pool, id, handle).await });
        }
    }

    /// Reserves a slot and the template's resources for a new booting session.
    fn allocate(&self, sessions: &mut Sessions, t: &Template) -> Result<(SessionRef, BootHandle), Error> {
        let reserved = sessions.reserved();
        if reserved.vcpus + t.vcpus.get() > self.cfg.max_vcpus || reserved.memory_mib + t.mem_mib > self.cfg.max_memory_mib {
            return Err(Error::SlotsExhausted);
        }
        let index = (0..self.capacity).find(|i| !sessions.slots.contains(i)).ok_or(Error::SlotsExhausted)?;
        let slot = Slot::new(self.cfg.subnet, index).context("slot outside the subnet")?;
        let name = format!("{}-{index}", self.name_prefix);
        let generation = sessions.gens.get(&name).map_or(NonZeroU64::MIN, |g| NonZeroU64::MIN.saturating_add(*g));
        sessions.gens.insert(name.clone(), generation.get());

        // the driver fills in the paths it owns
        let mut instance = vmm::Instance {
            name: name.clone(),
            generation: generation.get(),
            slot: index,
            disk: self.store.disk_path(&name, generation.get()),
            ..vmm::Instance::default()
        };
        let mac = guestnet::GUEST_MAC.to_owned();
        let guest = self.guest(&instance, &mac, t, &slot);
        self.driver.allocate(&mut instance, &guest);
        let rec = Record {
            instance,
            state: State::Booting,
            template_id: t.template_id.clone(),
            vcpus: t.vcpus.get(),
            mem_mib: t.mem_mib,
            conn_limit: t.conn_limit,
            netns: slot.netns(),
            tap: slot.tap(),
            mac,
            guest_ip: slot.guest,
            gateway_ip: slot.gateway,
            endpoints: self.endpoints(t, index),
            manifest: t.manifest.clone(),
            version: 1,
            labels: BTreeMap::new(),
            claim_key: None,
            egress: None,
            fqdn_addrs: BTreeMap::new(),
            created_at: SystemTime::now(),
            pooled_at: None,
            expires_at: None,
        };
        let handle = BootHandle::new(&self.stop);
        sessions.slots.insert(index);
        let id = SessionRef { name: name.clone(), generation };
        // the boot records it before anything uses its generation
        let session = Session { id: id.clone(), rec, slot, boot: Some(handle.clone()), teardown: Arc::default(), recorded: false };
        sessions.by_name.insert(name, session);
        Ok((id, handle))
    }

    /// Each endpoint's host port, from the slot's block in name order.
    fn endpoints(&self, t: &Template, slot: u32) -> BTreeMap<String, Endpoint> {
        let base = u32::from(self.cfg.dnat_port_start) + slot * ENDPOINT_BLOCK;
        t.endpoints()
            .zip(base..)
            .map(|((name, guest_port), host_port)| {
                (name.clone(), Endpoint { host_port: u16::try_from(host_port).expect("validation bounds the port range"), guest_port })
            })
            .collect()
    }

    fn guest(&self, inst: &vmm::Instance, mac: &str, t: &Template, slot: &Slot) -> vmm::Guest {
        vmm::Guest {
            vcpus: t.vcpus,
            mem_mib: t.mem_mib,
            tap: guestnet::GUEST_TAP.to_owned(),
            netns: Some(slot.netns_path()),
            mac: mac.to_owned(),
            run_dir: self.run_dir(inst),
            base_disk: t.base_disk.clone(),
            blobs: t.blobs.clone(),
        }
    }

    fn register_gauges(self: &Arc<Self>, meter: &Meter) {
        let weak = Arc::downgrade(self);
        let observe = move |f: &dyn Fn(&Self)| {
            if let Some(m) = Weak::upgrade(&weak) {
                f(&m);
            }
        };
        let (by_state, targets, deficits) = (observe.clone(), observe.clone(), observe.clone());
        meter
            .u64_observable_gauge("birdfeeder.roost.sessions")
            .with_description("sessions by state")
            .with_callback(move |o| {
                by_state(&|m| {
                    let sessions = m.sessions();
                    // report every state, so an empty one shows zero.
                    for state in State::ALL {
                        let n = sessions.by_name.values().filter(|s| s.rec.state == state).count();
                        o.observe(n as u64, &[KeyValue::new("birdfeeder.session.state", state.as_str())]);
                    }
                });
            })
            .build();
        meter
            .u64_observable_gauge("birdfeeder.roost.pool.target")
            .with_description("configured pool target per image and size")
            .with_callback(move |o| {
                targets(&|m| {
                    for fill in m.pool_fills(&m.sessions()) {
                        o.observe(u64::from(fill.target), &[KeyValue::new("birdfeeder.template.id", fill.template_id)]);
                    }
                });
            })
            .build();
        meter
            .i64_observable_gauge("birdfeeder.roost.pool.deficit")
            .with_description("pool target minus pooled (claimable) sessions; booting ones still count as missing")
            .with_callback(move |o| {
                deficits(&|m| {
                    for fill in m.pool_fills(&m.sessions()) {
                        o.observe(
                            i64::from(fill.target) - i64::from(fill.ready),
                            &[KeyValue::new("birdfeeder.template.id", fill.template_id)],
                        );
                    }
                });
            })
            .build();
        if self.cfg.hugepages_2m {
            for (name, description, path) in [
                ("birdfeeder.roost.hugepages.total", "reserved 2M hugepages on the host", sysctl::NR_HUGEPAGES),
                ("birdfeeder.roost.hugepages.free", "free 2M hugepages on the host", sysctl::FREE_HUGEPAGES),
            ] {
                meter
                    .u64_observable_gauge(name)
                    .with_description(description)
                    .with_callback(move |o| {
                        if let Ok(n) = sysctl::read_u64(Path::new(path)) {
                            o.observe(n, &[]);
                        }
                    })
                    .build();
            }
        }
    }
}

/// The session `name` if `generation`, as a caller sent it, is its current one.
fn fenced<'a>(sessions: &'a mut Sessions, name: &str, generation: u64) -> Result<&'a mut Session, Error> {
    let s = sessions.by_name.get_mut(name).filter(|s| s.recorded).ok_or(Error::NotFound)?;
    if s.id.generation.get() != generation {
        return Err(Error::GenerationMismatch);
    }
    Ok(s)
}

/// Locks every state directory so two roosts can't share one.
fn lock_state(cfg: &Config) -> Result<Vec<Flock<File>>> {
    let mut dirs = vec![cfg.state_dir.as_path()];
    if cfg.session_state_dir() != cfg.state_dir {
        dirs.push(cfg.session_state_dir());
    }
    dirs.into_iter()
        .map(|dir| {
            let path = dir.join("roost.lock");
            let file = OpenOptions::new().create(true).truncate(false).read(true).write(true).mode(0o600).open(&path);
            let file = file.with_context(|| format!("open state lock {}", path.display()))?;
            Flock::lock(file, FlockArg::LockExclusiveNonblock)
                .map_err(|(_, errno)| errno)
                .with_context(|| format!("another agent owns the state directory {}", dir.display()))
        })
        .collect()
}

/// The host id as a name prefix that nftables and the session table accept. Hashed if sanitizing changed or truncated
/// it, so different hosts still get different prefixes.
fn name_prefix(host_id: &str) -> String {
    let sanitized: String =
        host_id.chars().flat_map(char::to_lowercase).map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() { c } else { '-' }).collect();
    let trimmed = sanitized.trim_matches('-');
    let mut prefix = if trimmed.is_empty() { "roost".to_owned() } else { trimmed.to_owned() };
    if prefix.len() > MAX_NAME_PREFIX || prefix != host_id {
        let hash = host_id.bytes().fold(0x811c_9dc5_u32, |h, b| (h ^ u32::from(b)).wrapping_mul(0x0100_0193));
        prefix.truncate(MAX_NAME_PREFIX - HOST_HASH_SUFFIX);
        prefix = format!("{prefix}-{hash:08x}");
    }
    prefix
}

/// Ticks now, then every `period`. A tick that runs long pushes back the next one.
fn ticker(period: Duration) -> tokio::time::Interval {
    let mut ticks = tokio::time::interval(period);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticks
}

fn step_span(name: &'static str) -> Span {
    tracing::info_span!("step", otel.name = name, otel.status_code = Empty, otel.status_description = Empty)
}

/// Runs `fut` in `span`, marking the span failed if it fails.
async fn traced<T>(span: Span, fut: impl Future<Output = Result<T>>) -> Result<T> {
    let result = fut.instrument(span.clone()).await;
    if let Err(err) = &result {
        span.record("otel.status_code", "error");
        span.record("otel.status_description", format!("{err:#}"));
    }
    result
}

/// A boot or teardown step: a span of its own, and its stage on any error.
async fn step<T>(stage: Stage, fut: impl Future<Output = Result<T>>) -> Result<T> {
    traced(step_span(stage.as_str()), fut).await.map_err(|err| vmm::staged(stage, err).into())
}

fn stage_label(stage: Option<Stage>) -> &'static str {
    stage.map_or("unknown", Stage::as_str)
}

/// Writes a change the caller can't do anything about if it fails. A later change to the same file, or the reaper,
/// retries it.
async fn persist_logged(change: Pending, name: &str, what: &'static str) {
    if let Err(err) = change.write().await {
        tracing::error!(name, error = format!("{err:#}"), "{what}");
    }
}
