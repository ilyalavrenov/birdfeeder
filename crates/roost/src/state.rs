//! What roost keeps on disk, fsynced on every change so a restarted roost can adopt its live guests. That's one record
//! per session, the last generation of each session name, deleted sessions' idempotency keys, and each template's
//! pinned identity.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::{Context as _, Result, bail};
use guestapi::workload::Manifest;
use guestnet::dnsgate::FqdnPattern;
use guestnet::{Egress, Endpoint};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::config::{Sha256Hex, Template};

const FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Owned by its boot task until the guest is ready.
    Booting,
    Pooled,
    Claimed,
    /// Being torn down. The reaper keeps retrying until teardown works.
    Stopping,
}

impl State {
    pub const ALL: [Self; 4] = [Self::Booting, Self::Pooled, Self::Claimed, Self::Stopping];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Booting => "booting",
            Self::Pooled => "pooled",
            Self::Claimed => "claimed",
            Self::Stopping => "stopping",
        }
    }
}

/// A session as its state file holds it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    #[serde(flatten)]
    pub instance: vmm::Instance,
    pub state: State,
    pub template_id: String,
    pub vcpus: u32,
    pub mem_mib: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conn_limit: Option<NonZeroU32>,
    /// The slot's names and addresses. If the subnet or naming changed, recovery fails instead of misrouting.
    #[serde(default)]
    pub netns: String,
    pub tap: String,
    pub mac: String,
    /// The guest's address after the namespace translates it.
    pub guest_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub endpoints: BTreeMap<String, Endpoint>,
    pub manifest: Manifest,
    pub version: u32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Written in the same fsync as the claim, so a restart can't lose a claim it already answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_key: Option<ClaimKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<Egress>,
    /// Absolute expiries, so rebuilding the ruleset doesn't reset the DNS answers' TTLs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty", with = "fqdn_addrs")]
    pub fqdn_addrs: BTreeMap<Ipv4Addr, SystemTime>,
    #[serde(with = "rfc3339")]
    pub created_at: SystemTime,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "rfc3339::option")]
    pub pooled_at: Option<SystemTime>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "rfc3339::option")]
    pub expires_at: Option<SystemTime>,
}

/// An idempotency key plus a digest of the claim request it came with. That's how we tell a retry from a reuse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimKey {
    pub key: String,
    pub digest: String,
}

/// What a deleted session's idempotency key still answers with, until its retention runs out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Released {
    pub name: String,
    pub generation: u64,
    pub template_id: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    pub digest: String,
    #[serde(with = "rfc3339")]
    pub deleted_at: SystemTime,
}

impl Record {
    pub fn name(&self) -> &str {
        &self.instance.name
    }

    pub fn generation(&self) -> u64 {
        self.instance.generation
    }

    /// Only claimed sessions publish endpoints or get egress, so only their FQDN allowlist resolves.
    pub fn fqdn_allowlist(&self) -> Option<&[FqdnPattern]> {
        let egress = self.egress.as_ref().filter(|_| self.state == State::Claimed)?;
        Some(&egress.fqdn_allowlist).filter(|a| !a.is_empty()).map(Vec::as_slice)
    }
}

/// RFC 3339 so the state files stay readable. roost writes UTC but reads any offset.
mod rfc3339 {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    use super::{Deserialize, Deserializer, Serializer, SystemTime};

    pub fn format(t: SystemTime) -> String {
        // panics past year 9999, but roost_api::validate_expiry keeps those out of every stored time.
        OffsetDateTime::from(t).format(&Rfc3339).expect("roost stores only times RFC 3339 can hold")
    }

    pub fn parse<E: serde::de::Error>(s: &str) -> Result<SystemTime, E> {
        OffsetDateTime::parse(s, &Rfc3339).map(SystemTime::from).map_err(E::custom)
    }

    pub fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format(*t))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
        parse(&String::deserialize(d)?)
    }

    pub mod option {
        use super::{Deserialize, Deserializer, Serializer, SystemTime, parse};

        #[expect(clippy::ref_option, reason = "serde's with = hands the field by reference")]
        pub fn serialize<S: Serializer>(t: &Option<SystemTime>, s: S) -> Result<S::Ok, S::Error> {
            match t {
                Some(t) => super::serialize(t, s),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SystemTime>, D::Error> {
            Option::<String>::deserialize(d)?.map(|s| parse(&s)).transpose()
        }
    }
}

mod fqdn_addrs {
    use super::{BTreeMap, Deserialize, Deserializer, Ipv4Addr, Serializer, SystemTime, rfc3339};

    pub fn serialize<S: Serializer>(addrs: &BTreeMap<Ipv4Addr, SystemTime>, s: S) -> Result<S::Ok, S::Error> {
        s.collect_map(addrs.iter().map(|(ip, t)| (ip, rfc3339::format(*t))))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<BTreeMap<Ipv4Addr, SystemTime>, D::Error> {
        BTreeMap::<Ipv4Addr, String>::deserialize(d)?.into_iter().map(|(ip, t)| Ok((ip, rfc3339::parse(&t)?))).collect()
    }
}

/// Keeps fsynced records under `dir` and guests' scratch disks under `disk_root`.
///
/// Changes get staged while the session table is locked, which puts them in order with the file's other changes.
/// They're written after the lock drops, so an fsync never holds up the table.
pub struct Store {
    dir: PathBuf,
    disk_root: PathBuf,
    /// One per state file this process has written. The slots bound session names, so this can't grow forever.
    journals: Mutex<HashMap<PathBuf, Arc<Journal>>>,
}

/// A state file's newest staged change, and how far its writes have got.
struct Journal {
    staged: Mutex<(u64, Change)>,
    /// The newest change on disk. Held during a write so writes to the same file take turns.
    written: tokio::sync::Mutex<u64>,
}

#[derive(Clone)]
enum Change {
    Write(Arc<[u8]>),
    Remove,
}

impl Change {
    fn apply(&self, path: &Path) -> Result<()> {
        match self {
            Self::Write(data) => write_state(path, data),
            Self::Remove => match fs::remove_file(path) {
                Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err).with_context(|| format!("remove {}", path.display())),
                _ => Ok(()),
            },
        }
    }
}

/// A staged change, durable once written.
#[must_use = "a staged change lands only once it's written"]
pub struct Pending {
    path: PathBuf,
    journal: Arc<Journal>,
    seq: u64,
}

impl Pending {
    /// Makes this change durable, or a newer change to the same file that includes it. The write finishes even if the
    /// caller stops waiting, so a dropped request can't leave its change unwritten.
    pub fn write(self) -> impl Future<Output = Result<()>> {
        let task = tokio::spawn(self.land());
        async move { task.await.context("state writer panicked")? }
    }

    async fn land(self) -> Result<()> {
        let mut written = self.journal.written.lock().await;
        if *written >= self.seq {
            return Ok(());
        }
        // the newest staged change already includes this one, so a burst of changes costs one write
        let (seq, change) = self.journal.staged.lock().expect("journal holders don't panic").clone();
        let path = self.path;
        tokio::task::spawn_blocking(move || change.apply(&path)).await.context("state writer panicked")??;
        *written = seq;
        Ok(())
    }
}

impl Store {
    pub fn new(dir: &Path, disk_root: &Path) -> Result<Self> {
        for d in [dir.join("sessions"), disk_root.join("disks")] {
            fs::create_dir_all(&d).with_context(|| format!("mkdir {}", d.display()))?;
        }
        Ok(Self { dir: dir.to_owned(), disk_root: disk_root.to_owned(), journals: Mutex::default() })
    }

    fn session_path(&self, name: &str) -> PathBuf {
        self.dir.join("sessions").join(format!("{name}.json"))
    }

    pub fn disk_path(&self, name: &str, generation: u64) -> PathBuf {
        self.disk_root.join("disks").join(format!("{name}.{generation}.ext4"))
    }

    /// Stages `r` as its session's state. Call it with the session table locked so changes stage in the order they
    /// happened.
    pub fn stage(&self, r: &Record) -> Pending {
        let data = serde_json::to_vec_pretty(r).expect("records encode");
        self.stage_change(self.session_path(r.name()), Change::Write(data.into()))
    }

    pub fn stage_remove(&self, name: &str) -> Pending {
        self.stage_change(self.session_path(name), Change::Remove)
    }

    fn stage_change(&self, path: PathBuf, change: Change) -> Pending {
        let journal = Arc::clone(
            self.journals
                .lock()
                .expect("journal holders don't panic")
                .entry(path.clone())
                .or_insert_with(|| Arc::new(Journal { staged: Mutex::new((0, Change::Remove)), written: tokio::sync::Mutex::new(0) })),
        );
        let seq = {
            let mut staged = journal.staged.lock().expect("journal holders don't panic");
            *staged = (staged.0 + 1, change);
            staged.0
        };
        Pending { path, journal, seq }
    }

    /// Writes `r` and `gens` in one go. For tests setting up state while nothing else is writing.
    #[cfg(test)]
    pub fn save_now(&self, r: &Record, gens: &BTreeMap<String, u64>) {
        write_state(&self.gens_path(), &serde_json::to_vec(gens).unwrap()).unwrap();
        write_state(&self.session_path(r.name()), &serde_json::to_vec_pretty(r).unwrap()).unwrap();
    }

    pub fn load(&self) -> Result<Vec<Record>> {
        let dir = self.dir.join("sessions");
        let mut records = Vec::new();
        for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
            let path = entry?.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let data = fs::read(&path).with_context(|| format!("read session state {}", path.display()))?;
            records.push(serde_json::from_slice(&data).with_context(|| format!("parse session state {}", path.display()))?);
        }
        Ok(records)
    }

    fn gens_path(&self) -> PathBuf {
        self.dir.join("gens.json")
    }

    /// The last generation of each session name. Corrupt state is an error, never rebuilt, since reusing a generation
    /// would break fencing.
    pub fn load_gens(&self) -> Result<BTreeMap<String, u64>> {
        match fs::read(self.gens_path()) {
            Ok(data) => serde_json::from_slice(&data).context("parse gens"),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(err) => Err(err).context("read gens"),
        }
    }

    pub fn stage_gens(&self, gens: &BTreeMap<String, u64>) -> Pending {
        self.stage_change(self.gens_path(), Change::Write(serde_json::to_vec(gens).expect("generations encode").into()))
    }

    fn keys_path(&self) -> PathBuf {
        self.dir.join("keys.json")
    }

    /// Deleted sessions' idempotency keys. Corrupt state is an error, since dropping a key would let a retry claim
    /// again.
    pub fn load_keys(&self) -> Result<BTreeMap<String, Released>> {
        match fs::read(self.keys_path()) {
            Ok(data) => serde_json::from_slice(&data).context("parse idempotency keys"),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(err) => Err(err).context("read idempotency keys"),
        }
    }

    pub fn stage_keys(&self, keys: &BTreeMap<String, Released>) -> Pending {
        let data = serde_json::to_vec_pretty(keys).expect("keys encode");
        self.stage_change(self.keys_path(), Change::Write(data.into()))
    }

    /// Records each template's identity. Refuses a template whose identity changed under the same id, because its live
    /// and snapshotted guests were built from the old one.
    pub fn pin_templates(&self, templates: &[Arc<Template>], kernel_sha256: &Sha256Hex, boot_args: &str) -> Result<()> {
        let path = self.dir.join("templates.json");
        let mut pinned: BTreeMap<String, String> = match fs::read(&path) {
            Ok(data) => serde_json::from_slice(&data).context("read template identities")?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(err) => return Err(err).context("read template identities"),
        };
        for t in templates {
            let fingerprint = t.fingerprint(kernel_sha256, boot_args);
            if pinned.get(&t.template_id).is_some_and(|old| *old != fingerprint) {
                bail!("template {:?} changed; use a new template_id", t.template_id);
            }
            pinned.insert(t.template_id.clone(), fingerprint);
        }
        write_state(&path, &serde_json::to_vec(&pinned)?)
    }
}

/// Durably replaces `path` with `data`: write a temp file, fsync it, rename it over, then fsync the directory.
fn write_state(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    let written = (|| {
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(FILE_MODE).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if let Err(err) = written {
        let _ = fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("write {}", path.display()));
    }
    let dir = path.parent().context("state file has no directory")?;
    File::open(dir).and_then(|d| d.sync_all()).with_context(|| format!("sync {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn reads_a_session_record() {
        let record = record();
        assert_eq!((record.name(), record.generation(), record.instance.pid), ("smoke-1", 3, Some(42)));
        assert_eq!((record.state, record.conn_limit), (State::Pooled, NonZeroU32::new(64)));
        assert_eq!(record.guest_ip, Ipv4Addr::new(172, 20, 0, 6));
        assert_eq!(record.endpoints["http"], Endpoint { host_port: 31016, guest_port: 8080 });
        assert_eq!(record.manifest.containers[0].args[2], "a && b <c>");
        assert_eq!(record.egress.as_ref().unwrap().fqdn_allowlist, [FqdnPattern::Exact("example.com".to_owned())]);
        let at = |secs: u64, nanos: u32| SystemTime::UNIX_EPOCH + Duration::new(secs, nanos);
        // 19:00:00.000000005Z and 10:00:00.123456789Z on 2026-11-03.
        assert_eq!(record.fqdn_addrs[&Ipv4Addr::new(93, 184, 216, 34)], at(1_793_732_400, 5));
        assert_eq!(record.created_at, at(1_793_700_000, 123_456_789));
        assert_eq!(record.expires_at, None);

        let again: Record = serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        assert_eq!(again, record);
    }

    #[test]
    fn max_expiry_round_trips() {
        let latest = SystemTime::UNIX_EPOCH + Duration::from_millis(roost_api::MAX_EXPIRES_AT_MS.cast_unsigned());
        let formatted = rfc3339::format(latest);
        assert_eq!(formatted, "9999-12-31T23:59:59.999Z");
        assert_eq!(rfc3339::parse::<serde_json::Error>(&formatted).unwrap(), latest);
    }

    fn store(dir: &Path) -> Store {
        Store::new(&dir.join("records"), &dir.join("state")).unwrap()
    }

    fn record() -> Record {
        serde_json::from_str(include_str!("testdata/session.json")).unwrap()
    }

    #[tokio::test]
    async fn store_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut record = record();
        record.expires_at = Some(SystemTime::now());
        store.stage(&record).write().await.unwrap();
        assert_eq!(store.load().unwrap(), [record.clone()]);
        assert!(dir.path().join("records/sessions/smoke-1.json").exists());
        assert_eq!(store.disk_path("smoke-1", 3), dir.path().join("state/disks/smoke-1.3.ext4"));
        store.stage_remove("smoke-1").write().await.unwrap();
        store.stage_remove("smoke-1").write().await.unwrap();
        assert_eq!(store.load().unwrap(), []);

        assert!(store.load_gens().unwrap().is_empty());
        store.stage_gens(&[("smoke-1".to_owned(), 4)].into()).write().await.unwrap();
        assert_eq!(store.load_gens().unwrap()["smoke-1"], 4);
        fs::write(dir.path().join("records/gens.json"), "{").unwrap();
        assert!(store.load_gens().is_err(), "corrupt generations must not reset");

        assert!(store.load_keys().unwrap().is_empty());
        let released = Released {
            name: "smoke-1".into(),
            generation: 3,
            template_id: "web-v1".into(),
            labels: [("job".into(), "7".into())].into(),
            digest: "abc".into(),
            deleted_at: SystemTime::UNIX_EPOCH + Duration::from_hours(498_250),
        };
        store.stage_keys(&[("k".to_owned(), released.clone())].into()).write().await.unwrap();
        assert_eq!(store.load_keys().unwrap()["k"], released);
        fs::write(dir.path().join("records/keys.json"), "{").unwrap();
        assert!(store.load_keys().is_err(), "corrupt keys must not reset");
    }

    #[tokio::test]
    async fn newest_staged_change_wins() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut record = record();
        let older = store.stage(&record);
        record.state = State::Claimed;
        let newer = store.stage(&record);
        older.write().await.unwrap();
        assert_eq!(store.load().unwrap()[0].state, State::Claimed, "the first write lands the newest change");
        newer.write().await.unwrap();
        assert_eq!(store.load().unwrap()[0].state, State::Claimed);

        let save = store.stage(&record);
        let remove = store.stage_remove(record.name());
        remove.write().await.unwrap();
        save.write().await.unwrap();
        assert_eq!(store.load().unwrap(), [], "a save staged before the removal can't bring the record back");
    }

    #[tokio::test]
    async fn dropped_write_still_lands() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        drop(store.stage(&record()).write());
        let path = dir.path().join("records/sessions/smoke-1.json");
        tokio::time::timeout(Duration::from_secs(5), async {
            while !path.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the abandoned write landed");
    }

    #[tokio::test]
    async fn failed_write_retried_by_next() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let sessions = dir.path().join("records/sessions");
        fs::remove_dir(&sessions).unwrap();
        assert!(store.stage(&record()).write().await.is_err());
        fs::create_dir(&sessions).unwrap();
        let mut record = record();
        record.state = State::Claimed;
        store.stage(&record).write().await.unwrap();
        assert_eq!(store.load().unwrap()[0].state, State::Claimed);
    }
}
