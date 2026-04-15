use std::sync::atomic::Ordering;

use guestnet::dnsgate::Policy as _;
use serde_json::{Value, json};
use tempfile::TempDir;

use super::*;
use crate::testing::{FakeDriver, FakeHost, config_json};

type Test = Manager<FakeDriver, FakeHost>;

struct Harness {
    dir: TempDir,
    cfg: Value,
    m: Arc<Test>,
}

async fn start(cfg: &Value) -> Result<Arc<Test>> {
    let cfg: Config = serde_json::from_value(cfg.clone())?;
    Manager::start(cfg, FakeDriver::default(), FakeHost::default(), &opentelemetry::global::meter("test")).await
}

async fn harness(edit: impl FnOnce(&mut Value)) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config_json(dir.path());
    edit(&mut cfg);
    let m = start(&cfg).await.unwrap();
    Harness { dir, cfg, m }
}

impl Harness {
    /// Stops this roost and starts a new one on the same state, like a restart.
    async fn restart(self, edit: impl FnOnce(&mut Value)) -> Result<Self> {
        let Self { dir, mut cfg, m } = self;
        m.shutdown().await;
        let stopped = Arc::downgrade(&m);
        drop(m);
        while stopped.strong_count() > 0 {
            tokio::task::yield_now().await;
        }
        edit(&mut cfg);
        let m = start(&cfg).await?;
        Ok(Self { dir, cfg, m })
    }
}

/// A pooled session whose vmm is running, as if it booted.
fn seed_pooled(m: &Test) -> SessionRef {
    let mut sessions = m.sessions();
    let (id, boot) = m.allocate(&mut sessions, &m.cfg.templates[0]).unwrap();
    boot.done.cancel();
    let gens = sessions.gens.clone();
    let s = sessions.get_mut(&id).unwrap();
    s.rec.state = State::Pooled;
    s.rec.pooled_at = Some(SystemTime::now());
    s.rec.instance.pid = Some(4242 + s.slot.index);
    s.recorded = true;
    m.store.save_now(&s.rec, &gens);
    id
}

fn session_ref(name: &str, generation: u64) -> SessionRef {
    SessionRef { name: name.to_owned(), generation: NonZeroU64::new(generation).unwrap() }
}

impl Test {
    /// Deletes `id` as a caller would, by its name and generation.
    async fn delete_ref(&self, id: &SessionRef) -> Result<(), Error> {
        self.delete(&id.name, id.generation.get()).await
    }
}

fn state(m: &Test, name: &str) -> Option<State> {
    m.get(name).ok().map(|i| i.state)
}

/// Waits for `f` to be true, giving up after a few seconds.
async fn until(what: &str, f: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !f() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

fn claim(template_id: &str) -> Claim {
    Claim { template_id: template_id.to_owned(), ..Claim::default() }
}

#[tokio::test]
async fn claims_take_a_pooled_guest() {
    let h = harness(|_| {}).await;
    let id = seed_pooled(&h.m);
    assert!(matches!(h.m.claim(claim("db-v1")).await, Err(Error::UnknownTemplate)));

    let egress = Egress { cidr_allowlist: vec!["1.1.1.0/24".parse().unwrap()], ..Egress::default() };
    let c = Claim { labels: [("team".into(), "a".into())].into(), egress: Some(egress), ..claim("web-v1") };
    let info = h.m.claim(c).await.unwrap();
    assert_eq!((info.name.as_str(), info.generation, info.state), (id.name.as_str(), id.generation.get(), State::Claimed));
    assert_eq!(info.endpoints["http"], "10.0.0.1:31000");
    assert_eq!(info.host_id, "test-host");
    let ruleset = h.m.host.last_ruleset();
    assert!(ruleset.contains("dnat ip to 172.20.0.2:8080"), "{ruleset}");
    assert!(ruleset.contains("ip daddr { 1.1.1.0/24 } accept"), "{ruleset}");
    let persisted = h.m.store.load().unwrap();
    assert_eq!((persisted[0].state, persisted[0].labels["team"].as_str()), (State::Claimed, "a"));

    assert!(matches!(h.m.claim(claim("web-v1")).await, Err(Error::PoolEmpty)));
}

#[tokio::test]
async fn concurrent_claims_have_one_winner() {
    let h = harness(|_| {}).await;
    seed_pooled(&h.m);
    let claims = (0..8).map(|_| h.m.claim(claim("web-v1")));
    let results = futures_util::future::join_all(claims).await;
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(results.iter().all(|r| matches!(r, Ok(_) | Err(Error::PoolEmpty))));
}

#[tokio::test]
async fn generations_fence_deletes() {
    let h = harness(|_| {}).await;
    let id = seed_pooled(&h.m);
    let name = id.name.as_str();
    assert_eq!(id.generation.get(), 1);
    assert!(matches!(h.m.delete(name, 0).await, Err(Error::GenerationMismatch)));
    assert!(matches!(h.m.delete(name, 2).await, Err(Error::GenerationMismatch)));
    assert!(matches!(h.m.set_expiry(name, 0, None).await, Err(Error::GenerationMismatch)));
    assert!(matches!(h.m.delete("nobody", 1).await, Err(Error::NotFound)));
    h.m.delete_ref(&id).await.unwrap();
    assert!(matches!(h.m.get(name), Err(Error::NotFound)));
    assert_eq!(h.m.status().reserved_vcpus, 0);
    assert_eq!(seed_pooled(&h.m), session_ref(name, 2), "the slot is free and its name's next generation fences the last");
}

#[tokio::test]
async fn delete_during_boot_cancel_is_busy() {
    let h = harness(|_| {}).await;
    let id = {
        let mut sessions = h.m.sessions();
        let (id, _boot) = h.m.allocate(&mut sessions, &h.m.cfg.templates[0]).unwrap();
        let s = sessions.get_mut(&id).unwrap();
        // its boot recorded it, then a delete began canceling the boot
        s.recorded = true;
        s.rec.state = State::Stopping;
        id
    };
    assert!(matches!(h.m.delete_ref(&id).await, Err(Error::Busy)));
}

#[tokio::test]
async fn failed_teardown_holds_slot() {
    let h = harness(|_| {}).await;
    let id = seed_pooled(&h.m);
    h.m.driver.kill_fails.store(true, Ordering::Relaxed);
    let err = h.m.delete_ref(&id).await.unwrap_err();
    assert!(format!("{err:#}").contains("kill_vmm"), "{err:#}");
    assert_eq!(state(&h.m, &id.name), Some(State::Stopping));
    assert_eq!(seed_pooled(&h.m).name, "test-host-1", "the stuck session keeps slot 0");

    h.m.driver.kill_fails.store(false, Ordering::Relaxed);
    h.m.maintain().await;
    assert_eq!(state(&h.m, &id.name), None);
    assert_eq!(seed_pooled(&h.m), session_ref(&id.name, 2));
}

#[tokio::test]
async fn failed_reap_stays_stopping_across_restart() {
    let h = harness(|_| {}).await;
    let SessionRef { name, .. } = seed_pooled(&h.m);
    h.m.sessions().by_name.get_mut(&name).unwrap().rec.pooled_at = Some(SystemTime::now() - Duration::from_hours(1));
    h.m.driver.kill_fails.store(true, Ordering::Relaxed);
    h.m.maintain().await;
    assert_eq!(h.m.store.load().unwrap()[0].state, State::Stopping, "the reap is persisted");

    let h = h.restart(|_| {}).await.unwrap();
    assert!(matches!(h.m.claim(claim("web-v1")).await, Err(Error::PoolEmpty)), "a reaped guest is never claimable again");
}

#[tokio::test]
async fn failed_claim_is_quarantined() {
    let h = harness(|_| {}).await;
    let SessionRef { name, .. } = seed_pooled(&h.m);
    h.m.host.apply_fails.store(true, Ordering::Relaxed);
    let err = h.m.claim(claim("web-v1")).await.unwrap_err();
    assert!(format!("{err:#}").contains("nft says no"), "{err:#}");
    assert_eq!(state(&h.m, &name), Some(State::Stopping));
    assert_eq!(h.m.store.load().unwrap()[0].state, State::Stopping);
    assert!(matches!(h.m.claim(claim("web-v1")).await, Err(Error::PoolEmpty)));
    assert_eq!(h.m.status().reserved_vcpus, 1, "the guest's resources stay reserved until it's torn down");
}

fn keyed(key: &str, digest: &str) -> Claim {
    let labels = [("job".to_owned(), key.to_owned())].into();
    Claim { labels, key: Some(ClaimKey { key: key.to_owned(), digest: digest.to_owned() }), ..claim("web-v1") }
}

#[tokio::test]
async fn keyed_claim_retry_replays() {
    let h = harness(|_| {}).await;
    let id = seed_pooled(&h.m);
    seed_pooled(&h.m);
    // the first answer is lost; the caller retries, concurrently and then after a restart.
    let first = h.m.claim(keyed("job-7", "a")).await.unwrap();
    let retries = futures_util::future::join_all((0..4).map(|_| h.m.claim(keyed("job-7", "a")))).await;
    for retry in retries {
        assert_eq!(retry.unwrap(), first);
    }
    assert_eq!(session_ref(&first.name, first.generation), id);
    assert!(matches!(h.m.claim(keyed("job-7", "b")).await, Err(Error::KeyReused)));
    assert_eq!(h.m.status().pools[0].ready, 1, "no retry claimed the second guest");

    let h = h.restart(|_| {}).await.unwrap();
    assert_eq!(h.m.claim(keyed("job-7", "a")).await.unwrap(), first, "the key was durable with the claim");
    assert_eq!(h.m.get_keyed("job-7").await.unwrap(), Keyed::Live(first));
    assert!(matches!(h.m.get_keyed("job-8").await, Err(Error::NotFound)));
}

#[tokio::test]
async fn deleted_key_held_for_retention() {
    let h = harness(|_| {}).await;
    seed_pooled(&h.m);
    let first = h.m.claim(keyed("job-7", "a")).await.unwrap();
    h.m.delete(&first.name, first.generation).await.unwrap();
    seed_pooled(&h.m);
    assert!(matches!(h.m.claim(keyed("job-7", "a")).await, Err(Error::KeyDeleted)));
    assert!(matches!(h.m.claim(keyed("job-7", "b")).await, Err(Error::KeyReused)));
    let Keyed::Deleted(released) = h.m.get_keyed("job-7").await.unwrap() else { panic!("the key's session is deleted") };
    assert_eq!((released.name.as_str(), released.generation, released.labels["job"].as_str()), (first.name.as_str(), 1, "job-7"));

    let h = h.restart(|_| {}).await.unwrap();
    assert!(matches!(h.m.claim(keyed("job-7", "a")).await, Err(Error::KeyDeleted)), "the deleted key survives a restart");
    h.m.maintain().await;
    assert!(matches!(h.m.claim(keyed("job-7", "a")).await, Err(Error::KeyDeleted)), "within its retention");

    // startup's maintenance round prunes it.
    let h = h.restart(|cfg| cfg["claim_key_retention_sec"] = json!(0)).await.unwrap();
    assert!(h.m.store.load_keys().unwrap().is_empty(), "the pruned key is persisted");
    assert_eq!(h.m.claim(keyed("job-7", "a")).await.unwrap().state, State::Claimed);
}

#[tokio::test]
async fn dead_keyed_session_keeps_key() {
    let h = harness(|_| {}).await;
    seed_pooled(&h.m);
    let first = h.m.claim(keyed("job-7", "a")).await.unwrap();
    h.m.sessions().by_name.get_mut(&first.name).unwrap().rec.instance.pid = None;
    let gens = h.m.sessions().gens.clone();
    h.m.store.save_now(&h.m.sessions().by_name[&first.name].rec, &gens);
    let h = h.restart(|_| {}).await.unwrap();
    seed_pooled(&h.m);
    assert!(matches!(h.m.claim(keyed("job-7", "a")).await, Err(Error::KeyDeleted)));
}

#[tokio::test]
async fn failed_keyed_claim_frees_key() {
    let h = harness(|_| {}).await;
    seed_pooled(&h.m);
    seed_pooled(&h.m);
    h.m.host.apply_fails.store(true, Ordering::Relaxed);
    h.m.claim(keyed("job-7", "a")).await.unwrap_err();
    h.m.host.apply_fails.store(false, Ordering::Relaxed);
    let retried = h.m.claim(keyed("job-7", "a")).await.unwrap();
    assert_eq!((retried.name.as_str(), retried.state), ("test-host-1", State::Claimed), "nobody holds the quarantined guest");
}

#[tokio::test]
async fn sessions_list_by_label() {
    let h = harness(|_| {}).await;
    seed_pooled(&h.m);
    seed_pooled(&h.m);
    let seven = h.m.claim(keyed("job-7", "a")).await.unwrap();
    h.m.claim(keyed("job-8", "a")).await.unwrap();
    let selector = |pairs: &[(&str, &str)]| pairs.iter().map(|&(k, v)| (k.to_owned(), v.to_owned())).collect::<BTreeMap<_, _>>();
    assert_eq!(h.m.list(&selector(&[("job", "job-7")])), [seven]);
    assert_eq!(h.m.list(&selector(&[("job", "job-7"), ("team", "a")])), []);
    assert_eq!(h.m.list(&selector(&[])).len(), 2);
}

#[tokio::test]
async fn concurrent_teardowns_run_once() {
    let h = harness(|_| {}).await;
    let id = seed_pooled(&h.m);
    let destroys = (0..8).map(|_| h.m.destroy(&id));
    for result in futures_util::future::join_all(destroys).await {
        result.unwrap();
    }
    assert_eq!(*h.m.host.deleted.lock().unwrap(), [0]);
    assert_eq!(h.m.status().reserved_memory_mib, 0);
}

#[rstest::rstest]
#[case::vcpus("max_vcpus", 1)]
#[case::memory("max_memory_mib", 512)]
#[tokio::test]
async fn admission_reserves_resources_before_boot(#[case] budget: &str, #[case] limit: u32) {
    let h = harness(|cfg| cfg[budget] = json!(limit)).await;
    let t = &h.m.cfg.templates[0];
    let (id, _) = h.m.allocate(&mut h.m.sessions(), t).unwrap();
    assert!(matches!(h.m.allocate(&mut h.m.sessions(), t), Err(Error::SlotsExhausted)));
    let status = h.m.status();
    assert_eq!((status.reserved_vcpus, status.reserved_memory_mib), (1, 512));
    h.m.sessions().get_mut(&id).unwrap().boot.as_ref().unwrap().done.cancel();
    h.m.destroy(&id).await.unwrap();
    h.m.allocate(&mut h.m.sessions(), t).unwrap();
}

#[tokio::test]
async fn allocated_session_hidden_until_recorded() {
    let h = harness(|_| {}).await;
    let (id, _) = h.m.allocate(&mut h.m.sessions(), &h.m.cfg.templates[0]).unwrap();
    let (name, generation) = (id.name.as_str(), id.generation.get());
    assert_eq!(h.m.list(&BTreeMap::new()), []);
    assert!(matches!(h.m.get(name), Err(Error::NotFound)));
    assert!(matches!(h.m.set_expiry(name, generation, None).await, Err(Error::NotFound)));
    assert!(h.m.store.load().unwrap().is_empty() && h.m.store.load_gens().unwrap().is_empty());

    h.m.record(&id).await.unwrap();
    assert_eq!(h.m.store.load_gens().unwrap()[name], generation);
    assert_eq!(h.m.store.load().unwrap()[0].generation(), generation);
    assert_eq!(h.m.get(name).unwrap().generation, generation);
}

#[tokio::test]
async fn named_endpoints_get_disjoint_port_blocks() {
    let h = harness(|cfg| cfg["templates"][0]["endpoints"] = json!({"http": 8080, "admin": 9000})).await;
    seed_pooled(&h.m);
    let SessionRef { name, .. } = seed_pooled(&h.m);
    let rec = h.m.sessions().by_name[&name].rec.clone();
    assert_eq!(rec.endpoints["admin"], Endpoint { host_port: 31016, guest_port: 9000 });
    assert_eq!(rec.endpoints["http"], Endpoint { host_port: 31017, guest_port: 8080 });
}

#[tokio::test]
async fn pools_refill() {
    let h = harness(|cfg| cfg["templates"][0]["pool_target"] = json!(1)).await;
    // the table shows the guest pooled a moment before its record says so
    until("a pooled record", || h.m.store.load().unwrap().first().is_some_and(|r| r.state == State::Pooled)).await;
    assert_eq!(h.m.status().pools[0].ready, 1);
    assert_eq!(h.m.driver.starts.load(Ordering::Relaxed), 1);
    let rec = h.m.store.load().unwrap().remove(0);
    assert!(rec.instance.pid.is_some(), "the vmm's pid is persisted");
    assert!(rec.instance.disk.exists(), "the scratch disk was copied");
    h.m.maintain().await;
    assert_eq!(h.m.list(&BTreeMap::new()).len(), 1, "a full pool boots no more");
}

#[tokio::test]
async fn delete_cancels_boot() {
    let h = harness(|cfg| cfg["templates"][0]["pool_target"] = json!(1)).await;
    h.m.host.ready.store(false, Ordering::Relaxed);
    until("the vmm to start", || h.m.driver.starts.load(Ordering::Relaxed) == 1).await;
    let name = h.m.list(&BTreeMap::new())[0].name.clone();
    assert_eq!(state(&h.m, &name), Some(State::Booting));
    h.m.delete(&name, 1).await.unwrap();
    assert_eq!(state(&h.m, &name), None);
    assert_eq!(*h.m.host.deleted.lock().unwrap(), [0], "torn down once, after the boot stopped");
}

#[tokio::test]
async fn bad_artifact_fails_boot_and_backs_off() {
    let h = harness(|cfg| {
        cfg["templates"][0]["pool_target"] = json!(1);
        cfg["templates"][0]["base_disk_sha256"] = json!("0".repeat(64));
    })
    .await;
    until("the failed boot's teardown", || h.m.list(&BTreeMap::new()).is_empty() && !h.m.host.deleted.lock().unwrap().is_empty()).await;
    assert_eq!(h.m.driver.starts.load(Ordering::Relaxed), 0, "the boot failed before the vmm started");
    h.m.refill();
    assert!(h.m.sessions().by_name.is_empty(), "a pool backing off boots nothing");

    h.m.pools[0].backoff.lock().unwrap().until = Some(Instant::now());
    h.m.refill();
    // allocated, but not yet listed: its boot task records it first
    assert_eq!(h.m.sessions().by_name.len(), 1, "the backoff over, the pool tries again");
    until("the second failure", || h.m.pools[0].backoff.lock().unwrap().failures == 2).await;
}

#[test]
fn backoff_doubles_per_round() {
    let (mut b, now) = (Backoff::default(), Instant::now());
    assert_eq!(b.failed(now), Some(REFILL_BACKOFF));
    assert!(b.blocks(now));
    assert_eq!(b.failed(now), None, "a sibling failing into the backoff doesn't stretch it");
    let later = now + REFILL_BACKOFF;
    assert!(!b.blocks(later));
    assert_eq!(b.failed(later), Some(REFILL_BACKOFF * 2));
    b.failures = 40;
    assert_eq!(b.failed(later + MAX_REFILL_BACKOFF), Some(MAX_REFILL_BACKOFF));
    b.succeeded();
    assert!(!b.blocks(later) && b.failures == 0);
}

#[tokio::test]
async fn mismatch_rehashed_only_on_change() {
    let h = harness(|_| {}).await;
    let path = h.m.cfg.templates[0].base_disk.clone();
    fs::write(&path, "x").unwrap();
    let empty = crate::config::Sha256Hex::try_from(crate::testing::EMPTY_SHA256.to_owned()).unwrap();
    for _ in 0..2 {
        let err = h.m.verify(&path, &empty).await.unwrap_err();
        assert!(format!("{err:#}").contains("SHA-256 mismatch"), "{err:#}");
    }
    fs::write(&path, "").unwrap();
    h.m.verify(&path, &empty).await.unwrap();
}

#[tokio::test]
async fn lazy_templates_record_then_prefetch() {
    let h = harness(|cfg| {
        let t = &mut cfg["templates"][0];
        t["pool_target"] = json!(1);
        t["snapshot"] = json!("lazy");
        // jailed restores need the uffd handler installed.
        cfg["jailer"] = json!({"disabled": true});
    })
    .await;
    for _ in 0..3 {
        until("a pooled guest", || h.m.status().pools[0].ready == 1).await;
        let info = h.m.claim(claim("web-v1")).await.unwrap();
        h.m.delete(&info.name, info.generation).await.unwrap();
        h.m.refill();
    }
    let modes: Vec<_> = h.m.driver.restores.lock().unwrap().iter().map(|r| r.mode).collect();
    assert_eq!(modes, [vmm::RestoreMode::Record, vmm::RestoreMode::Prefetch]);
    assert!(h.m.driver.restores.lock().unwrap().iter().all(|r| r.remote.is_none()), "no snapshot store");
}

#[tokio::test]
async fn expired_and_dead_guests_are_reaped() {
    let h = harness(|_| {}).await;
    let claimed = seed_pooled(&h.m);
    h.m.claim(claim("web-v1")).await.unwrap();
    let SessionRef { name: dead, .. } = seed_pooled(&h.m);
    h.m.set_expiry(&claimed.name, claimed.generation.get(), Some(SystemTime::now() - Duration::from_secs(1))).await.unwrap();
    h.m.driver.crash(&h.m.sessions().by_name[&dead].rec.instance);
    h.m.maintain().await;
    assert_eq!(h.m.list(&BTreeMap::new()), []);
}

#[tokio::test]
async fn restart_adopts_live_cleans_dead() {
    let h = harness(|_| {}).await;
    let SessionRef { name: live, .. } = seed_pooled(&h.m);
    let SessionRef { name: dead, .. } = seed_pooled(&h.m);
    h.m.sessions().by_name.get_mut(&dead).unwrap().rec.instance.pid = None;
    let gens = h.m.sessions().gens.clone();
    h.m.store.save_now(&h.m.sessions().by_name[&dead].rec, &gens);
    let h = h.restart(|_| {}).await.unwrap();
    assert_eq!(h.m.list(&BTreeMap::new()).iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), [live.as_str()]);
    assert_eq!(*h.m.host.deleted.lock().unwrap(), [1]);
    assert_eq!(h.m.status().reserved_vcpus, 1);
    assert_eq!(seed_pooled(&h.m), session_ref(&dead, 2), "the dead session's generation still fences");
}

#[tokio::test]
async fn restart_refuses_foreign_state() {
    let h = harness(|_| {}).await;
    seed_pooled(&h.m);
    let err = h.restart(|cfg| cfg["dnat_port_start"] = json!(32000)).await.err().unwrap();
    assert!(format!("{err:#}").contains("port configuration changed"), "{err:#}");
}

#[tokio::test]
async fn changed_template_needs_new_id() {
    let h = harness(|_| {}).await;
    let h = h.restart(|cfg| cfg["templates"][0]["pool_target"] = json!(0)).await.unwrap();
    let err = h.restart(|cfg| cfg["templates"][0]["mem_mib"] = json!(1024)).await.err().unwrap();
    assert!(format!("{err:#}").contains("use a new template_id"), "{err:#}");
}

#[tokio::test]
async fn one_roost_per_state_directory() {
    let h = harness(|_| {}).await;
    let err = start(&h.cfg).await.err().unwrap();
    assert!(format!("{err:#}").contains("another agent owns the state directory"), "{err:#}");
}

#[tokio::test]
async fn dns_gate_grants_allowed_claims() {
    let h = harness(|_| {}).await;
    let id = seed_pooled(&h.m);
    let gate = dnsgate::Gate(Arc::clone(&h.m));
    let guest = Ipv4Addr::new(172, 20, 0, 2);
    assert_eq!(gate.grant(guest, "a.example.com."), None, "a pooled guest has no egress");
    let egress = Egress { fqdn_allowlist: vec!["*.example.com".parse().unwrap()], ..Egress::default() };
    h.m.claim(Claim { egress: Some(egress), ..claim("web-v1") }).await.unwrap();
    assert_eq!(gate.grant(guest, "example.com."), None);
    assert_eq!(gate.grant(Ipv4Addr::new(172, 20, 0, 6), "a.example.com."), None);
    let grant = gate.grant(guest, "a.example.com.").unwrap();
    gate.program(grant.clone(), [(Ipv4Addr::new(93, 184, 216, 34), 60)].into()).await.unwrap();
    let ruleset = h.m.host.last_ruleset();
    assert!(ruleset.contains("93.184.216.34 timeout"), "{ruleset}");
    assert_ne!(h.m.dns_port, 0);
    assert!(ruleset.contains(&format!("redirect to :{}", h.m.dns_port)), "lookups go to the port the gate bound: {ruleset}");

    h.m.delete_ref(&id).await.unwrap();
    seed_pooled(&h.m);
    assert!(gate.program(grant, [(Ipv4Addr::new(1, 2, 3, 4), 60)].into()).await.is_err(), "a replacement can't use the old grant");
}

#[tokio::test]
async fn fqdn_cap_drops_soonest_expiry() {
    let h = harness(|cfg| cfg["fqdn_max_ips"] = json!(2)).await;
    let id = seed_pooled(&h.m);
    let egress = Egress { fqdn_allowlist: vec!["example.com".parse().unwrap()], ..Egress::default() };
    h.m.claim(Claim { egress: Some(egress), ..claim("web-v1") }).await.unwrap();
    let ip = |n| Ipv4Addr::new(10, 9, 0, n);
    h.m.program_fqdn(&id, [(ip(1), 30), (ip(2), 90)].into()).await.unwrap();
    h.m.program_fqdn(&id, [(ip(3), 60)].into()).await.unwrap();
    let kept: Vec<_> = h.m.sessions().by_name[&id.name].rec.fqdn_addrs.keys().copied().collect();
    assert_eq!(kept, [ip(2), ip(3)]);
}

#[tokio::test]
async fn log_targets_skip_stopping() {
    let h = harness(|cfg| cfg["max_sessions"] = json!(2)).await;
    let SessionRef { name: pooled, .. } = seed_pooled(&h.m);
    let SessionRef { name: stopping, .. } = seed_pooled(&h.m);
    h.m.sessions().by_name.get_mut(&stopping).unwrap().rec.state = State::Stopping;
    let targets = h.m.log_targets();
    assert_eq!(targets.len(), 1);
    assert_eq!((targets[0].session_id.as_str(), targets[0].container.as_str(), targets[0].generation), (pooled.as_str(), "web", 1));
    assert_eq!(h.m.max_containers(), 1);
}

#[test]
fn name_prefixes() {
    assert_eq!(name_prefix("smoke"), "smoke");
    assert_eq!(name_prefix("Smoke.Host"), "smoke-host-09d4eeaa");
    assert_eq!(name_prefix("---"), "roost-c4e4dc86");
    assert_eq!(name_prefix(&"a".repeat(60)), format!("{}-92b9e111", "a".repeat(39)));
}
