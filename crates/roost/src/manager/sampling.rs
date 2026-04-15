//! Per-vm metrics, sampled every interval from the vm's host cgroup and the guest's `STATS` reply. Counters are
//! cumulative, so each sample gets diffed against the session's previous one. A new generation resets that.

use futures_util::StreamExt as _;
use guestapi::stats::{ContainerStats, Stats};

use super::{BTreeMap, Driver, Duration, HashMap, Host, Instant, KeyValue, Manager, Path, State, fs, sysctl, ticker};

const SAMPLE_WORKERS: usize = 4;
const USEC_PER_SEC: f64 = 1e6;
const PSI_PERCENT: f64 = 100.0;

/// One tick's cumulative readings for one vm. `None` where the tick couldn't get one.
#[derive(Debug, Clone, Default)]
struct Sample {
    generation: u64,
    at: Option<Instant>,
    cpu_usec: Option<u64>,
    oom_kills: Option<u64>,
    containers: BTreeMap<String, ContainerStats>,
}

struct Target {
    instance: vmm::Instance,
    template_id: String,
    containers: Vec<String>,
}

impl<D: Driver + 'static, H: Host> Manager<D, H> {
    pub(super) async fn sample_loop(&self) {
        let interval = self.cfg.metrics_interval;
        let mut ticks = ticker(interval);
        ticks.tick().await;
        let mut previous = HashMap::new();
        loop {
            ticks.tick().await;
            previous = self.sample_vms(previous, interval).await;
        }
    }

    /// Samples every pooled and claimed vm, a few at a time, within one interval. A pile of stalled guests shouldn't
    /// stack up workers or hold up later rounds.
    async fn sample_vms(&self, previous: HashMap<String, Sample>, within: Duration) -> HashMap<String, Sample> {
        let targets: Vec<_> = self
            .sessions()
            .by_name
            .values()
            .filter(|s| matches!(s.rec.state, State::Pooled | State::Claimed))
            .map(|s| Target {
                instance: s.rec.instance.clone(),
                template_id: s.rec.template_id.clone(),
                containers: s.rec.manifest.containers.iter().map(|c| c.name.to_string()).collect(),
            })
            .collect();
        let deadline = tokio::time::Instant::now() + within;
        let mut current = HashMap::with_capacity(targets.len());
        let work = targets.into_iter().map(|t| {
            let prev = previous.get(&t.instance.name).filter(|p| p.generation == t.instance.generation).cloned().unwrap_or_default();
            async move {
                let sample = self.sample_vm(&t, &prev).await;
                (t.instance.name, sample)
            }
        });
        let mut samples = futures_util::stream::iter(work).buffer_unordered(SAMPLE_WORKERS);
        while let Ok(Some((name, sample))) = tokio::time::timeout_at(deadline, samples.next()).await {
            current.insert(name, sample);
        }
        current
    }

    async fn sample_vm(&self, t: &Target, prev: &Sample) -> Sample {
        let vm = &self.metrics.vm;
        let attrs = [KeyValue::new("birdfeeder.template.id", t.template_id.clone())];
        let mut cur = Sample { generation: t.instance.generation, at: Some(Instant::now()), ..Sample::default() };
        if let Some(leaf) = self.driver.cgroup(&t.instance) {
            cur.cpu_usec = cgroup_field(&leaf, "cpu.stat", "usage_usec");
            if let Ok(bytes) = sysctl::read_u64(&leaf.join("memory.current")) {
                vm.mem_current.record(bytes, &attrs);
            }
            if let Some(p) = cgroup_avg10(&leaf, "cpu.pressure") {
                vm.cpu_pressure.record(p, &attrs);
            }
            if let Some(p) = cgroup_avg10(&leaf, "memory.pressure") {
                vm.mem_pressure.record(p, &attrs);
            }
        }
        if let Some(rate) = per_sec(prev.at, cur.at, prev.cpu_usec, cur.cpu_usec) {
            vm.cpu_usage.record(rate / USEC_PER_SEC, &attrs);
        }
        let stats = guestapi::stats(&t.instance.vsock_path, &t.containers).await;
        let outcome = if stats.is_ok() { "ok" } else { "error" };
        vm.stats_requests.add(1, &[attrs[0].clone(), KeyValue::new("birdfeeder.operation.outcome", outcome)]);
        match stats {
            Ok(stats) => self.record_guest(&t.template_id, stats, prev, &mut cur),
            Err(err) => tracing::debug!(name = t.instance.name, error = format!("{err:#}"), "guest stats"),
        }
        cur
    }

    fn record_guest(&self, template_id: &str, stats: Stats, prev: &Sample, cur: &mut Sample) {
        let vm = &self.metrics.vm;
        let attrs = [KeyValue::new("birdfeeder.template.id", template_id.to_owned())];
        if let Some(mem) = &stats.memory {
            vm.guest_mem_total.record(mem.total_bytes, &attrs);
            vm.guest_mem_available.record(mem.available_bytes, &attrs);
            cur.oom_kills = mem.oom_kill;
            if let Some(more) = increase(prev, prev.oom_kills, cur.oom_kills) {
                vm.guest_oom_kills.add(more, &attrs);
            }
        }
        if let Some(disk) = &stats.disk {
            vm.disk_used.record(disk.total_bytes - disk.free_bytes, &attrs);
        }
        for (name, c) in &stats.containers {
            let attrs = [attrs[0].clone(), KeyValue::new("birdfeeder.container.name", name.clone())];
            if let Some(bytes) = c.memory_bytes {
                vm.container_memory.record(bytes, &attrs);
            }
            if let Some(pids) = c.pids {
                vm.container_pids.record(pids, &attrs);
            }
            let Some(old) = prev.containers.get(name) else { continue };
            if let Some(rate) = per_sec(prev.at, cur.at, old.cpu_usec, c.cpu_usec) {
                vm.container_cpu.record(rate / USEC_PER_SEC, &attrs);
            }
            if let Some(more) = increase(prev, old.oom_kill, c.oom_kill) {
                vm.container_oom_kills.add(more, &attrs);
            }
        }
        cur.containers = stats.containers;
    }
}

/// How much a counter grew per second between two samples, if both read it and it didn't reset.
fn per_sec(before_at: Option<Instant>, now_at: Option<Instant>, before: Option<u64>, now: Option<u64>) -> Option<f64> {
    let (before_at, now_at, before, now) = (before_at?, now_at?, before?, now?);
    let secs = now_at.duration_since(before_at).as_secs_f64();
    #[expect(clippy::cast_precision_loss, reason = "a rate needn't be exact to the microsecond")]
    (now >= before && secs > 0.0).then(|| (now - before) as f64 / secs)
}

/// A counter's growth since the previous sample, when there was one and it grew.
fn increase(prev: &Sample, before: Option<u64>, now: Option<u64>) -> Option<u64> {
    prev.at?;
    now?.checked_sub(before?).filter(|n| *n > 0)
}

fn cgroup_field(leaf: &Path, file: &str, key: &str) -> Option<u64> {
    stat_field(&fs::read_to_string(leaf.join(file)).ok()?, key)
}

/// `key`'s value in a flat `key value` cgroup file such as cpu.stat or memory.events.
fn stat_field(data: &str, key: &str) -> Option<u64> {
    data.lines().find_map(|line| line.strip_prefix(key)?.strip_prefix(' ')?.trim().parse().ok())
}

fn cgroup_avg10(leaf: &Path, file: &str) -> Option<f64> {
    pressure_avg10(&fs::read_to_string(leaf.join(file)).ok()?)
}

/// A pressure file's psi `some avg10` percentage, as a 0-1 ratio.
fn pressure_avg10(data: &str) -> Option<f64> {
    let some = data.lines().find_map(|line| line.strip_prefix("some "))?;
    let pct: f64 = some.split_whitespace().find_map(|kv| kv.strip_prefix("avg10="))?.parse().ok()?;
    Some(pct / PSI_PERCENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_cgroup_files() {
        let stat = "usage_usec 1500\nuser_usec 1000\nsystem_usec 500\n";
        assert_eq!(stat_field(stat, "usage_usec"), Some(1500));
        assert_eq!(stat_field(stat, "usage"), None);
        assert_eq!(stat_field("oom 1\noom_kill 2\n", "oom_kill"), Some(2));
        assert_eq!(stat_field("usage_usec -3\n", "usage_usec"), None);

        let pressure = "some avg10=12.50 avg60=1.00 avg300=0.00 total=5\nfull avg10=3.00 avg60=0.00 avg300=0.00 total=1\n";
        assert_eq!(pressure_avg10(pressure), Some(0.125));
        assert_eq!(pressure_avg10("full avg10=3.00\n"), None);
        assert_eq!(pressure_avg10("some avg60=1.00\n"), None);
    }

    #[test]
    fn deltas_need_two_readings() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(2);
        assert_eq!(per_sec(Some(t0), Some(t1), Some(1_000_000), Some(3_000_000)), Some(1_000_000.0));
        assert_eq!(per_sec(None, Some(t1), Some(0), Some(1)), None, "no previous sample");
        assert_eq!(per_sec(Some(t0), Some(t1), Some(5), Some(1)), None, "a reset counter");
        assert_eq!(per_sec(Some(t0), Some(t1), None, Some(1)), None, "a failed earlier read");

        let prev = Sample { at: Some(t0), ..Sample::default() };
        assert_eq!(increase(&prev, Some(1), Some(3)), Some(2));
        assert_eq!(increase(&prev, Some(3), Some(3)), None);
        assert_eq!(increase(&Sample::default(), Some(1), Some(3)), None, "a new generation's first sample");
    }
}
