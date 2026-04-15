//! The guest's resource counters, served as `STATS 1` replies.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub use guestapi::stats::{ContainerStats, Disk, Memory, Stats};

/// Caps procfs reads no matter how many clients poll.
const CACHE_FOR: Duration = Duration::from_secs(1);
/// meminfo's "kB" unit is KiB.
const MEMINFO_KB: u64 = 1024;

/// `D` reads the disk, so a test can fake it without a real filesystem.
pub struct StatsProvider<D> {
    proc: PathBuf,
    cgroups: PathBuf,
    names: Vec<String>,
    disk: D,
    cache: Mutex<Option<(Instant, Stats)>>,
}

impl<D: Fn() -> Option<Disk>> StatsProvider<D> {
    pub fn new(proc: impl Into<PathBuf>, cgroups: impl Into<PathBuf>, names: Vec<String>, disk: D) -> Self {
        Self { proc: proc.into(), cgroups: cgroups.into(), names, disk, cache: Mutex::new(None) }
    }

    pub fn get(&self) -> Stats {
        let mut cache = self.cache.lock().expect("a stats reader panicked holding the cache");
        if let Some((at, stats)) = &*cache
            && at.elapsed() < CACHE_FOR
        {
            return stats.clone();
        }
        let mut stats = self.collect();
        stats.disk = (self.disk)();
        *cache = Some((Instant::now(), stats.clone()));
        stats
    }

    fn collect(&self) -> Stats {
        let memory = fs::read_to_string(self.proc.join("meminfo")).ok().and_then(|mem| {
            Some(Memory {
                total_bytes: memory_field(&mem, "MemTotal:")?,
                available_bytes: memory_field(&mem, "MemAvailable:")?,
                oom_kill: counter(&self.proc, "vmstat", Some("oom_kill")),
            })
        });
        let containers = self
            .names
            .iter()
            .map(|name| {
                let leaf = self.cgroups.join(name);
                let stats = ContainerStats {
                    cpu_usec: counter(&leaf, "cpu.stat", Some("usage_usec")),
                    memory_bytes: counter(&leaf, "memory.current", None),
                    oom_kill: counter(&leaf, "memory.events", Some("oom_kill")),
                    pids: counter(&leaf, "pids.current", None),
                };
                (name.clone(), stats)
            })
            .collect();
        Stats { version: 1, memory, disk: None, containers }
    }
}

/// A counter: either the whole file, or the value on its `key value` line.
fn counter(dir: &Path, file: &str, key: Option<&str>) -> Option<u64> {
    let data = fs::read_to_string(dir.join(file)).ok()?;
    let value = match key {
        None => data.trim(),
        Some(key) => data.lines().find_map(|line| match line.split_whitespace().collect::<Vec<_>>()[..] {
            [k, v] if k == key => Some(v),
            _ => None,
        })?,
    };
    value.parse().ok()
}

fn memory_field(data: &str, key: &str) -> Option<u64> {
    data.lines().find_map(|line| match line.split_whitespace().collect::<Vec<_>>()[..] {
        [k, v, "kB"] if k == key => Some(v.parse::<u64>().ok().and_then(|v| v.checked_mul(MEMINFO_KB))),
        _ => None,
    })?
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn collects_and_caches() {
        let (proc, cg) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        fs::write(proc.path().join("meminfo"), "MemTotal: 1024 kB\nMemAvailable: 512 kB\n").unwrap();
        fs::write(proc.path().join("vmstat"), "oom_kill 3\n").unwrap();
        let web = cg.path().join("web");
        fs::create_dir(&web).unwrap();
        for (name, body) in
            [("cpu.stat", "usage_usec 1000\n"), ("memory.current", "512\n"), ("memory.events", "oom_kill 2\n"), ("pids.current", "4\n")]
        {
            fs::write(web.join(name), body).unwrap();
        }
        let disk_reads = Cell::new(0);
        let provider = StatsProvider::new(proc.path(), cg.path(), vec!["web".into(), "missing".into()], || {
            disk_reads.set(disk_reads.get() + 1);
            Some(Disk { total_bytes: 100, free_bytes: 60 })
        });
        let s = provider.get();
        assert_eq!(s.memory, Some(Memory { total_bytes: 1 << 20, available_bytes: 512 << 10, oom_kill: Some(3) }));
        assert_eq!(s.containers["web"], ContainerStats { cpu_usec: Some(1000), memory_bytes: Some(512), oom_kill: Some(2), pids: Some(4) });
        assert_eq!(s.containers["missing"], ContainerStats::default());
        assert_eq!(provider.get(), s);
        assert_eq!(disk_reads.get(), 1);
    }

    #[test]
    fn rejects_unrepresentable_memory() {
        assert_eq!(memory_field("MemTotal: 18014398509481984 kB\n", "MemTotal:"), None);
        assert_eq!(memory_field("MemTotal: 1 MB\n", "MemTotal:"), None);
        assert_eq!(memory_field("MemTotal: -1 kB\n", "MemTotal:"), None);
    }
}
