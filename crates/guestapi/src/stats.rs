//! The `STATS 1` reply: one JSON line of the guest's resource counters.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::workload::MAX_ITEMS;

/// Max size of a reply.
pub const MAX_STATS_BYTES: usize = 16 << 10;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<Memory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk: Option<Disk>,
    #[serde(default)]
    pub containers: BTreeMap<String, ContainerStats>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Memory {
    pub total_bytes: u64,
    pub available_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oom_kill: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disk {
    pub total_bytes: u64,
    pub free_bytes: u64,
}

/// A container's cgroup counters. Each one's missing if the guest couldn't read it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerStats {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_usec: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oom_kill: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StatsError {
    #[error("invalid guest statistics version or container count")]
    Shape,
    #[error("unknown container in guest statistics")]
    UnknownContainer,
    #[error("invalid guest memory")]
    Memory,
    #[error("invalid guest disk")]
    Disk,
}

impl Stats {
    /// Checks a guest's reply against the containers it runs. The host can't trust what the guest sends.
    pub fn validate(&self, containers: &[String]) -> Result<(), StatsError> {
        if self.version != 1 || self.containers.len() > MAX_ITEMS.min(containers.len()) {
            return Err(StatsError::Shape);
        }
        if !self.containers.keys().all(|name| containers.contains(name)) {
            return Err(StatsError::UnknownContainer);
        }
        if let Some(m) = &self.memory
            && (m.total_bytes == 0 || m.available_bytes > m.total_bytes)
        {
            return Err(StatsError::Memory);
        }
        if let Some(d) = &self.disk
            && (d.total_bytes == 0 || d.free_bytes > d.total_bytes)
        {
            return Err(StatsError::Disk);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn names() -> Vec<String> {
        vec!["web".into()]
    }

    fn ok() -> Stats {
        Stats {
            version: 1,
            memory: Some(Memory { total_bytes: 100, available_bytes: 40, oom_kill: None }),
            disk: Some(Disk { total_bytes: 10, free_bytes: 5 }),
            containers: [("web".into(), ContainerStats::default())].into(),
        }
    }

    #[test]
    fn accepts_valid_stats() {
        let stats: Stats = serde_json::from_str(
            r#"{"version":1,"memory":{"total_bytes":100,"available_bytes":40,"oom_kill":0},"disk":{"total_bytes":10,"free_bytes":10},
                "containers":{"web":{"cpu_usec":5,"pids":1}}}"#,
        )
        .unwrap();
        stats.validate(&names()).unwrap();
        assert_eq!(stats.containers["web"].memory_bytes, None);
        ok().validate(&names()).unwrap();
    }

    #[rstest]
    #[case::version(|s: &mut Stats| s.version = 2, StatsError::Shape)]
    #[case::unknown_container(|s: &mut Stats| s.containers = [("db".into(), ContainerStats::default())].into(), StatsError::UnknownContainer)]
    #[case::available_over_total(|s: &mut Stats| s.memory.as_mut().unwrap().available_bytes = 101, StatsError::Memory)]
    #[case::empty_memory(|s: &mut Stats| s.memory.as_mut().unwrap().total_bytes = 0, StatsError::Memory)]
    #[case::free_over_total(|s: &mut Stats| s.disk.as_mut().unwrap().free_bytes = 11, StatsError::Disk)]
    fn rejects_impossible_stats(#[case] break_it: fn(&mut Stats), #[case] want: StatsError) {
        let mut bad = ok();
        break_it(&mut bad);
        assert_eq!(bad.validate(&names()), Err(want));
    }
}
