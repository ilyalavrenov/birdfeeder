use std::sync::atomic::{AtomicU64, Ordering};

use tracing::info;

/// A running counter we only ever log, so relaxed ordering is fine.
#[derive(Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
pub struct Stats {
    pub faults: Counter,
    pub copied_bytes: Counter,
    pub zeroed_bytes: Counter,
    pub removes: Counter,
    pub fetches: Counter,
    pub fetched_bytes: Counter,
    pub fetch_failures: Counter,
}

impl Stats {
    pub fn log(&self, msg: &str) {
        info!(
            faults = self.faults.get(),
            copied_bytes = self.copied_bytes.get(),
            zeroed_bytes = self.zeroed_bytes.get(),
            removes = self.removes.get(),
            fetches = self.fetches.get(),
            fetched_bytes = self.fetched_bytes.get(),
            fetch_failures = self.fetch_failures.get(),
            "{msg}"
        );
    }
}
