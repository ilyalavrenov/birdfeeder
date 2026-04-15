//! roost's instruments. Dashboards and the smoke suite depend on these names and units.

use opentelemetry::metrics::{Counter, Histogram, Meter};

pub struct Metrics {
    pub boot_duration: Histogram<f64>,
    pub boot_queue: Histogram<f64>,
    pub boot_failures: Counter<u64>,
    pub claim_duration: Histogram<f64>,
    pub reaps: Counter<u64>,
    pub teardown_failures: Counter<u64>,
    pub vm: VmMetrics,
}

/// Per-vm samples: the host cgroup's view, and what the guest reports.
pub struct VmMetrics {
    pub cpu_usage: Histogram<f64>,
    pub cpu_pressure: Histogram<f64>,
    pub mem_pressure: Histogram<f64>,
    pub mem_current: Histogram<u64>,
    pub guest_mem_total: Histogram<u64>,
    pub guest_mem_available: Histogram<u64>,
    pub guest_oom_kills: Counter<u64>,
    pub disk_used: Histogram<u64>,
    pub container_memory: Histogram<u64>,
    pub container_cpu: Histogram<f64>,
    pub container_pids: Histogram<u64>,
    pub container_oom_kills: Counter<u64>,
    pub stats_requests: Counter<u64>,
}

const SECONDS: &str = "s";
const BYTES: &str = "By";
const CPUS: &str = "{cpu}";
const RATIO: &str = "1";

impl Metrics {
    pub fn new(meter: &Meter) -> Self {
        let seconds = |name: &'static str, description: &'static str| {
            meter.f64_histogram(name).with_unit(SECONDS).with_description(description).build()
        };
        let counter = |name: &'static str, description: &'static str| meter.u64_counter(name).with_description(description).build();
        Self {
            boot_duration: seconds("birdfeeder.roost.boot.duration", "vm boot wall time, disk copy through guest ready"),
            boot_queue: seconds("birdfeeder.roost.boot.queue.duration", "time a boot waited for a max_concurrent_boots slot"),
            boot_failures: counter("birdfeeder.roost.boot.failures", "failed boots by the stage that failed; canceled boots don't count"),
            claim_duration: seconds("birdfeeder.roost.claim.duration", "claim wall time by outcome"),
            reaps: counter("birdfeeder.roost.reaps", "sessions reaped by the maintenance loop, by reason"),
            teardown_failures: counter(
                "birdfeeder.roost.teardown.failures",
                "teardown step failures by stage; kill_vmm and delete_tap leave the session in stopping",
            ),
            vm: VmMetrics::new(meter),
        }
    }
}

impl VmMetrics {
    fn new(meter: &Meter) -> Self {
        let f64s = |name: &'static str, unit: &'static str, description: &'static str| {
            meter.f64_histogram(name).with_unit(unit).with_description(description).build()
        };
        let u64s = |name: &'static str, unit: &'static str, description: &'static str| {
            meter.u64_histogram(name).with_unit(unit).with_description(description).build()
        };
        Self {
            cpu_usage: f64s("birdfeeder.vm.cpu.usage", CPUS, "cores the vm's host cgroup burned since the last sample"),
            cpu_pressure: f64s("birdfeeder.vm.cpu.pressure", RATIO, "psi cpu some avg10 of the vm's host cgroup"),
            mem_pressure: f64s("birdfeeder.vm.mem.pressure", RATIO, "psi memory some avg10 of the vm's host cgroup"),
            mem_current: u64s("birdfeeder.vm.mem.current", BYTES, "memory.current of the vm's host cgroup"),
            guest_mem_total: u64s("birdfeeder.guest.mem.total", BYTES, "guest total memory from procfs"),
            guest_mem_available: u64s("birdfeeder.guest.mem.available", BYTES, "guest available memory from procfs"),
            guest_oom_kills: meter.u64_counter("birdfeeder.guest.mem.oom_kill").with_description("guest oom killer invocations").build(),
            disk_used: u64s("birdfeeder.guest.disk.used", BYTES, "guest root filesystem allocated bytes"),
            container_memory: u64s("birdfeeder.guest.container.mem.current", BYTES, "guest container cgroup memory usage"),
            container_cpu: f64s("birdfeeder.guest.container.cpu.usage", CPUS, "cores the guest container consumed since the last sample"),
            container_pids: u64s("birdfeeder.guest.container.pids", "{process}", "guest container cgroup process count"),
            container_oom_kills: meter.u64_counter("birdfeeder.guest.container.oom_kills").with_unit("{event}").build(),
            stats_requests: meter.u64_counter("birdfeeder.guest.stats.requests").with_unit("{request}").build(),
        }
    }
}
