use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::FileTypeExt;

use hyper::StatusCode;
use serde_json::{Value, json};

use super::api::fake::FakeApi;
use super::*;
use crate::Driver as _;

const BOOT_ARGS: &str = "reboot=k panic=-1";

/// Each request as it goes on the wire.
fn wire(requests: &[ConfigRequest<'_>]) -> Vec<(String, Value)> {
    requests.iter().map(|r| (r.path().into_owned(), serde_json::to_value(r).unwrap())).collect()
}

struct Fixture {
    driver: Driver,
    dir: tempfile::TempDir,
}

fn fixture(jailed: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config {
        firecracker_bin: "/bin/false".into(),
        kernel_image_path: "/dev/null".into(),
        boot_args: BOOT_ARGS.into(),
        hugepages_2m: false,
        jailer: jailed.then(|| Jailer {
            bin: "/bin/false".into(),
            chroot_base: dir.path().join("nest"),
            uid_base: 10000,
            cgroup_limits: false,
        }),
        serial_bytes_per_sec: NonZeroU64::new(64 * 1024),
        uffd_handler_bin: "/bin/false".into(),
    };
    let mut driver = Driver::new(cfg, &opentelemetry::global::meter("test"));
    driver.cgroup_root = dir.path().join("cgroup");
    Fixture { driver, dir }
}

impl Fixture {
    fn allocate(&self) -> (Instance, Guest) {
        let mut inst = Instance {
            name: "test-host-example-0".into(),
            generation: 1,
            slot: 0,
            disk: self.dir.path().join("disks/test-host-example-0.1.ext4"),
            ..Instance::default()
        };
        let guest = Guest {
            vcpus: 4.try_into().unwrap(),
            mem_mib: 2048,
            tap: "wt0".into(),
            netns: None,
            mac: "06:00:ac:14:00:02".into(),
            run_dir: self.dir.path().join("run/test-host-example-0.1"),
            base_disk: "/a/base.ext4".into(),
            blobs: BTreeMap::new(),
        };
        self.driver.allocate(&mut inst, &guest);
        (inst, guest)
    }
}

fn boot(guest: Guest, metadata: Value) -> Boot {
    Boot {
        guest,
        limits: Limits {
            disk_bytes_per_sec: NonZeroU64::new(64 * MIB),
            disk_ops_per_sec: None,
            net_bytes_per_sec: NonZeroU64::new(250 * MIB),
            net_packets_per_sec: NonZeroU64::new(250_000),
        },
        metadata,
        console: "/dev/null".into(),
    }
}

#[test]
fn jailed_instances_live_in_their_nest() {
    let f = fixture(true);
    let (inst, _) = f.allocate();
    let root = f.dir.path().join("nest/firecracker/s0-g1/root");
    assert_eq!(inst.sandbox, Sandbox::Jailed(NestId::new(0, 1)));
    assert_eq!(inst.disk, root.join("scratch.ext4"));
    assert_eq!(inst.api_sock, root.join("run/firecracker.socket"));
    assert_eq!(inst.vsock_path, root.join("run/v.sock"));
    assert_eq!(f.driver.uid(&inst), 10000);
    assert_eq!(f.driver.cgroup(&inst), Some(f.dir.path().join("cgroup/birdfeeder/s0-g1")));
}

#[test]
fn unjailed_instances_keep_the_managers_disk() {
    let f = fixture(false);
    let (inst, guest) = f.allocate();
    assert_eq!(inst.sandbox, Sandbox::Host);
    assert_eq!(inst.api_sock, guest.run_dir.join("fc.sock"));
    assert_eq!(inst.vsock_path, guest.run_dir.join("v.sock"));
    assert_eq!(inst.disk, f.dir.path().join("disks/test-host-example-0.1.ext4"));
    assert_eq!(f.driver.uid(&inst), 0);
    assert_eq!(f.driver.cgroup(&inst), None);
}

#[test]
fn markers_tell_reused_pids_apart() {
    let inst = Instance { api_sock: "/run/roost/x.1/fc.sock".into(), ..Instance::default() };
    assert_eq!(marker(&inst), b"/run/roost/x.1/fc.sock");

    let jailed = Instance { sandbox: Sandbox::Jailed(NestId::new(3, 7)), ..Instance::default() };
    let cmdline = b"/firecracker\0--id\0s3-g7\0--start-time-us\x001\0";
    assert!(has_marker(cmdline, &marker(&jailed)));
    assert!(!has_marker(cmdline, &nest::marker(&NestId("s3-g70".into()))));
    assert!(!alive(u32::MAX, b"x"));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn kills_wait_for_the_process_to_let_go() {
    let mut child = std::process::Command::new("sleep").arg("60").spawn().unwrap();
    let pid = child.id();
    let deadline = Instant::now() + SOCK_WAIT;
    while !alive(pid, b"sleep") {
        assert!(Instant::now() < deadline, "sleep never showed its cmdline");
        sleep(SOCKET_POLL_INTERVAL).await;
    }
    assert!(!exited(pid, b"sleep"), "running");
    assert!(exited(pid, b"not-its-marker"), "a reused pid isn't the vmm");
    kill_vmm(pid, b"sleep").await.unwrap();
    // never reaped, so it's a zombie: its files are closed and kill returned without reaping it
    assert!(exited(pid, b"sleep"));
    child.wait().unwrap();
    assert!(exited(pid, b"sleep"));
}

#[test]
fn unlimited_devices_get_no_rate_limiter() {
    assert_eq!(rate_limiter(None, None, DISK_BOOT_BURST_SECS), None);
}

#[test]
fn configures_a_jailed_guest() {
    let mut f = fixture(true);
    f.driver.cfg.hugepages_2m = true;
    let (inst, guest) = f.allocate();
    let mac = guest.mac.clone();
    let boot = boot(guest, json!({"k": "v"}));
    let requests = wire(&f.driver.config_requests(&inst, &boot));

    let drive_limits = json!({"bandwidth": {"one_time_burst": 1_u64 << 30, "refill_time": 1000, "size": 64 << 20}});
    let drive = |id: &str, path: &str, root: bool, read_only: bool| {
        json!({"drive_id": id, "path_on_host": path, "is_root_device": root, "is_read_only": read_only, "rate_limiter": drive_limits,
            "blk_size": 512, "cache_type": "Unsafe", "discard": false, "io_engine": "Sync"})
    };
    let net_limits = json!({"bandwidth": {"refill_time": 1000, "size": 250 << 20}, "ops": {"refill_time": 1000, "size": 250_000}});
    let want = [
        ("/machine-config", json!({"huge_pages": "2M", "mem_size_mib": 2048, "vcpu_count": 4, "smt": false, "track_dirty_pages": false})),
        ("/boot-source", json!({"boot_args": BOOT_ARGS, "kernel_image_path": "/vmlinux"})),
        ("/drives/rootfs", drive("rootfs", "/base.ext4", true, true)),
        ("/drives/scratch", drive("scratch", "/scratch.ext4", false, false)),
        (
            "/network-interfaces/net1",
            json!({"guest_mac": mac, "host_dev_name": "wt0", "iface_id": "net1", "rx_rate_limiter": net_limits, "tx_rate_limiter": net_limits}),
        ),
        ("/vsock", json!({"guest_cid": 3, "uds_path": "/run/v.sock"})),
        ("/mmds/config", json!({"ipv4_address": "169.254.169.254", "network_interfaces": ["net1"], "version": "V2", "imds_compat": false})),
        ("/mmds", json!({"k": "v"})),
        ("/serial", json!({"rate_limiter": {"one_time_burst": 4 << 20, "refill_time": 1000, "size": 65536}})),
        ("/actions", json!({"action_type": "InstanceStart"})),
    ];
    assert_eq!(requests, want.map(|(path, body)| (path.to_owned(), body)));
}

#[test]
fn blobs_attach_after_scratch_in_name_order() {
    let f = fixture(true);
    let (inst, mut guest) = f.allocate();
    guest.blobs = BTreeMap::from([("worker".into(), "/a/worker-k1.squashfs".into()), ("web".into(), "/a/web-s1.squashfs".into())]);
    let boot_req = boot(guest, json!({}));
    let requests = wire(&f.driver.config_requests(&inst, &boot_req));
    let paths: Vec<_> = requests.iter().map(|(path, _)| path.as_str()).skip(2).take(5).collect();
    assert_eq!(paths, ["/drives/rootfs", "/drives/scratch", "/drives/blob_00", "/drives/blob_01", "/network-interfaces/net1"]);
    assert_eq!(requests[5].1["path_on_host"], "/worker.squashfs");
    assert_eq!(requests[5].1["is_read_only"], true);

    let f = fixture(false);
    let (inst, mut guest) = f.allocate();
    guest.blobs = BTreeMap::from([("rootfs".into(), "/a/workload-v1.squashfs".into())]);
    let boot_req = boot(guest, json!({}));
    let requests = wire(&f.driver.config_requests(&inst, &boot_req));
    assert_eq!(requests[2].1["path_on_host"], "/a/base.ext4");
    assert_eq!(requests[3].1["path_on_host"], path_str(&inst.disk));
    assert_eq!(requests[4].1["path_on_host"], "/a/workload-v1.squashfs");
    assert_eq!(requests.iter().find(|(p, _)| p == "/vsock").unwrap().1["uds_path"], path_str(&inst.vsock_path));
}

fn argv(cmd: &std::process::Command) -> Vec<String> {
    std::iter::once(cmd.get_program()).chain(cmd.get_args()).map(|a| a.to_string_lossy().into_owned()).collect()
}

#[test]
fn commands_join_the_guests_netns() {
    let f = fixture(true);
    let (inst, mut guest) = f.allocate();
    guest.netns = Some("/var/run/netns/birdfeeder-0".into());
    fs::create_dir_all(inst.disk.parent().unwrap()).unwrap();
    fs::write(&inst.disk, b"").unwrap();
    let args = argv(&f.driver.command(&inst, &guest).unwrap());
    assert_eq!(args[0], "/bin/false");
    assert_eq!(args[args.len() - 2..], ["--netns", "/var/run/netns/birdfeeder-0"]);
    let fsize = args.iter().find(|a| a.starts_with("fsize=")).unwrap();
    assert_eq!(fsize, &format!("fsize={}", 2048 * MIB), "the file size limit covers guest memory");

    // unjailed firecracker has no --netns, so ip execs it in place inside the namespace
    let f = fixture(false);
    let (inst, mut guest) = f.allocate();
    guest.netns = Some("/var/run/netns/birdfeeder-0".into());
    let api_sock = path_str(&inst.api_sock);
    assert_eq!(
        argv(&f.driver.command(&inst, &guest).unwrap()),
        ["ip", "netns", "exec", "birdfeeder-0", "/bin/false", "--api-sock", &api_sock, "--id", "test-host-example-0"]
    );
    guest.netns = None;
    assert_eq!(argv(&f.driver.command(&inst, &guest).unwrap())[0], "/bin/false");
}

#[tokio::test]
async fn sweeps_remove_orphan_cgroups() {
    let f = fixture(true);
    let (orphan, owned) = (f.driver.cgroup_leaf(&NestId::new(9, 9)), f.driver.cgroup_leaf(&NestId::new(1, 1)));
    fs::create_dir_all(&orphan).unwrap();
    fs::create_dir_all(&owned).unwrap();
    let live = Instance { sandbox: Sandbox::Jailed(NestId::new(1, 1)), ..Instance::default() };
    f.driver.sweep(&[&live]).await.unwrap();
    assert!(!orphan.exists());
    assert!(owned.exists());
}

#[tokio::test]
async fn sweeps_remove_orphan_nests() {
    let f = fixture(true);
    let root = nest::root(&f.dir.path().join("nest"), &NestId::new(2, 5));
    fs::create_dir_all(root.join("run")).unwrap();
    // a pid that isn't its vmm (the marker doesn't match), so the sweep only removes the nest
    fs::write(root.join("firecracker.pid"), std::process::id().to_string()).unwrap();
    f.driver.sweep(&[]).await.unwrap();
    assert!(!root.parent().unwrap().exists());
}

#[tokio::test]
async fn unjailed_cleanup_removes_disk_and_stage() {
    let f = fixture(false);
    let (inst, _) = f.allocate();
    let stage = snapshot::stage_dir(&inst);
    fs::create_dir_all(&stage).unwrap();
    fs::write(stage.join("vmstate"), b"").unwrap();
    fs::write(&inst.disk, b"").unwrap();
    f.driver.cleanup(&inst).await.unwrap();
    assert!(!inst.disk.exists());
    assert!(!stage.exists());
    f.driver.cleanup(&inst).await.expect("already gone isn't a failure");

    fs::create_dir_all(inst.disk.join("x")).unwrap();
    let err = f.driver.cleanup(&inst).await.unwrap_err();
    assert_eq!(err.0.iter().map(|s| s.stage).collect::<Vec<_>>(), [Stage::Disk]);
}

#[tokio::test]
async fn telemetry_attaches_through_fifos() {
    let f = fixture(false);
    let (inst, guest) = f.allocate();
    fs::create_dir_all(&guest.run_dir).unwrap();
    let fc = FakeApi::start(StatusCode::NO_CONTENT);
    f.driver.attach_telemetry(&Api::new(fc.path()), &inst).await.unwrap();

    let (log, metrics) = (guest.run_dir.join("fc.log"), guest.run_dir.join("fc-metrics"));
    assert_eq!(
        fc.take(),
        [
            (
                "PUT".into(),
                "/logger".into(),
                json!({"log_path": path_str(&log), "level": "Warning", "show_level": true, "show_log_origin": false})
            ),
            ("PUT".into(), "/metrics".into(), json!({"metrics_path": path_str(&metrics), "emit_id": false})),
        ]
    );
    for fifo in [log, metrics] {
        assert!(fs::metadata(&fifo).unwrap().file_type().is_fifo(), "{}", fifo.display());
    }
}

#[tokio::test]
async fn listeners_are_awaited_past_their_bind() {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, bind, listen, socket};

    let dir = tempfile::Builder::new().prefix("fc").tempdir_in("/tmp").unwrap();
    let sock = dir.path().join("api.sock");
    let fd = socket(AddressFamily::Unix, SockType::Stream, SockFlag::empty(), None).unwrap();
    bind(std::os::fd::AsRawFd::as_raw_fd(&fd), &UnixAddr::new(&sock).unwrap()).unwrap();
    let early = timeout(Duration::from_millis(50), wait_for_listener(&sock)).await;
    assert!(early.is_err(), "bound but not listening");
    listen(&fd, nix::sys::socket::Backlog::new(1).unwrap()).unwrap();
    wait_for_listener(&sock).await.unwrap();
}

#[tokio::test]
async fn cleanup_reports_a_nest_it_cant_find() {
    let f = fixture(false);
    let inst = Instance { sandbox: Sandbox::Jailed(NestId::new(0, 1)), ..Instance::default() };
    let err = f.driver.cleanup(&inst).await.unwrap_err();
    assert_eq!(err.0.iter().map(|s| s.stage).collect::<Vec<_>>(), [Stage::Nest]);
    assert!(err.to_string().contains("nest s0-g1 left behind"), "{err}");
}

#[test]
fn start_failures_carry_the_console_head() {
    let dir = tempfile::tempdir().unwrap();
    let console = dir.path().join("console.log");
    fs::write(&console, format!("  booting\n{}", "x".repeat(4096))).unwrap();
    let err = with_console(anyhow::anyhow!("no api socket"), &console);
    let context = err.to_string();
    assert!(context.starts_with("console: booting\n"), "{context}");
    assert_eq!(context.len(), "console: ".len() + usize::try_from(CONSOLE_HEAD_BYTES).unwrap() - 2, "trimmed head only");
    assert_eq!(with_console(anyhow::anyhow!("x"), &dir.path().join("missing")).to_string(), "x");
}
