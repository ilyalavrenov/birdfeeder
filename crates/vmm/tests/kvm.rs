//! Boots, snapshots and restores real guests through the driver, in every restore mode, local and remote. Needs root
//! on an idle KVM host, with Firecracker, its jailer and the uffd handler in /usr/local/bin, plus the guest artifacts
//! from `dev/run-linux.sh artifacts`. Run it with `dev/run-linux.sh snapshot`.
#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::num::NonZeroU64;
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::sched::{CloneFlags, setns};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::{Value, json};
use vmm::firecracker::{Config, Driver, Jailer};
use vmm::{Boot, Driver as _, Guest, Instance, Limits, RemoteMemory, RestoreMode, RestoreSource};

const BIN_DIR: &str = "/usr/local/bin";
const ARTIFACTS: &str = "/var/lib/birdfeeder/artifacts/artifacts.json";
// roost's default
const BOOT_ARGS: &str = "init=/sbin/init birdfeeder.guest=1 reboot=k panic=-1 nomodule transparent_hugepage=always console=ttyS0 \
                         i8042.noaux i8042.nomux i8042.dumbkbd swiotlb=noforce pci=off";
const UID_BASE: u32 = 10000;
// every guest's nic looks the same from inside its own namespace, as roost sets it up
const GUEST_ADDR: &str = "172.16.0.2:8080";
const GATEWAY: &str = "172.16.0.1/30";
const GATEWAY_MAC: &str = "06:00:ac:10:00:01";
const GUEST_MAC: &str = "06:00:ac:10:00:02";
const GUEST_PORT: u32 = 5000;
const READY_TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs root and KVM; dev/run-linux.sh snapshot runs it"]
async fn restores_in_every_mode() {
    assert!(nix::unistd::geteuid().is_root(), "run this as root on an idle development host");
    // the driver logs Firecracker's own warnings and errors
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let h = Harness::new();
    let snap = h.state.path().join("snapshots/http");

    let golden = h.boot(0, None).await;
    h.driver.snapshot(&golden.inst, &snap, false).await.expect("snapshot");
    h.destroy(golden).await;
    // clones wake up with the snapshot's wall clock until something sets it
    tokio::time::sleep(Duration::from_secs(3)).await;

    for mode in [RestoreMode::Eager, RestoreMode::Lazy, RestoreMode::Record, RestoreMode::Prefetch] {
        let vm = h.boot(0, Some(RestoreSource { dir: snap.clone(), mode, remote: None })).await;
        if mode == RestoreMode::Record {
            assert_eq!(vm.get("/"), "hello from birdfeeder\n", "warm-up");
            h.driver.finish_recording(&vm.inst, &snap).await.expect("finish recording");
        }
        h.destroy(vm).await;
    }

    let mem = h.driver.export_memory(&snap).await.expect("export memory");
    let store = RangeServer::start(vec![("/mem", mem), ("/working-set.pack", snap.join(vmm::SNAPSHOT_WORKING_SET_PACK))]);
    let remote = RemoteMemory { mem_url: format!("{}/mem", store.url), working_set_url: Some(format!("{}/working-set.pack", store.url)) };
    for mode in [RestoreMode::Eager, RestoreMode::Lazy, RestoreMode::Prefetch] {
        let vm = h.boot(0, Some(RestoreSource { dir: snap.clone(), mode, remote: Some(remote.clone()) })).await;
        let log = fs::read_to_string(vm.uffd_log()).unwrap();
        assert!(log.contains(r#""remote":true"#), "{mode:?} read the local memory file:\n{log}");
        if mode == RestoreMode::Prefetch {
            assert!(log.contains(r#""packed":true"#), "prefetch didn't read the packed working set:\n{log}");
        }
        h.destroy(vm).await;
    }
    assert!(store.served() > 0);

    let clones = [
        h.boot(0, Some(RestoreSource { dir: snap.clone(), mode: RestoreMode::Lazy, remote: None })).await,
        h.boot(1, Some(RestoreSource { dir: snap.clone(), mode: RestoreMode::Prefetch, remote: None })).await,
    ];
    assert_ne!(clones[0].get("/test/random"), clones[1].get("/test/random"), "clones share the golden guest's random stream");
    for vm in clones {
        // vsock resets on restore, and the guest's listener still has to serve stats and logs
        let stats: Value = serde_json::from_str(&vm.guest_call("STATS 1\n")).unwrap();
        assert!(stats["memory"].is_object(), "{stats}");
        let record: Value = serde_json::from_str(&vm.guest_call("LOGS web 0\n")).unwrap();
        assert!(record["line"].as_str().unwrap().contains("serving /srv"), "{record}");
        h.destroy(vm).await;
    }
}

struct Harness {
    driver: Driver,
    state: tempfile::TempDir,
    run: tempfile::TempDir,
    artifacts: HashMap<String, PathBuf>,
    metadata: Value,
    netns: [Netns; 2],
    generation: AtomicU64,
}

impl Harness {
    fn new() -> Self {
        #[derive(serde::Deserialize)]
        struct Artifact {
            path: PathBuf,
        }
        let artifacts: HashMap<String, Artifact> = serde_json::from_slice(&fs::read(ARTIFACTS).unwrap()).unwrap();
        let artifacts: HashMap<_, _> = artifacts.into_iter().map(|(name, a)| (name, a.path)).collect();
        // nest hardlinks have to be on the artifacts' filesystem, and the handler runs unchrooted as the vm's uid, so it
        // needs to be able to traverse to the nest
        let state = tempfile::Builder::new().prefix("vmm-kvm.").tempdir_in("/var/lib/birdfeeder").unwrap();
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let run = tempfile::Builder::new().prefix("vmm-kvm.").tempdir_in("/run").unwrap();

        let driver = Driver::new(
            Config {
                firecracker_bin: Path::new(BIN_DIR).join("firecracker"),
                kernel_image_path: artifacts["kernel"].clone(),
                boot_args: BOOT_ARGS.into(),
                hugepages_2m: false,
                jailer: Some(Jailer {
                    bin: Path::new(BIN_DIR).join("jailer"),
                    chroot_base: state.path().join("nest"),
                    uid_base: UID_BASE,
                    cgroup_limits: false,
                }),
                serial_bytes_per_sec: NonZeroU64::new(64 << 10),
                uffd_handler_bin: Path::new(BIN_DIR).join("uffd-handler"),
            },
            &opentelemetry::global::meter("kvm"),
        );
        driver.setup().expect("cgroup setup");

        let mut manifest: Value =
            serde_json::from_slice(&fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/http.json")).unwrap()).unwrap();
        manifest["containers"][0]["args"] = json!(["/usr/local/bin/serve", "--test-control"]);
        let metadata = json!({"version": 1, "template_id": "vmm-kvm", "manifest": manifest, "blobs": ["alpine"]});
        let netns = [Netns::create(0), Netns::create(1)];
        Self { driver, state, run, artifacts, metadata, netns, generation: AtomicU64::new(0) }
    }

    /// Boots slot's guest cold or from `restore` and waits for its workload to serve.
    async fn boot(&self, slot: u32, restore: Option<RestoreSource>) -> Vm {
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let name = format!("vmm-kvm-{slot}");
        let mut inst = Instance {
            name: name.clone(),
            generation,
            slot,
            disk: self.state.path().join(format!("disks/{name}.{generation}.ext4")),
            ..Instance::default()
        };
        let run_dir = self.run.path().join(format!("{name}.{generation}"));
        let guest = Guest {
            vcpus: 1.try_into().unwrap(),
            mem_mib: 512,
            tap: "tap0".into(),
            netns: Some(self.netns[slot as usize].path()),
            mac: GUEST_MAC.into(),
            run_dir: run_dir.clone(),
            base_disk: self.artifacts["base.ext4"].clone(),
            blobs: BTreeMap::from([("alpine".into(), self.artifacts["alpine.squashfs"].clone())]),
        };
        self.driver.allocate(&mut inst, &guest);
        let scratch = restore.as_ref().map_or_else(|| self.artifacts["scratch.ext4"].clone(), |src| src.dir.join(vmm::SNAPSHOT_DISK));
        fs::create_dir_all(inst.disk.parent().unwrap()).unwrap();
        vmm::copy_disk(&scratch, &inst.disk).await.expect("copy disk");
        self.driver.prepare(&inst, &guest).expect("prepare");

        let boot = Boot { guest, limits: Limits::default(), metadata: self.metadata.clone(), console: run_dir.join("console.log") };
        let started = Instant::now();
        let result = match &restore {
            None => self.driver.start(&mut inst, &boot).await,
            Some(src) => self.driver.restore(&mut inst, &boot, src).await,
        };
        let vm = Vm { inst, run_dir, netns: self.netns[slot as usize].path(), destroyed: false };
        let what = restore.as_ref().map_or_else(|| "cold".to_owned(), |src| format!("{:?} remote={}", src.mode, src.remote.is_some()));
        if let Err(err) = result {
            vm.dump_logs();
            panic!("{what} boot: {err:#}");
        }
        if restore.is_some() {
            vm.set_clock();
        }
        if !vm.wait_ready() {
            vm.dump_logs();
            panic!("{what} guest never served");
        }
        eprintln!("{what}: ready in {:?}", started.elapsed());

        let guest_ns: i128 = vm.get("/test/time").trim().parse().unwrap();
        let skew = Duration::from_nanos((now_ns() - guest_ns).unsigned_abs().try_into().unwrap());
        assert!(skew < Duration::from_secs(1), "{what} guest clock is {skew:?} off");
        assert!(self.driver.alive(&vm.inst), "{what} vmm died");
        vm
    }

    async fn destroy(&self, mut vm: Vm) {
        self.driver.kill(&vm.inst).await.expect("kill");
        self.driver.cleanup(&vm.inst).await.expect("cleanup");
        assert!(!self.driver.alive(&vm.inst));
        fs::remove_dir_all(&vm.run_dir).unwrap();
        vm.destroyed = true;
    }
}

struct Vm {
    inst: Instance,
    run_dir: PathBuf,
    netns: PathBuf,
    destroyed: bool,
}

impl Vm {
    fn uffd_log(&self) -> PathBuf {
        self.run_dir.join("uffd-handler.log")
    }

    fn dump_logs(&self) {
        for path in [self.run_dir.join("console.log"), self.uffd_log()] {
            let data = fs::read(&path).unwrap_or_default();
            eprintln!("{}:\n{}", path.display(), String::from_utf8_lossy(&data[data.len().saturating_sub(16000)..]));
        }
    }

    fn wait_ready(&self) -> bool {
        let deadline = Instant::now() + READY_TIMEOUT;
        while Instant::now() < deadline {
            if self.try_get("/").is_ok_and(|body| body == "hello from birdfeeder\n") {
                return true;
            }
            thread::sleep(Duration::from_millis(100));
        }
        false
    }

    fn get(&self, path: &str) -> String {
        self.try_get(path).unwrap_or_else(|err| panic!("GET {path}: {err}"))
    }

    /// GETs `path` from the guest's workload, from inside its namespace.
    fn try_get(&self, path: &str) -> std::io::Result<String> {
        let (netns, path) = (self.netns.clone(), path.to_owned());
        // setns only moves the calling thread, and that thread then exits, so nothing else runs in the guest's namespace
        thread::spawn(move || {
            setns(File::open(netns)?, CloneFlags::CLONE_NEWNET)?;
            let mut conn = TcpStream::connect_timeout(&GUEST_ADDR.parse().unwrap(), Duration::from_secs(1))?;
            conn.set_read_timeout(Some(Duration::from_secs(10)))?;
            write!(conn, "GET {path} HTTP/1.0\r\nHost: guest\r\n\r\n")?;
            let mut resp = String::new();
            conn.read_to_string(&mut resp)?;
            let (head, body) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
            if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
                return Err(std::io::Error::other(head.lines().next().unwrap_or_default().to_owned()));
            }
            Ok(body.to_owned())
        })
        .join()
        .unwrap()
    }

    /// One request to birdfeeder-init's vsock server, returning the first reply line.
    fn guest_call(&self, request: &str) -> String {
        self.try_guest_call(request).unwrap_or_else(|err| {
            self.dump_logs();
            panic!("{} {}: {err}", self.inst.name, request.trim_end());
        })
    }

    fn try_guest_call(&self, request: &str) -> std::io::Result<String> {
        let conn = UnixStream::connect(&self.inst.vsock_path)?;
        conn.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut reader = BufReader::new(conn.try_clone()?);
        // single write: Firecracker drops the connection if it can't read the whole CONNECT line when it wakes up
        (&conn).write_all(format!("CONNECT {GUEST_PORT}\n").as_bytes())?;
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if !line.starts_with("OK ") {
            return Err(std::io::Error::other(format!("vsock handshake: {line:?}")));
        }
        (&conn).write_all(request.as_bytes())?;
        line.clear();
        reader.read_line(&mut line)?;
        Ok(line)
    }

    /// What roost does after every restore.
    fn set_clock(&self) {
        // Firecracker before 1.16 can break a connection made before the guest acknowledges the restore's transport
        // reset (firecracker#5882), so like roost, this retries on a new connection with a fresh time.
        // a hung attempt only gives up at try_guest_call's 5s read timeout, so the window has to fit several.
        let started = Instant::now();
        loop {
            match self.try_guest_call(&format!("CLOCK 1 {}\n", now_ns())) {
                Ok(reply) if reply == "OK\n" => return,
                result => assert!(started.elapsed() < Duration::from_secs(30), "{} set clock: {result:?}", self.inst.name),
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Vm {
    // a failed assertion shouldn't leave guests running. without the runtime, killing the processes is all we can do
    fn drop(&mut self) {
        if !self.destroyed {
            for pid in [self.inst.pid, self.inst.uffd_pid].into_iter().flatten() {
                let _ = kill(Pid::from_raw(pid.cast_signed()), Signal::SIGKILL);
            }
        }
    }
}

fn now_ns() -> i128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().cast_signed()
}

/// A namespace with a slot's tap in it, owned by the slot's vm uid, like roost's would be.
struct Netns(String);

impl Netns {
    fn create(slot: u32) -> Self {
        let name = format!("bfvmm-kvm-{slot}");
        let uid = (UID_BASE + slot).to_string();
        let _ = Command::new("ip").args(["netns", "del", &name]).status();
        for args in [
            vec!["netns", "add", &name],
            vec!["-n", &name, "tuntap", "add", "dev", "tap0", "mode", "tap", "user", &uid, "group", &uid],
            vec!["-n", &name, "link", "set", "tap0", "address", GATEWAY_MAC],
            vec!["-n", &name, "addr", "add", GATEWAY, "dev", "tap0"],
            vec!["-n", &name, "link", "set", "tap0", "up"],
        ] {
            let status = Command::new("ip").args(&args).status().unwrap();
            assert!(status.success(), "ip {}: {status}", args.join(" "));
        }
        Self(name)
    }

    fn path(&self) -> PathBuf {
        Path::new("/run/netns").join(&self.0)
    }
}

impl Drop for Netns {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.0]).status();
    }
}

/// Serves files by range, like the presigned GETs roost hands the handler.
struct RangeServer {
    url: String,
    served: Arc<AtomicU64>,
}

impl RangeServer {
    fn start(files: Vec<(&'static str, PathBuf)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let files: Arc<HashMap<_, _>> = Arc::new(files.into_iter().map(|(path, file)| (path, File::open(file).unwrap())).collect());
        let served = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&served);
        thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let (files, counter) = (Arc::clone(&files), Arc::clone(&counter));
                thread::spawn(move || {
                    let _ = serve(conn, &files, &counter);
                });
            }
        });
        Self { url, served }
    }

    fn served(&self) -> u64 {
        self.served.load(Ordering::Relaxed)
    }
}

fn serve(conn: TcpStream, files: &HashMap<&str, File>, served: &AtomicU64) -> std::io::Result<()> {
    let mut reader = BufReader::new(conn.try_clone()?);
    let mut out = conn;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let path = line.split_whitespace().nth(1).unwrap_or("/").to_owned();
        let mut range = None;
        loop {
            let mut header = String::new();
            reader.read_line(&mut header)?;
            if header.trim().is_empty() {
                break;
            }
            if let Some(v) = header.to_ascii_lowercase().strip_prefix("range: bytes=") {
                let (a, b) = v.trim().split_once('-').unwrap();
                range = Some((a.parse::<u64>().unwrap(), b.parse::<u64>().unwrap()));
            }
        }
        let (Some(file), Some((start, last))) = (files.get(path.as_str()), range) else {
            write!(out, "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")?;
            continue;
        };
        let last = last.min(file.metadata()?.len() - 1);
        let mut body = vec![0; usize::try_from(last + 1 - start).unwrap()];
        file.read_exact_at(&mut body, start)?;
        write!(out, "HTTP/1.1 206 Partial Content\r\ncontent-length: {}\r\n\r\n", body.len())?;
        out.write_all(&body)?;
        served.fetch_add(1, Ordering::Relaxed);
    }
}
