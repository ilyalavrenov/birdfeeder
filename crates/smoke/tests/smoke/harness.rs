//! A roost and dispatcher under test, their clients, and the cleanup that leaves the host idle for the next test.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use roost_api::v1::{self, roost_service_client::RoostServiceClient};
use serde::de::DeserializeOwned;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};

use crate::contract::{Artifact, RoostConfig, Saved};
use crate::snapshots::SnapshotStore;
use crate::telemetry::Telemetry;

pub const REPO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const ARTIFACTS: &str = "/var/lib/birdfeeder/artifacts/artifacts.json";
const CGROUPS: &str = "/sys/fs/cgroup/birdfeeder";
const HOST_ADDR: &str = "127.0.0.1:17443";
pub const DISPATCHER_ADDR: &str = "127.0.0.1:18080";
/// every call carries this trace, which the telemetry checks follow through the dispatcher into roost.
const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
pub const TRACE_ID: &str = "0123456789abcdef0123456789abcdef";

pub type Client = RoostServiceClient<Channel>;

/// A service's executable in bin/, where dev/run-linux.sh installs them.
pub fn bin(name: &str) -> PathBuf {
    Path::new(REPO).join("bin").join(name)
}

pub fn artifacts() -> BTreeMap<String, Artifact> {
    read_json(ARTIFACTS)
}

pub struct Harness {
    pub state: PathBuf,
    pub run: PathBuf,
    pub config: RoostConfig,
    pub telemetry: Option<Telemetry>,
    pub store: Option<SnapshotStore>,
    host: Client,
    dispatcher: Client,
    roost_service: Option<Service>,
    dispatcher_service: Option<Service>,
}

impl Harness {
    pub fn new() -> Self {
        assert!(nix::unistd::geteuid().is_root(), "smoke tests need root on an idle development host");
        let roost = Command::new("pgrep").args(["-x", "roost"]).output().expect("run pgrep");
        assert_eq!(roost.status.code(), Some(1), "smoke tests need an idle development host; roost is running");
        assert!(command("ip", ["netns", "list"]).trim().is_empty(), "smoke tests need an idle development host; network namespaces exist");
        check_cgroups();
        // kept after a failed test for its logs, and on the artifacts' filesystem so nests can hardlink them.
        let state = tempfile::Builder::new().prefix("smoke.").tempdir_in("/var/lib/birdfeeder").expect("create state dir").keep();
        // restores run the uffd handler as vm uids, which need to reach the nest like they do /var/lib/birdfeeder.
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).expect("open up state dir");
        // run_dir lives on tmpfs like /run/birdfeeder.
        let run = tempfile::Builder::new().prefix("birdfeeder-smoke.").tempdir_in("/run").expect("create run dir").keep();
        let config = RoostConfig {
            listen_addr: HOST_ADDR,
            state_dir: state.clone(),
            run_dir: run.clone(),
            host_id: "smoke",
            max_sessions: 2,
            max_vcpus: 2,
            max_memory_mib: 1024,
            dnsgate_port: 15354,
            dns_upstream: None,
            ready_timeout_sec: 60,
            reap_interval_sec: 1,
            // the telemetry checks wait for roost's first VM metrics sample.
            metrics_interval_sec: 1,
            firecracker_bin: "/usr/local/bin/firecracker",
            kernel_image_path: String::new(),
            kernel_sha256: String::new(),
            snapshot_store: None,
            templates: Vec::new(),
        };
        let client = |addr: &str| {
            let endpoint = Endpoint::from_shared(format!("http://{addr}")).expect("endpoint");
            RoostServiceClient::new(endpoint.timeout(Duration::from_secs(15)).connect_lazy())
        };
        Self {
            state,
            run,
            config,
            telemetry: None,
            store: None,
            host: client(HOST_ADDR),
            dispatcher: client(DISPATCHER_ADDR),
            roost_service: None,
            dispatcher_service: None,
        }
    }

    pub fn host(&self) -> Client {
        self.host.clone()
    }

    pub fn dispatcher(&self) -> Client {
        self.dispatcher.clone()
    }

    pub fn start_roost(&mut self) {
        assert!(self.roost_service.is_none(), "roost is already running");
        let config = self.state.join("config.json");
        fs::write(&config, serde_json::to_vec(&self.config).unwrap()).expect("write roost config");
        self.roost_service = Some(self.start_service("roost", &[], &[OsStr::new("--config"), config.as_os_str()]));
    }

    pub fn stop_roost(&mut self) {
        self.roost_service.take().expect("roost is running").stop().unwrap_or_else(|e| panic!("{e:#}"));
    }

    pub fn start_dispatcher(&mut self) {
        assert!(self.dispatcher_service.is_none(), "the dispatcher is already running");
        let env = [
            ("BIRDFEEDER_HOSTS", HOST_ADDR),
            ("BIRDFEEDER_DISPATCHER_LISTEN_ADDR", DISPATCHER_ADDR),
            ("BIRDFEEDER_POLL_INTERVAL", "100ms"),
        ];
        self.dispatcher_service = Some(self.start_service("dispatcher", &env, &[]));
    }

    pub fn stop_dispatcher(&mut self) {
        self.dispatcher_service.take().expect("the dispatcher is running").stop().unwrap_or_else(|e| panic!("{e:#}"));
    }

    fn start_service(&self, kind: &str, env: &[(&str, &str)], args: &[&OsStr]) -> Service {
        let mut cmd = Command::new(bin(kind));
        cmd.args(args).envs(env.iter().copied());
        if self.telemetry.is_some() {
            cmd.envs(Telemetry::env(kind));
        }
        if self.store.is_some() {
            cmd.envs(SnapshotStore::env());
        }
        Service::start(kind, &self.state.join(format!("{kind}.log")), cmd)
    }

    /// Whether both roost and the dispatcher report a guest waiting in a pool.
    pub async fn ready(&self) -> anyhow::Result<bool> {
        Ok(has_ready(self.host()).await? && has_ready(self.dispatcher()).await?)
    }

    /// Whether roost has a guest waiting in a pool.
    pub async fn pooled(&self) -> anyhow::Result<bool> {
        has_ready(self.host()).await
    }

    pub async fn check_budget(&self, vcpus: i32, memory_mib: i32) {
        let status = ok(self.host().host_status(req(v1::HostStatusRequest {}))).await;
        assert_eq!((status.reserved_vcpus, status.reserved_memory_mib), (vcpus, memory_mib), "reserved vCPUs and MiB");
    }

    pub fn saved(&self, session: &v1::Session) -> Saved {
        read_json(self.state.join("sessions").join(format!("{}.json", session.name)))
    }

    /// Checks what any supervisor must preserve when it stops roost: VMMs, the uffd handlers serving restored
    /// guests' memory, vsock sockets, and the runtime directory.
    pub fn verify_detached(&self, saved: &BTreeMap<String, Saved>) {
        assert!(self.run.is_dir(), "stopping roost removed the live guest runtime directory");
        for session in saved.values() {
            assert!(proc_exists(session.pid()), "stopping roost killed a VMM");
            if let Some(uffd) = session.uffd_pid.filter(|&p| p != 0) {
                assert!(proc_exists(uffd), "stopping roost killed a uffd handler");
            }
            assert!(session.vsock_path.exists(), "stopping roost removed a live vsock socket");
        }
    }

    /// Kills the guests this test's roost recorded. They outlive roost on purpose.
    fn retire_guests(&self) -> Vec<String> {
        let mut failures = Vec::new();
        let records = match fs::read_dir(self.state.join("sessions")) {
            Ok(entries) => entries.flatten().map(|e| e.path()).filter(|p| p.extension() == Some(OsStr::new("json"))).collect(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return vec![format!("list session records: {e}")],
        };
        for path in records {
            let saved: Saved = match fs::read(&path).map_err(anyhow::Error::from).and_then(|d| Ok(serde_json::from_slice(&d)?)) {
                Ok(saved) => saved,
                Err(e) => {
                    failures.push(format!("read {}: {e}", path.display()));
                    continue;
                }
            };
            if let Some(nest) = saved.nest_id.filter(|n| !n.is_empty()) {
                match fs::write(Path::new(CGROUPS).join(nest).join("cgroup.kill"), "1") {
                    Err(e) if e.kind() != io::ErrorKind::NotFound => failures.push(format!("kill {}: {e}", path.display())),
                    _ => {}
                }
            }
            if !saved.netns.is_empty() {
                let _ = Command::new("ip").args(["netns", "delete", &saved.netns]).status();
            }
        }
        failures
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        // stop the services first so roost can't replace the guests we retire below.
        let services = [
            self.dispatcher_service.take(),
            self.roost_service.take(),
            self.telemetry.as_mut().and_then(|t| t.collector.take()),
            self.store.as_mut().and_then(|s| s.weed.take()),
        ];
        let mut failures: Vec<String> = services.into_iter().flatten().filter_map(|s| s.stop().err()).map(|e| format!("{e:#}")).collect();
        failures.extend(self.retire_guests());
        if std::thread::panicking() {
            eprintln!("failure logs: {}; guest consoles: {}", self.state.display(), self.run.display());
            for log in [&self.state, &self.run].into_iter().flat_map(|d| files(d)).filter(|p| p.extension() == Some(OsStr::new("log"))) {
                eprintln!("{}:\n{}", log.display(), tail(&log, 16000));
            }
        } else {
            for dir in [&self.state, &self.run] {
                if let Err(e) = fs::remove_dir_all(dir) {
                    failures.push(format!("remove {}: {e}", dir.display()));
                }
            }
        }
        assert!(failures.is_empty() || std::thread::panicking(), "cleanup failed:\n{}", failures.join("\n"));
    }
}

async fn has_ready(mut client: Client) -> anyhow::Result<bool> {
    let status = client.host_status(req(v1::HostStatusRequest {})).await?.into_inner();
    Ok(status.pools.iter().any(|p| p.ready >= 1))
}

/// A child process whose output goes to a log file, which [`Service::stop`] ends with a signal.
pub struct Service {
    name: String,
    log: PathBuf,
    signal: Signal,
    /// taken by [`Service::stop`], so a drop only kills what wasn't stopped.
    child: Option<Child>,
}

impl Service {
    /// Starts `cmd`, which [`Service::stop`] ends with SIGTERM.
    pub fn start(name: &str, log: &Path, cmd: Command) -> Self {
        Self::start_stopped_by(Signal::SIGTERM, name, log, cmd)
    }

    pub fn start_stopped_by(signal: Signal, name: &str, log: &Path, mut cmd: Command) -> Self {
        let out = OpenOptions::new().create(true).append(true).open(log).expect("open service log");
        let child = cmd
            .stdin(Stdio::null())
            .stdout(out.try_clone().expect("clone log fd"))
            .stderr(out)
            .spawn()
            .unwrap_or_else(|e| panic!("start {name}: {e}"));
        Self { name: name.to_owned(), log: log.to_owned(), signal, child: Some(child) }
    }

    /// Signals the process and waits for it, reporting an early exit, a failed one, or one that took too long.
    pub fn stop(mut self) -> anyhow::Result<()> {
        let mut child = self.child.take().expect("only stop takes the child");
        let see = format!("see {}", self.log.display());
        if let Some(status) = child.try_wait()? {
            bail!("{} exited before shutdown: {status}; {see}", self.name);
        }
        let pid = Pid::from_raw(i32::try_from(child.id()).expect("pid fits i32"));
        kill(pid, self.signal).with_context(|| format!("signal {}", self.name))?;
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            match child.try_wait()? {
                Some(status) if status.success() || status.signal() == Some(self.signal as i32) => return Ok(()),
                Some(status) => bail!("{} exited with {status}; {see}", self.name),
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        bail!("{} did not stop within 20 seconds; {see}", self.name)
    }
}

impl Drop for Service {
    /// If a test panicked before stopping a service, the service mustn't outlive it.
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Runs a command that must succeed and returns its stdout.
pub fn command<S: AsRef<OsStr>>(program: impl AsRef<OsStr>, args: impl IntoIterator<Item = S>) -> String {
    let mut cmd = Command::new(program);
    cmd.args(args);
    let out = cmd.output().unwrap_or_else(|e| panic!("run {cmd:?}: {e}"));
    assert!(out.status.success(), "{cmd:?}: {}\n{}", out.status, String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).expect("utf-8 output")
}

pub fn req<T>(msg: T) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut().insert("traceparent", MetadataValue::from_static(TRACEPARENT));
    req
}

/// The response of a call that must succeed.
pub async fn ok<T>(call: impl Future<Output = Result<Response<T>, Status>>) -> T {
    call.await.unwrap_or_else(|status| panic!("{status}")).into_inner()
}

pub fn claim_request(template: &str) -> v1::ClaimSessionRequest {
    v1::ClaimSessionRequest { template_id: template.to_owned(), ..Default::default() }
}

pub async fn claim(mut client: Client, claim: v1::ClaimSessionRequest) -> v1::Session {
    ok(client.claim_session(req(claim))).await.session.expect("claim answered a session")
}

pub async fn release(mut client: Client, session: &v1::Session) {
    let delete = v1::DeleteSessionRequest { name: session.name.clone(), generation: session.generation };
    ok(client.delete_session(req(delete))).await;
}

pub async fn sessions(mut client: Client) -> anyhow::Result<Vec<v1::Session>> {
    Ok(client.list_sessions(req(v1::ListSessionsRequest::default())).await?.into_inner().sessions)
}

/// Retries `check` for up to 90 seconds until it reports true.
pub async fn eventually(what: &str, mut check: impl AsyncFnMut() -> anyhow::Result<bool>) {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let last = match check().await {
            Ok(true) => return,
            Ok(false) => None,
            Err(e) => Some(e),
        };
        assert!(Instant::now() < deadline, "timed out waiting for {what}: {last:?}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Whether `addr` accepts a TCP connection within a second.
pub async fn listening(addr: &str) -> anyhow::Result<bool> {
    tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(addr)).await??;
    Ok(true)
}

// pooled connections would outlive the guest behind an endpoint, and its replacement reuses the host port.
static HTTP: LazyLock<reqwest::Client> = LazyLock::new(|| {
    // building with the rest of the workspace gives reqwest rustls with no crypto provider, and a client needs one.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder().pool_max_idle_per_host(0).timeout(Duration::from_secs(5)).build().expect("HTTP client")
});

/// Sends a request to the session's `http` endpoint and returns the body of the response, which must have `status`.
pub async fn guest_request(session: &v1::Session, method: reqwest::Method, path: &str, body: &str, status: u16) -> Vec<u8> {
    let url = format!("http://{}{path}", session.endpoints["http"]);
    let res = HTTP.request(method, &url).body(body.to_owned()).send().await.unwrap_or_else(|e| panic!("{url}: {e}"));
    let got = res.status().as_u16();
    let data = res.bytes().await.unwrap_or_else(|e| panic!("{url}: {e}")).to_vec();
    assert_eq!(got, status, "{path}: {}", String::from_utf8_lossy(&data));
    data
}

pub async fn get(session: &v1::Session, path: &str, status: u16) -> Vec<u8> {
    guest_request(session, reqwest::Method::GET, path, "", status).await
}

pub async fn post(session: &v1::Session, path: &str, body: &str, status: u16) -> Vec<u8> {
    guest_request(session, reqwest::Method::POST, path, body, status).await
}

pub fn read_json<T: DeserializeOwned>(path: impl AsRef<Path>) -> T {
    let path = path.as_ref();
    let data = fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&data).unwrap_or_else(|e| panic!("decode {}: {e}", path.display()))
}

/// The regular files under `dir`, which might vanish or change underneath us. Skips FIFOs like Firecracker's log,
/// since opening one blocks until a writer shows up.
pub fn files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else { return found };
    for entry in entries.flatten() {
        match entry.file_type() {
            Ok(t) if t.is_dir() => found.extend(files(&entry.path())),
            Ok(t) if t.is_file() => found.push(entry.path()),
            _ => {}
        }
    }
    found
}

/// Fails if a VMM is still in a birdfeeder cgroup.
pub fn check_cgroups() {
    for procs in files(Path::new(CGROUPS)).into_iter().filter(|p| p.file_name() == Some(OsStr::new("cgroup.procs"))) {
        let pids = fs::read_to_string(&procs).unwrap_or_default();
        assert!(pids.trim().is_empty(), "VMM still in {}: {pids}", procs.display());
    }
}

pub fn proc_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// The last `n` bytes of a file.
fn tail(path: &Path, n: u64) -> String {
    let read = || -> io::Result<Vec<u8>> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len();
        file.seek(SeekFrom::Start(len.saturating_sub(n)))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    };
    read().map_or_else(|e| format!("<{e}>"), |d| String::from_utf8_lossy(&d).into_owned())
}
