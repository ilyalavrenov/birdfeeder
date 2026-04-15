//! Runs the example workloads through the dispatcher and roost: claims, the host budget, adoption across a roost
//! restart, and teardown, with the lifecycle and telemetry checks on top.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, Instant};

use roost_api::v1;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tonic::Code;

use crate::cli;
use crate::contract::{Artifact, Saved, Snapshot, Template, Warmup};
use crate::harness::{
    Harness, REPO, artifacts, bin, check_cgroups, claim, claim_request, command, eventually, files, get, ok, read_json, release, req,
    sessions,
};
use crate::lifecycle::{Ending, Lifecycle};
use crate::telemetry::{Telemetry, modes};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Example {
    Http,
    Shared,
}

impl Example {
    fn name(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Shared => "shared",
        }
    }

    pub fn manifest(self) -> Value {
        read_json(Path::new(REPO).join("examples").join(format!("{}.json", self.name())))
    }

    /// What the workload serves at /.
    pub fn body(self) -> &'static str {
        match self {
            Self::Http => "hello from birdfeeder\n",
            Self::Shared => "hello through a shared volume\n",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    Plain,
    /// claims, isolation, replacement after expiry and failure, and a dispatcher restart, on restored clones.
    Lifecycle,
    /// the guest's logs, the services' logs, traces and metrics, and a collector outage.
    Telemetry,
}

/// Both services on a template that can't boot. That's enough to check discovery, the budget, and the state lock.
pub async fn services() {
    let mut h = Harness::new();
    let null = Artifact { path: "/dev/null".into(), sha256: hex::encode(Sha256::digest(b"")) };
    h.config.use_kernel(&null);
    let manifest = json!({"containers": [{"name": "web", "blob": "web"}], "readiness": [{"name": "http", "tcp_port": 8080}]});
    let mut template = Template::new("smoke-v1".into(), &null, &null, &[("web", &null)], manifest);
    template.pool_target = 0;
    h.config.templates = vec![template];
    h.start_roost();
    h.start_dispatcher();
    eventually("dispatcher discovery", async || {
        Ok(h.dispatcher().host_status(req(v1::HostStatusRequest {})).await?.into_inner().capacity == 2)
    })
    .await;
    for mut client in [h.host(), h.dispatcher()] {
        let status = ok(client.host_status(req(v1::HostStatusRequest {}))).await;
        assert_eq!((status.max_vcpus, status.max_memory_mib, status.reserved_vcpus, status.reserved_memory_mib), (2, 1024, 0, 0));
        let [pool] = status.pools.as_slice() else { panic!("one pool, got {:?}", status.pools) };
        assert_eq!(pool.template_id, "smoke-v1");
        assert_eq!(pool.fingerprint.len(), 64);
    }
    assert_eq!(sessions(h.dispatcher()).await.unwrap(), []);
    let err = h.dispatcher().claim_session(req(claim_request("smoke-v1"))).await.unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted, "{err}");

    let mut second = tokio::process::Command::new(bin("roost"));
    second.arg("--config").arg(h.state.join("config.json")).kill_on_drop(true);
    let out = tokio::time::timeout(Duration::from_secs(10), second.output()).await.expect("a second agent kept running").unwrap();
    assert!(!out.status.success(), "a second agent acquired the state directory");
    let output = String::from_utf8_lossy(&out.stderr) + String::from_utf8_lossy(&out.stdout);
    assert!(output.contains("another agent owns the state directory"), "{output}");
}

pub async fn run(example: Example, scenario: Scenario) {
    let mut h = Harness::new();
    let expected = example.body().as_bytes();
    let mut manifest = example.manifest();
    let mut snapshot = None;
    if scenario == Scenario::Lifecycle {
        manifest["containers"][0]["args"] = json!(["/usr/local/bin/serve", "--test-control"]);
        // claims, isolation, failure, and adoption all run against restored clones.
        snapshot = Some(Snapshot::Lazy);
    }
    let spec = h.example_template(example, manifest, snapshot);
    let template = spec.id.clone();
    h.config.templates = vec![spec];
    // the lifecycle reads boot modes from roost's spans.
    if scenario != Scenario::Plain {
        h.telemetry = Some(Telemetry::start(&h.state).await);
    }
    let checks = match scenario {
        Scenario::Lifecycle => Some(Lifecycle::new(&mut h).await),
        _ => None,
    };
    h.start_roost();
    h.start_dispatcher();
    eventually("warm pool", async || h.ready().await).await;
    if example == Example::Http && scenario == Scenario::Plain {
        cli::check(&h, &template, example.body()).await;
    }
    let mut first = match &checks {
        Some(checks) => checks.concurrent_claim(&h, &template).await,
        None => claim(h.dispatcher(), claim_request(&template)).await,
    };
    assert_eq!(get(&first, "/", 200).await, expected);
    eventually("replacement warm guest", async || h.ready().await).await;
    h.check_budget(2, 1024).await;
    let second = match &checks {
        Some(checks) => checks.keyed_claim(&h, &template).await,
        None => claim(h.dispatcher(), claim_request(&template)).await,
    };
    assert_eq!(get(&second, "/", 200).await, expected);
    let err = h.dispatcher().claim_session(req(claim_request(&template))).await.unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted, "third guest exceeded the host budget: {err}");
    if example == Example::Shared {
        h.check_writer_log(&first).await;
    }
    if let Some(checks) = &checks {
        checks.check_isolation(&h, &first, &second).await;
        h.stop_dispatcher();
        h.start_dispatcher();
        for session in [&first, &second] {
            eventually("dispatcher discovery after restart", async || {
                let found =
                    h.dispatcher().get_session(req(v1::GetSessionRequest { name: session.name.clone(), ..Default::default() })).await?;
                Ok(found.into_inner().session.as_ref() == Some(session))
            })
            .await;
        }
        first = checks.replace(&h, &first, &template, Ending::Expiry).await;
        first = checks.replace(&h, &first, &template, Ending::Exit).await;
    }
    let before: BTreeMap<String, Saved> = [&first, &second].map(|s| (s.name.clone(), h.saved(s))).into();
    let guest_logs = match &h.telemetry {
        Some(tm) if scenario == Scenario::Telemetry => tm.verify_initial(&before).await,
        _ => Vec::new(),
    };
    h.stop_roost();
    h.verify_detached(&before);
    // pool targets aren't part of template identity, so stop replenishing before cleanup.
    h.config.templates[0].pool_target = 0;
    h.start_roost();
    eventually("adoption after agent restart", async || Ok(sessions(h.host()).await?.len() == 2)).await;
    if scenario == Scenario::Telemetry {
        h.verify_restart_and_outage(&first, expected, &guest_logs).await;
    }
    for session in [&first, &second] {
        let adopted =
            ok(h.host().get_session(req(v1::GetSessionRequest { name: session.name.clone(), ..Default::default() }))).await.session;
        assert_eq!(adopted.as_ref(), Some(session), "adopted session changed");
        assert_eq!(before[&session.name].pid(), h.saved(session).pid());
        assert_eq!(get(session, "/", 200).await, expected);
        release(h.host(), session).await;
    }
    eventually("guest deletion", async || Ok(sessions(h.host()).await?.is_empty())).await;
    h.check_budget(0, 0).await;
    if let (Some(tm), Some(_)) = (&h.telemetry, snapshot) {
        // a lazy template's first restore records the pages its guest touches, and later restores prefetch them.
        eventually("record and prefetch restores", async || {
            let boots = tm.boot_spans(&template)?;
            let modes = modes(&boots);
            Ok(modes.contains(&"record") && modes.contains(&"prefetch"))
        })
        .await;
    }
    for path in files(&h.state.join("nest")) {
        assert_ne!(path.file_name(), Some(OsStr::new("rootfs.ext4")), "leaked disk: {}", path.display());
    }
    for line in command("ip", ["netns", "list"]).lines() {
        assert!(!line.starts_with("birdfeeder-"), "{line}");
    }
    check_cgroups();
    if let (Some(tm), Scenario::Telemetry) = (&h.telemetry, scenario) {
        eventually("retired log cursors", async || Ok(tm.cursors().is_empty())).await;
    }
}

impl Harness {
    /// A one-guest pool of examples/<name> on the artifacts setup built. It's named after their digests so a
    /// rebuilt artifact gets a fresh template. It points the config at the same kernel.
    pub fn example_template(&mut self, example: Example, manifest: Value, snapshot: Option<Snapshot>) -> Template {
        let artifacts = artifacts();
        let identity = serde_json::to_vec(&json!([artifacts, manifest, snapshot])).unwrap();
        let digest = Sha256::digest(identity);
        self.config.use_kernel(&artifacts["kernel"]);
        let id = format!("{}-{}", example.name(), hex::encode(&digest[..8]));
        let alpine = &artifacts["alpine.squashfs"];
        let mut template = Template::new(id, &artifacts["base.ext4"], &artifacts["scratch.ext4"], &[("alpine", alpine)], manifest);
        template.snapshot = snapshot;
        // only a lazy template records a working set to warm.
        if snapshot == Some(Snapshot::Lazy) {
            template.snapshot_warmup = vec![Warmup { endpoint: "http", path: "/" }];
        }
        template
    }

    async fn check_writer_log(&self, session: &v1::Session) {
        let record: crate::contract::LogLine =
            crate::contract::ask_guest(&self.saved(session).vsock_path, "LOGS writer 0").await.expect("writer's first log line");
        assert_eq!(record.container, "writer");
        assert!(record.seq > 0);
        assert_eq!(record.line, "shared volume initialized");
    }

    /// Checks that restarting roost didn't replay guest logs, and that a collector outage doesn't block workloads.
    async fn verify_restart_and_outage(&mut self, session: &v1::Session, expected: &[u8], guest_logs: &[String]) {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let tm = self.telemetry.as_mut().expect("telemetry");
        let mut uids = tm.guest_log_uids();
        uids.sort();
        let mut want = guest_logs.to_vec();
        want.sort();
        assert_eq!(uids, want, "restart replayed guest logs");
        tm.collector.take().expect("collector running").stop().unwrap_or_else(|e| panic!("{e:#}"));
        let start = Instant::now();
        for _ in 0..10 {
            sessions(self.dispatcher()).await.unwrap();
            assert_eq!(get(session, "/", 200).await, expected);
        }
        assert!(start.elapsed() < Duration::from_secs(10), "collector outage blocked workload operations");
    }
}
