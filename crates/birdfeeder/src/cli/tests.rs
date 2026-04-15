use std::{
    collections::BTreeMap,
    process::ExitCode,
    sync::{Arc, Mutex},
};

use chrono::{DateTime, FixedOffset, TimeZone as _, Utc};
use roost_api::v1::{
    ClaimSessionRequest, ClaimSessionResponse, DeleteSessionRequest, DeleteSessionResponse, EgressPolicy, GetSessionRequest,
    GetSessionResponse, HostStatusRequest, HostStatusResponse, ListSessionsRequest, ListSessionsResponse, PoolFill, Session, SessionState,
    SetSessionExpiryRequest, SetSessionExpiryResponse,
    roost_service_server::{RoostService, RoostServiceServer},
};
use rstest::rstest;
use tokio::net::TcpListener;
use tonic::{Request, Response, Status};

fn now() -> DateTime<FixedOffset> {
    Utc.with_ymd_and_hms(2026, 11, 3, 12, 0, 0).unwrap().fixed_offset()
}

#[derive(Default)]
struct State {
    sessions: BTreeMap<String, Session>,
    err: Option<Status>,
    /// `GetSession` answers OK with no session, as a misbehaving server might.
    hollow: bool,
    claims: Vec<ClaimSessionRequest>,
    deletes: Vec<DeleteSessionRequest>,
    expiries: Vec<SetSessionExpiryRequest>,
}

/// Records requests and answers from its sessions, or with err if that's set.
#[derive(Clone, Default)]
struct Fake(Arc<Mutex<State>>);

impl Fake {
    fn fail(&self, err: Status) {
        self.0.lock().unwrap().err = Some(err);
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }
}

fn check(s: &State) -> Result<(), Status> {
    s.err.clone().map_or(Ok(()), Err)
}

fn mutate(s: &State, name: &str, generation: u64) -> Result<(), Status> {
    check(s)?;
    match s.sessions.get(name) {
        None => Err(Status::not_found("session not found")),
        Some(found) if found.generation != generation => Err(Status::failed_precondition("generation mismatch")),
        Some(_) => Ok(()),
    }
}

#[tonic::async_trait]
impl RoostService for Fake {
    async fn claim_session(&self, req: Request<ClaimSessionRequest>) -> Result<Response<ClaimSessionResponse>, Status> {
        let mut s = self.state();
        let req = req.into_inner();
        s.claims.push(req.clone());
        check(&s)?;
        let session = Session {
            name: "host-a-3".into(),
            generation: 7,
            state: SessionState::Claimed.into(),
            host_id: "host-a".into(),
            template_id: req.template_id,
            endpoints: BTreeMap::from([("exec".into(), "10.0.0.5:31008".into())]),
            labels: req.labels,
        };
        s.sessions.insert(session.name.clone(), session.clone());
        Ok(Response::new(ClaimSessionResponse { session: Some(session) }))
    }

    async fn get_session(&self, req: Request<GetSessionRequest>) -> Result<Response<GetSessionResponse>, Status> {
        let s = self.state();
        check(&s)?;
        if s.hollow {
            return Ok(Response::new(GetSessionResponse { session: None }));
        }
        let session = s.sessions.get(&req.get_ref().name).cloned().ok_or_else(|| Status::not_found("session not found"))?;
        Ok(Response::new(GetSessionResponse { session: Some(session) }))
    }

    async fn list_sessions(&self, req: Request<ListSessionsRequest>) -> Result<Response<ListSessionsResponse>, Status> {
        let s = self.state();
        check(&s)?;
        let selector = req.into_inner().labels;
        let matching = s.sessions.values().filter(|session| selector.iter().all(|(k, v)| session.labels.get(k) == Some(v)));
        // unsorted, so the CLI's own ordering shows.
        Ok(Response::new(ListSessionsResponse { sessions: matching.rev().cloned().collect() }))
    }

    async fn delete_session(&self, req: Request<DeleteSessionRequest>) -> Result<Response<DeleteSessionResponse>, Status> {
        let mut s = self.state();
        let req = req.into_inner();
        s.deletes.push(req.clone());
        mutate(&s, &req.name, req.generation)?;
        s.sessions.remove(&req.name);
        Ok(Response::new(DeleteSessionResponse {}))
    }

    async fn set_session_expiry(&self, req: Request<SetSessionExpiryRequest>) -> Result<Response<SetSessionExpiryResponse>, Status> {
        let mut s = self.state();
        let req = req.into_inner();
        s.expiries.push(req.clone());
        mutate(&s, &req.name, req.generation)?;
        Ok(Response::new(SetSessionExpiryResponse {}))
    }

    async fn host_status(&self, _: Request<HostStatusRequest>) -> Result<Response<HostStatusResponse>, Status> {
        check(&self.state())?;
        Ok(Response::new(HostStatusResponse {
            capacity: 8,
            running: 5,
            max_vcpus: 8,
            reserved_vcpus: 5,
            max_memory_mib: 4096,
            reserved_memory_mib: 2560,
            pools: vec![PoolFill { template_id: "agent-sandbox-v1".into(), ready: 3, target: 4, fingerprint: "ab".repeat(32) }],
        }))
    }
}

/// Serves a fake with sessions and returns it with its host:port.
async fn serve(sessions: impl IntoIterator<Item = Session>) -> (Fake, String) {
    let fake = Fake::default();
    fake.state().sessions = sessions.into_iter().map(|s| (s.name.clone(), s)).collect();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let svc = RoostServiceServer::new(fake.clone());
    tokio::spawn(
        tonic::transport::Server::builder().add_service(svc).serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    (fake, addr)
}

struct Ran {
    code: u8,
    stdout: String,
    stderr: String,
}

/// Runs the CLI against server, which `BIRDFEEDER_SERVER` names unless args pass --server.
async fn run(server: &str, args: &[&str]) -> Ran {
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let env = super::Env { stdout: &mut stdout, stderr: &mut stderr, server: Some(server.into()), now: now() };
    let exit = super::run(std::iter::once("birdfeeder").chain(args.iter().copied()), env).await;
    // ExitCode hides the number, and scripts depend on it, so dig it out to assert on.
    let code = (0..=u8::MAX).find(|&n| ExitCode::from(n) == exit).expect("exit codes are u8");
    Ran { code, stdout: String::from_utf8(stdout).unwrap(), stderr: String::from_utf8(stderr).unwrap() }
}

fn session(name: &str, generation: u64, state: SessionState, template: &str, host: &str) -> Session {
    Session {
        name: name.into(),
        generation,
        state: state.into(),
        template_id: template.into(),
        host_id: host.into(),
        endpoints: BTreeMap::from([("http".into(), "10.0.0.1:31000".into())]),
        labels: BTreeMap::from([("team".into(), host.into())]),
    }
}

#[tokio::test]
async fn claim() {
    let (f, addr) = serve([]).await;
    let res = run(
        &addr,
        &[
            "claim",
            "agent-sandbox-v1",
            "--label",
            "agent_run=run-8812",
            "--allow-fqdn",
            "pypi.org, files.pythonhosted.org",
            "--allow-cidr",
            "10.1.0.0/16",
            "--idle-timeout",
            "15m",
            "--idempotency-key",
            "run-8812-sandbox",
        ],
    )
    .await;
    assert_eq!(res.code, 0, "{}", res.stderr);
    let want = ClaimSessionRequest {
        template_id: "agent-sandbox-v1".into(),
        labels: BTreeMap::from([("agent_run".into(), "run-8812".into())]),
        egress: Some(EgressPolicy {
            fqdn_allowlist: vec!["pypi.org".into(), "files.pythonhosted.org".into()],
            cidr_allowlist: vec!["10.1.0.0/16".into()],
            smtp_allowed: false,
        }),
        idle_timeout_ms: 900_000,
        idempotency_key: "run-8812-sandbox".into(),
    };
    assert_eq!(f.state().claims, [want]);
    assert_eq!(
        res.stdout,
        "NAME      GENERATION  STATE    TEMPLATE          HOST    ENDPOINTS\n\
         host-a-3  7           claimed  agent-sandbox-v1  host-a  exec=10.0.0.5:31008\n"
    );
}

#[tokio::test]
async fn claim_output() {
    let (_, addr) = serve([]).await;
    // flags are accepted before the command too, and the JSON is the API's.
    let res = run(&addr, &["-o", "json", "claim", "web"]).await;
    assert_eq!(res.code, 0, "{}", res.stderr);
    let out: serde_json::Value = serde_json::from_str(&res.stdout).unwrap();
    assert_eq!(
        out,
        serde_json::json!({"session": {
            "name": "host-a-3", "generation": "7", "state": "SESSION_STATE_CLAIMED", "hostId": "host-a",
            "templateId": "web", "endpoints": {"exec": "10.0.0.5:31008"}, "labels": {},
        }})
    );
    let res = run(&addr, &["claim", "web", "-o", "name"]).await;
    assert_eq!((res.code, res.stdout.as_str()), (0, "host-a-3\n"), "{}", res.stderr);
}

#[rstest]
#[case::no_capacity(Status::resource_exhausted("pool empty"), 5, r#"no ready guest for template "web""#)]
#[case::unavailable(Status::unavailable("host down"), 6, "may or may not have succeeded (unavailable: host down)")]
#[case::internal(Status::internal("boom"), 6, "birdfeeder ls --template web")]
#[case::invalid(Status::invalid_argument("no such template"), 2, "invalid request: no such template")]
#[tokio::test]
async fn claim_errors(#[case] err: Status, #[case] code: u8, #[case] msg: &str) {
    let (f, addr) = serve([]).await;
    f.fail(err);
    let res = run(&addr, &["claim", "web"]).await;
    assert_eq!(res.code, code, "{}", res.stderr);
    assert!(res.stderr.contains(msg), "{}", res.stderr);
    assert_eq!(res.stdout, "");
}

#[tokio::test]
async fn claim_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    // a refused connection proves the claim was never sent, so its outcome isn't in doubt.
    let res = run("", &["--server", &closed, "claim", "web"]).await;
    assert_eq!(res.code, 1, "{}", res.stderr);
    assert!(res.stderr.contains(&format!("cannot reach {closed}")), "{}", res.stderr);
    assert!(res.stderr.contains(": tcp connect error: Connection refused"), "the cause shows once: {}", res.stderr);
}

#[tokio::test]
async fn claim_timeout() {
    // a server that accepts but never answers leaves the claim's outcome unknown.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let _hold = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((conn, _)) = listener.accept().await {
            held.push(conn);
        }
    });
    let res = run(&addr, &["claim", "web", "--timeout", "200ms"]).await;
    assert_eq!(res.code, 6, "{}", res.stderr);
    assert!(res.stderr.contains("(deadline_exceeded: timed out)"), "{}", res.stderr);
    assert!(res.stderr.contains("birdfeeder ls --template web"), "{}", res.stderr);
    let res = run(&addr, &["claim", "web", "--timeout", "200ms", "--idempotency-key", "k"]).await;
    assert_eq!(res.code, 6, "{}", res.stderr);
    assert!(res.stderr.contains("claim again with the same --idempotency-key"), "{}", res.stderr);
}

#[rstest]
#[case::no_command(&[])]
#[case::label_without_value(&["claim", "web", "--label", "novalue"])]
#[case::label_twice(&["claim", "web", "--label", "k=1", "--label", "k=2"])]
#[case::idle_timeout_not_a_duration(&["claim", "web", "--idle-timeout", "soon"])]
#[case::idle_timeout_too_long(&["claim", "web", "--idle-timeout", "200h"])]
#[case::idle_timeout_under_a_millisecond(&["claim", "web", "--idle-timeout", "1us"])]
#[case::idle_timeout_zero(&["claim", "web", "--idle-timeout", "0s"])]
#[case::invalid_fqdn(&["claim", "web", "--allow-fqdn", "not a domain"])]
#[case::invalid_template(&["claim", "Not_A_Template"])]
#[case::unknown_state(&["ls", "--state", "sleeping"])]
#[case::unspecified_state(&["ls", "--state", "unspecified"])]
#[case::expire_without_when(&["expire", "s1"])]
#[case::expire_two_whens(&["expire", "s1", "--in", "1h", "--never"])]
#[case::expire_in_zero(&["expire", "s1", "--in", "0s"])]
#[case::expire_at_not_a_time(&["expire", "s1", "--at", "tomorrow"])]
#[case::expire_in_overflowing(&["expire", "s1", "--in", "1000000years"])]
#[case::expire_in_too_far(&["expire", "s1", "--in", "100000years"])]
#[case::rm_generation_of_several(&["rm", "s1", "s2", "--generation", "1"])]
#[case::convert_too_many_platform_slashes(&["convert", "alpine", "a.squashfs", "--platform", "a/b/c/d"])]
#[case::server_not_http(&["--server", "ftp://example.com", "ls"])]
#[tokio::test]
async fn usage_errors(#[case] args: &[&str]) {
    let (f, addr) = serve([session("s1", 1, SessionState::Claimed, "web", "a")]).await;
    let res = run(&addr, args).await;
    assert_eq!(res.code, 2, "{}", res.stderr);
    assert_ne!(res.stderr, "");
    let s = f.state();
    assert!(s.claims.is_empty() && s.deletes.is_empty() && s.expiries.is_empty());
}

#[tokio::test]
async fn help() {
    let (_, addr) = serve([]).await;
    let res = run(&addr, &["help"]).await;
    assert_eq!(res.code, 0);
    for want in ["claim", "endpoint", "status", "convert", "pack", "BIRDFEEDER_SERVER", "exit status"] {
        assert!(res.stdout.contains(want), "{want}: {}", res.stdout);
    }
    let res = run(&addr, &["help", "claim"]).await;
    assert_eq!(res.code, 0);
    assert!(res.stdout.contains("--allow-fqdn"), "{}", res.stdout);
}

#[tokio::test]
async fn get() {
    let (_, addr) = serve([session("s1", 3, SessionState::Claimed, "web", "a")]).await;
    let res = run(&addr, &["get", "s1", "-o", "name"]).await;
    assert_eq!((res.code, res.stdout.as_str()), (0, "s1\n"), "{}", res.stderr);
    let res = run(&addr, &["get", "missing"]).await;
    assert_eq!(res.code, 3);
    assert!(res.stderr.contains(r#"session "missing" not found"#), "{}", res.stderr);
}

async fn serve_three() -> (Fake, String) {
    serve([
        session("b-2", 1, SessionState::Pooled, "web", "b"),
        session("a-1", 4, SessionState::Claimed, "web", "a"),
        session("a-2", 2, SessionState::Claimed, "api", "a"),
    ])
    .await
}

#[tokio::test]
async fn list() {
    let (_, addr) = serve_three().await;
    let res = run(&addr, &["ls"]).await;
    assert_eq!(res.code, 0, "{}", res.stderr);
    assert_eq!(
        res.stdout,
        "NAME  GENERATION  STATE    TEMPLATE  HOST  ENDPOINTS\n\
         a-1   4           claimed  web       a     http=10.0.0.1:31000\n\
         a-2   2           claimed  api       a     http=10.0.0.1:31000\n\
         b-2   1           pooled   web       b     http=10.0.0.1:31000\n"
    );
    let res = run(&addr, &["ls", "--host", "c"]).await;
    assert_eq!((res.code, res.stdout.as_str(), res.stderr.as_str()), (0, "", "no sessions\n"));
    // an empty JSON list is still a list, so `jq '.sessions[]'` works.
    let res = run(&addr, &["ls", "--host", "c", "-o", "json"]).await;
    assert_eq!(res.code, 0, "{}", res.stderr);
    assert_eq!(serde_json::from_str::<serde_json::Value>(&res.stdout).unwrap(), serde_json::json!({"sessions": []}));
}

#[rstest]
#[case::template(&["--template", "web"], "a-1\nb-2\n")]
#[case::state(&["--state", "claimed"], "a-1\na-2\n")]
#[case::all_filters_any_case(&["--state", "CLAIMED", "--host", "a", "--template", "api"], "a-2\n")]
#[case::label(&["--label", "team=a"], "a-1\na-2\n")]
#[case::labels_all_match(&["--label", "team=a", "--label", "tier=gold"], "")]
#[tokio::test]
async fn list_filters(#[case] args: &[&str], #[case] want: &str) {
    let (_, addr) = serve_three().await;
    let res = run(&addr, &[&["ls", "-o", "name"][..], args].concat()).await;
    assert_eq!((res.code, res.stdout.as_str()), (0, want), "{}", res.stderr);
}

#[tokio::test]
async fn list_unavailable() {
    let (f, addr) = serve([]).await;
    f.fail(Status::unavailable("cannot list sessions while hosts are unavailable"));
    let res = run(&addr, &["ls"]).await;
    assert_eq!(res.code, 1);
    assert!(res.stderr.contains("list sessions: unavailable: cannot list sessions while hosts are unavailable"), "{}", res.stderr);
}

#[rstest]
#[case::only_one(&["one"], 0, "10.0.0.1:31000\n", "")]
#[case::named(&["multi", "admin"], 0, "10.0.0.1:31001\n", "")]
#[case::unnamed_of_several(&["multi"], 2, "", "name one of: admin, http")]
#[case::unknown_name(&["multi", "ssh"], 3, "", r#"no endpoint "ssh" (it has: admin, http)"#)]
#[case::missing_session(&["missing"], 3, "", "not found")]
#[tokio::test]
async fn endpoint(#[case] args: &[&str], #[case] code: u8, #[case] out: &str, #[case] err: &str) {
    let mut multi = session("multi", 1, SessionState::Claimed, "web", "a");
    multi.endpoints = BTreeMap::from([("http".into(), "10.0.0.1:31000".into()), ("admin".into(), "10.0.0.1:31001".into())]);
    let (_, addr) = serve([session("one", 1, SessionState::Claimed, "web", "a"), multi]).await;
    let res = run(&addr, &[&["endpoint"][..], args].concat()).await;
    assert_eq!((res.code, res.stdout.as_str()), (code, out), "{}", res.stderr);
    assert!(res.stderr.contains(err), "{}", res.stderr);
}

#[tokio::test]
async fn delete() {
    let (f, addr) = serve([session("s1", 7, SessionState::Claimed, "web", "a"), session("s2", 2, SessionState::Claimed, "web", "a")]).await;
    // without --generation, the current one is looked up; flags may follow the name.
    let res = run(&addr, &["rm", "s1"]).await;
    assert_eq!((res.code, res.stdout.as_str()), (0, "deleted s1 (generation 7)\n"), "{}", res.stderr);
    assert_eq!(f.state().deletes, [DeleteSessionRequest { name: "s1".into(), generation: 7 }]);

    let res = run(&addr, &["rm", "s2", "--generation", "1"]).await;
    assert_eq!(res.code, 4);
    assert!(res.stderr.contains(r#"session "s2" is no longer at generation 1"#), "{}", res.stderr);

    let res = run(&addr, &["rm", "s2", "--generation", "2", "-o", "json"]).await;
    assert_eq!(res.code, 0, "{}", res.stderr);
    assert_eq!(serde_json::from_str::<serde_json::Value>(&res.stdout).unwrap(), serde_json::json!({"name": "s2", "generation": "2"}));

    let res = run(&addr, &["rm", "s2"]).await;
    assert_eq!(res.code, 3);
    assert!(res.stderr.contains(r#"session "s2" not found"#), "{}", res.stderr);
}

#[tokio::test]
async fn rm_refuses_an_answer_without_a_session() {
    let (f, addr) = serve([session("s1", 7, SessionState::Claimed, "web", "a")]).await;
    f.state().hollow = true;
    let res = run(&addr, &["rm", "s1"]).await;
    assert_eq!(res.code, 3, "{}", res.stderr);
    assert!(res.stderr.contains(r#"session "s1" not found"#), "{}", res.stderr);
    assert!(f.state().deletes.is_empty(), "no delete is sent for a guessed generation");
}

#[tokio::test]
async fn delete_several() {
    let (f, addr) = serve([session("s1", 1, SessionState::Claimed, "web", "a"), session("s3", 3, SessionState::Claimed, "web", "a")]).await;
    // a missing session doesn't stop the others from being deleted.
    let res = run(&addr, &["rm", "-o", "name", "s1", "s2", "s3"]).await;
    assert_eq!((res.code, res.stdout.as_str()), (3, "s1\ns3\n"));
    assert!(res.stderr.contains(r#"birdfeeder rm: session "s2" not found"#), "{}", res.stderr);
    assert!(res.stderr.contains("some sessions weren't deleted"), "{}", res.stderr);
    assert!(f.state().sessions.is_empty());
}

#[tokio::test]
async fn expire() {
    let (f, addr) = serve([session("s1", 7, SessionState::Claimed, "web", "a")]).await;
    let res = run(&addr, &["expire", "s1", "--in", "30m"]).await;
    assert_eq!((res.code, res.stdout.as_str()), (0, "s1 (generation 7) expires at 2026-11-03T12:30:00Z\n"), "{}", res.stderr);
    let res = run(&addr, &["expire", "s1", "--at", "2026-11-04T09:00:00+01:00", "--generation", "7"]).await;
    assert_eq!((res.code, res.stdout.as_str()), (0, "s1 (generation 7) expires at 2026-11-04T09:00:00+01:00\n"), "{}", res.stderr);
    let res = run(&addr, &["expire", "s1", "--never"]).await;
    assert_eq!((res.code, res.stdout.as_str()), (0, "s1 (generation 7) no longer expires\n"), "{}", res.stderr);

    let expiries: Vec<i64> = f.state().expiries.iter().map(|e| e.expires_at_ms).collect();
    let at = |y, mo, d, h, mi| Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap().timestamp_millis();
    assert_eq!(expiries, [at(2026, 11, 3, 12, 30), at(2026, 11, 4, 8, 0), 0]);
    assert!(f.state().expiries.iter().all(|e| e.generation == 7));

    assert_eq!(run(&addr, &["expire", "s1", "--never", "--generation", "6"]).await.code, 4);
}

#[tokio::test]
async fn status() {
    let (_, addr) = serve([]).await;
    // a bare host:port and a URL with a trailing slash both name the server.
    for server in [addr.clone(), format!("http://{addr}/")] {
        let res = run("", &["--server", &server, "status"]).await;
        assert_eq!(res.code, 0, "{}", res.stderr);
        assert_eq!(
            res.stdout,
            "sessions  5 running of 8\n\
             vcpus     5 reserved of 8\n\
             memory    2560 MiB reserved of 4096 MiB\n\
             \n\
             TEMPLATE          READY  TARGET  FINGERPRINT\n\
             agent-sandbox-v1  3      4       abababababab\n"
        );
    }
    let res = run(&addr, &["status", "-o", "name"]).await;
    assert_eq!((res.code, res.stdout.as_str()), (0, "agent-sandbox-v1\n"), "{}", res.stderr);
    let res = run(&addr, &["status", "-o", "json"]).await;
    let out: serde_json::Value = serde_json::from_str(&res.stdout).unwrap();
    assert_eq!(out["pools"][0]["fingerprint"], "ab".repeat(32));
    assert_eq!(out["capacity"], 8, "int32 fields stay numbers");
}

#[test]
fn convert_takes_global_flags() {
    use clap::Parser as _;
    let args = super::Args::try_parse_from(["birdfeeder", "convert", "-o", "name", "alpine", "a.squashfs", "--timeout", "5m"]).unwrap();
    assert_eq!(args.output, super::Output::Name);
    let super::Command::Convert(c) = args.command else { panic!("parsed {:?}", args.command) };
    assert_eq!((c.image.as_str(), c.dest.to_str()), ("alpine", Some("a.squashfs")));
}
