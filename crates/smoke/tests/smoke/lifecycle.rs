//! Claim races, keyed claim retries, guest isolation, and replacement of expired and failed sessions. A veth pair to
//! a namespace stands in for the internet: 198.18.0.2 and 198.18.0.5 listen on 80 and 25, and the host side is
//! 198.18.0.1. A DNS server on the host answers every name with 198.18.0.5, which only a name grant opens.

use std::fs::File;
use std::net::{Ipv4Addr, TcpListener as StdListener};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use nix::sched::{CloneFlags, setns};
use roost_api::v1;
use roost_api::v1::roost_service_client::RoostServiceClient;
use serde::Deserialize;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Barrier;
use tokio::task::{JoinHandle, JoinSet};
use tonic::Code;
use tonic::transport::Endpoint;

use crate::harness::{DISPATCHER_ADDR, Harness, claim, claim_request, command, eventually, get, listening, ok, post, proc_exists, req};

const NETNS: &str = "egress-smoke";
const CLAIMERS: usize = 8;
/// what the DNS server answers for every name, outside the CIDR grants the lifecycle makes.
const NAMED: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 5);
/// the name the lifecycle's second session may resolve.
pub const ALLOWED_NAME: &str = "allowed.smoke";

pub struct Lifecycle {
    /// a host listener that guests must not reach.
    host_port: u16,
    listeners: Vec<JoinHandle<()>>,
}

/// How a claimed session ends before its replacement is claimed.
#[derive(Clone, Copy)]
pub enum Ending {
    Expiry,
    /// the workload exits, which fails the session.
    Exit,
}

impl Lifecycle {
    /// Sets up the stand-in internet and points `h`'s roost at its DNS server.
    pub async fn new(h: &mut Harness) -> Self {
        let host = TcpListener::bind("0.0.0.0:0").await.expect("bind host listener");
        let host_port = host.local_addr().unwrap().port();
        let dns = UdpSocket::bind("127.0.0.1:0").await.expect("bind DNS server");
        h.config.dns_upstream = Some(dns.local_addr().unwrap());
        // build this first so its drop cleans up whatever the rest of the setup made.
        let mut checks = Self { host_port, listeners: vec![accept(host), tokio::spawn(resolve(dns))] };
        command("ip", ["netns", "add", NETNS]);
        command("ip", ["link", "add", "probe-host", "type", "veth", "peer", "name", "probe-peer"]);
        for args in [
            &["link", "set", "probe-peer", "netns", NETNS][..],
            &["addr", "add", "198.18.0.1/29", "dev", "probe-host"],
            &["link", "set", "probe-host", "up"],
            &["-n", NETNS, "addr", "add", "198.18.0.2/29", "dev", "probe-peer"],
            &["-n", NETNS, "addr", "add", "198.18.0.5/29", "dev", "probe-peer"],
            &["-n", NETNS, "link", "set", "probe-peer", "up"],
            &["-n", NETNS, "link", "set", "lo", "up"],
            &["-n", NETNS, "route", "add", "default", "via", "198.18.0.1"],
        ] {
            command("ip", args);
        }
        // a dedicated thread enters the namespace. its sockets stay there after the thread exits.
        let peers = std::thread::spawn(|| -> std::io::Result<Vec<StdListener>> {
            setns(File::open(Path::new("/run/netns").join(NETNS))?, CloneFlags::CLONE_NEWNET)?;
            ["0.0.0.0:80", "0.0.0.0:25"].into_iter().map(StdListener::bind).collect()
        });
        for peer in peers.join().unwrap().expect("listen in the peer namespace") {
            peer.set_nonblocking(true).unwrap();
            checks.listeners.push(accept(TcpListener::from_std(peer).unwrap()));
        }
        for addr in ["198.18.0.2:80".to_owned(), "198.18.0.2:25".to_owned(), format!("{NAMED}:80"), format!("127.0.0.1:{host_port}")] {
            eventually(&format!("positive control on {addr}"), async || listening(&addr).await).await;
        }
        checks
    }

    pub async fn concurrent_claim(&self, h: &Harness, template: &str) -> v1::Session {
        let start = Arc::new(Barrier::new(CLAIMERS));
        let mut claims = JoinSet::new();
        for _ in 0..CLAIMERS {
            let (start, mut client, request) = (Arc::clone(&start), h.dispatcher(), req(claim_request(template)));
            claims.spawn(async move {
                start.wait().await;
                client.claim_session(request).await
            });
        }
        let mut winners = Vec::new();
        for result in claims.join_all().await {
            match result {
                Ok(res) => winners.extend(res.into_inner().session),
                Err(status) => assert_eq!(status.code(), Code::ResourceExhausted, "{status}"),
            }
        }
        let n = winners.len();
        let [winner] = <[_; 1]>::try_from(winners).unwrap_or_else(|_| panic!("concurrent claims must have one winner, got {n}"));
        winner
    }

    /// Claims with an idempotency key on a connection that's dropped mid-claim, then claims again with
    /// the same key. Whether or not the first attempt went through, there's exactly one session for it after.
    pub async fn keyed_claim(&self, h: &Harness, template: &str) -> v1::Session {
        const KEY: &str = "smoke-keyed-claim";
        let mut request = claim_request(template);
        // broad grants show the host and cross-guest guards still win.
        let cidrs = vec!["198.18.0.0/30".into(), "172.20.0.0/24".into()];
        let fqdns = vec![ALLOWED_NAME.into()];
        request.egress = Some(v1::EgressPolicy { cidr_allowlist: cidrs, fqdn_allowlist: fqdns, ..Default::default() });
        request.idempotency_key = KEY.into();
        request.labels.insert("job".into(), KEY.into());
        let channel =
            Endpoint::from_shared(format!("http://{DISPATCHER_ADDR}")).unwrap().connect().await.expect("connect to the dispatcher");
        let mut doomed = RoostServiceClient::new(channel);
        let sent = request.clone();
        let attempt = tokio::spawn(async move { doomed.claim_session(req(sent)).await });
        tokio::time::sleep(Duration::from_millis(5)).await;
        // dropping the task's client closes the connection, wherever the claim got to.
        attempt.abort();
        let _ = attempt.await;
        let session = claim(h.dispatcher(), request.clone()).await;
        assert_eq!(claim(h.dispatcher(), request).await, session, "a second retry answers the same session");
        let by_key = v1::GetSessionRequest { idempotency_key: KEY.into(), ..Default::default() };
        assert_eq!(ok(h.dispatcher().get_session(req(by_key))).await.session.as_ref(), Some(&session));
        let selector = v1::ListSessionsRequest { labels: [("job".into(), KEY.into())].into() };
        let listed = ok(h.dispatcher().list_sessions(req(selector))).await.sessions;
        assert_eq!(listed, std::slice::from_ref(&session), "the dropped attempt claimed no other session");
        session
    }

    pub async fn check_isolation(&self, h: &Harness, first: &v1::Session, second: &v1::Session) {
        post(first, "/test/value", "private to the first guest", 204).await;
        assert_eq!(get(first, "/value", 200).await, b"private to the first guest");
        get(second, "/value", 404).await;
        // a refused dial sits through the guest's dial timeout, so run the independent checks in parallel.
        let mut independent = vec![
            (first.clone(), "198.18.0.2:80".to_owned(), false),
            (second.clone(), "198.18.0.2:80".to_owned(), true),
            (second.clone(), "198.18.0.2:25".to_owned(), false),
        ];
        for (from, to) in [(first, second), (second, first)] {
            let saved = h.saved(to);
            independent.extend([
                (from.clone(), format!("{}:8080", saved.guest_ip), false),
                (from.clone(), format!("198.18.0.1:{}", saved.host_port("http")), false),
                (from.clone(), format!("198.18.0.1:{}", self.host_port), false),
            ]);
        }
        // the address opens only once the gate answers a granted name with it, and only for the session that asked.
        let gate = async {
            reaches(second, "refused.smoke:80", false).await;
            reaches(second, &format!("{NAMED}:80"), false).await;
            reaches(second, &format!("{ALLOWED_NAME}:80"), true).await;
            reaches(second, &format!("{NAMED}:80"), true).await;
            all_reach(vec![(second.clone(), format!("{ALLOWED_NAME}:25"), false), (first.clone(), format!("{NAMED}:80"), false)]).await;
        };
        tokio::join!(all_reach(independent), gate);
    }

    /// Ends `session` and claims its replacement, which must be a fresh guest under the same name.
    pub async fn replace(&self, h: &Harness, session: &v1::Session, template: &str, ending: Ending) -> v1::Session {
        let saved = h.saved(session);
        let (name, generation) = (session.name.clone(), session.generation);
        match ending {
            Ending::Exit => {
                post(session, "/test/exit", "", 204).await;
            }
            Ending::Expiry => {
                let expires_at_ms = unix_ms(SystemTime::now() + Duration::from_millis(300));
                let expire = v1::SetSessionExpiryRequest { name: name.clone(), generation, expires_at_ms };
                ok(h.dispatcher().set_session_expiry(req(expire))).await;
            }
        }
        eventually("replacement after expiry or container exit", async || h.ready().await).await;
        let replacement = claim(h.dispatcher(), claim_request(template)).await;
        assert_eq!(replacement.name, name);
        assert!(replacement.generation > generation);
        assert!(!h.state.join("nest").join(saved.nest_id.as_deref().unwrap_or_default()).exists(), "retired nest remains");
        assert!(!proc_exists(saved.pid()), "retired VMM is still alive");
        get(&replacement, "/value", 404).await;
        let err = h.dispatcher().delete_session(req(v1::DeleteSessionRequest { name: name.clone(), generation })).await.unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
        let expire = v1::SetSessionExpiryRequest { name: name.clone(), generation, expires_at_ms: 1 };
        let err = h.dispatcher().set_session_expiry(req(expire)).await.unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
        let found = ok(h.dispatcher().get_session(req(v1::GetSessionRequest { name, ..Default::default() }))).await.session;
        assert_eq!(found.as_ref(), Some(&replacement));
        h.check_budget(2, 1024).await;
        replacement
    }
}

impl Drop for Lifecycle {
    fn drop(&mut self) {
        for listener in &self.listeners {
            listener.abort();
        }
        // the peer end of the pair goes away with the namespace.
        if Command::new("ip").args(["link", "show", "probe-host"]).output().is_ok_and(|o| o.status.success()) {
            undo(&["link", "delete", "probe-host"]);
        }
        if Path::new("/run/netns").join(NETNS).exists() {
            undo(&["netns", "delete", NETNS]);
        }
    }
}

/// Runs a teardown `ip` command. It can't panic, since a failed test might be unwinding.
fn undo(args: &[&str]) {
    let out = Command::new("ip").args(args).output();
    if !out.as_ref().is_ok_and(|o| o.status.success()) {
        let failure = format!("ip {args:?}: {out:?}");
        if std::thread::panicking() {
            eprintln!("{failure}");
        } else {
            panic!("{failure}");
        }
    }
}

/// Accepts and closes connections, so a dial succeeds.
fn accept(listener: TcpListener) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            drop(conn);
        }
    })
}

/// Answers every A query with [`NAMED`] and every other query with no records.
async fn resolve(sock: UdpSocket) {
    let mut buf = vec![0; 512];
    while let Ok((n, from)) = sock.recv_from(&mut buf).await {
        let Ok(req) = Message::from_vec(&buf[..n]) else { continue };
        let mut resp = Message::error_msg(req.id(), req.op_code(), ResponseCode::NoError);
        resp.set_recursion_desired(req.recursion_desired()).set_recursion_available(true).add_queries(req.queries().to_vec());
        for q in req.queries().iter().filter(|q| q.query_type() == RecordType::A) {
            resp.add_answer(Record::from_rdata(q.name().clone(), 60, RData::A(A(NAMED))));
        }
        let _ = sock.send_to(&resp.to_vec().expect("encode DNS answer"), from).await;
    }
}

/// Asks the guest whether it can open a TCP connection to `target`.
async fn reaches(session: &v1::Session, target: &str, want: bool) {
    #[derive(Deserialize)]
    struct Dial {
        reachable: bool,
    }
    let body = serde_json::json!({ "address": target }).to_string();
    let dial: Dial = serde_json::from_slice(&post(session, "/test/dial", &body, 200).await).expect("dial answer");
    assert_eq!(dial.reachable, want, "{} -> {target}", session.name);
}

async fn all_reach(checks: Vec<(v1::Session, String, bool)>) {
    let mut dials = JoinSet::new();
    for (session, target, want) in checks {
        dials.spawn(async move { reaches(&session, &target, want).await });
    }
    while let Some(done) = dials.join_next().await {
        if let Err(e) = done {
            std::panic::resume_unwind(e.into_panic());
        }
    }
}

fn unix_ms(t: SystemTime) -> i64 {
    i64::try_from(t.duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}
