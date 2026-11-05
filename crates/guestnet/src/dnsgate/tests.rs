use std::sync::Mutex;

use hickory_proto::op::{MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, Record, RecordType};
use rstest::rstest;

use super::*;

fn patterns(entries: &[&str]) -> Vec<FqdnPattern> {
    entries.iter().map(|e| e.parse().unwrap()).collect()
}

const ALLOW: [&str; 3] = ["example.com", "*.s3.amazonaws.com", "Mixed.Case.IO."];

#[rstest]
#[case::exact("example.com.")]
#[case::any_case("EXAMPLE.COM.")]
#[case::no_root_dot("example.com")]
#[case::entry_normalized("mixed.case.io.")]
#[case::wildcard_subdomain("bucket.s3.amazonaws.com.")]
#[case::wildcard_nested_subdomain("a.b.s3.amazonaws.com.")]
fn allowlist_admits(#[case] qname: &str) {
    assert!(fqdn_allowed(&patterns(&ALLOW), qname));
}

#[rstest]
#[case::wildcard_skips_its_apex("s3.amazonaws.com.")]
#[case::wildcard_needs_a_label_boundary("xs3.amazonaws.com.")]
#[case::exact_skips_subdomains("sub.example.com.")]
#[case::exact_needs_a_label_boundary("notexample.com.")]
#[case::exact_isnt_a_prefix("example.com.evil.io.")]
fn allowlist_refuses(#[case] qname: &str) {
    assert!(!fqdn_allowed(&patterns(&ALLOW), qname));
}

#[rstest]
#[case::exact("example.com", FqdnPattern::Exact("example.com".into()))]
#[case::lowercased_without_root_dot("Example.COM.", FqdnPattern::Exact("example.com".into()))]
#[case::wildcard("*.Example.com.", FqdnPattern::Wildcard("example.com".into()))]
#[case::bare_star("*.", FqdnPattern::Exact("*".into()))]
fn patterns_parse_normalized(#[case] entry: &str, #[case] want: FqdnPattern) {
    assert_eq!(entry.parse::<FqdnPattern>(), Ok(want));
}

#[rstest]
#[case::empty("")]
#[case::root(".")]
#[case::empty_wildcard("*..")]
fn empty_patterns_are_rejected(#[case] entry: &str) {
    assert_eq!(entry.parse::<FqdnPattern>(), Err(EmptyFqdnPattern));
}

#[test]
fn patterns_serialize_as_their_text() {
    let allow: Vec<FqdnPattern> = serde_json::from_str(r#"["example.com","*.Example.org."]"#).unwrap();
    assert_eq!(allow, patterns(&["example.com", "*.example.org"]));
    assert_eq!(serde_json::to_string(&allow).unwrap(), r#"["example.com","*.example.org"]"#);
    assert!(serde_json::from_str::<Vec<FqdnPattern>>(r#"[""]"#).is_err());
}

#[rstest]
#[case::first_of_several("# generated\nsearch lan\nnameserver  fd00::1\nnameserver 10.0.0.53\n", Some("[fd00::1]:53"))]
#[case::skips_unparsable("nameserver bogus\nnameserver 1.1.1.1 # cf\n", Some("1.1.1.1:53"))]
#[case::none("search lan\n", None)]
fn upstream_is_the_first_nameserver(#[case] conf: &str, #[case] want: Option<&str>) {
    assert_eq!(resolv_conf_upstream(conf), want.map(|w| w.parse().unwrap()));
}

/// Grants loopback clients example.com and its subdomains, and records what the gate programs.
#[derive(Default)]
struct FakePolicy {
    programmed: Mutex<Vec<BTreeMap<Ipv4Addr, u32>>>,
    fail: bool,
}

impl Policy for Arc<FakePolicy> {
    type Grant = ();

    fn grant(&self, client: Ipv4Addr, qname: &str) -> Option<()> {
        (client.is_loopback() && fqdn_allowed(&patterns(&["example.com", "*.example.com"]), qname)).then_some(())
    }

    fn program(&self, (): (), addrs: BTreeMap<Ipv4Addr, u32>) -> impl Future<Output = anyhow::Result<()>> + Send {
        let programmed = (!self.fail).then(|| self.programmed.lock().unwrap().push(addrs)).ok_or_else(|| anyhow::anyhow!("nft refused"));
        std::future::ready(programmed)
    }
}

/// Answers A queries with two records, one TTL under the clamp and one over. `big.` names come back truncated and empty
/// over UDP, and answered over TCP.
async fn upstream() -> SocketAddr {
    fn answer(query: &[u8], udp: bool) -> Vec<u8> {
        let req = Message::from_vec(query).unwrap();
        let name = req.queries[0].name.clone();
        let mut resp = Message::response(req.metadata.id, req.metadata.op_code);
        resp.queries.clone_from(&req.queries);
        if udp && name.to_ascii().starts_with("big.") {
            resp.metadata.truncation = true;
        } else {
            resp.add_answer(Record::from_rdata(name.clone(), 1, RData::A(A::new(93, 184, 215, 14))));
            resp.add_answer(Record::from_rdata(name, 86400, RData::A(A::new(93, 184, 215, 15))));
        }
        resp.to_vec().unwrap()
    }

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0; MAX_MESSAGE];
        loop {
            let (n, from) = udp.recv_from(&mut buf).await.unwrap();
            udp.send_to(&answer(&buf[..n], true), from).await.unwrap();
        }
    });
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut query = vec![0; usize::from(stream.read_u16().await.unwrap())];
            stream.read_exact(&mut query).await.unwrap();
            write_framed(&mut stream, &answer(&query, false)).await.unwrap();
        }
    });
    addr
}

async fn gate(upstream: SocketAddr, policy: &Arc<FakePolicy>) -> SocketAddr {
    let cfg = Config { upstream, min_ttl: 15, max_ttl: 300 };
    let meter = opentelemetry::global::meter("dnsgate-test");
    let gate = DnsGate::bind("127.0.0.1:0".parse().unwrap(), &meter).await.unwrap();
    let addr = gate.local_addr().unwrap();
    tokio::spawn(gate.serve(cfg, Arc::clone(policy)));
    addr
}

fn query(name: &str) -> Vec<u8> {
    let mut msg = Message::new(0xbeef, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    msg.to_vec().unwrap()
}

async fn ask_udp(gate: SocketAddr, name: &str) -> Message {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&query(name), gate).await.unwrap();
    let mut buf = vec![0; MAX_MESSAGE];
    let n = timeout(Duration::from_secs(5), sock.recv(&mut buf)).await.unwrap().unwrap();
    Message::from_vec(&buf[..n]).unwrap()
}

fn a_records(msg: &Message) -> Vec<(Ipv4Addr, u32)> {
    msg.answers
        .iter()
        .filter_map(|rr| match rr.data {
            RData::A(a) => Some((a.0, rr.ttl)),
            _ => None,
        })
        .collect()
}

const CLAMPED: [(Ipv4Addr, u32); 2] = [(Ipv4Addr::new(93, 184, 215, 14), 15), (Ipv4Addr::new(93, 184, 215, 15), 300)];

#[tokio::test]
async fn programs_before_relaying() {
    let policy = Arc::new(FakePolicy::default());
    let gate = gate(upstream().await, &policy).await;

    let resp = ask_udp(gate, "Example.com.").await;
    assert_eq!((resp.metadata.id, resp.metadata.response_code), (0xbeef, ResponseCode::NoError));
    assert_eq!(a_records(&resp), CLAMPED);
    assert_eq!(*policy.programmed.lock().unwrap(), [BTreeMap::from(CLAMPED)]);

    let refused = ask_udp(gate, "example.org.").await;
    assert_eq!(refused.metadata.response_code, ResponseCode::Refused);
    assert_eq!(refused.queries, Message::from_vec(&query("example.org.")).unwrap().queries);
    assert!(refused.metadata.recursion_desired);
    assert_eq!(policy.programmed.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn truncated_answers_send_udp_guests_to_tcp() {
    let policy = Arc::new(FakePolicy::default());
    let gate = gate(upstream().await, &policy).await;

    // if upstream truncated an answer, a UDP guest gets it truncated, not as a TCP-sized datagram.
    let resp = ask_udp(gate, "big.example.com.").await;
    assert!(resp.metadata.truncation);
    assert_eq!((resp.metadata.id, resp.metadata.response_code), (0xbeef, ResponseCode::NoError));
    assert_eq!(a_records(&resp), []);
    assert!(policy.programmed.lock().unwrap().is_empty(), "the truncated answer carried no addresses");

    // its resolver retries over TCP, and the gate fetches over TCP too. several queries share one connection.
    let mut stream = TcpStream::connect(gate).await.unwrap();
    for name in ["big.example.com.", "a.example.com.", "evil.org."] {
        write_framed(&mut stream, &query(name)).await.unwrap();
        let mut resp = vec![0; usize::from(stream.read_u16().await.unwrap())];
        stream.read_exact(&mut resp).await.unwrap();
        let resp = Message::from_vec(&resp).unwrap();
        let want = if name == "evil.org." { ResponseCode::Refused } else { ResponseCode::NoError };
        assert_eq!(resp.metadata.response_code, want, "{name}");
        assert!(!resp.metadata.truncation, "{name}");
        if name == "big.example.com." {
            assert_eq!(a_records(&resp), CLAMPED);
        }
    }
    assert_eq!(policy.programmed.lock().unwrap().len(), 2);
}

#[test]
fn truncated_replies_are_answerless_with_tc_set() {
    let req = Message::from_vec(&query("example.com.")).unwrap();
    let resp = Message::from_vec(&truncated(&req).unwrap()).unwrap();
    assert!(resp.metadata.truncation);
    assert_eq!((resp.metadata.id, resp.metadata.response_code), (0xbeef, ResponseCode::NoError));
    assert_eq!(resp.queries, req.queries);
    assert_eq!(resp.answers, []);
    assert!(resp.metadata.recursion_desired);
}

#[tokio::test]
async fn failures_answer_servfail() {
    let failing = Arc::new(FakePolicy { fail: true, ..FakePolicy::default() });
    let gate_addr = gate(upstream().await, &failing).await;
    let resp = ask_udp(gate_addr, "example.com.").await;
    assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
    assert!(resp.answers.is_empty(), "an unprogrammed address must not reach the guest");

    // nothing's listening on a port we just freed.
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let policy = Arc::new(FakePolicy::default());
    let resp = ask_udp(gate(dead, &policy).await, "example.com.").await;
    assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
    assert!(policy.programmed.lock().unwrap().is_empty());
}

#[test]
fn limits_cap_each_client_and_the_total() {
    let limits = Arc::new(Limits::new(3, 2));
    let (a, b, c): (IpAddr, IpAddr, IpAddr) = ([10, 0, 0, 1].into(), [10, 0, 0, 2].into(), [10, 0, 0, 3].into());

    let a1 = Limits::try_admit(&limits, a).unwrap();
    let a2 = Limits::try_admit(&limits, a).unwrap();
    assert!(Limits::try_admit(&limits, a).is_none(), "a is at its share");
    let _b1 = Limits::try_admit(&limits, b).unwrap();
    assert!(Limits::try_admit(&limits, c).is_none(), "the total is spent");

    drop(a1);
    let _a3 = Limits::try_admit(&limits, a).unwrap();
    drop(a2);
    assert!(Limits::try_admit(&limits, c).is_some(), "a released one");
    assert_eq!(limits.in_flight.lock().unwrap().per_client.len(), 2, "c's entry goes once it has nothing in flight");
}

#[test]
fn throttle_reports_what_it_held_back() {
    let throttle = Throttle::new(2);
    let t0 = Instant::now();
    assert_eq!(throttle.admit(t0), Some(0));
    assert_eq!(throttle.admit(t0), Some(0));
    assert_eq!(throttle.admit(t0 + Duration::from_millis(500)), None);
    assert_eq!(throttle.admit(t0 + Duration::from_millis(999)), None);
    assert_eq!(throttle.admit(t0 + Duration::from_secs(1)), Some(2));
    assert_eq!(throttle.admit(t0 + Duration::from_secs(1)), Some(0));
}

#[tokio::test]
async fn edns_queries_relay_with_their_advertised_payload() {
    let policy = Arc::new(FakePolicy::default());
    let gate = gate(upstream().await, &policy).await;
    let mut msg = Message::from_vec(&query("example.com.")).unwrap();
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(1232);
    msg.edns = Some(edns);
    assert_eq!(msg.max_payload(), 1232);

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&msg.to_vec().unwrap(), gate).await.unwrap();
    let mut buf = vec![0; MAX_MESSAGE];
    let n = timeout(Duration::from_secs(5), sock.recv(&mut buf)).await.unwrap().unwrap();
    assert_eq!(a_records(&Message::from_vec(&buf[..n]).unwrap()), CLAMPED);
}

#[tokio::test]
async fn any_port_finds_one_free_for_both_protocols() {
    // holding TCP on ports UDP just freed makes a collision likely when UDP reuses one.
    let mut held = Vec::new();
    for _ in 0..64 {
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        if let Ok(tcp) = TcpListener::bind(probe.local_addr().unwrap()).await {
            held.push(tcp);
        }
    }
    for _ in 0..64 {
        let (udp, tcp) = bind_pair("127.0.0.1:0".parse().unwrap()).await.unwrap();
        assert_eq!(udp.local_addr().unwrap(), tcp.local_addr().unwrap());
    }

    // a port asked for by number doesn't get a second try.
    let busy = held[0].local_addr().unwrap();
    assert_eq!(bind_pair(busy).await.unwrap_err().kind(), io::ErrorKind::AddrInUse);
}
