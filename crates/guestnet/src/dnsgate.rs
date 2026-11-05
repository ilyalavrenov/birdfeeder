//! The DNS gate. Guests with an FQDN allowlist resolve through it, and every A record it relays goes into the session's
//! FQDN set before the guest sees the answer, so the guest's first connection is already allowed.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RData;
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::timeout;

/// Timeout for each upstream exchange, UDP and any TCP retry.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a guest's TCP connection can sit idle between queries.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_MESSAGE: usize = u16::MAX as usize;
/// UDP queries and TCP connections served at once, across all guests. Each one holds an upstream socket and a buffer,
/// so past this we shed new work. The guest's resolver will retry a dropped datagram.
const MAX_IN_FLIGHT: usize = 256;
/// One guest's share of [`MAX_IN_FLIGHT`], so a guest flooding allowed names can't starve everyone else.
const MAX_IN_FLIGHT_PER_CLIENT: usize = 16;
/// Refusals logged per second. The rest still count in the metric and get summed into the next line we log.
const REFUSED_LOGS_PER_SEC: u32 = 10;

/// Decides which guests the gate answers, and installs what it resolves for them.
pub trait Policy: Send + Sync + 'static {
    /// Identifies the session a grant was for, so programming can refuse one that's been replaced since.
    type Grant: Send;

    /// The grant for `client` to resolve `qname`, or `None` to refuse it. [`fqdn_allowed`] matches an allowlist.
    fn grant(&self, client: Ipv4Addr, qname: &str) -> Option<Self::Grant>;

    /// Lets the resolved addresses in for the grant's session, each with its clamped TTL in seconds.
    fn program(&self, grant: Self::Grant, addrs: BTreeMap<Ipv4Addr, u32>) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// Whether any pattern in `allow` matches `qname`.
#[must_use]
pub fn fqdn_allowed(allow: &[FqdnPattern], qname: &str) -> bool {
    allow.iter().any(|p| p.matches(qname))
}

/// An FQDN allowlist entry, lowercased, without the root's trailing dot. Reads and writes as the entry's text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum FqdnPattern {
    Exact(String),
    /// `*.suffix`, which covers the suffix's subdomains but not the suffix itself.
    Wildcard(String),
}

impl FqdnPattern {
    /// Whether this pattern allows `qname`, in any case, with or without the trailing dot.
    pub(crate) fn matches(&self, qname: &str) -> bool {
        // bytes, not str: splitting a non-ASCII name at the suffix length could land mid-char.
        let name = qname.strip_suffix('.').unwrap_or(qname).as_bytes();
        match self {
            Self::Exact(exact) => name.eq_ignore_ascii_case(exact.as_bytes()),
            Self::Wildcard(suffix) => {
                name.len() > suffix.len() && {
                    let (sub, tail) = name.split_at(name.len() - suffix.len());
                    sub.ends_with(b".") && tail.eq_ignore_ascii_case(suffix.as_bytes())
                }
            }
        }
    }
}

impl std::str::FromStr for FqdnPattern {
    type Err = EmptyFqdnPattern;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase();
        let pattern = match name.strip_prefix("*.") {
            Some(suffix) => Self::Wildcard(suffix.to_owned()),
            None => Self::Exact(name),
        };
        match &pattern {
            Self::Exact(n) | Self::Wildcard(n) if n.is_empty() => Err(EmptyFqdnPattern),
            _ => Ok(pattern),
        }
    }
}

impl TryFrom<String> for FqdnPattern {
    type Error = EmptyFqdnPattern;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Display for FqdnPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(name) => f.write_str(name),
            Self::Wildcard(suffix) => write!(f, "*.{suffix}"),
        }
    }
}

impl From<FqdnPattern> for String {
    fn from(p: FqdnPattern) -> Self {
        p.to_string()
    }
}

/// An FQDN pattern with no name to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyFqdnPattern;

impl fmt::Display for EmptyFqdnPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("empty fqdn pattern")
    }
}

impl std::error::Error for EmptyFqdnPattern {}

/// The first nameserver in a resolv.conf.
#[must_use]
pub fn resolv_conf_upstream(conf: &str) -> Option<SocketAddr> {
    conf.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|rest| rest.split_whitespace().next()?.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .next()
}

#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub upstream: SocketAddr,
    /// Relayed A records' TTLs get clamped into this range, which caps how long an address stays allowed.
    pub min_ttl: u32,
    pub max_ttl: u32,
}

/// The gate's sockets and metrics, bound before roost has a policy to serve them with.
pub struct DnsGate {
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
    metrics: Metrics,
}

struct Inner<P> {
    policy: P,
    cfg: Config,
    metrics: Metrics,
    limits: Arc<Limits>,
    refused_logs: Throttle,
}

// per-query spans would swamp this high-volume path.
struct Metrics {
    queries: Counter<u64>,
    upstream_duration: Histogram<f64>,
}

/// How the gate handled a query. It's the label on the queries metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryOutcome {
    /// Turned away at the in-flight limits.
    Shed,
    Malformed,
    Refused,
    UpstreamError,
    ProgramError,
    Relayed,
}

impl QueryOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Shed => "shed",
            Self::Malformed => "malformed",
            Self::Refused => "refused",
            Self::UpstreamError => "upstream_error",
            Self::ProgramError => "program_error",
            Self::Relayed => "relayed",
        }
    }
}

impl DnsGate {
    /// Binds UDP and TCP on `addr`, so a busy port fails roost at startup instead of on a guest's first lookup.
    pub async fn bind(addr: SocketAddr, meter: &Meter) -> io::Result<Self> {
        let (udp, tcp) = bind_pair(addr).await?;
        let metrics = Metrics {
            queries: meter.u64_counter("birdfeeder.roost.dnsgate.queries").with_description("dnsgate queries by outcome").build(),
            upstream_duration: meter
                .f64_histogram("birdfeeder.roost.dnsgate.upstream.duration")
                .with_unit("s")
                .with_description("upstream dns exchange wall time")
                .build(),
        };
        Ok(Self { udp: Arc::new(udp), tcp, metrics })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    /// Answers queries with `policy` until dropped. Dropping it also aborts any queries in flight.
    pub async fn serve<P: Policy>(self, cfg: Config, policy: P) {
        let Self { udp, tcp, metrics } = self;
        let limits = Arc::new(Limits::new(MAX_IN_FLIGHT, MAX_IN_FLIGHT_PER_CLIENT));
        let inner = Arc::new(Inner { policy, cfg, metrics, limits, refused_logs: Throttle::new(REFUSED_LOGS_PER_SEC) });
        let mut tasks = JoinSet::new();
        let mut buf = vec![0; MAX_MESSAGE];
        loop {
            tokio::select! {
                recv = udp.recv_from(&mut buf) => match recv {
                    Ok((n, client)) => {
                        let Some(admitted) = inner.admit(client.ip()) else { continue };
                        let (inner, udp, query) = (Arc::clone(&inner), Arc::clone(&udp), buf[..n].to_vec());
                        tasks.spawn(async move {
                            let _admitted = admitted;
                            if let Some(reply) = inner.handle(client.ip(), &query, Transport::Udp).await
                                && let Err(err) = udp.send_to(&reply, client).await
                            {
                                tracing::debug!(%client, error = %err, "dnsgate reply");
                            }
                        });
                    }
                    // on Linux an ICMP error from an earlier reply shows up here, but the socket's still good.
                    Err(err) => tracing::debug!(error = %err, "dnsgate udp recv"),
                },
                accept = tcp.accept() => match accept {
                    // a connection keeps its admission for as long as it lives, since it holds a socket the whole time.
                    Ok((stream, client)) => {
                        if let Some(admitted) = inner.admit(client.ip()) {
                            let inner = Arc::clone(&inner);
                            tasks.spawn(async move {
                                let _admitted = admitted;
                                inner.serve_tcp(stream, client.ip()).await;
                            });
                        }
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "dnsgate tcp accept");
                        // otherwise fd exhaustion would spin.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
                Some(_) = tasks.join_next() => {}
            }
        }
    }
}

impl<P: Policy> Inner<P> {
    fn admit(&self, client: IpAddr) -> Option<Admitted> {
        let admitted = Limits::try_admit(&self.limits, client);
        if admitted.is_none() {
            self.count(QueryOutcome::Shed);
        }
        admitted
    }

    async fn serve_tcp(&self, mut stream: TcpStream, client: IpAddr) {
        loop {
            let Ok(Ok(len)) = timeout(TCP_IDLE_TIMEOUT, stream.read_u16()).await else { return };
            let mut query = vec![0; usize::from(len)];
            if !matches!(timeout(EXCHANGE_TIMEOUT, stream.read_exact(&mut query)).await, Ok(Ok(_))) {
                return;
            }
            let Some(reply) = self.handle(client, &query, Transport::Tcp).await else { return };
            if write_framed(&mut stream, &reply).await.is_err() {
                return;
            }
        }
    }

    fn count(&self, outcome: QueryOutcome) {
        self.metrics.queries.add(1, &[KeyValue::new("birdfeeder.operation.outcome", outcome.as_str())]);
    }

    /// Refuses a query `client` isn't allowed to make. `qname` is `None` when it didn't ask exactly one question.
    fn refuse(&self, req: &Message, client: IpAddr, qname: Option<&str>) -> Option<Vec<u8>> {
        self.count(QueryOutcome::Refused);
        if let Some(suppressed) = self.refused_logs.admit(Instant::now()) {
            tracing::info!(%client, q = qname.unwrap_or_default(), suppressed, "dnsgate refused");
        }
        reply(req, ResponseCode::Refused)
    }

    /// The wire reply to one query, or `None` for a message too broken to answer.
    async fn handle(&self, client: IpAddr, query: &[u8], transport: Transport) -> Option<Vec<u8>> {
        let Ok(req) = Message::from_vec(query) else {
            self.count(QueryOutcome::Malformed);
            return None;
        };
        let [q] = req.queries.as_slice() else { return self.refuse(&req, client, None) };
        let qname = q.name.to_ascii();
        let v4 = match client {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(ip) => ip.to_ipv4_mapped(),
        };
        let Some(grant) = v4.and_then(|ip| self.policy.grant(ip, &qname)) else { return self.refuse(&req, client, Some(&qname)) };

        let mut resp = match self.exchange(query, req.metadata.id, req.max_payload(), transport).await {
            Ok(resp) => resp,
            Err(err) => {
                self.count(QueryOutcome::UpstreamError);
                tracing::warn!(q = qname, error = format!("{err:#}"), "dnsgate upstream");
                return reply(&req, ResponseCode::ServFail);
            }
        };

        let mut addrs = BTreeMap::new();
        for rr in &mut resp.answers {
            // AAAA goes through without programming anything: guests are v4-only and their chain drops v6.
            if let RData::A(a) = rr.data {
                rr.ttl = rr.ttl.clamp(self.cfg.min_ttl, self.cfg.max_ttl);
                addrs.insert(a.0, rr.ttl);
            }
        }
        if !addrs.is_empty()
            && let Err(err) = self.policy.program(grant, addrs).await
        {
            self.count(QueryOutcome::ProgramError);
            tracing::error!(q = qname, error = format!("{err:#}"), "dnsgate program");
            return reply(&req, ResponseCode::ServFail);
        }

        self.count(QueryOutcome::Relayed);
        let wire = resp.to_vec().inspect_err(|err| tracing::warn!(q = qname, error = %err, "dnsgate encode")).ok()?;
        // re-encoding can come out bigger than what upstream sized for the guest, and a UDP guest can't take that.
        if transport == Transport::Udp && wire.len() > usize::from(req.max_payload()) {
            return truncated(&req);
        }
        Some(wire)
    }

    /// Asks upstream over UDP first. If the answer's truncated, we refetch over TCP only for a TCP guest. A UDP guest
    /// gets it truncated, the way upstream sized it, and retries over TCP on its own.
    async fn exchange(&self, query: &[u8], id: u16, max_payload: u16, transport: Transport) -> anyhow::Result<Message> {
        let start = Instant::now();
        let resp = async {
            let resp =
                timeout(EXCHANGE_TIMEOUT, exchange_udp(self.cfg.upstream, query, id, max_payload)).await.context("udp timed out")??;
            if !resp.metadata.truncation || transport == Transport::Udp {
                return Ok(resp);
            }
            timeout(EXCHANGE_TIMEOUT, exchange_tcp(self.cfg.upstream, query)).await.context("tcp timed out")?
        }
        .await
        .with_context(|| format!("exchange {}", self.cfg.upstream));
        self.metrics.upstream_duration.record(start.elapsed().as_secs_f64(), &[]);
        resp
    }
}

/// Relays `query` as-is, so upstream sizes its UDP answer to the guest's advertised `max_payload` (512 without EDNS)
/// and truncates past it. So the buffer never needs more.
async fn exchange_udp(upstream: SocketAddr, query: &[u8], id: u16, max_payload: u16) -> anyhow::Result<Message> {
    let local: SocketAddr = if upstream.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
    let sock = UdpSocket::bind(local).await?;
    sock.connect(upstream).await?;
    sock.send(query).await?;
    let mut buf = vec![0; usize::from(max_payload)];
    loop {
        let n = sock.recv(&mut buf).await?;
        // a stray or spoofed datagram can't count as the answer.
        if let Ok(resp) = Message::from_vec(&buf[..n])
            && resp.metadata.id == id
        {
            return Ok(resp);
        }
    }
}

async fn exchange_tcp(upstream: SocketAddr, query: &[u8]) -> anyhow::Result<Message> {
    let mut stream = TcpStream::connect(upstream).await?;
    write_framed(&mut stream, query).await?;
    let mut resp = vec![0; usize::from(stream.read_u16().await?)];
    stream.read_exact(&mut resp).await?;
    Ok(Message::from_vec(&resp)?)
}

/// Tries for a port that's free for both UDP and TCP when `addr` asks for any port.
const BIND_ATTEMPTS: usize = 16;

/// Binds UDP and TCP on one port. With port 0 UDP picks it, but that port might already be taken for TCP, so then we
/// try a fresh UDP port.
async fn bind_pair(addr: SocketAddr) -> io::Result<(UdpSocket, TcpListener)> {
    let mut attempts = if addr.port() == 0 { BIND_ATTEMPTS } else { 1 };
    loop {
        let udp = UdpSocket::bind(addr).await?;
        match TcpListener::bind(udp.local_addr()?).await {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(err) if err.kind() == io::ErrorKind::AddrInUse && attempts > 1 => attempts -= 1,
            Err(err) => return Err(err),
        }
    }
}

async fn write_framed(stream: &mut TcpStream, msg: &[u8]) -> io::Result<()> {
    let len = u16::try_from(msg.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "dns message over 64 KiB"))?;
    let mut framed = Vec::with_capacity(msg.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(msg);
    stream.write_all(&framed).await
}

/// How a guest's query came in, which caps the reply: UDP to the guest's advertised payload, TCP to 64 KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
}

/// Caps work in flight, overall and per client.
struct Limits {
    max_total: usize,
    max_per_client: usize,
    in_flight: Mutex<InFlight>,
}

#[derive(Default)]
struct InFlight {
    total: usize,
    per_client: HashMap<IpAddr, usize>,
}

/// One admitted query or connection, released on drop.
struct Admitted {
    limits: Arc<Limits>,
    client: IpAddr,
}

impl Limits {
    fn new(max_total: usize, max_per_client: usize) -> Self {
        Self { max_total, max_per_client, in_flight: Mutex::default() }
    }

    fn try_admit(this: &Arc<Self>, client: IpAddr) -> Option<Admitted> {
        let mut in_flight = this.in_flight.lock().unwrap();
        if in_flight.total >= this.max_total {
            return None;
        }
        let mine = in_flight.per_client.entry(client).or_default();
        if *mine >= this.max_per_client {
            return None;
        }
        *mine += 1;
        in_flight.total += 1;
        Some(Admitted { limits: Arc::clone(this), client })
    }
}

impl Drop for Admitted {
    fn drop(&mut self) {
        let mut in_flight = self.limits.in_flight.lock().unwrap();
        in_flight.total -= 1;
        // drop idle clients so the map only holds clients with work in flight.
        if let Some(mine) = in_flight.per_client.get_mut(&self.client) {
            *mine -= 1;
            if *mine == 0 {
                in_flight.per_client.remove(&self.client);
            }
        }
    }
}

/// Lets `per_sec` events through each second, and tells each one it lets through how many got held back before it.
struct Throttle {
    per_sec: u32,
    state: Mutex<ThrottleState>,
}

struct ThrottleState {
    window: Option<Instant>,
    used: u32,
    held: u64,
}

impl Throttle {
    fn new(per_sec: u32) -> Self {
        Self { per_sec, state: Mutex::new(ThrottleState { window: None, used: 0, held: 0 }) }
    }

    fn admit(&self, now: Instant) -> Option<u64> {
        let mut s = self.state.lock().unwrap();
        if s.window.is_none_or(|w| now.duration_since(w) >= Duration::from_secs(1)) {
            s.window = Some(now);
            s.used = 0;
        }
        if s.used < self.per_sec {
            s.used += 1;
            Some(std::mem::take(&mut s.held))
        } else {
            s.held += 1;
            None
        }
    }
}

/// An answerless reply carrying `rcode`, shaped like the request.
fn reply(req: &Message, rcode: ResponseCode) -> Option<Vec<u8>> {
    answerless(req, rcode).to_vec().ok()
}

/// An answerless reply with TC set, which sends the guest's resolver back over TCP.
fn truncated(req: &Message) -> Option<Vec<u8>> {
    let mut resp = answerless(req, ResponseCode::NoError);
    resp.metadata.truncation = true;
    resp.to_vec().ok()
}

fn answerless(req: &Message, rcode: ResponseCode) -> Message {
    let mut resp = Message::error_msg(req.metadata.id, req.metadata.op_code, rcode);
    resp.metadata.recursion_desired = req.metadata.recursion_desired;
    resp.metadata.checking_disabled = req.metadata.checking_disabled;
    resp.queries.clone_from(&req.queries);
    resp
}

#[cfg(test)]
mod tests;
