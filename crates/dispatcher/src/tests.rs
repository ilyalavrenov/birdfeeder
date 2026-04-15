use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use opentelemetry::metrics::MeterProvider as _;
use opentelemetry_sdk::metrics::{
    InMemoryMetricExporter, PeriodicReader, SdkMeterProvider,
    data::{AggregatedMetrics, MetricData},
};
use roost_api::v1::{
    ClaimSessionRequest, ClaimSessionResponse, DeleteSessionRequest, DeleteSessionResponse, GetSessionRequest, GetSessionResponse,
    HostStatusRequest, HostStatusResponse, ListSessionsRequest, ListSessionsResponse, PoolFill, Session, SessionState,
    SetSessionExpiryRequest, SetSessionExpiryResponse,
    roost_service_client::RoostServiceClient,
    roost_service_server::{RoostService, RoostServiceServer},
};
use rstest::rstest;
use tokio::{net::TcpListener, sync::oneshot};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Code, Request, Response, Status, transport::Server};

use super::*;

#[derive(Default)]
struct State {
    status: HostStatusResponse,
    status_err: bool,
    claim_err: Option<Code>,
    /// commits the claim, then fails like the answer got lost.
    claim_lost: Option<Code>,
    claim_delay: Option<Duration>,
    /// each idempotency key and the session it claimed.
    keys: BTreeMap<String, String>,
    list_err: bool,
    sessions: BTreeMap<String, Session>,
    claims: usize,
    gets: usize,
    expiries: usize,
}

/// A roost whose status, failures, and sessions a test sets.
#[derive(Clone)]
struct FakeRoost {
    name: &'static str,
    state: Arc<Mutex<State>>,
}

impl FakeRoost {
    fn new(name: &'static str, status: HostStatusResponse) -> Self {
        Self { name, state: Arc::new(Mutex::new(State { status, ..State::default() })) }
    }

    fn set(&self, f: impl FnOnce(&mut State)) {
        f(&mut self.state.lock().unwrap());
    }

    fn get<T>(&self, f: impl FnOnce(&State) -> T) -> T {
        f(&self.state.lock().unwrap())
    }

    fn seed(&self, name: &str) {
        let session = self.session(name);
        self.set(|s| {
            s.sessions.insert(name.to_owned(), session);
        });
    }

    fn session(&self, name: &str) -> Session {
        Session {
            name: name.to_owned(),
            endpoints: BTreeMap::from([("http".to_owned(), "10.0.0.1:31000".to_owned())]),
            generation: 1,
            state: SessionState::Claimed.into(),
            host_id: self.name.to_owned(),
            ..Session::default()
        }
    }

    fn lookup(&self, name: &str) -> Result<Session, Status> {
        self.get(|s| s.sessions.get(name).cloned()).ok_or_else(|| Status::not_found("no such session"))
    }
}

#[tonic::async_trait]
impl RoostService for FakeRoost {
    async fn claim_session(&self, req: Request<ClaimSessionRequest>) -> Result<Response<ClaimSessionResponse>, Status> {
        if let Some(delay) = self.get(|s| s.claim_delay) {
            tokio::time::sleep(delay).await;
        }
        let mut s = self.state.lock().unwrap();
        let msg = req.into_inner();
        if let Some(name) = s.keys.get(&msg.idempotency_key) {
            return Ok(Response::new(ClaimSessionResponse { session: s.sessions.get(name).cloned() }));
        }
        if let Some(code) = s.claim_err {
            return Err(Status::new(code, "claim refused"));
        }
        let mut session = self.session(&format!("{}-{}-{}", self.name, msg.template_id, s.claims));
        session.labels = msg.labels;
        s.claims += 1;
        s.sessions.insert(session.name.clone(), session.clone());
        if !msg.idempotency_key.is_empty() {
            s.keys.insert(msg.idempotency_key, session.name.clone());
        }
        if let Some(code) = s.claim_lost {
            return Err(Status::new(code, "answer lost"));
        }
        Ok(Response::new(ClaimSessionResponse { session: Some(session) }))
    }

    async fn get_session(&self, req: Request<GetSessionRequest>) -> Result<Response<GetSessionResponse>, Status> {
        self.set(|s| s.gets += 1);
        let msg = req.into_inner();
        let name = if msg.idempotency_key.is_empty() {
            msg.name
        } else {
            self.get(|s| s.keys.get(&msg.idempotency_key).cloned()).ok_or_else(|| Status::not_found("no such key"))?
        };
        Ok(Response::new(GetSessionResponse { session: Some(self.lookup(&name)?) }))
    }

    async fn delete_session(&self, req: Request<DeleteSessionRequest>) -> Result<Response<DeleteSessionResponse>, Status> {
        self.lookup(&req.get_ref().name)?;
        self.set(|s| {
            s.sessions.remove(&req.get_ref().name);
        });
        Ok(Response::new(DeleteSessionResponse {}))
    }

    async fn list_sessions(&self, req: Request<ListSessionsRequest>) -> Result<Response<ListSessionsResponse>, Status> {
        let s = self.state.lock().unwrap();
        if s.list_err {
            return Err(Status::unavailable("list refused"));
        }
        let selector = req.into_inner().labels;
        let matching = s.sessions.values().filter(|session| selector.iter().all(|(k, v)| session.labels.get(k) == Some(v)));
        Ok(Response::new(ListSessionsResponse { sessions: matching.cloned().collect() }))
    }

    async fn set_session_expiry(&self, req: Request<SetSessionExpiryRequest>) -> Result<Response<SetSessionExpiryResponse>, Status> {
        self.lookup(&req.get_ref().name)?;
        self.set(|s| s.expiries += 1);
        Ok(Response::new(SetSessionExpiryResponse {}))
    }

    async fn host_status(&self, _: Request<HostStatusRequest>) -> Result<Response<HostStatusResponse>, Status> {
        let s = self.state.lock().unwrap();
        if s.status_err {
            return Err(Status::unavailable("status refused"));
        }
        Ok(Response::new(s.status.clone()))
    }
}

/// Serves `routes` on a loopback port until the returned sender fires or drops.
async fn serve(routes: Routes) -> (SocketAddr, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let server = Server::builder().add_routes(routes).serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
        let _ = stopped.await;
    });
    tokio::spawn(server);
    (addr, stop)
}

struct Harness {
    registry: Arc<Registry>,
    dispatcher: Arc<Dispatcher>,
    meters: SdkMeterProvider,
    metrics: InMemoryMetricExporter,
    servers: Vec<oneshot::Sender<()>>,
}

const CLAIM_TIMEOUT: Duration = Duration::from_secs(5);

async fn harness(suspect_after: u32, roosts: &[&FakeRoost]) -> Harness {
    harness_with(suspect_after, CLAIM_TIMEOUT, roosts).await
}

/// A dispatcher over `roosts`, polled once.
async fn harness_with(suspect_after: u32, claim_timeout: Duration, roosts: &[&FakeRoost]) -> Harness {
    let h = unpolled(suspect_after, claim_timeout, roosts).await;
    h.registry.poll().await;
    h
}

async fn unpolled(suspect_after: u32, claim_timeout: Duration, roosts: &[&FakeRoost]) -> Harness {
    let mut hosts = Vec::new();
    let mut servers = Vec::new();
    for roost in roosts {
        let (addr, stop) = serve(Routes::new(RoostServiceServer::new((*roost).clone()))).await;
        hosts.push(Host::new(roost.name, addr.to_string().parse().unwrap()));
        servers.push(stop);
    }
    let metrics = InMemoryMetricExporter::default();
    let meters = SdkMeterProvider::builder().with_reader(PeriodicReader::builder(metrics.clone()).build()).build();
    let meter = meters.meter("test");
    let registry = Registry::new(hosts, Duration::from_secs(5), suspect_after, &meter).unwrap();
    let dispatcher = Dispatcher::new(registry.clone(), claim_timeout, Duration::from_secs(5), &meter);
    Harness { registry, dispatcher, meters, metrics, servers }
}

impl Harness {
    async fn claim(&self, template: &str) -> Result<Session, Status> {
        let req = Request::new(ClaimSessionRequest { template_id: template.to_owned(), ..ClaimSessionRequest::default() });
        Ok(self.dispatcher.claim_session(req).await?.into_inner().session.unwrap())
    }

    async fn get(&self, name: &str) -> Result<Session, Status> {
        Ok(self
            .dispatcher
            .get_session(Request::new(GetSessionRequest { name: name.to_owned(), ..GetSessionRequest::default() }))
            .await?
            .into_inner()
            .session
            .unwrap())
    }

    async fn delete(&self, name: &str) -> Result<(), Status> {
        let req = DeleteSessionRequest { name: name.to_owned(), generation: 1 };
        self.dispatcher.delete_session(Request::new(req)).await.map(drop)
    }

    async fn list(&self) -> Result<Vec<String>, Status> {
        let list = self.dispatcher.list_sessions(Request::new(ListSessionsRequest::default())).await?.into_inner();
        Ok(list.sessions.into_iter().map(|s| s.name).collect())
    }

    async fn claim_keyed(&self, template: &str, key: &str) -> Result<Session, Status> {
        let req = ClaimSessionRequest {
            template_id: template.to_owned(),
            labels: [("job".to_owned(), key.to_owned())].into(),
            idempotency_key: key.to_owned(),
            ..ClaimSessionRequest::default()
        };
        Ok(self.dispatcher.claim_session(Request::new(req)).await?.into_inner().session.unwrap())
    }

    async fn status(&self) -> Result<HostStatusResponse, Status> {
        Ok(self.dispatcher.host_status(Request::new(HostStatusRequest {})).await?.into_inner())
    }

    /// The latest cumulative value of counter `name`, by the value of attribute `key`.
    fn counts(&self, name: &str, key: &str) -> BTreeMap<String, u64> {
        self.meters.force_flush().unwrap();
        let batches = self.metrics.get_finished_metrics().unwrap();
        let mut out = BTreeMap::new();
        let Some(latest) = batches.last() else { return out };
        for metric in latest.scope_metrics().flat_map(opentelemetry_sdk::metrics::data::ScopeMetrics::metrics) {
            if metric.name() != name {
                continue;
            }
            let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() else { continue };
            for point in sum.data_points() {
                let value = point.attributes().find(|kv| kv.key.as_str() == key).map(|kv| kv.value.to_string()).unwrap_or_default();
                *out.entry(value).or_default() += point.value();
            }
        }
        out
    }
}

fn status(capacity: i32, running: i32, pools: Vec<PoolFill>) -> HostStatusResponse {
    HostStatusResponse { capacity, running, pools, ..HostStatusResponse::default() }
}

fn pool(template: &str, ready: i32, target: i32) -> PoolFill {
    PoolFill { template_id: template.to_owned(), ready, target, fingerprint: "abc".to_owned() }
}

fn counts(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
    pairs.iter().map(|&(k, v)| (k.to_owned(), v)).collect()
}

#[tokio::test]
async fn keyed_retry_returns_to_the_claiming_host() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 3, 5)]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![pool("web-v1", 1, 5)]));
    let h = harness(3, &[&wa, &wb]).await;
    wa.set(|s| s.claim_lost = Some(Code::Unavailable));
    assert_eq!(h.claim_keyed("web-v1", "job-7").await.unwrap_err().code(), Code::Unavailable);
    // wb now has the most pooled guests, where an unkeyed claim would go.
    wa.set(|s| s.claim_lost = None);
    wb.set(|s| s.status = status(10, 2, vec![pool("web-v1", 5, 5)]));
    h.registry.poll().await;
    let retried = h.claim_keyed("web-v1", "job-7").await.unwrap();
    assert_eq!(retried.name, "wa-web-v1-0");
    assert_eq!((wa.get(|s| s.claims), wb.get(|s| s.claims)), (1, 0));
    let by_key = GetSessionRequest { idempotency_key: "job-7".into(), ..GetSessionRequest::default() };
    assert_eq!(h.dispatcher.get_session(Request::new(by_key)).await.unwrap().into_inner().session.unwrap(), retried);
    assert_eq!(h.counts("birdfeeder.dispatcher.claims", "birdfeeder.operation.outcome"), counts(&[("ambiguous", 1), ("replayed", 1)]));
    assert_eq!(h.claim_keyed("web-v1", "job-8").await.unwrap().host_id, "wb", "a new key is placed like any claim");
}

#[tokio::test]
async fn keyed_claim_waits_for_an_abandoned_attempt() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 3, 5)]));
    wa.set(|s| s.claim_delay = Some(Duration::from_millis(300)));
    let h = harness(3, &[&wa]).await;
    let abandoned = tokio::time::timeout(Duration::from_millis(50), h.claim_keyed("web-v1", "job-7")).await;
    assert!(abandoned.is_err());
    let retried = h.claim_keyed("web-v1", "job-7").await.unwrap();
    assert_eq!((retried.name.as_str(), wa.get(|s| s.claims)), ("wa-web-v1-0", 1));
}

#[tokio::test]
async fn keyed_claims_and_lookups_need_every_host() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 3, 5)]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![]));
    wb.set(|s| s.status_err = true);
    let h = harness(3, &[&wa, &wb]).await;
    assert_eq!(h.claim_keyed("web-v1", "job-7").await.unwrap_err().code(), Code::Unavailable, "wb may hold the key");
    assert_eq!(wa.get(|s| s.claims), 0);
    let by_key = GetSessionRequest { idempotency_key: "job-7".into(), ..GetSessionRequest::default() };
    assert_eq!(h.dispatcher.get_session(Request::new(by_key)).await.unwrap_err().code(), Code::Unavailable);
    wb.set(|s| s.status_err = false);
    h.registry.poll().await;
    let by_key = GetSessionRequest { idempotency_key: "job-7".into(), ..GetSessionRequest::default() };
    assert_eq!(h.dispatcher.get_session(Request::new(by_key)).await.unwrap_err().code(), Code::NotFound);
    let both = GetSessionRequest { name: "wa-web-v1-0".into(), idempotency_key: "job-7".into() };
    assert_eq!(h.dispatcher.get_session(Request::new(both)).await.unwrap_err().code(), Code::InvalidArgument);
}

#[tokio::test]
async fn sessions_list_by_label_across_hosts() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 3, 5)]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![pool("web-v1", 1, 5)]));
    let h = harness(3, &[&wa, &wb]).await;
    let seven = h.claim_keyed("web-v1", "job-7").await.unwrap();
    wa.set(|s| s.claim_err = Some(Code::ResourceExhausted));
    let eight = h.claim_keyed("web-v1", "job-8").await.unwrap();
    assert_eq!((seven.host_id.as_str(), eight.host_id.as_str()), ("wa", "wb"));
    for (job, want) in [("job-8", vec![eight]), ("job-9", vec![])] {
        let select = ListSessionsRequest { labels: [("job".to_owned(), job.to_owned())].into() };
        assert_eq!(h.dispatcher.list_sessions(Request::new(select)).await.unwrap().into_inner().sessions, want, "{job}");
    }
}

#[tokio::test]
async fn claim_outcomes_are_counted() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 3, 5)]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![pool("web-v1", 1, 5)]));
    let h = harness(3, &[&wa, &wb]).await;
    h.claim("web-v1").await.unwrap();
    wa.set(|s| s.claim_err = Some(Code::ResourceExhausted));
    h.claim("web-v1").await.unwrap();
    wb.set(|s| s.claim_err = Some(Code::ResourceExhausted));
    h.claim("web-v1").await.unwrap_err();
    h.claim("worker-v1").await.unwrap_err();
    h.claim("").await.unwrap_err();
    let cancelled = h.dispatcher.claim_session(Request::new(ClaimSessionRequest { template_id: "web-v1".into(), ..Default::default() }));
    drop(cancelled);
    assert_eq!(
        h.counts("birdfeeder.dispatcher.claims", "birdfeeder.operation.outcome"),
        counts(&[("ok", 1), ("failed_over", 1), ("all_failed", 1), ("no_candidates", 1), ("invalid", 1)])
    );
}

#[tokio::test]
async fn dropped_claim_counts_as_canceled() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 3, 5)]));
    wa.set(|s| s.claim_delay = Some(Duration::from_secs(5)));
    let h = harness(3, &[&wa]).await;
    let attempt = tokio::time::timeout(Duration::from_millis(50), h.claim("web-v1")).await;
    assert!(attempt.is_err());
    assert_eq!(h.counts("birdfeeder.dispatcher.claims", "birdfeeder.operation.outcome"), counts(&[("canceled", 1)]));
}

#[tokio::test]
async fn host_transitions_are_counted() {
    let wa = FakeRoost::new("wa", status(10, 0, vec![]));
    let h = harness(1, &[&wa]).await;
    wa.set(|s| s.status_err = true);
    h.registry.poll().await;
    h.registry.poll().await;
    wa.set(|s| s.status_err = false);
    h.registry.poll().await;
    assert_eq!(h.counts("birdfeeder.dispatcher.host.transitions", "birdfeeder.host.state"), counts(&[("ready", 2), ("suspect", 1)]));
}

#[tokio::test]
async fn claims_go_to_the_most_pooled_host() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 3, 5)]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![pool("web-v1", 1, 5)]));
    let h = harness(3, &[&wa, &wb]).await;
    let session = h.claim("web-v1").await.unwrap();
    assert_eq!(session.name, "wa-web-v1-0");
    assert_eq!(session.host_id, "wa", "roost's host_id passes through");
    assert_eq!((wa.get(|s| s.claims), wb.get(|s| s.claims)), (1, 0));
}

#[tokio::test]
async fn claims_need_the_exact_template() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v2", 5, 5)]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![pool("web-v1", 1, 1)]));
    let h = harness(3, &[&wa, &wb]).await;
    assert_eq!(h.claim("web-v1").await.unwrap().host_id, "wb");
    assert_eq!(h.claim("").await.unwrap_err().code(), Code::InvalidArgument);
}

#[tokio::test]
async fn claims_fail_over_only_on_exhaustion() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 3, 5)]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![pool("web-v1", 1, 5)]));
    let h = harness(3, &[&wa, &wb]).await;
    wa.set(|s| s.claim_err = Some(Code::ResourceExhausted));
    assert_eq!(h.claim("web-v1").await.unwrap().name, "wb-web-v1-0");
    wb.set(|s| s.claim_err = Some(Code::ResourceExhausted));
    let err = h.claim("web-v1").await.unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert!(err.message().contains("wa: claim refused") && err.message().contains("wb: claim refused"), "{err:?}");
}

#[tokio::test]
async fn claims_skip_unbooted_capacity() {
    let wa = FakeRoost::new("wa", status(10, 0, vec![]));
    let h = harness(3, &[&wa]).await;
    assert_eq!(h.claim("web-v1").await.unwrap_err().code(), Code::ResourceExhausted);
    assert_eq!(wa.get(|s| s.claims), 0);
}

#[rstest]
#[case::unavailable(Code::Unavailable)]
#[case::deadline_exceeded(Code::DeadlineExceeded)]
#[case::internal(Code::Internal)]
#[case::cancelled(Code::Cancelled)]
#[tokio::test]
async fn ambiguous_claim_failures_are_not_retried(#[case] code: Code) {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 3, 5)]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![pool("web-v1", 1, 5)]));
    let h = harness(3, &[&wa, &wb]).await;
    wa.set(|s| s.claim_err = Some(code));
    let err = h.claim("web-v1").await.unwrap_err();
    assert_eq!((err.code(), err.message()), (code, "claim refused"));
    assert_eq!(wb.get(|s| s.claims), 0, "{code:?} was retried");
}

#[tokio::test]
async fn claims_fail_over_on_refused_connections() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 3, 5)]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![pool("web-v1", 1, 5)]));
    let mut h = harness(3, &[&wa, &wb]).await;
    // wa stays ready (and first in line) until a poll notices it's gone.
    drop(h.servers.remove(0));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(h.claim("web-v1").await.unwrap().name, "wb-web-v1-0");
    assert_eq!(h.counts("birdfeeder.dispatcher.claims", "birdfeeder.operation.outcome"), counts(&[("failed_over", 1)]));
    h.servers.clear();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let err = h.claim("web-v1").await.unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted, "nothing was claimed anywhere: {err:?}");
    assert!(err.message().contains("wa: claim on host wa") && err.message().contains("wb: claim on host wb"), "{err:?}");
}

#[tokio::test]
async fn failing_hosts_get_claims_last() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 3, 5)]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![pool("web-v1", 1, 5)]));
    let h = harness(3, &[&wa, &wb]).await;
    wa.set(|s| s.status_err = true);
    h.registry.poll().await;
    assert_eq!(h.claim("web-v1").await.unwrap().name, "wb-web-v1-0");
    wb.set(|s| s.claim_err = Some(Code::ResourceExhausted));
    assert_eq!(h.claim("web-v1").await.unwrap().name, "wa-web-v1-0", "a failing host is still a candidate");
    wa.set(|s| s.status_err = false);
    wb.set(|s| s.claim_err = None);
    h.registry.poll().await;
    assert_eq!(h.claim("web-v1").await.unwrap().host_id, "wa", "a healthy poll restores its place");
}

#[tokio::test]
async fn a_slow_claim_times_out_without_a_retry() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 3, 5)]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![pool("web-v1", 1, 5)]));
    wa.set(|s| s.claim_delay = Some(Duration::from_secs(5)));
    let h = harness_with(3, Duration::from_millis(100), &[&wa, &wb]).await;
    let err = h.claim("web-v1").await.unwrap_err();
    assert_eq!(err.code(), Code::DeadlineExceeded, "{err:?}");
    assert!(err.message().contains("claim on host wa"), "{err:?}");
    assert_eq!(wb.get(|s| s.claims), 0);
}

#[rstest]
#[case::other_pool_empty(0)]
#[case::other_pool_ready(1)]
#[tokio::test]
async fn conflicting_template_definitions_refuse_claims(#[case] ready: i32) {
    let mut other = pool("web-v1", ready, 1);
    other.fingerprint = "different".into();
    let wa = FakeRoost::new("wa", status(2, 2, vec![pool("web-v1", 2, 2)]));
    let wb = FakeRoost::new("wb", status(2, 1, vec![other]));
    let h = harness(3, &[&wa, &wb]).await;
    assert_eq!(h.claim("web-v1").await.unwrap_err().code(), Code::FailedPrecondition);
    assert_eq!(wa.get(|s| s.claims) + wb.get(|s| s.claims), 0);
}

#[tokio::test]
async fn session_rpcs_route_by_name() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 3, 5)]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![]));
    let h = harness(3, &[&wa, &wb]).await;
    let name = h.claim("web-v1").await.unwrap().name;
    assert_eq!(h.get(&name).await.unwrap().name, name);
    assert_eq!((wa.get(|s| s.gets), wb.get(|s| s.gets)), (1, 0));
    let expiry = SetSessionExpiryRequest { name: name.clone(), generation: 1, expires_at_ms: 1234 };
    h.dispatcher.set_session_expiry(Request::new(expiry)).await.unwrap();
    assert_eq!(wa.get(|s| s.expiries), 1);
    let unstorable = SetSessionExpiryRequest { name: name.clone(), generation: 1, expires_at_ms: i64::MAX };
    assert_eq!(h.dispatcher.set_session_expiry(Request::new(unstorable)).await.unwrap_err().code(), Code::InvalidArgument);
    assert_eq!(wa.get(|s| s.expiries), 1, "an unstorable expiry must not reach the host");
    h.delete(&name).await.unwrap();
    assert!(wa.lookup(&name).is_err());
    assert_eq!(h.get(&name).await.unwrap_err().code(), Code::NotFound);
}

#[tokio::test]
async fn deletes_reach_only_the_owning_host() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 3, 5)]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![pool("web-v1", 3, 5)]));
    let h = harness(3, &[&wa, &wb]).await;
    wa.seed("wa-web-v1-0");
    wb.seed("wb-web-v1-0");
    h.dispatcher.sweep().await;
    h.delete("wb-web-v1-0").await.unwrap();
    assert!(wb.lookup("wb-web-v1-0").is_err());
    assert!(wa.lookup("wa-web-v1-0").is_ok(), "a delete for wb's session reached wa");
    h.delete("wa-web-v1-0").await.unwrap();
    assert!(wa.lookup("wa-web-v1-0").is_err());
}

#[tokio::test]
async fn an_index_miss_asks_every_host_once() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![]));
    let h = harness(3, &[&wa, &wb]).await;
    wb.seed("orphan-1");
    assert_eq!(h.get("orphan-1").await.unwrap().name, "orphan-1");
    assert_eq!(wa.get(|s| s.gets), 1);
    h.get("orphan-1").await.unwrap();
    assert_eq!(wa.get(|s| s.gets), 1, "the second get should hit the index");
}

#[tokio::test]
async fn sweeps_rebuild_the_index() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![]));
    let h = harness(3, &[&wa, &wb]).await;
    wa.seed("a-s1");
    wb.seed("b-s1");
    h.dispatcher.sweep().await;
    h.get("b-s1").await.unwrap();
    assert_eq!(wa.get(|s| s.gets), 0, "the sweep should have indexed b-s1 to wb");
}

#[tokio::test]
async fn listings_merge_every_host() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![]));
    let h = harness(3, &[&wa, &wb]).await;
    wa.seed("a-s1");
    wa.seed("a-s2");
    wb.seed("b-s1");
    assert_eq!(h.list().await.unwrap(), ["a-s1", "a-s2", "b-s1"]);
    wb.set(|s| s.list_err = true);
    assert_eq!(h.list().await.unwrap_err().code(), Code::Unavailable, "a ready host failing to list must fail the listing");
}

#[tokio::test]
async fn suspect_hosts_get_no_claims() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 5, 5)]));
    let wb = FakeRoost::new("wb", status(10, 2, vec![pool("web-v1", 1, 5)]));
    let h = harness(2, &[&wa, &wb]).await;
    wa.set(|s| s.status_err = true);
    h.registry.poll().await;
    h.registry.poll().await;
    assert_eq!(h.claim("web-v1").await.unwrap().name, "wb-web-v1-0");
    assert_eq!(wa.get(|s| s.claims), 0);
    assert_eq!(h.list().await.unwrap_err().code(), Code::Unavailable, "sessions on suspect hosts must not silently disappear");
}

#[tokio::test]
async fn host_status_sums_ready_hosts() {
    let wa = FakeRoost::new("wa", status(10, 3, vec![pool("web-v1", 3, 5), pool("web-large-v1", 1, 2)]));
    let wb = FakeRoost::new("wb", status(8, 2, vec![pool("web-v1", 1, 5)]));
    let h = harness(3, &[&wa, &wb]).await;
    let total = h.status().await.unwrap();
    assert_eq!((total.capacity, total.running), (18, 5));
    let pools: Vec<_> = total.pools.iter().map(|p| (p.template_id.as_str(), p.ready, p.target)).collect();
    assert_eq!(pools, [("web-large-v1", 1, 2), ("web-v1", 4, 10)]);
}

#[tokio::test]
async fn listings_need_every_host_ready() {
    let wa = FakeRoost::new("wa", status(2, 0, vec![]));
    let h = unpolled(1, CLAIM_TIMEOUT, &[&wa]).await;
    assert_eq!(h.list().await.unwrap_err().code(), Code::Unavailable, "no poll has run");
    wa.set(|s| s.status_err = true);
    h.registry.poll().await;
    assert_eq!(h.list().await.unwrap_err().code(), Code::Unavailable, "the host has never been healthy");
    wa.set(|s| s.status_err = false);
    h.registry.poll().await;
    assert_eq!(h.list().await.unwrap(), Vec::<String>::new());
    wa.seed("still-running");
    wa.set(|s| s.status_err = true);
    h.registry.poll().await;
    assert_eq!(h.list().await.unwrap_err().code(), Code::Unavailable, "every host is suspect");
}

#[tokio::test]
async fn roost_errors_reach_callers_unchanged() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 1, 5)]));
    let h = harness(3, &[&wa]).await;
    let (addr, _stop) = serve(Routes::new(RoostServiceServer::from_arc(h.dispatcher.clone()))).await;
    let channel = tonic::transport::Channel::from_shared(format!("http://{addr}")).unwrap().connect().await.unwrap();
    let mut client = RoostServiceClient::new(channel);
    let claim = ClaimSessionRequest { template_id: "web-v1".into(), ..Default::default() };
    let name = client.claim_session(claim.clone()).await.unwrap().into_inner().session.unwrap().name;
    wa.set(|s| {
        s.sessions.remove(&name);
    });
    let err = client.get_session(GetSessionRequest { name, ..GetSessionRequest::default() }).await.unwrap_err();
    assert_eq!((err.code(), err.message()), (Code::NotFound, "no such session"));
    wa.set(|s| s.claim_err = Some(Code::ResourceExhausted));
    let err = client.claim_session(claim).await.unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert!(err.message().contains("claim refused"), "{err:?}");
}

#[tokio::test]
async fn unreachable_hosts_are_named() {
    let wa = FakeRoost::new("wa", status(10, 2, vec![pool("web-v1", 1, 5)]));
    let mut h = harness(3, &[&wa]).await;
    let name = h.claim("web-v1").await.unwrap().name;
    // the host stays ready until a poll notices it's gone.
    h.servers.clear();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let err = h.get(&name).await.unwrap_err();
    assert_eq!(err.code(), Code::Unavailable, "{err:?}");
    assert!(err.message().starts_with("get session on host wa: "), "{err:?}");
}

#[test]
fn registries_refuse_bad_host_lists() {
    let meter = opentelemetry::global::meter("test");
    let host = Host::new("wa", "127.0.0.1:1".parse().unwrap());
    assert!(Registry::new(vec![host.clone(), host], Duration::from_secs(1), 1, &meter).is_err());
    assert!(Registry::new(vec![], Duration::from_secs(1), 1, &meter).is_err());
    let many = (1..=129).map(|port| Host::new(&format!("h{port}"), format!("127.0.0.1:{port}").parse().unwrap())).collect();
    assert!(Registry::new(many, Duration::from_secs(1), 1, &meter).is_err());
}

#[rstest]
#[case::zero_interval(&["--sweep-interval", "0s"])]
#[case::zero_suspect_after(&["--suspect-after", "0"])]
fn config_refuses_zero(#[case] flags: &[&str]) {
    let args = ["dispatcher", "--hosts", "a:1"].iter().chain(flags);
    assert!(Config::try_parse_from(args).is_err());
}
