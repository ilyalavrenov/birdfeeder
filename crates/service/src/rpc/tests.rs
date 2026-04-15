use std::{net::SocketAddr, sync::Arc, time::Duration};

use opentelemetry::{
    global,
    metrics::MeterProvider as _,
    trace::{SpanKind, Status as SpanStatus, TraceContextExt as _, TracerProvider as _},
};
use opentelemetry_sdk::{
    metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider, data::AggregatedMetrics},
    propagation::TraceContextPropagator,
    trace::{InMemorySpanExporter, SdkTracerProvider, SpanData},
};
use roost_api::v1::{
    ClaimSessionRequest, ClaimSessionResponse, DeleteSessionRequest, DeleteSessionResponse, GetSessionRequest, GetSessionResponse,
    HostStatusRequest, HostStatusResponse, ListSessionsRequest, ListSessionsResponse, SetSessionExpiryRequest, SetSessionExpiryResponse,
    roost_service_client::RoostServiceClient,
    roost_service_server::{RoostService, RoostServiceServer},
};
use tokio::{net::TcpListener, sync::Notify};
use tonic::{Request, Response, Status, transport::Channel};
use tracing::Instrument as _;
use tracing_subscriber::{Layer as _, layer::SubscriberExt as _};

use super::*;

/// Held by every test that goes through `TraceLayer`. A callsite registered while the trace test's thread-local
/// subscriber is still registering can get cached as never enabled, and that test loses its server spans.
static TRACE_LAYER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Finds nothing, and answers `HostStatus` once released.
#[derive(Clone, Default)]
struct Stub {
    release: Arc<Notify>,
    hold: bool,
}

#[tonic::async_trait]
impl RoostService for Stub {
    async fn claim_session(&self, _: Request<ClaimSessionRequest>) -> Result<Response<ClaimSessionResponse>, Status> {
        Err(Status::unimplemented("claim"))
    }

    async fn get_session(&self, _: Request<GetSessionRequest>) -> Result<Response<GetSessionResponse>, Status> {
        Err(Status::not_found("no such session"))
    }

    async fn delete_session(&self, _: Request<DeleteSessionRequest>) -> Result<Response<DeleteSessionResponse>, Status> {
        Err(Status::unimplemented("delete"))
    }

    async fn list_sessions(&self, _: Request<ListSessionsRequest>) -> Result<Response<ListSessionsResponse>, Status> {
        Err(Status::unimplemented("list"))
    }

    async fn set_session_expiry(&self, _: Request<SetSessionExpiryRequest>) -> Result<Response<SetSessionExpiryResponse>, Status> {
        Err(Status::unimplemented("expiry"))
    }

    async fn host_status(&self, _: Request<HostStatusRequest>) -> Result<Response<HostStatusResponse>, Status> {
        if self.hold {
            self.release.notified().await;
        }
        Ok(Response::new(HostStatusResponse { capacity: 4, ..Default::default() }))
    }
}

async fn listen() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

async fn client(addr: SocketAddr, meter: &Meter) -> RoostServiceClient<Trace<Channel>> {
    let channel = Channel::from_shared(format!("http://{addr}")).unwrap().connect().await.unwrap();
    RoostServiceClient::new(TraceLayer::client(meter, &addr.to_string().parse().unwrap()).layer(channel))
}

fn attribute(span: &SpanData, key: &str) -> Option<String> {
    span.attributes.iter().find(|kv| kv.key.as_str() == key).map(|kv| kv.value.to_string())
}

#[tokio::test]
async fn calls_continue_the_callers_trace() {
    let _serial = TRACE_LAYER.lock().await;
    global::set_text_map_propagator(TraceContextPropagator::new());
    let spans = InMemorySpanExporter::default();
    let tracer = SdkTracerProvider::builder().with_simple_exporter(spans.clone()).build();
    let metrics = InMemoryMetricExporter::default();
    let meters = SdkMeterProvider::builder().with_reader(PeriodicReader::builder(metrics.clone()).build()).build();
    let meter = meters.meter("test");
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(tracer.tracer("test")).with_filter(tracing_subscriber::filter::LevelFilter::INFO));
    let _default = tracing::subscriber::set_default(subscriber);

    let (listener, addr) = listen().await;
    let server = Server::builder().layer(TraceLayer::server(&meter)).add_service(RoostServiceServer::new(Stub::default()));
    tokio::spawn(server.serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)));
    let mut roost = client(addr, &meter).await;
    let outer = tracing::info_span!("outer");
    let (missing, status) = async {
        (
            roost.get_session(GetSessionRequest { name: "gone".into(), ..GetSessionRequest::default() }).await,
            roost.host_status(HostStatusRequest {}).await,
        )
    }
    .instrument(outer.clone())
    .await;
    assert_eq!(missing.unwrap_err().code(), Code::NotFound);
    assert_eq!(status.unwrap().into_inner().capacity, 4);
    let outer_id = outer.context().span().span_context().clone();
    drop(outer);
    // a server span ends once hyper has sent the trailers, which can be a bit after the client already has its answer.
    let spans = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tracer.force_flush().unwrap();
            let finished = spans.get_finished_spans().unwrap();
            if finished.iter().filter(|s| s.span_kind == SpanKind::Server).count() == 2 {
                return finished;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both server spans end");
    let find = |kind: SpanKind, method: &str| {
        spans
            .iter()
            .find(|s| s.span_kind == kind && s.name == format!("birdfeeder.roost.v1.RoostService/{method}"))
            .unwrap_or_else(|| panic!("no {kind:?} span for {method} in {spans:#?}"))
    };
    let (client_get, server_get) = (find(SpanKind::Client, "GetSession"), find(SpanKind::Server, "GetSession"));
    assert_eq!(client_get.span_context.trace_id(), outer_id.trace_id());
    assert_eq!(client_get.parent_span_id, outer_id.span_id());
    assert_eq!(server_get.span_context.trace_id(), outer_id.trace_id());
    assert_eq!(server_get.parent_span_id, client_get.span_context.span_id());
    assert_eq!(attribute(server_get, "rpc.response.status_code").as_deref(), Some("NOT_FOUND"));
    assert_eq!(server_get.status, SpanStatus::Unset, "not found is the caller's problem, not the server's");
    assert!(matches!(client_get.status, SpanStatus::Error { .. }));
    assert_eq!(attribute(client_get, "server.port"), Some(addr.port().to_string()));
    let server_status = find(SpanKind::Server, "HostStatus");
    assert_eq!(attribute(server_status, "rpc.response.status_code").as_deref(), Some("OK"));

    meters.force_flush().unwrap();
    let mut recorded = Vec::new();
    for batch in metrics.get_finished_metrics().unwrap() {
        for scope in batch.scope_metrics() {
            for metric in scope.metrics() {
                if let AggregatedMetrics::F64(data) = metric.data() {
                    recorded.push((metric.name().to_owned(), format!("{data:?}")));
                }
            }
        }
    }
    for name in ["rpc.server.call.duration", "rpc.client.call.duration"] {
        let (_, data) = recorded.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("no {name} in {recorded:?}"));
        assert!(data.contains("NOT_FOUND") && data.contains("\"OK\""), "{name}: {data}");
    }
}

#[tokio::test]
async fn serve_drains_calls_in_flight() {
    let _serial = TRACE_LAYER.lock().await;
    let meter = global::meter("test");
    let stub = Stub { hold: true, ..Stub::default() };
    let release = stub.release.clone();
    let (listener, addr) = listen().await;
    let stop = Arc::new(Notify::new());
    let shutdown = {
        let stop = stop.clone();
        async move { stop.notified().await }
    };
    let served =
        tokio::spawn(serve(listener, Routes::new(RoostServiceServer::new(stub)), global::meter("test"), shutdown, Duration::from_secs(5)));
    let mut roost = client(addr, &meter).await;
    let call = tokio::spawn(async move { roost.host_status(HostStatusRequest {}).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    stop.notify_one();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!served.is_finished(), "returned before the call in flight finished");
    release.notify_one();
    assert_eq!(call.await.unwrap().unwrap().into_inner().capacity, 4);
    served.await.unwrap().unwrap();
}

#[tokio::test]
async fn serve_bounds_the_drain() {
    let _serial = TRACE_LAYER.lock().await;
    let meter = global::meter("test");
    let (listener, addr) = listen().await;
    let stop = Arc::new(Notify::new());
    let shutdown = {
        let stop = stop.clone();
        async move { stop.notified().await }
    };
    let routes = Routes::new(RoostServiceServer::new(Stub { hold: true, ..Stub::default() }));
    let served = tokio::spawn(serve(listener, routes, global::meter("test"), shutdown, Duration::from_millis(50)));
    let mut roost = client(addr, &meter).await;
    let call = tokio::spawn(async move { roost.host_status(HostStatusRequest {}).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    stop.notify_one();
    let err = served.await.unwrap().unwrap_err();
    assert!(err.to_string().contains("still in flight"), "{err:#}");
    call.abort();
}

#[tokio::test]
async fn accepted_connections_have_nodelay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut accepts = std::pin::pin!(incoming(listener));
    let _client = TcpStream::connect(addr).await.unwrap();
    let accepted = accepts.next().await.unwrap().unwrap();
    assert!(accepted.nodelay().unwrap());
}

#[tokio::test(start_paused = true)]
async fn accept_errors_are_held_back() {
    let errors = tokio_stream::iter([Err(io::Error::other("EMFILE")), Err(io::Error::other("EMFILE")), Ok(())]);
    let mut accepts = std::pin::pin!(pace_errors(errors, Duration::from_millis(100)));
    let start = tokio::time::Instant::now();
    while let Some(accepted) = accepts.next().await {
        if accepted.is_ok() {
            break;
        }
    }
    assert_eq!(start.elapsed(), Duration::from_millis(200));
}
