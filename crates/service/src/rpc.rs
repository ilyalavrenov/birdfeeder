//! gRPC plumbing the services share: OTel spans, W3C propagation and call-duration metrics for both ends of a call,
//! plus serving with a bounded graceful shutdown.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::{Duration, Instant},
};

use anyhow::{Context as _, anyhow};
use http::{HeaderMap, uri::Authority};
use http_body::{Body, Frame, SizeHint};
use opentelemetry::{
    KeyValue, global,
    metrics::{Histogram, Meter},
};
use opentelemetry_http::{HeaderExtractor, HeaderInjector};
use pin_project_lite::pin_project;
use tokio::{
    net::{TcpListener, TcpStream},
    signal::unix::{SignalKind, signal},
    sync::oneshot,
};
use tokio_stream::{Stream, StreamExt as _};
use tonic::{
    Code,
    service::Routes,
    transport::{Server, server::TcpIncoming},
};
use tower_layer::Layer;
use tower_service::Service;
use tracing::{Span, field::Empty};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Server,
    Client,
}

/// Wraps a gRPC server or client so each call gets an OTel span and a `rpc.{server,client}.call.duration` sample.
/// The server end continues the caller's W3C trace; the client end sends the current one.
#[derive(Clone)]
pub struct TraceLayer {
    /// whom a client calls; a server has no peer.
    peer: Option<Peer>,
    duration: Histogram<f64>,
}

#[derive(Clone)]
struct Peer {
    host: Arc<str>,
    port: Option<u16>,
}

impl TraceLayer {
    #[must_use]
    pub fn server(meter: &Meter) -> Self {
        Self { peer: None, duration: duration(meter, "rpc.server.call.duration") }
    }

    /// `peer` is whom the client calls, recorded as `server.address` and `server.port`.
    #[must_use]
    pub fn client(meter: &Meter, peer: &Authority) -> Self {
        let peer = Peer { host: peer.host().into(), port: peer.port_u16() };
        Self { peer: Some(peer), duration: duration(meter, "rpc.client.call.duration") }
    }
}

fn duration(meter: &Meter, name: &'static str) -> Histogram<f64> {
    meter.f64_histogram(name).with_unit("s").with_description("duration of gRPC calls").build()
}

impl<S> Layer<S> for TraceLayer {
    type Service = Trace<S>;

    fn layer(&self, inner: S) -> Trace<S> {
        Trace { inner, layer: self.clone() }
    }
}

#[derive(Clone)]
pub struct Trace<S> {
    inner: S,
    layer: TraceLayer,
}

impl<S, B, RB> Service<http::Request<B>> for Trace<S>
where
    S: Service<http::Request<B>, Response = http::Response<RB>>,
{
    type Response = http::Response<TracedBody<RB>>;
    type Error = S::Error;
    type Future = TracedFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        let method = req.uri().path().trim_start_matches('/').to_owned();
        let (span, side) = match &self.layer.peer {
            None => {
                let span = tracing::info_span!("grpc", otel.name = %method, otel.kind = "server", rpc.system.name = "grpc",
                    rpc.method = %method, rpc.response.status_code = Empty, error.type = Empty, otel.status_code = Empty);
                let parent = global::get_text_map_propagator(|p| p.extract(&HeaderExtractor(req.headers())));
                // only fails without an OTel layer, and then there's no trace to continue anyway.
                let _ = span.set_parent(parent);
                (span, Side::Server)
            }
            Some(peer) => {
                let span = tracing::info_span!("grpc", otel.name = %method, otel.kind = "client", rpc.system.name = "grpc",
                    rpc.method = %method, server.address = %peer.host, server.port = peer.port,
                    rpc.response.status_code = Empty, error.type = Empty, otel.status_code = Empty);
                let cx = span.context();
                global::get_text_map_propagator(|p| p.inject_context(&cx, &mut HeaderInjector(req.headers_mut())));
                (span, Side::Client)
            }
        };
        let inner = span.in_scope(|| self.inner.call(req));
        let call = Call { span, start: Instant::now(), side, method, duration: self.layer.duration.clone(), code: None };
        TracedFuture { inner, call: Some(call) }
    }
}

/// One call in flight. Dropping it closes the span and records the duration, with the status it finished with, or as
/// cancelled if the caller or server gave up first.
struct Call {
    span: Span,
    start: Instant,
    side: Side,
    method: String,
    duration: Histogram<f64>,
    code: Option<Code>,
}

impl Call {
    fn finish(mut self, code: Code) {
        self.code = Some(code);
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        let code = self.code.unwrap_or(Code::Cancelled);
        let name = code_name(code);
        let failed = is_error(self.side, code);
        self.span.record("rpc.response.status_code", name);
        if failed {
            self.span.record("error.type", name);
            self.span.record("otel.status_code", "error");
        }
        // a server answers any path, so unknown ones share a single value instead of blowing up the metric's
        // cardinality.
        let method =
            if self.side == Side::Server && code == Code::Unimplemented { "_OTHER".to_owned() } else { std::mem::take(&mut self.method) };
        let mut attributes = vec![
            KeyValue::new("rpc.system.name", "grpc"),
            KeyValue::new("rpc.method", method),
            KeyValue::new("rpc.response.status_code", name),
        ];
        if failed {
            attributes.push(KeyValue::new("error.type", name));
        }
        self.duration.record(self.start.elapsed().as_secs_f64(), &attributes);
    }
}

pin_project! {
    pub struct TracedFuture<F> {
        #[pin]
        inner: F,
        call: Option<Call>,
    }
}

impl<F, RB, E> Future for TracedFuture<F>
where
    F: Future<Output = Result<http::Response<RB>, E>>,
{
    type Output = Result<http::Response<TracedBody<RB>>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let span = this.call.as_ref().expect("TracedFuture polled after completion").span.clone();
        let result = ready!(span.in_scope(|| this.inner.poll(cx)));
        let call = this.call.take().expect("TracedFuture polled after completion");
        Poll::Ready(match result {
            Ok(response) => {
                // errors usually come trailers-only: status in the headers, empty body.
                let call = match grpc_status(response.headers()) {
                    Some(code) => {
                        call.finish(code);
                        None
                    }
                    None => Some(call),
                };
                Ok(response.map(|inner| TracedBody { inner, call }))
            }
            Err(err) => {
                // only a transport failure gets here: tonic answers handler errors with a response.
                call.finish(Code::Unavailable);
                Err(err)
            }
        })
    }
}

pin_project! {
    /// A response body that ends its call at the trailers carrying the status.
    pub struct TracedBody<B> {
        #[pin]
        inner: B,
        call: Option<Call>,
    }
}

impl<B: Body> Body for TracedBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<B::Data>, B::Error>>> {
        let this = self.project();
        let frame = ready!(this.inner.poll_frame(cx));
        let code = match &frame {
            Some(Ok(frame)) => frame.trailers_ref().map(|trailers| grpc_status(trailers).unwrap_or(Code::Unknown)),
            // a gRPC response that ends without a status is broken.
            Some(Err(_)) | None => Some(Code::Unknown),
        };
        if let Some(code) = code
            && let Some(call) = this.call.take()
        {
            call.finish(code);
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn grpc_status(headers: &HeaderMap) -> Option<Code> {
    headers.get("grpc-status").map(|v| Code::from_bytes(v.as_bytes()))
}

/// The semconv gRPC error statuses. A server only owns the failures that are its fault.
fn is_error(side: Side, code: Code) -> bool {
    match side {
        Side::Client => code != Code::Ok,
        Side::Server => matches!(
            code,
            Code::Unknown | Code::DeadlineExceeded | Code::Unimplemented | Code::Internal | Code::Unavailable | Code::DataLoss
        ),
    }
}

/// The canonical upper-case name gRPC gives a status code.
#[must_use]
pub fn code_name(code: Code) -> &'static str {
    match code {
        Code::Ok => "OK",
        Code::Cancelled => "CANCELLED",
        Code::Unknown => "UNKNOWN",
        Code::InvalidArgument => "INVALID_ARGUMENT",
        Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
        Code::NotFound => "NOT_FOUND",
        Code::AlreadyExists => "ALREADY_EXISTS",
        Code::PermissionDenied => "PERMISSION_DENIED",
        Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
        Code::FailedPrecondition => "FAILED_PRECONDITION",
        Code::Aborted => "ABORTED",
        Code::OutOfRange => "OUT_OF_RANGE",
        Code::Unimplemented => "UNIMPLEMENTED",
        Code::Internal => "INTERNAL",
        Code::Unavailable => "UNAVAILABLE",
        Code::DataLoss => "DATA_LOSS",
        Code::Unauthenticated => "UNAUTHENTICATED",
    }
}

/// Resolves on SIGINT or SIGTERM. The handlers install when you call this, not when it's first awaited.
pub fn shutdown_signal() -> io::Result<impl Future<Output = ()>> {
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    })
}

/// Serves `routes` with [`TraceLayer`] until `shutdown` resolves, then gives calls in flight up to `drain` to finish
/// before failing. Plain HTTP/2 only: the services don't terminate TLS, and gRPC doesn't need anything older.
pub async fn serve(
    listener: TcpListener,
    routes: Routes,
    meter: Meter,
    shutdown: impl Future<Output = ()>,
    drain: Duration,
) -> anyhow::Result<()> {
    let (stopping, stopped) = oneshot::channel();
    let server = Server::builder().layer(TraceLayer::server(&meter)).add_routes(routes).serve_with_incoming_shutdown(
        incoming(listener),
        async move {
            shutdown.await;
            tracing::info!("shutting down");
            let _ = stopping.send(());
        },
    );
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => return result.context("serve"),
        _ = stopped => {}
    }
    tokio::time::timeout(drain, server).await.map_err(|_| anyhow!("calls still in flight after {drain:?}"))?.context("serve")
}

/// How long to wait after a failed accept. When we're out of descriptors, accept keeps failing until some close. tonic
/// retries immediately and only logs at trace, so without a pause the loop silently spins a core.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The listener's connections with `TCP_NODELAY` set, since a custom incoming skips the builder's socket options.
fn incoming(listener: TcpListener) -> impl Stream<Item = io::Result<TcpStream>> {
    pace_errors(TcpIncoming::from(listener).with_nodelay(Some(true)), ACCEPT_BACKOFF)
}

/// Passes `accepts` through, logging each error and holding it back for `backoff`.
fn pace_errors<T>(accepts: impl Stream<Item = io::Result<T>>, backoff: Duration) -> impl Stream<Item = io::Result<T>> {
    accepts.then(move |accepted| async move {
        if let Err(err) = &accepted {
            tracing::warn!(%err, "accept failed");
            tokio::time::sleep(backoff).await;
        }
        accepted
    })
}

#[cfg(test)]
mod tests;
