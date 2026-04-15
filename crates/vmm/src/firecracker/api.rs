//! A client for Firecracker's API on its unix socket.

use std::borrow::Cow;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use fcapi::{
    BootSource, Drive, InstanceActionInfo, Logger, MachineConfiguration, Metrics, MmdsConfig, NetworkInterface, SerialDevice,
    SnapshotCreateParams, SnapshotLoadParams, Vm, Vsock,
};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{CONTENT_TYPE, HOST};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::net::UnixStream;
use tokio::task::AbortHandle;
use tokio::time::Instant;
use tracing::Instrument;
use tracing::field::Empty;

use super::record_error;

/// Max time for a request, end to end. Config calls answer in milliseconds, so this just has to cover a loaded host.
/// Past it Firecracker is wedged, and waiting longer only stalls the boot that's holding the slot.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// `/snapshot/create` writes all of guest memory to disk before it answers, so it scales with guest size. 5 minutes
/// covers tens of GiB at normal disk speeds. `/snapshot/load` uses it too since a file-backed load maps the same file.
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(300);

/// A request body that knows where it goes.
pub trait Endpoint: Serialize {
    fn path(&self) -> Cow<'static, str>;

    fn method(&self) -> Method {
        Method::PUT
    }

    fn timeout(&self) -> Duration {
        REQUEST_TIMEOUT
    }
}

macro_rules! endpoint {
    ($($body:ty => $path:literal),* $(,)?) => {$(
        impl Endpoint for $body {
            fn path(&self) -> Cow<'static, str> {
                Cow::Borrowed($path)
            }
        }
    )*};
}

endpoint! {
    BootSource => "/boot-source",
    InstanceActionInfo => "/actions",
    Logger => "/logger",
    MachineConfiguration => "/machine-config",
    Metrics => "/metrics",
    MmdsConfig => "/mmds/config",
    SerialDevice => "/serial",
    Vsock => "/vsock",
}

impl Endpoint for Drive {
    fn path(&self) -> Cow<'static, str> {
        format!("/drives/{}", self.drive_id).into()
    }
}

impl Endpoint for NetworkInterface {
    fn path(&self) -> Cow<'static, str> {
        format!("/network-interfaces/{}", self.iface_id).into()
    }
}

impl Endpoint for Vm {
    fn path(&self) -> Cow<'static, str> {
        "/vm".into()
    }

    fn method(&self) -> Method {
        Method::PATCH
    }
}

impl Endpoint for SnapshotCreateParams {
    fn path(&self) -> Cow<'static, str> {
        "/snapshot/create".into()
    }

    fn timeout(&self) -> Duration {
        SNAPSHOT_TIMEOUT
    }
}

impl Endpoint for SnapshotLoadParams {
    fn path(&self) -> Cow<'static, str> {
        "/snapshot/load".into()
    }

    fn timeout(&self) -> Duration {
        SNAPSHOT_TIMEOUT
    }
}

/// What goes in the mmds data store. The guest's runtime makes sense of it.
#[derive(Debug, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Mmds<'a>(pub &'a serde_json::Value);

impl Endpoint for Mmds<'_> {
    fn path(&self) -> Cow<'static, str> {
        "/mmds".into()
    }
}

/// A reply outside 2xx.
#[derive(Debug, thiserror::Error)]
#[error("{status}: {fault_message}")]
pub struct ApiError {
    pub status: StatusCode,
    pub fault_message: String,
}

pub struct Api {
    sock: PathBuf,
}

impl Api {
    pub fn new(sock: &Path) -> Self {
        Self { sock: sock.to_owned() }
    }

    pub async fn send(&self, req: &impl Endpoint) -> Result<()> {
        let (method, path) = (req.method(), req.path());
        let body = serde_json::to_vec(req).with_context(|| format!("marshal {path} body"))?;
        // the fixed API paths keep span names bounded
        let span = tracing::info_span!("fc", otel.name = format!("fc {path}"), otel.kind = "client", http.request.method = %method,
            url.path = &*path, http.response.status_code = Empty, otel.status_code = Empty, otel.status_description = Empty);
        let result = self.request(method, &path, body, req.timeout()).instrument(span.clone()).await;
        record_error(&span, &result);
        result
    }

    // new connection per request: Firecracker serves one client at a time and the socket is local, so reuse buys nothing
    async fn request(&self, method: Method, path: &str, body: Vec<u8>, limit: Duration) -> Result<()> {
        let deadline = Instant::now() + limit;
        let at = |stage: &str| format!("{method} {path}: {stage}");
        let stream = within(deadline, limit, UnixStream::connect(&self.sock))
            .await
            .map_err(|err| err.context(at(&format!("dial {}", self.sock.display()))))?;
        let (mut sender, conn) = within(deadline, limit, hyper::client::conn::http1::handshake(TokioIo::new(stream)))
            .await
            .map_err(|err| err.context(at("http handshake")))?;
        // giving up mid-request leaves Firecracker's end of the connection open, so the conn driver gets aborted too
        let _conn = AbortOnDrop(tokio::spawn(conn).abort_handle());
        let req = Request::builder()
            .method(&method)
            .uri(path)
            .header(HOST, "localhost")
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .with_context(|| format!("build {path} request"))?;
        let resp = within(deadline, limit, sender.send_request(req)).await.map_err(|err| err.context(at("await response")))?;
        let status = resp.status();
        tracing::Span::current().record("http.response.status_code", status.as_u16());
        if status.is_success() {
            return Ok(());
        }
        let body =
            within(deadline, limit, resp.into_body().collect()).await.map_err(|err| err.context(at(&format!("read {status} reply"))))?;
        let body = body.to_bytes();
        // Firecracker's faults are JSON, but anything can answer on a stale socket path
        let fault_message = serde_json::from_slice::<fcapi::Error>(&body)
            .ok()
            .and_then(|fault| fault.fault_message)
            .unwrap_or_else(|| String::from_utf8_lossy(&body).trim().to_owned());
        Err(anyhow::Error::new(ApiError { status, fault_message }).context(format!("{method} {path}")))
    }
}

/// Runs one stage of a request against the request's overall deadline.
async fn within<T, E>(deadline: Instant, limit: Duration, stage: impl Future<Output = Result<T, E>>) -> Result<T>
where
    E: std::error::Error + Send + Sync + 'static,
{
    match tokio::time::timeout_at(deadline, stage).await {
        Ok(result) => result.map_err(anyhow::Error::new),
        Err(_) => Err(anyhow!("no answer within {limit:?}")),
    }
}

struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
pub mod fake {
    //! Fake Firecracker API that records what it gets sent.

    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use http_body_util::{BodyExt, Full};
    use hyper::body::{Bytes, Incoming};
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixListener;

    /// Each request as `(method, path, body)`.
    type Requests = Arc<Mutex<Vec<(String, String, serde_json::Value)>>>;

    pub struct FakeApi {
        sock: PathBuf,
        requests: Requests,
        _dir: tempfile::TempDir,
    }

    impl FakeApi {
        /// Answers every request with `status`, and a fault message when it isn't 204.
        pub fn start(status: StatusCode) -> Self {
            // keep it short: macOS caps unix socket paths at 104 bytes and a nested tempdir can blow past that
            let dir = tempfile::Builder::new().prefix("fc").tempdir_in("/tmp").unwrap();
            let sock = dir.path().join("api.sock");
            let listener = UnixListener::bind(&sock).unwrap();
            let requests = Requests::default();
            let seen = Arc::clone(&requests);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let seen = Arc::clone(&seen);
                    let service = service_fn(move |req: Request<Incoming>| {
                        let seen = Arc::clone(&seen);
                        async move {
                            let (parts, body) = req.into_parts();
                            let body = body.collect().await?.to_bytes();
                            let body = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                            seen.lock().unwrap().push((parts.method.to_string(), parts.uri.path().to_owned(), body));
                            let reply =
                                if status == StatusCode::NO_CONTENT { Bytes::new() } else { Bytes::from(r#"{"fault_message":"nope"}"#) };
                            Ok::<_, hyper::Error>(Response::builder().status(status).body(Full::new(reply)).unwrap())
                        }
                    });
                    tokio::spawn(hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service));
                }
            });
            Self { sock, requests, _dir: dir }
        }

        pub fn path(&self) -> &Path {
            &self.sock
        }

        pub fn take(&self) -> Vec<(String, String, serde_json::Value)> {
            std::mem::take(&mut self.requests.lock().unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use fcapi::{InstanceActionInfoActionType, VmState};
    use serde_json::json;

    use super::fake::FakeApi;
    use super::*;

    #[tokio::test]
    async fn sends_json_and_reports_faults() {
        let fc = FakeApi::start(StatusCode::NO_CONTENT);
        let api = Api::new(fc.path());
        api.send(&Vsock { guest_cid: 3, uds_path: "/run/v.sock".into(), vsock_id: None }).await.unwrap();
        api.send(&Vm { state: VmState::Paused }).await.unwrap();
        assert_eq!(
            fc.take(),
            [
                ("PUT".into(), "/vsock".into(), json!({"guest_cid": 3, "uds_path": "/run/v.sock"})),
                ("PATCH".into(), "/vm".into(), json!({"state": "Paused"}))
            ]
        );

        let fc = FakeApi::start(StatusCode::BAD_REQUEST);
        let err =
            Api::new(fc.path()).send(&InstanceActionInfo { action_type: InstanceActionInfoActionType::InstanceStart }).await.unwrap_err();
        assert_eq!(format!("{err:#}"), "PUT /actions: 400 Bad Request: nope");
        let fault = err.downcast_ref::<ApiError>().unwrap();
        assert_eq!((fault.status, fault.fault_message.as_str()), (StatusCode::BAD_REQUEST, "nope"));
    }

    #[tokio::test(start_paused = true)]
    async fn unanswered_requests_time_out() {
        let dir = tempfile::Builder::new().prefix("fc").tempdir_in("/tmp").unwrap();
        let sock = dir.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        // accepts each connection and just sits on it, never reads
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let started = Instant::now();
        let err = Api::new(&sock).send(&Vm { state: VmState::Paused }).await.unwrap_err();
        assert_eq!(format!("{err:#}"), "PATCH /vm: await response: no answer within 10s");
        assert!(started.elapsed() >= REQUEST_TIMEOUT);
    }
}
