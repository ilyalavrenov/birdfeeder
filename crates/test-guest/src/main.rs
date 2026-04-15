//! The guest workload the smoke suites boot: a static file server, with endpoints the lifecycle smoke checks drive when
//! `--test-control` is set.

use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncWriteExt as _,
    net::{TcpListener, TcpStream},
    sync::Notify,
};

const MAX_CONTROL_BODY: usize = 1 << 10;
const DIAL_TIMEOUT: Duration = Duration::from_millis(500);
/// the lifecycle check tells a forced exit apart from a clean one.
const FORCED_EXIT: u8 = 17;

/// serves a directory over HTTP
#[derive(Debug, Parser)]
struct Args {
    /// listen address
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: SocketAddr,
    /// directory to serve
    #[arg(long, default_value = "/srv")]
    root: PathBuf,
    /// enable development lifecycle test endpoints
    #[arg(long)]
    test_control: bool,
}

#[derive(Clone)]
struct Server {
    root: Arc<Path>,
    exit: Arc<Notify>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();
    let listener = TcpListener::bind(args.listen).await.with_context(|| format!("listen on {}", args.listen))?;
    eprintln!("serving {} on {}", args.root.display(), args.listen);
    serve(listener, &args.root, args.test_control).await?;
    Ok(ExitCode::from(FORCED_EXIT))
}

/// Serves root until a request to /test/exit.
async fn serve(listener: TcpListener, root: &Path, test_control: bool) -> anyhow::Result<()> {
    let server = Server { root: root.into(), exit: Arc::new(Notify::new()) };
    let exit = server.exit.clone();
    axum::serve(listener, app(server, test_control)).with_graceful_shutdown(async move { exit.notified().await }).await.context("serve")
}

fn app(server: Server, test_control: bool) -> Router {
    let mut app = Router::new();
    if test_control {
        app = app
            .route("/test/dial", post(dial))
            .route("/test/value", post(value))
            // snapshot clones must not share the golden guest's wall clock or random stream.
            .route("/test/time", get(time))
            .route("/test/random", get(random))
            .route("/test/exit", post(exit))
            .layer(DefaultBodyLimit::max(MAX_CONTROL_BODY));
    }
    app.fallback(file).with_state(server)
}

async fn file(State(s): State<Server>, uri: Uri) -> Response {
    let Some(mut path) = resolve(&s.root, uri.path()) else { return StatusCode::NOT_FOUND.into_response() };
    let read = async {
        if tokio::fs::metadata(&path).await?.is_dir() {
            path.push("index.html");
        }
        tokio::fs::read(&path).await
    };
    match read.await {
        Ok(body) => {
            let html = path.extension().is_some_and(|e| e == "html");
            let kind = if html { "text/html; charset=utf-8" } else { "application/octet-stream" };
            ([(header::CONTENT_TYPE, kind)], body).into_response()
        }
        Err(e) => error_status(&e).into_response(),
    }
}

/// Maps a request path under root, refusing one that climbs out of it.
fn resolve(root: &Path, request: &str) -> Option<PathBuf> {
    let mut path = root.to_path_buf();
    for part in request.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            part => path.push(part),
        }
    }
    Some(path)
}

fn error_status(e: &io::Error) -> StatusCode {
    match e.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => StatusCode::NOT_FOUND,
        io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[derive(Deserialize)]
struct DialRequest {
    address: String,
}

#[derive(Serialize)]
struct Dialed {
    reachable: bool,
}

/// The body is parsed by hand: the smoke client sends no content type, which axum's Json extractor requires.
async fn dial(body: Bytes) -> Result<Json<Dialed>, StatusCode> {
    let req: DialRequest = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let connected = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(req.address.as_str())).await;
    Ok(Json(Dialed { reachable: matches!(connected, Ok(Ok(_))) }))
}

async fn value(State(s): State<Server>, body: Bytes) -> Result<StatusCode, (StatusCode, String)> {
    let write = async {
        let mut f = tokio::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(s.root.join("value")).await?;
        f.write_all(&body).await?;
        // tokio's File finishes writes on a blocking thread; without this the 204 can beat the data to disk
        f.flush().await
    };
    write.await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn time() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("{}\n", now.as_nanos())
}

async fn random() -> Result<String, StatusCode> {
    let mut buf = [0; 16];
    getrandom::fill(&mut buf).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(format!("{:032x}\n", u128::from_ne_bytes(buf)))
}

async fn exit(State(s): State<Server>) -> StatusCode {
    // graceful shutdown finishes this response before main exits.
    s.exit.notify_one();
    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests;
