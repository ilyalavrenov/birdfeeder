//! Converts an image from a registry the test serves with `birdfeeder convert`, then serves from it in a guest. The
//! top layer's file has to win, the whiteout has to apply, and the named USER can't be root.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tokio::task::JoinHandle;

use crate::contract::{Artifact, Template};
use crate::harness::{Harness, artifacts, bin, claim, claim_request, command, eventually, get, release};

const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

pub async fn run() {
    let mut h = Harness::new();
    let server = fs::read(bin("test-guest")).expect("read the test guest");
    let layers = [
        layer(&[
            ("etc/passwd", b"root:x:0:0::/root:/bin/sh\napp:x:1000:1000::/:/bin/sh\n", 0o644),
            ("etc/group", b"root:x:0:\napp:x:1000:\n", 0o644),
            ("usr/local/bin/serve", &server, 0o755),
            ("srv/index.html", b"stale\n", 0o644),
            ("srv/removed", b"removed\n", 0o644),
            // root can read it (it keeps CAP_DAC_OVERRIDE) but the image's user can't.
            ("srv/root-only", b"secret\n", 0o600),
        ]),
        layer(&[("srv/index.html", b"hello from a registry image\n", 0o644), ("srv/.wh.removed", b"", 0o644)]),
    ];
    let registry = Registry::serve("smoke/http", "v1", &layers).await;

    let blob = h.state.join("registry.squashfs");
    let reference = format!("{}/smoke/http:v1", registry.addr);
    let blob_path = blob.to_str().expect("utf-8 state dir");
    let convert = command(bin("birdfeeder"), ["convert", "-o", "name", &reference, blob_path]);
    let digest = convert.trim();
    assert_eq!(digest.len(), 64, "convert -o name prints the blob's sha256: {convert}");
    let artifacts = artifacts();
    h.config.use_kernel(&artifacts["kernel"]);
    let template = format!("registry-{}", &digest[..16]);
    let app = Artifact { path: blob_path.to_owned(), sha256: digest.to_owned() };
    let manifest = json!({"containers": [{"name": "web", "blob": "app"}], "readiness": [{"name": "http", "tcp_port": 8080}]});
    h.config.templates =
        vec![Template::new(template.clone(), &artifacts["base.ext4"], &artifacts["scratch.ext4"], &[("app", &app)], manifest)];
    h.start_roost();
    h.start_dispatcher();
    eventually("warm pool", async || h.ready().await).await;
    let session = claim(h.dispatcher(), claim_request(&template)).await;
    assert_eq!(get(&session, "/", 200).await, b"hello from a registry image\n");
    get(&session, "/removed", 404).await;
    get(&session, "/root-only", 403).await;
    release(h.host(), &session).await;
}

/// A tar of `(path, contents, mode)` files, with their parent directories.
fn layer(files: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    let mut dirs = BTreeSet::new();
    for &(path, body, mode) in files {
        let mut parents: Vec<&Path> = Path::new(path).ancestors().skip(1).filter(|d| !d.as_os_str().is_empty()).collect();
        parents.reverse();
        for dir in parents.into_iter().filter(|d| dirs.insert(d.to_owned())) {
            tar.append_data(&mut header(tar::EntryType::Directory, 0o755, 0), dir, &[][..]).unwrap();
        }
        tar.append_data(&mut header(tar::EntryType::Regular, mode, body.len() as u64), path, body).unwrap();
    }
    tar.into_inner().unwrap()
}

/// A read-only registry with one image for the host's platform, over plain HTTP since convert uses that for
/// loopback registries.
struct Registry {
    addr: std::net::SocketAddr,
    server: JoinHandle<()>,
}

impl Registry {
    async fn serve(repository: &str, tag: &str, layers: &[Vec<u8>]) -> Self {
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        let diff_ids: Vec<String> = layers.iter().map(|l| digest(l)).collect();
        let layers: Vec<Vec<u8>> = layers.iter().map(|l| gzip(l)).collect();
        let config = json!({
            "architecture": arch,
            "os": "linux",
            "config": {"Entrypoint": ["/usr/local/bin/serve"], "Cmd": ["--listen", "0.0.0.0:8080", "--root", "/srv"], "User": "app"},
            "rootfs": {"type": "layers", "diff_ids": diff_ids},
        })
        .to_string()
        .into_bytes();
        let descriptor = |media_type: &str, blob: &[u8]| json!({"mediaType": media_type, "digest": digest(blob), "size": blob.len()});
        let manifest = json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST,
            "config": descriptor("application/vnd.oci.image.config.v1+json", &config),
            "layers": layers.iter().map(|l| descriptor("application/vnd.oci.image.layer.v1.tar+gzip", l)).collect::<Vec<_>>(),
        })
        .to_string()
        .into_bytes();

        // every path a pull asks for, with its content type and digest.
        let mut paths: HashMap<String, (&'static str, String, Bytes)> = HashMap::new();
        paths.insert("/v2/".into(), ("application/json", String::new(), Bytes::from_static(b"{}")));
        for blob in layers.iter().chain([&config]) {
            let d = digest(blob);
            paths.insert(format!("/v2/{repository}/blobs/{d}"), ("application/octet-stream", d, Bytes::from(blob.clone())));
        }
        let d = digest(&manifest);
        let manifest = Bytes::from(manifest);
        for reference in [tag, &d] {
            paths.insert(format!("/v2/{repository}/manifests/{reference}"), (MANIFEST, d.clone(), manifest.clone()));
        }
        let paths = Arc::new(paths);
        let app = axum::Router::new().fallback(async move |uri: Uri| -> Response {
            match paths.get(uri.path()) {
                Some((content_type, d, body)) => (
                    [(header::CONTENT_TYPE, *content_type), (header::HeaderName::from_static("docker-content-digest"), d.as_str())],
                    body.clone(),
                )
                    .into_response(),
                None => StatusCode::NOT_FOUND.into_response(),
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind registry");
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("serve registry") });
        Self { addr, server }
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// A root-owned entry. A new header's numeric fields are NULs, and readers reject those instead of reading zero.
fn header(kind: tar::EntryType, mode: u32, size: u64) -> tar::Header {
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(kind);
    header.set_mode(mode);
    header.set_size(size);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(data).unwrap();
    gz.finish().unwrap()
}

fn digest(blob: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(blob)))
}
