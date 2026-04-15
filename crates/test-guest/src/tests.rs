use std::{fs, os::unix::fs::PermissionsExt as _, path::Path};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

struct Running {
    addr: std::net::SocketAddr,
    server: JoinHandle<anyhow::Result<()>>,
}

async fn start(root: &Path, test_control: bool) -> Running {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let root = root.to_owned();
    Running { addr, server: tokio::spawn(async move { super::serve(listener, &root, test_control).await }) }
}

/// Sends one request and returns the status code and body.
async fn request(addr: std::net::SocketAddr, method: &str, path: &str, body: &str) -> (u16, String) {
    let mut conn = TcpStream::connect(addr).await.unwrap();
    let head = format!("{method} {path} HTTP/1.1\r\nhost: guest\r\nconnection: close\r\ncontent-length: {}\r\n\r\n", body.len());
    conn.write_all(format!("{head}{body}").as_bytes()).await.unwrap();
    let mut res = String::new();
    conn.read_to_string(&mut res).await.unwrap();
    let (head, body) = res.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, body.to_owned())
}

#[tokio::test]
async fn serves_files_under_root() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("index.html"), "hello\n").unwrap();
    fs::create_dir(root.path().join("docs")).unwrap();
    fs::write(root.path().join("docs/index.html"), "docs\n").unwrap();
    let secret = root.path().join("secret");
    fs::write(&secret, "secret\n").unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o000)).unwrap();
    let s = start(root.path(), false).await;
    assert_eq!(request(s.addr, "GET", "/", "").await, (200, "hello\n".into()));
    assert_eq!(request(s.addr, "GET", "/docs/", "").await, (200, "docs\n".into()));
    assert_eq!(request(s.addr, "GET", "/missing", "").await.0, 404);
    assert_eq!(request(s.addr, "GET", "/index.html/x", "").await.0, 404);
    assert_eq!(request(s.addr, "GET", "/../index.html", "").await.0, 404);
    // root reads the file anyway.
    if fs::read(&secret).is_err() {
        assert_eq!(request(s.addr, "GET", "/secret", "").await.0, 403);
    }
    assert_eq!(request(s.addr, "POST", "/test/exit", "").await.0, 404, "test endpoints are off by default");
}

#[tokio::test]
async fn test_control() {
    let root = tempfile::tempdir().unwrap();
    let s = start(root.path(), true).await;
    assert_eq!(request(s.addr, "POST", "/test/value", "kept").await.0, 204);
    assert_eq!(request(s.addr, "GET", "/value", "").await, (200, "kept".into()));
    assert_eq!(fs::metadata(root.path().join("value")).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(request(s.addr, "POST", "/test/value", &"x".repeat(2 << 10)).await.0, 413);

    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    for (target, reachable) in [(s.addr, true), (closed, false)] {
        let (status, body) = request(s.addr, "POST", "/test/dial", &format!(r#"{{"address":"{target}"}}"#)).await;
        assert_eq!((status, body), (200, format!(r#"{{"reachable":{reachable}}}"#)));
    }
    assert_eq!(request(s.addr, "POST", "/test/dial", "{").await.0, 400);

    let (_, a) = request(s.addr, "GET", "/test/random", "").await;
    let (_, b) = request(s.addr, "GET", "/test/random", "").await;
    assert_ne!(a, b);
    let (_, nanos) = request(s.addr, "GET", "/test/time", "").await;
    assert!(nanos.trim().parse::<u128>().unwrap() > 0);

    assert_eq!(request(s.addr, "POST", "/test/exit", "").await.0, 204);
    s.server.await.unwrap().unwrap();
}
