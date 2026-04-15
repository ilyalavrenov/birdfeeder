//! The host side of the vsock API, over Firecracker's hybrid vsock. That's a Unix socket where each connection
//! sends `CONNECT <port>` first, then carries that guest port's stream.

use std::{
    io,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, bail};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::UnixStream,
    time::timeout,
};

use crate::{
    PORT,
    protocol::{Reply, Request},
    stats::{MAX_STATS_BYTES, Stats},
};

/// Caps each request, connecting included. Callers poll, and a stuck guest shouldn't hold them up.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_CLOCK_REPLY: u64 = 128;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
/// Also caps the handshake reply. Firecracker writes that one, not the guest.
const READ_BUFFER_BYTES: usize = 4096;

/// A connection to `port` in the guest behind the hybrid vsock at `path`. Bytes the guest sends right after
/// Firecracker's `OK` sit in the returned reader's buffer, so read through it, not the bare stream.
pub async fn connect(path: &Path, port: u32) -> io::Result<BufReader<UnixStream>> {
    timeout(HANDSHAKE_TIMEOUT, handshake(path, port))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "vsock handshake timed out"))?
}

async fn handshake(path: &Path, port: u32) -> io::Result<BufReader<UnixStream>> {
    let mut stream = BufReader::with_capacity(READ_BUFFER_BYTES, UnixStream::connect(path).await?);
    // has to be one write. Firecracker reads the line without blocking when the socket wakes it, and drops the
    // connection if the whole line isn't there yet.
    stream.write_all(format!("CONNECT {port}\n").as_bytes()).await?;
    let mut reply = Vec::new();
    (&mut stream).take(READ_BUFFER_BYTES as u64).read_until(b'\n', &mut reply).await?;
    match reply.strip_prefix(b"OK ").and_then(|rest| rest.strip_suffix(b"\n")) {
        Some(port) if !port.is_empty() && port.iter().all(u8::is_ascii_digit) => Ok(stream),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, format!("invalid vsock handshake {:?}", String::from_utf8_lossy(&reply)))),
    }
}

/// The guest's resource counters, checked against the `containers` it's running.
pub async fn stats(path: &Path, containers: &[String]) -> anyhow::Result<Stats> {
    let line = request(path, &Request::Stats, MAX_STATS_BYTES as u64 + 1).await?;
    let stats: Stats = serde_json::from_slice(&line).context("decode guest stats")?;
    stats.validate(containers)?;
    Ok(stats)
}

/// Sets the guest's wall clock to `now`, since a restored guest wakes up with the snapshot's time.
pub async fn set_clock(path: &Path, now: SystemTime) -> anyhow::Result<()> {
    let since_epoch = now.duration_since(UNIX_EPOCH).context("clock before 1970")?;
    let reply = request(path, &Request::Clock(since_epoch), MAX_CLOCK_REPLY).await?;
    match String::from_utf8_lossy(&reply).parse()? {
        Reply::Ok => Ok(()),
        Reply::Refused(reason) => bail!("guest refused clock: {reason}"),
    }
}

/// Sends `req` and reads back one reply line, at most `limit` bytes, minus the newline.
async fn request(path: &Path, req: &Request, limit: u64) -> anyhow::Result<Vec<u8>> {
    timeout(REQUEST_TIMEOUT, async {
        let mut conn = connect(path, PORT).await.context("connect to guest")?;
        conn.write_all(format!("{req}\n").as_bytes()).await.context("send guest request")?;
        let mut reply = Vec::new();
        (&mut conn).take(limit).read_until(b'\n', &mut reply).await.context("read guest reply")?;
        match reply.pop() {
            Some(b'\n') => Ok(reply),
            _ => bail!("guest reply unterminated or over {limit} bytes"),
        }
    })
    .await
    .context("guest request timed out")?
}

#[cfg(test)]
mod tests {
    use tokio::net::UnixListener;

    use super::*;

    fn firecracker(reply: &'static [u8]) -> (tempfile::TempDir, tokio::task::JoinHandle<Vec<u8>>) {
        let dir = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(dir.path().join("v.sock")).unwrap();
        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut request = [0; 13];
            conn.read_exact(&mut request).await.unwrap();
            conn.write_all(reply).await.unwrap();
            request.to_vec()
        });
        (dir, server)
    }

    #[tokio::test]
    async fn keeps_bytes_behind_the_handshake() {
        let (dir, server) = firecracker(b"OK 1073741824\nfirst line\n");
        let mut conn = connect(&dir.path().join("v.sock"), PORT).await.unwrap();
        assert_eq!(server.await.unwrap(), b"CONNECT 5000\n");
        let mut line = String::new();
        conn.read_line(&mut line).await.unwrap();
        assert_eq!(line, "first line\n");
    }

    #[rstest::rstest]
    #[case::refused(b"ERR 5000\n")]
    #[case::no_port(b"OK \n")]
    #[case::unterminated(b"OK 12")]
    #[tokio::test]
    async fn refused_handshakes_fail(#[case] reply: &'static [u8]) {
        let (dir, server) = firecracker(reply);
        let err = connect(&dir.path().join("v.sock"), PORT).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        server.await.unwrap();
    }

    /// A fake guest that answers one request with `reply` and hands back what it got asked.
    fn guest(reply: &'static [u8]) -> (tempfile::TempDir, tokio::task::JoinHandle<String>) {
        let dir = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(dir.path().join("v.sock")).unwrap();
        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let mut conn = BufReader::new(conn);
            let mut connect = String::new();
            conn.read_line(&mut connect).await.unwrap();
            conn.get_mut().write_all(b"OK 1\n").await.unwrap();
            let mut request = String::new();
            conn.read_line(&mut request).await.unwrap();
            conn.get_mut().write_all(reply).await.unwrap();
            request
        });
        (dir, server)
    }

    #[tokio::test]
    async fn stats_are_validated() {
        let (dir, server) = guest(b"{\"version\":1,\"containers\":{\"web\":{\"pids\":2}}}\n");
        let stats = stats(&dir.path().join("v.sock"), &["web".into()]).await.unwrap();
        assert_eq!(server.await.unwrap(), "STATS 1\n");
        assert_eq!(stats.containers["web"].pids, Some(2));

        let (dir, _server) = guest(b"{\"version\":1,\"containers\":{\"db\":{}}}\n");
        assert!(super::stats(&dir.path().join("v.sock"), &["web".into()]).await.is_err());
    }

    #[tokio::test]
    async fn clock_needs_the_guests_ok() {
        let (dir, server) = guest(b"OK\n");
        set_clock(&dir.path().join("v.sock"), UNIX_EPOCH + Duration::from_nanos(1_700_000_000_123_456_789)).await.unwrap();
        assert_eq!(server.await.unwrap(), "CLOCK 1 1700000000123456789\n");

        let (dir, _server) = guest(b"ERR set clock failed\n");
        let err = set_clock(&dir.path().join("v.sock"), SystemTime::now()).await.unwrap_err();
        assert_eq!(err.to_string(), "guest refused clock: set clock failed");
    }
}
