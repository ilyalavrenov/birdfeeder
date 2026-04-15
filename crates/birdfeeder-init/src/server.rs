//! The guest's vsock telemetry endpoint, one [`Request`] per connection. Once the guest is stopping, a `LOGS` stream
//! ends after the last record and then waits for the client to hang up, which is how we know it read everything.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use socket2::{Domain, SockAddr, Socket, Type};
use tracing::warn;

use crate::logs::FramedLog;
use crate::stream;
use guestapi::protocol::{ParseRequestError, Reply, Request};
use guestapi::stats::{MAX_STATS_BYTES, Stats};

const LISTEN_BACKLOG: i32 = 32;
const MAX_CONNS: usize = 32;
const MAX_REQUEST_BYTES: usize = 256;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_ACCEPT_BACKOFF: Duration = Duration::from_millis(5);
const MAX_ACCEPT_BACKOFF: Duration = Duration::from_secs(1);

/// A connected stream socket. vsock in the guest, a socketpair in tests.
pub trait Conn: Read + Write + Send + Sized + 'static {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn try_clone(&self) -> io::Result<Self>;
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
}

impl Conn for Socket {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        Socket::set_read_timeout(self, timeout)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        Socket::set_write_timeout(self, timeout)
    }
    fn try_clone(&self) -> io::Result<Self> {
        Socket::try_clone(self)
    }
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        Socket::shutdown(self, how)
    }
}

/// What telemetry reads and changes on the guest's system. Tests fake it.
pub trait System: Send + Sync {
    fn stats(&self) -> Stats;
    fn set_clock(&self, since_epoch: Duration) -> io::Result<()>;
}

pub struct Telemetry<S> {
    pub logs: BTreeMap<String, Arc<FramedLog>>,
    pub system: S,
}

impl<S: System> Telemetry<S> {
    /// Serves one connection. Protocol errors get a reply instead of being returned.
    pub fn handle(&self, mut conn: impl Conn) -> Result<()> {
        conn.set_write_timeout(Some(WRITE_TIMEOUT)).context("set write timeout")?;
        conn.set_read_timeout(Some(REQUEST_TIMEOUT)).context("set request timeout")?;
        let request = read_request(&mut conn);
        conn.set_read_timeout(None).context("clear request timeout")?;
        match request {
            Err(e) => reply(&mut conn, &refused(e)),
            Ok(Request::Stats) => {
                let mut data = serde_json::to_vec(&self.system.stats())?;
                if data.len() > MAX_STATS_BYTES {
                    return reply(&mut conn, &refused("statistics unavailable"));
                }
                data.push(b'\n');
                conn.write_all(&data).context("write reply")
            }
            Ok(Request::Clock(now)) => match self.system.set_clock(now) {
                Ok(()) => reply(&mut conn, &Reply::Ok),
                Err(e) => {
                    reply(&mut conn, &refused("set clock failed"))?;
                    Err(e).context("set clock")
                }
            },
            Ok(Request::Logs { container, after }) => match self.logs.get(&container) {
                Some(log) => stream_logs(conn, log, after),
                None => reply(&mut conn, &refused("unknown container")),
            },
        }
    }
}

/// Streams until the client hangs up, which a reader on a second handle picks up. Counts as a
/// follower until then, so a stopping guest can wait for the client to read the last record.
fn stream_logs(mut conn: impl Conn, log: &FramedLog, after: u64) -> Result<()> {
    let _following = log.followers.join();
    let stop = AtomicBool::new(false);
    let mut reader = conn.try_clone().context("clone connection")?;
    thread::scope(|s| {
        s.spawn(|| {
            // any return means the client hung up or the stream ended. either way, stop.
            let _ = io::copy(&mut reader, &mut io::sink());
            stop.store(true, Ordering::Release);
            log.notify.wake();
        });
        let res = stream::serve(log, &mut conn, after, &stop);
        // a stream that ended cleanly sends EOF and lets the client hang up once it's read everything.
        // a failed one unblocks the hangup reader itself.
        let _ = conn.shutdown(if res.is_ok() { Shutdown::Write } else { Shutdown::Both });
        res
    })
}

fn refused(reason: impl Display) -> Reply {
    Reply::Refused(reason.to_string())
}

fn reply(conn: &mut impl Write, reply: &Reply) -> Result<()> {
    conn.write_all(format!("{reply}\n").as_bytes()).context("write reply")
}

fn read_request(conn: &mut impl Read) -> Result<Request, ParseRequestError> {
    let line = read_line(conn).ok_or(ParseRequestError::Malformed)?;
    std::str::from_utf8(&line).map_err(|_| ParseRequestError::Malformed)?.parse()
}

/// The request line minus its newline. None if it's too long, times out, or never ends.
fn read_line(conn: &mut impl Read) -> Option<Vec<u8>> {
    let mut buf = [0; MAX_REQUEST_BYTES];
    let mut len = 0;
    while len < buf.len() {
        let n = match conn.read(&mut buf[len..]) {
            Ok(0) => return None,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        };
        if let Some(i) = buf[len..len + n].iter().position(|&b| b == b'\n') {
            return Some(buf[..len + i].to_vec());
        }
        len += n;
    }
    None
}

pub fn listen(port: u32) -> Result<Socket> {
    let socket = Socket::new(Domain::VSOCK, Type::STREAM, None).context("vsock socket")?;
    socket
        .bind(&SockAddr::vsock(libc::VMADDR_CID_ANY, port))
        .and_then(|()| socket.listen(LISTEN_BACKLOG))
        .with_context(|| format!("listen vsock port {port}"))?;
    Ok(socket)
}

/// Keeps the guest's only telemetry endpoint alive through transient accept errors (ECONNABORTED,
/// EMFILE, ...) for as long as the guest runs.
pub fn serve<S: System + 'static>(listener: &Socket, telemetry: &Arc<Telemetry<S>>) -> ! {
    let active = Arc::new(AtomicUsize::new(0));
    let mut backoff = Backoff::default();
    loop {
        let conn = match listener.accept() {
            Ok((conn, _)) => conn,
            Err(err) => {
                let wait = backoff.next();
                warn!(err = %err, retry_in = ?wait, "telemetry accept");
                thread::sleep(wait);
                continue;
            }
        };
        backoff = Backoff::default();
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNS {
            active.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let (telemetry, slots) = (Arc::clone(telemetry), Arc::clone(&active));
        let spawned = thread::Builder::new().spawn(move || {
            if let Err(err) = telemetry.handle(conn) {
                warn!(err = format!("{err:#}"), "telemetry connection");
            }
            slots.fetch_sub(1, Ordering::AcqRel);
        });
        if let Err(err) = spawned {
            active.fetch_sub(1, Ordering::AcqRel);
            warn!(err = %err, "telemetry connection");
        }
    }
}

#[derive(Default)]
struct Backoff(Duration);

impl Backoff {
    fn next(&mut self) -> Duration {
        self.0 = (2 * self.0).clamp(MIN_ACCEPT_BACKOFF, MAX_ACCEPT_BACKOFF);
        self.0
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;
    use std::time::Instant;

    use rstest::rstest;

    use super::*;
    use crate::logs::{DEFAULT_LOG_CAP, Record, Stream, Tailer};
    use crate::stats::{ContainerStats, Disk};

    impl Conn for UnixStream {
        fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            UnixStream::set_read_timeout(self, timeout)
        }
        fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            UnixStream::set_write_timeout(self, timeout)
        }
        fn try_clone(&self) -> io::Result<Self> {
            UnixStream::try_clone(self)
        }
        fn shutdown(&self, how: Shutdown) -> io::Result<()> {
            UnixStream::shutdown(self, how)
        }
    }

    #[derive(Default)]
    struct FakeSystem {
        stats: Stats,
        clock: Mutex<Option<Duration>>,
        clock_fails: bool,
    }

    impl System for FakeSystem {
        fn stats(&self) -> Stats {
            self.stats.clone()
        }

        fn set_clock(&self, since_epoch: Duration) -> io::Result<()> {
            if self.clock_fails {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            *self.clock.lock().unwrap() = Some(since_epoch);
            Ok(())
        }
    }

    fn telemetry(logs: BTreeMap<String, Arc<FramedLog>>) -> Arc<Telemetry<FakeSystem>> {
        Arc::new(Telemetry { logs, system: FakeSystem::default() })
    }

    fn request(t: &Arc<Telemetry<FakeSystem>>, req: &str) -> String {
        let (mut client, server) = UnixStream::pair().unwrap();
        let t = Arc::clone(t);
        let done = thread::spawn(move || t.handle(server));
        client.write_all(req.as_bytes()).unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        let _ = done.join().unwrap();
        reply
    }

    #[rstest]
    #[case::unknown_container("LOGS bogus 0\n", "ERR unknown container\n")]
    #[case::unknown_verb("HELLO\n", "ERR malformed request\n")]
    #[case::bad_seq("LOGS kernel abc\n", "ERR bad seq\n")]
    #[case::unterminated(&"x".repeat(MAX_REQUEST_BYTES), "ERR malformed request\n")]
    fn answers_malformed_requests(#[case] req: &str, #[case] want: &str) {
        let dir = tempfile::tempdir().unwrap();
        let tailer = Tailer::open(dir.path(), "kernel", DEFAULT_LOG_CAP).unwrap();
        assert_eq!(request(&telemetry([("kernel".into(), tailer.log())].into()), req), want);
    }

    #[test]
    fn logs_stream_until_hangup() {
        let dir = tempfile::tempdir().unwrap();
        let mut tailer = Tailer::open(dir.path(), "kernel", DEFAULT_LOG_CAP).unwrap();
        tailer.write_raw(Stream::Stdout, "hello\n");
        tailer.poll().unwrap();
        let t = telemetry([("kernel".into(), tailer.log())].into());
        let (mut client, server) = UnixStream::pair().unwrap();
        let done = thread::spawn(move || t.handle(server));
        client.write_all(b"LOGS kernel 0\n").unwrap();
        let mut line = String::new();
        BufReader::new(&client).read_line(&mut line).unwrap();
        assert_eq!(serde_json::from_str::<Record>(&line).unwrap().line, "hello");
        client.shutdown(Shutdown::Write).unwrap();
        let started = Instant::now();
        done.join().unwrap().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5), "handler outlived the client");
    }

    #[test]
    fn closed_log_counts_follower_until_hangup() {
        let dir = tempfile::tempdir().unwrap();
        let mut tailer = Tailer::open(dir.path(), "kernel", DEFAULT_LOG_CAP).unwrap();
        let log = tailer.log();
        let t = telemetry([("kernel".into(), Arc::clone(&log))].into());
        let (mut client, server) = UnixStream::pair().unwrap();
        let done = thread::spawn(move || t.handle(server));
        client.write_all(b"LOGS kernel 0\n").unwrap();
        tailer.write_raw(Stream::Stderr, "crashed");
        tailer.finish().unwrap();
        log.close();
        let mut rest = String::new();
        client.read_to_string(&mut rest).unwrap();
        assert_eq!(serde_json::from_str::<Record>(&rest).unwrap().line, "crashed", "the stream ends after the last record");
        assert!(!log.followers.wait_gone(Instant::now() + Duration::from_millis(50)), "counted until the client hangs up");
        drop(client);
        assert!(log.followers.wait_gone(Instant::now() + Duration::from_secs(5)));
        done.join().unwrap().unwrap();
    }

    #[test]
    fn sets_the_clock() {
        let t = telemetry(BTreeMap::new());
        assert_eq!(request(&t, "CLOCK 1 1700000000123456789\n"), "OK\n");
        assert_eq!(*t.system.clock.lock().unwrap(), Some(Duration::from_nanos(1_700_000_000_123_456_789)));
        let failing = Arc::new(Telemetry { logs: BTreeMap::new(), system: FakeSystem { clock_fails: true, ..FakeSystem::default() } });
        assert_eq!(request(&failing, "CLOCK 1 1\n"), "ERR set clock failed\n");
    }

    #[test]
    fn replies_with_stats() {
        let stats = Stats {
            version: 1,
            disk: Some(Disk { total_bytes: 100, free_bytes: 60 }),
            containers: [("web".into(), ContainerStats { pids: Some(4), ..ContainerStats::default() })].into(),
            ..Stats::default()
        };
        let t = Arc::new(Telemetry { logs: BTreeMap::new(), system: FakeSystem { stats: stats.clone(), ..FakeSystem::default() } });
        let reply = request(&t, "STATS 1\n");
        assert!(reply.ends_with('\n'));
        assert_eq!(serde_json::from_str::<Stats>(&reply).unwrap(), stats);
    }

    #[test]
    fn accept_backoff_doubles_to_cap() {
        let mut b = Backoff::default();
        let waits: Vec<_> = (0..10).map(|_| b.next().as_millis()).collect();
        assert_eq!(waits, [5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000]);
    }
}
