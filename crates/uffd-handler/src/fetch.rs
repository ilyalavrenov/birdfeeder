use std::fmt;
use std::io::Read;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Error, Result, anyhow};
use ureq::Agent;

const ATTEMPTS: u32 = 3;
const BACKOFF: Duration = Duration::from_millis(50);
const TIMEOUT: Duration = Duration::from_secs(30);

/// Reads byte ranges of one object over HTTP. A presigned S3 URL keeps credentials and an SDK out
/// of the handler, and any server that supports Range works too.
pub struct RangeFetcher {
    url: String,
    agent: Agent,
}

/// Retrying won't change the server's answer, e.g. an expired URL's 403.
#[derive(Debug)]
pub struct Refused(ureq::http::StatusCode);

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "get: {}, want 206", self.0)
    }
}

impl std::error::Error for Refused {}

/// Whether `err` came from a [`Refused`] fetch, which retrying later won't fix either.
pub fn is_refused(err: &Error) -> bool {
    err.chain().any(<dyn std::error::Error>::is::<Refused>)
}

enum Failure {
    Retry(Error),
    Permanent(Error),
}

impl RangeFetcher {
    pub fn new(url: &str) -> Self {
        let config = Agent::config_builder().timeout_global(Some(TIMEOUT)).http_status_as_error(false).build();
        Self { url: url.to_owned(), agent: Agent::new_with_config(config) }
    }

    /// Fills `dst` with the object's bytes from `off`, retrying network and server errors.
    pub fn fetch(&self, off: u64, dst: &mut [u8]) -> Result<()> {
        let mut attempt = 0;
        loop {
            let err = match self.fetch_once(off, dst) {
                Ok(()) => return Ok(()),
                Err(Failure::Retry(_)) if attempt + 1 < ATTEMPTS => {
                    thread::sleep(BACKOFF * 2u32.pow(attempt));
                    attempt += 1;
                    continue;
                }
                Err(Failure::Retry(err) | Failure::Permanent(err)) => err,
            };
            return Err(err.context(format!("fetch {} bytes at {off:#x}", dst.len())));
        }
    }

    fn fetch_once(&self, off: u64, dst: &mut [u8]) -> Result<(), Failure> {
        let last = off + dst.len() as u64 - 1;
        let mut resp = self
            .agent
            .get(&self.url)
            .header("Range", format!("bytes={off}-{last}"))
            .call()
            .map_err(|e| Failure::Retry(Error::new(e).context("get")))?;
        let status = resp.status();
        if status.is_server_error() {
            return Err(Failure::Retry(anyhow!("get: {status}")));
        }
        // a 200 would be the whole object
        if status != ureq::http::StatusCode::PARTIAL_CONTENT {
            return Err(Failure::Permanent(Error::new(Refused(status))));
        }
        resp.body_mut().as_reader().read_exact(dst).context("read body").map_err(Failure::Retry)
    }
}

#[cfg(test)]
pub mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rstest::rstest;

    use super::*;

    /// A range server over `objects` keyed by path. It answers the first `failures.len()` requests
    /// with those statuses, and counts the ranges it serves per path.
    pub struct RangeServer {
        pub url: String,
        gets: Arc<Vec<(String, AtomicUsize)>>,
        requests: Arc<AtomicUsize>,
    }

    impl RangeServer {
        pub fn start(objects: Vec<(&str, Vec<u8>)>, failures: Vec<u16>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let gets: Arc<Vec<_>> = Arc::new(objects.iter().map(|(p, _)| ((*p).to_owned(), AtomicUsize::new(0))).collect());
            let requests = Arc::new(AtomicUsize::new(0));
            let objects: Arc<Vec<(String, Vec<u8>)>> = Arc::new(objects.into_iter().map(|(p, o)| (p.to_owned(), o)).collect());
            let (counts, seen) = (Arc::clone(&gets), Arc::clone(&requests));
            thread::spawn(move || {
                for conn in listener.incoming() {
                    let Ok(conn) = conn else { return };
                    let (objects, counts, seen, failures) =
                        (Arc::clone(&objects), Arc::clone(&counts), Arc::clone(&seen), failures.clone());
                    thread::spawn(move || serve_conn(conn, &objects, &counts, &seen, &failures));
                }
            });
            Self { url, gets, requests }
        }

        pub fn gets(&self, path: &str) -> usize {
            self.gets.iter().find(|(p, _)| p == path).map_or(0, |(_, n)| n.load(Ordering::Relaxed))
        }

        pub fn requests(&self) -> usize {
            self.requests.load(Ordering::Relaxed)
        }
    }

    fn serve_conn(
        conn: std::net::TcpStream,
        objects: &[(String, Vec<u8>)],
        counts: &[(String, AtomicUsize)],
        requests: &AtomicUsize,
        failures: &[u16],
    ) {
        let mut reader = BufReader::new(conn.try_clone().unwrap());
        let mut out = conn;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let path = line.split_whitespace().nth(1).unwrap_or("/").to_owned();
            let mut range = None;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header.trim().is_empty() {
                    break;
                }
                if let Some(v) = header.to_ascii_lowercase().strip_prefix("range: bytes=") {
                    let (a, b) = v.trim().split_once('-').unwrap();
                    range = Some((a.parse::<usize>().unwrap(), b.parse::<usize>().unwrap()));
                }
            }
            if let Some(status) = failures.get(requests.fetch_add(1, Ordering::Relaxed)) {
                write!(out, "HTTP/1.1 {status} Nope\r\ncontent-length: 0\r\n\r\n").unwrap();
                continue;
            }
            let Some((_, object)) = objects.iter().find(|(p, _)| *p == path) else {
                write!(out, "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n").unwrap();
                continue;
            };
            counts.iter().find(|(p, _)| *p == path).unwrap().1.fetch_add(1, Ordering::Relaxed);
            let (a, b) = range.expect("the fetcher always sends a range");
            let body = &object[a..=b.min(object.len() - 1)];
            write!(out, "HTTP/1.1 206 Partial Content\r\ncontent-length: {}\r\n\r\n", body.len()).unwrap();
            out.write_all(body).unwrap();
        }
    }

    fn object() -> Vec<u8> {
        (0..1 << 16).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        Fetched,
        Failed,
        Refused,
    }

    #[rstest]
    #[case::range(vec![], Outcome::Fetched, 1)]
    #[case::retries_server_errors(vec![503], Outcome::Fetched, 2)]
    #[case::gives_up_after_the_last_attempt(vec![500, 500, 500], Outcome::Failed, 3)]
    #[case::doesnt_retry_an_expired_url(vec![403], Outcome::Refused, 1)]
    // a server that ignores Range answers 200 with the whole object
    #[case::rejects_the_whole_object(vec![200], Outcome::Refused, 1)]
    fn fetches_ranges_and_retries_only_server_errors(#[case] failures: Vec<u16>, #[case] want: Outcome, #[case] requests: usize) {
        let srv = RangeServer::start(vec![("/mem", object())], failures);
        let mut dst = vec![0; 4096];
        let got = match RangeFetcher::new(&format!("{}/mem", srv.url)).fetch(8192, &mut dst) {
            Ok(()) => Outcome::Fetched,
            Err(err) if is_refused(&err) => Outcome::Refused,
            Err(_) => Outcome::Failed,
        };
        assert_eq!(got, want);
        assert_eq!(srv.requests(), requests);
        if got == Outcome::Fetched {
            assert_eq!(dst, object()[8192..12288]);
        }
    }
}
