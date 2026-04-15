//! Follows one container's stream: reconnects with backoff, rate-limits what the guest sends, and checkpoints the
//! cursor once a second.

use std::{
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime},
};

use guestapi::protocol::Request;
use guestapi::{MAX_LOG_LINE, MAX_LOG_RECORD};
use opentelemetry::logs::{AnyValue, LogRecord as _, Logger};
use serde::Deserialize;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _},
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

use crate::{StreamKey, Target, cursor};

const BYTES_PER_SECOND: u64 = 64 << 10;
const MIN_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);
const CHECKPOINT_EVERY: Duration = Duration::from_secs(1);

pub(crate) async fn follow(target: Target, key: StreamKey, path: PathBuf, logger: impl Logger, cancel: CancellationToken) {
    let initial = cursor::load(&path).await.unwrap_or_else(|err| {
        // logs are best effort. A corrupt cursor replays retained history (record ids let a backend dedupe it) instead
        // of keeping the stream down.
        tracing::warn!(container_id = %key, error = %err, "load guest log cursor");
        0
    });
    let seq = AtomicU64::new(initial);
    let stream = Stream { target: &target, key, seq: &seq, logger: &logger };
    tokio::join!(stream.run(&cancel), checkpoint(path, initial, &seq, &cancel));
}

/// Saves the cursor whenever it moved, plus once more after `cancel` so a stopped stream picks up where it left off.
async fn checkpoint(path: PathBuf, mut saved: u64, seq: &AtomicU64, cancel: &CancellationToken) {
    let mut done = false;
    while !done {
        done = cancel.run_until_cancelled(sleep(CHECKPOINT_EVERY)).await.is_none();
        let current = seq.load(Ordering::Relaxed);
        if current == saved {
            continue;
        }
        match cursor::save(path.clone(), current).await {
            Ok(()) => saved = current,
            Err(err) => tracing::warn!(error = %err, "save guest log cursor"),
        }
    }
}

struct Stream<'a, L> {
    target: &'a Target,
    key: StreamKey,
    seq: &'a AtomicU64,
    logger: &'a L,
}

impl<L: Logger> Stream<'_, L> {
    async fn run(&self, cancel: &CancellationToken) {
        let mut limiter = Limiter::new();
        let mut backoff = MIN_BACKOFF;
        loop {
            let before = self.seq.load(Ordering::Relaxed);
            let Some(result) = cancel.run_until_cancelled(self.read(&mut limiter)).await else { return };
            let err = result.err().map(|err| err.to_string());
            tracing::debug!(container_id = %self.key, error = err, "guest log stream reconnect");
            if self.seq.load(Ordering::Relaxed) != before {
                backoff = MIN_BACKOFF;
            }
            if cancel.run_until_cancelled(sleep(backoff)).await.is_none() {
                return;
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    /// Exports records until the stream ends, which never counts as success: the guest keeps streaming until it goes
    /// away.
    async fn read(&self, limiter: &mut Limiter) -> io::Result<()> {
        let mut conn = guestapi::connect(&self.target.socket, guestapi::PORT).await?;
        let request = Request::Logs { container: self.target.container.clone(), after: self.seq.load(Ordering::Relaxed) };
        timeout(WRITE_TIMEOUT, conn.write_all(format!("{request}\n").as_bytes()))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "send logs request timed out"))??;
        let mut line = Vec::new();
        let mut skipped = false;
        while read_record(&mut conn, &mut line).await? {
            limiter.wait(line.len() + 1).await;
            let previous = self.seq.load(Ordering::Relaxed);
            match decode(&line, &self.target.container, previous) {
                Ok(mut record) => {
                    record.gap |= std::mem::take(&mut skipped);
                    self.emit(&record);
                    self.seq.store(record.seq, Ordering::Relaxed);
                }
                Err(Refusal::Skip { seq, why }) => {
                    tracing::debug!(container_id = %self.key, seq, why, "skip unusable guest log record");
                    skipped = true;
                    self.seq.store(seq, Ordering::Relaxed);
                }
                Err(Refusal::Fatal(err)) => return Err(err),
            }
        }
        Ok(())
    }

    fn emit(&self, wire: &Wire) {
        let mut record = self.logger.create_log_record();
        record.set_timestamp(wire.ts);
        record.set_observed_timestamp(SystemTime::now());
        record.set_body(AnyValue::String(wire.line.clone().into()));
        record.add_attribute("log.iostream", wire.stream.as_str());
        record.add_attribute("log.record.uid", format!("{}:{}", self.key, wire.seq));
        if wire.gap {
            record.add_attribute("birdfeeder.log.gap", true);
        }
        self.logger.emit(record);
    }
}

/// Reads one newline-terminated record into `line`, minus the newline. `false` on a clean end of stream.
async fn read_record(conn: &mut (impl AsyncBufRead + Unpin), line: &mut Vec<u8>) -> io::Result<bool> {
    line.clear();
    (&mut *conn).take(MAX_LOG_RECORD as u64 + 1).read_until(b'\n', line).await?;
    if line.pop_if(|b| *b == b'\n').is_some() {
        return Ok(true);
    }
    match line.len() {
        0 => Ok(false),
        n if n > MAX_LOG_RECORD => Err(io::Error::new(io::ErrorKind::InvalidData, "guest log record too long")),
        _ => Err(io::ErrorKind::UnexpectedEof.into()),
    }
}

#[derive(Debug)]
struct Wire {
    seq: u64,
    ts: SystemTime,
    stream: Iostream,
    line: String,
    gap: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Iostream {
    Stdout,
    Stderr,
}

impl Iostream {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// Why [`decode`] refused a record.
#[derive(Debug)]
enum Refusal {
    /// A record in sequence whose content can't be exported. Resuming at it would refuse it forever, so the stream
    /// skips it and marks the gap.
    Skip { seq: u64, why: &'static str },
    /// The guest broke the protocol; the stream reconnects from its cursor.
    Fatal(io::Error),
}

/// The guest is untrusted: a record has to belong to the stream, move it forward, and stay within the guest's limits.
fn decode(data: &[u8], container: &str, previous: u64) -> Result<Wire, Refusal> {
    #[derive(Deserialize)]
    struct Raw<'a> {
        seq: u64,
        ts: &'a str,
        container: &'a str,
        stream: Iostream,
        #[serde(default)]
        line: String,
        #[serde(default)]
        gap: bool,
    }
    let fatal = |why: &str| Refusal::Fatal(io::Error::new(io::ErrorKind::InvalidData, format!("invalid guest log record: {why}")));
    let raw: Raw = serde_json::from_slice(data).map_err(|err| fatal(&err.to_string()))?;
    if raw.seq <= previous {
        return Err(fatal("sequence went backwards"));
    }
    if raw.container != container {
        return Err(fatal("another container's record"));
    }
    let skip = |why| Refusal::Skip { seq: raw.seq, why };
    let ts = humantime::parse_rfc3339(raw.ts).map_err(|_| skip("timestamp"))?;
    if raw.line.len() > MAX_LOG_LINE {
        return Err(skip("line too long"));
    }
    let gap = raw.gap || raw.seq != previous + 1;
    Ok(Wire { seq: raw.seq, ts, stream: raw.stream, line: raw.line, gap })
}

/// A token bucket of bytes, holding up to one maximal record.
struct Limiter {
    tokens: u64,
    refilled: Instant,
}

impl Limiter {
    const BURST: u64 = MAX_LOG_RECORD as u64 + 1;

    fn new() -> Self {
        Self { tokens: Self::BURST, refilled: Instant::now() }
    }

    async fn wait(&mut self, bytes: usize) {
        let bytes = bytes as u64;
        self.refill();
        if let Some(deficit) = bytes.checked_sub(self.tokens).filter(|d| *d > 0) {
            sleep(Duration::from_nanos(deficit.saturating_mul(1_000_000_000).div_ceil(BYTES_PER_SECOND))).await;
            self.refill();
        }
        self.tokens = self.tokens.saturating_sub(bytes);
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let earned = now.duration_since(self.refilled).as_nanos() * u128::from(BYTES_PER_SECOND) / 1_000_000_000;
        let earned = u64::try_from(earned).unwrap_or(u64::MAX);
        if earned > 0 {
            self.tokens = self.tokens.saturating_add(earned).min(Self::BURST);
            self.refilled = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;

    fn record(edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut wire = json!({"seq": 2, "ts": "2026-11-01T12:34:56.123456789Z", "container": "web", "stream": "stdout", "line": "hello"});
        edit(&mut wire);
        serde_json::to_vec(&wire).unwrap()
    }

    #[rstest]
    #[case::wrong_container(record(|w| w["container"] = json!("other")))]
    #[case::wrong_stream(record(|w| w["stream"] = json!("audit")))]
    #[case::repeated_sequence(record(|w| w["seq"] = json!(1)))]
    #[case::missing_sequence(record(|w| w["seq"] = serde_json::Value::Null))]
    #[case::not_json(b"not json".to_vec())]
    fn protocol_violations_end_the_stream(#[case] data: Vec<u8>) {
        assert!(matches!(decode(&data, "web", 1), Err(Refusal::Fatal(_))));
    }

    #[rstest]
    #[case::invalid_timestamp(record(|w| w["ts"] = json!("yesterday")))]
    #[case::oversize_body(record(|w| w["line"] = json!("a".repeat(MAX_LOG_LINE + 1))))]
    fn unusable_records_in_sequence_are_skipped(#[case] data: Vec<u8>) {
        assert!(matches!(decode(&data, "web", 1), Err(Refusal::Skip { seq: 2, .. })));
    }

    #[test]
    fn the_longest_line_is_exported() {
        assert!(decode(&record(|w| w["line"] = json!("a".repeat(MAX_LOG_LINE))), "web", 1).is_ok());
    }

    #[test]
    fn records_mark_gaps_in_the_sequence() {
        let wire = decode(&record(|_| {}), "web", 0).unwrap();
        assert_eq!((wire.seq, wire.stream, wire.line.as_str(), wire.gap), (2, Iostream::Stdout, "hello", true));
        let since = wire.ts.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(since.subsec_nanos(), 123_456_789);
        assert!(!decode(&record(|_| {}), "web", 1).unwrap().gap);
        assert!(decode(&record(|w| w["gap"] = json!(true)), "web", 1).unwrap().gap, "the guest dropped records");
    }

    #[tokio::test]
    async fn records_are_bounded_by_their_framing() {
        let max = [vec![b'a'; MAX_LOG_RECORD], b"\n".to_vec()].concat();
        let mut line = Vec::new();
        assert!(read_record(&mut max.as_slice(), &mut line).await.unwrap());
        assert_eq!(line.len(), MAX_LOG_RECORD);
        let over = [vec![b'a'; MAX_LOG_RECORD + 1], b"\n".to_vec()].concat();
        assert_eq!(read_record(&mut over.as_slice(), &mut line).await.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(read_record(&mut b"cut off".as_slice(), &mut line).await.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(!read_record(&mut b"".as_slice(), &mut line).await.unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn limiter_bursts_then_rate_limits() {
        let mut limiter = Limiter::new();
        let start = Instant::now();
        limiter.wait(MAX_LOG_RECORD + 1).await;
        assert_eq!(start.elapsed(), Duration::ZERO, "one maximal record goes straight through");
        limiter.wait(BYTES_PER_SECOND as usize * 2).await;
        assert_eq!(start.elapsed(), Duration::from_secs(2));
    }
}
