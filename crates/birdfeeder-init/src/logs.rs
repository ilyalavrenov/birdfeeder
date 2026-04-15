//! Turns each container's raw stdout/stderr into numbered JSON records for the telemetry server
//! to stream to roost, on a fixed disk budget.
//!
//! runc writes `<name>.out.log` and `<name>.err.log` through `O_APPEND` fds. Each poll reads what's
//! new and appends records to `<name>.jsonl`, which rotates to `<name>.jsonl.1` at the cap. Then it
//! punches holes in the raw files behind whatever it already read.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Instant, SystemTime};

use anyhow::{Context, Result};
use guestapi::{MAX_LOG_LINE, MAX_LOG_RECORD};
use serde::{Deserialize, Serialize};

use crate::sys;

pub const DEFAULT_LOG_CAP: u64 = 1 << 20;
const READ_CHUNK: usize = 64 << 10;
pub const FLUSH_BYTES: usize = 1 << 20;
const BLOCK_SIZE: u64 = 4096;
pub const FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    // has to come first so seq_of can grab it without decoding the record.
    pub seq: u64,
    #[serde(with = "rfc3339_nanos")]
    pub ts: SystemTime,
    pub container: String,
    pub stream: Stream,
    pub line: String,
    /// The record before this one got dropped.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub gap: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stream {
    Stdout,
    Stderr,
}

impl Stream {
    const ALL: [Self; 2] = [Self::Stdout, Self::Stderr];
}

/// RFC 3339 with all nine fractional digits, even on whole seconds.
mod rfc3339_nanos {
    use std::time::SystemTime;

    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S: Serializer>(ts: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&humantime::format_rfc3339_nanos(*ts))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
        humantime::parse_rfc3339(&String::deserialize(d)?).map_err(de::Error::custom)
    }
}

/// Lets a restart pick up where it left off, no renumbering or re-reading.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct TailState {
    seq: u64,
    stdout: u64,
    stderr: u64,
}

/// Reads whole lines from a growing file. An unterminated tail stays unread until it gets a
/// newline or grows past `max` bytes.
pub struct Lines {
    file: File,
    off: u64,
    max: usize,
    buf: Vec<u8>,
    start: usize,
}

impl Lines {
    pub fn new(file: File, off: u64, max: usize) -> Self {
        Self { file, off, max, buf: Vec::new(), start: 0 }
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            let pending = &self.buf[self.start..];
            if let Some(i) = pending.iter().position(|&b| b == b'\n').filter(|&i| i <= self.max) {
                let line = pending[..i].to_vec();
                self.start += i + 1;
                return Ok(Some(line));
            }
            // past max, so a newline right at max would've been caught above
            if pending.len() > self.max {
                let cut = char_floor(pending, self.max);
                let line = pending[..cut].to_vec();
                self.start += cut;
                return Ok(Some(line));
            }
            self.buf.drain(..self.start);
            self.start = 0;
            let len = self.buf.len();
            self.buf.resize(len + READ_CHUNK, 0);
            match self.file.read_at(&mut self.buf[len..], self.off) {
                Ok(n) => {
                    self.buf.truncate(len + n);
                    self.off += n as u64;
                    if n == 0 {
                        return Ok(None);
                    }
                }
                Err(e) => {
                    self.buf.truncate(len);
                    if e.kind() != io::ErrorKind::Interrupted {
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Grabs the unterminated tail `next` holds back, once nothing more is coming.
    fn rest(&mut self) -> Option<Vec<u8>> {
        let tail = &self.buf[self.start..];
        (!tail.is_empty()).then(|| {
            let tail = tail.to_vec();
            self.start = self.buf.len();
            tail
        })
    }

    /// Offset just past the last line returned.
    pub fn consumed(&self) -> u64 {
        self.off - (self.buf.len() - self.start) as u64
    }
}

/// Moves a split at `max` back to the start of any UTF-8 sequence it would cut, so the char
/// lands whole in the next line.
fn char_floor(buf: &[u8], max: usize) -> usize {
    // a sequence is 4 bytes max, so only the last 3 before the cut can start one we'd split
    let Some(start) = (max.saturating_sub(3)..max).rev().find(|&i| buf[i] & 0xC0 != 0x80) else { return max };
    match std::str::from_utf8(&buf[start..max]) {
        Err(e) if e.error_len().is_none() && start > 0 => start,
        _ => max,
    }
}

/// Splits decoded text into record lines of at most `max` bytes, on char boundaries. Lossy
/// decoding can blow past the raw split, since every invalid byte turns into three.
fn record_lines(text: &str, max: usize) -> impl Iterator<Item = &str> {
    let mut rest = Some(text);
    std::iter::from_fn(move || {
        let r = rest?;
        let cut = if r.len() <= max { r.len() } else { r.floor_char_boundary(max) };
        let (line, tail) = r.split_at(cut);
        rest = (!tail.is_empty()).then_some(tail);
        Some(line)
    })
}

struct RawStream {
    /// runc's `O_APPEND` fd. Punching holes through it needs write access.
    w: File,
    r: Lines,
    punched: u64,
}

impl RawStream {
    fn open(path: &Path, off: u64) -> Result<Self> {
        let w = open_append(path)?;
        let r = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let off = off.min(w.metadata().with_context(|| format!("stat {}", path.display()))?.len());
        Ok(Self { w, r: Lines::new(r, off, MAX_LOG_LINE), punched: 0 })
    }

    /// Punching frees blocks without moving offsets, so it's crash-safe too.
    fn trim(&mut self, cap: u64) -> Result<()> {
        let end = self.r.consumed() & !(BLOCK_SIZE - 1);
        if end - self.punched < cap {
            return Ok(());
        }
        sys::punch_hole(&self.w, self.punched, end - self.punched).context("punch raw log")?;
        self.punched = end;
        Ok(())
    }
}

/// Wakes followers up when records land or the framed file rotates.
#[derive(Default)]
pub struct Notifier {
    generation: Mutex<u64>,
    changed: Condvar,
}

impl Notifier {
    fn lock(&self) -> MutexGuard<'_, u64> {
        self.generation.lock().expect("a log writer panicked holding the notifier")
    }

    /// Read this before checking for data, then pass it to `wait`, so we don't miss a broadcast in between.
    pub fn generation(&self) -> u64 {
        *self.lock()
    }

    fn broadcast(&self) {
        *self.lock() += 1;
        self.changed.notify_all();
    }

    /// Pokes waiters so they recheck their stop flag.
    pub fn wake(&self) {
        let _held = self.lock();
        self.changed.notify_all();
    }

    /// Waits for a broadcast after `seen`, or for `stop`. Returns false if stopped.
    pub fn wait(&self, seen: u64, stop: &AtomicBool) -> bool {
        let _held = self.changed.wait_while(self.lock(), |g| *g == seen && !stop.load(Ordering::Acquire)).expect("notifier poisoned");
        !stop.load(Ordering::Acquire)
    }
}

/// Counts a log's connected followers so the guest can let them finish before it stops.
#[derive(Default)]
pub struct Followers {
    count: Mutex<usize>,
    left: Condvar,
}

impl Followers {
    fn lock(&self) -> MutexGuard<'_, usize> {
        self.count.lock().expect("a follower panicked holding the count")
    }

    /// Counts one follower until the returned guard drops.
    pub fn join(&self) -> Following<'_> {
        *self.lock() += 1;
        Following(self)
    }

    /// Waits until every follower is gone or `deadline` passes. Returns false if some are still around.
    pub fn wait_gone(&self, deadline: Instant) -> bool {
        let timeout = deadline.saturating_duration_since(Instant::now());
        let (count, _) = self.left.wait_timeout_while(self.lock(), timeout, |n| *n > 0).expect("follower count poisoned");
        *count == 0
    }
}

pub struct Following<'a>(&'a Followers);

impl Drop for Following<'_> {
    fn drop(&mut self) {
        *self.0.lock() -= 1;
        self.0.left.notify_all();
    }
}

/// The framed side of a container's log, shared by its tailer and every follower.
pub struct FramedLog {
    pub name: String,
    path: PathBuf,
    rotated_path: PathBuf,
    /// also keeps rotation from racing followers opening the pair.
    current: Mutex<Current>,
    pub notify: Notifier,
    /// Set once nothing else will be appended, so followers stop their streams at the last record.
    closed: AtomicBool,
    pub followers: Followers,
}

/// The framed file we append to.
struct Current {
    file: File,
    /// How much has been fully appended. A failed append truncates back to this.
    len: u64,
}

impl FramedLog {
    fn lock(&self) -> MutexGuard<'_, Current> {
        self.current.lock().expect("the tailer panicked holding the framed log")
    }

    /// Opens the rotated and current files together so a follower never sees a half-rotated pair.
    pub fn open(&self) -> Result<(Option<File>, File)> {
        let _held = self.lock();
        let old = match File::open(&self.rotated_path) {
            Ok(f) => Some(f),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).with_context(|| format!("open {}", self.rotated_path.display())),
        };
        let cur = File::open(&self.path).with_context(|| format!("open {}", self.path.display()))?;
        Ok((old, cur))
    }

    /// Marks the log done. Only call this once its tailer is gone.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.broadcast();
    }

    pub fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn rotated(&self, cur: &File) -> Result<bool> {
        let _held = self.lock();
        let (open, named) = (cur.metadata().context("stat framed log")?, fs::metadata(&self.path).context("stat framed log")?);
        Ok((open.dev(), open.ino()) != (named.dev(), named.ino()))
    }

    /// Appends all of `batch` or none of it, so a full disk can't leave half a record for the next
    /// append to land on.
    fn append(&self, batch: &[u8]) -> Result<()> {
        let mut current = self.lock();
        let Current { file, len } = &mut *current;
        // followers read without the lock, so running out of space has to fail before a single byte lands.
        sys::reserve(file, *len, batch.len() as u64).with_context(|| format!("reserve space in {}", self.path.display()))?;
        if let Err(e) = file.write_all(batch) {
            let e = anyhow::Error::from(e).context(format!("append {}", self.path.display()));
            return Err(match file.set_len(*len) {
                Ok(()) => e,
                Err(t) => e.context(format!("drop the partial append: {t}")),
            });
        }
        *len += batch.len() as u64;
        Ok(())
    }

    fn rotate(&self, cap: u64) -> Result<()> {
        let mut current = self.lock();
        if current.len < cap {
            return Ok(());
        }
        fs::rename(&self.path, &self.rotated_path).with_context(|| format!("rotate {}", self.path.display()))?;
        *current = Current { file: open_append(&self.path)?, len: 0 };
        self.notify.broadcast();
        Ok(())
    }
}

pub struct Tailer {
    log: Arc<FramedLog>,
    stdout: RawStream,
    stderr: RawStream,
    seq: u64,
    /// Records we've read and numbered but haven't appended yet. A failed append keeps them for the next poll.
    pending: Vec<u8>,
    cap: u64,
    state_path: PathBuf,
}

impl Tailer {
    pub fn open(dir: &Path, name: &str, cap: u64) -> Result<Self> {
        let state_path = dir.join(format!("{name}.state"));
        // only a missing file means a fresh start. treating any other error like that would renumber from 0.
        let state = match fs::read(&state_path) {
            Ok(data) => serde_json::from_slice(&data).with_context(|| format!("parse {}", state_path.display()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => TailState::default(),
            Err(e) => return Err(e).with_context(|| format!("read {}", state_path.display())),
        };
        let stdout = RawStream::open(&dir.join(format!("{name}.out.log")), state.stdout)?;
        let stderr = RawStream::open(&dir.join(format!("{name}.err.log")), state.stderr)?;
        let path = dir.join(format!("{name}.jsonl"));
        let rotated_path = dir.join(format!("{name}.jsonl.1"));
        let framed = open_append(&path)?;
        let size = framed.metadata().map_or(0, |m| m.len());
        // state trails the framed append by one write. taking the max means a crash in that window can't reuse a seq.
        let seq = state.seq.max(last_seq(&rotated_path)?).max(last_seq(&path)?);
        let log = FramedLog {
            name: name.into(),
            path,
            rotated_path,
            current: Mutex::new(Current { file: framed, len: size }),
            notify: Notifier::default(),
            closed: AtomicBool::new(false),
            followers: Followers::default(),
        };
        Ok(Self { log: log.into(), stdout, stderr, seq, pending: Vec::new(), cap, state_path })
    }

    pub fn log(&self) -> Arc<FramedLog> {
        Arc::clone(&self.log)
    }

    /// The fds runc writes the container's stdout and stderr to.
    pub fn stdio(&self) -> io::Result<(File, File)> {
        Ok((self.stdout.w.try_clone()?, self.stderr.w.try_clone()?))
    }

    fn raw(&mut self, stream: Stream) -> &mut RawStream {
        match stream {
            Stream::Stdout => &mut self.stdout,
            Stream::Stderr => &mut self.stderr,
        }
    }

    pub fn poll(&mut self) -> Result<()> {
        // leftovers from a failed append go first so seqs stay in file order.
        self.flush()?;
        for stream in Stream::ALL {
            while let Some(raw) = self.raw(stream).r.next().context("read raw log")? {
                self.frame(stream, &raw)?;
                if self.pending.len() >= FLUSH_BYTES {
                    self.flush()?;
                }
            }
        }
        self.flush()?;
        self.trim()
    }

    /// One last poll once the container's writers are gone. Frames even a final line with no newline,
    /// since nothing's going to finish it and it's often the crash message.
    pub fn finish(&mut self) -> Result<()> {
        self.poll()?;
        for stream in Stream::ALL {
            if let Some(raw) = self.raw(stream).r.rest() {
                self.frame(stream, &raw)?;
            }
        }
        self.flush()
    }

    fn frame(&mut self, stream: Stream, raw: &[u8]) -> Result<()> {
        for line in record_lines(&String::from_utf8_lossy(raw), MAX_LOG_LINE) {
            self.seq += 1;
            let record = Record {
                seq: self.seq,
                ts: SystemTime::now(),
                container: self.log.name.clone(),
                stream,
                line: line.to_owned(),
                gap: false,
            };
            serde_json::to_writer(&mut self.pending, &record).context("encode record")?;
            self.pending.push(b'\n');
        }
        Ok(())
    }

    /// Saves offsets only after their records are appended. A crash can replay lines but never skip them.
    fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.log.append(&self.pending)?;
        self.pending.clear();
        self.log.notify.broadcast();
        let state = TailState { seq: self.seq, stdout: self.stdout.r.consumed(), stderr: self.stderr.r.consumed() };
        write_atomic(&self.state_path, &serde_json::to_vec(&state)?)?;
        self.trim()
    }

    fn trim(&mut self) -> Result<()> {
        self.stdout.trim(self.cap)?;
        self.stderr.trim(self.cap)?;
        self.log.rotate(self.cap)
    }

    #[cfg(test)]
    pub fn write_raw(&self, stream: Stream, text: impl AsRef<[u8]>) {
        let raw = match stream {
            Stream::Stdout => &self.stdout,
            Stream::Stderr => &self.stderr,
        };
        (&raw.w).write_all(text.as_ref()).unwrap();
    }

    /// Swaps the framed log's fd for a read-only one so appends fail like they would on a full disk.
    #[cfg(test)]
    pub fn set_writable(&self, writable: bool) {
        let path = &self.log.path;
        self.log.lock().file = if writable { open_append(path).unwrap() } else { File::open(path).unwrap() };
    }
}

/// Pulls the seq number off a record's leading `{"seq":N,` without decoding it.
pub fn seq_of(line: &[u8]) -> Option<u64> {
    let rest = line.strip_prefix(br#"{"seq":"#)?;
    let digits = &rest[..rest.iter().position(|&b| b == b',')?];
    std::str::from_utf8(digits).ok()?.parse().ok()
}

/// The last seq number in the framed file at `path`. Only 0 if the file doesn't exist.
fn last_seq(path: &Path) -> Result<u64> {
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e).with_context(|| format!("open {}", path.display())),
    };
    let mut lines = Lines::new(f, 0, MAX_LOG_RECORD);
    let mut last = 0;
    while let Some(line) = lines.next().with_context(|| format!("read {}", path.display()))? {
        if let Some(seq) = seq_of(&line) {
            last = seq;
        }
    }
    Ok(last)
}

fn open_append(path: &Path) -> Result<File> {
    OpenOptions::new().append(true).create(true).mode(FILE_MODE).open(path).with_context(|| format!("open {}", path.display()))
}

pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(FILE_MODE)
        .open(path)
        .and_then(|mut f| f.write_all(data))
        .with_context(|| format!("write {}", path.display()))
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    write_private(&tmp, data)?;
    fs::rename(&tmp, path).with_context(|| format!("rename {}", tmp.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logged(dir: &Path) -> Tailer {
        let mut t = Tailer::open(dir, "app", DEFAULT_LOG_CAP).unwrap();
        t.write_raw(Stream::Stdout, "a\nb\n");
        t.poll().unwrap();
        t
    }

    #[test]
    fn seq_resumes_from_framed_log() {
        let dir = tempfile::tempdir().unwrap();
        drop(logged(dir.path()));
        fs::remove_file(dir.path().join("app.state")).unwrap();
        let t = Tailer::open(dir.path(), "app", DEFAULT_LOG_CAP).unwrap();
        assert_eq!(t.seq, 2);
    }

    #[test]
    fn unreadable_state_fails_open() {
        let dir = tempfile::tempdir().unwrap();
        drop(logged(dir.path()));
        fs::remove_file(dir.path().join("app.state")).unwrap();
        fs::create_dir(dir.path().join("app.state")).unwrap();
        let err = Tailer::open(dir.path(), "app", DEFAULT_LOG_CAP).err().expect("not a fresh start");
        assert!(format!("{err:#}").contains("app.state"), "{err:#}");
    }

    #[test]
    fn unreadable_framed_log_fails_open() {
        let dir = tempfile::tempdir().unwrap();
        // a directory opens fine but fails to read, and that can't count as hitting EOF.
        fs::create_dir(dir.path().join("app.jsonl.1")).unwrap();
        let err = Tailer::open(dir.path(), "app", DEFAULT_LOG_CAP).err().expect("it could hold higher seqs");
        assert!(format!("{err:#}").contains("app.jsonl.1"), "{err:#}");
        assert_eq!(last_seq(&dir.path().join("missing")).unwrap(), 0);
    }

    #[test]
    fn record_wire_form() {
        let line = r#"{"seq":1,"ts":"2026-11-04T15:00:00.000000000Z","container":"web","stream":"stderr","line":"x"}"#;
        let record: Record = serde_json::from_str(line).unwrap();
        assert_eq!((record.ts, record.stream), (humantime::parse_rfc3339("2026-11-04T15:00:00Z").unwrap(), Stream::Stderr));
        assert_eq!(serde_json::to_string(&record).unwrap(), line);
    }
}
