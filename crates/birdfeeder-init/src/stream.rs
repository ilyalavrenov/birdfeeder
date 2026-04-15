//! Streams a container's framed records after a given seq, then follows new ones as they land.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use guestapi::MAX_LOG_RECORD;

use crate::logs::{FramedLog, Lines, Record, seq_of};

/// Writes every record we still have after `after`, in order, then follows until the log is closed
/// and fully sent, or until `stop` is set and the log's notifier is woken. The first record after a
/// range that rotated out gets `gap` set.
pub fn serve(log: &FramedLog, w: &mut impl Write, after: u64, stop: &AtomicBool) -> Result<()> {
    let mut prev = after;
    let mut emit = |line: &[u8]| -> Result<()> {
        let Some(seq) = seq_of(line).filter(|&seq| seq > prev) else { return Ok(()) };
        let mut out = if seq == prev + 1 { line.to_vec() } else { with_gap(line)? };
        prev = seq;
        out.push(b'\n');
        w.write_all(&out).context("write record")
    };
    while !stop.load(Ordering::Acquire) {
        let (old, cur) = log.open()?;
        if let Some(old) = old {
            drain(&mut Lines::new(old, 0, MAX_LOG_RECORD), &mut emit)?;
        }
        if !follow(log, &mut Lines::new(cur, 0, MAX_LOG_RECORD), &mut emit, stop)? {
            break;
        }
    }
    Ok(())
}

/// Follows the current file until it rotates (returns true so the caller reopens), or until the
/// log is closed or `stop` is set (returns false).
fn follow(log: &FramedLog, lines: &mut Lines, emit: &mut impl FnMut(&[u8]) -> Result<()>, stop: &AtomicBool) -> Result<bool> {
    loop {
        let seen = log.notify.generation();
        // read this before draining, so if the log closes now its last record is in this drain.
        let closed = log.closed();
        drain(lines, emit)?;
        if log.rotated(lines.file())? {
            // rotation happens under the lock after the last append to this inode, so one more drain gets everything.
            drain(lines, emit)?;
            return Ok(true);
        }
        if closed {
            return Ok(false);
        }
        if !log.notify.wait(seen, stop) {
            return Ok(false);
        }
    }
}

fn drain(lines: &mut Lines, emit: &mut impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
    while let Some(line) = lines.next().context("read framed log")? {
        emit(&line)?;
    }
    Ok(())
}

fn with_gap(line: &[u8]) -> Result<Vec<u8>> {
    let mut record: Record = serde_json::from_slice(line).context("decode record")?;
    record.gap = true;
    Ok(serde_json::to_vec(&record)?)
}

#[cfg(test)]
mod tests {
    use std::io::{self, BufRead, BufReader, Read};
    use std::sync::Arc;
    use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
    use std::thread::{self, JoinHandle};

    use guestapi::MAX_LOG_LINE;

    use super::*;
    use crate::logs::{DEFAULT_LOG_CAP, FLUSH_BYTES, Stream, Tailer};

    const TEST_CAP: u64 = 1024;

    fn open(dir: &tempfile::TempDir, cap: u64) -> Tailer {
        Tailer::open(dir.path(), "kernel", cap).unwrap()
    }

    /// Every write waits on the reader, so a follower stalls whenever its client stops reading.
    struct Unbuffered(SyncSender<Vec<u8>>);

    impl Write for Unbuffered {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.send(b.to_vec()).map_err(|_| io::ErrorKind::BrokenPipe)?;
            Ok(b.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct Received {
        rx: Receiver<Vec<u8>>,
        buf: Vec<u8>,
        pos: usize,
    }

    impl Read for Received {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.pos == self.buf.len() {
                let Ok(buf) = self.rx.recv() else { return Ok(0) };
                (self.buf, self.pos) = (buf, 0);
            }
            let n = out.len().min(self.buf.len() - self.pos);
            out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    /// A running `serve` and the client end of its stream.
    struct Follower {
        records: BufReader<Received>,
        stop: Arc<AtomicBool>,
        log: Arc<FramedLog>,
        done: Option<JoinHandle<Result<()>>>,
    }

    impl Follower {
        fn start(t: &Tailer, after: u64) -> Self {
            let (tx, rx) = sync_channel(0);
            let (log, stop) = (t.log(), Arc::new(AtomicBool::new(false)));
            let (l, s) = (Arc::clone(&log), Arc::clone(&stop));
            let done = thread::spawn(move || serve(&l, &mut Unbuffered(tx), after, &s));
            Self { records: BufReader::new(Received { rx, buf: Vec::new(), pos: 0 }), stop, log, done: Some(done) }
        }

        fn next(&mut self) -> Record {
            let mut line = String::new();
            assert!(self.records.read_line(&mut line).unwrap() > 0, "stream ended");
            serde_json::from_str(&line).unwrap()
        }

        fn take(&mut self, n: usize) -> Vec<Record> {
            (0..n).map(|_| self.next()).collect()
        }

        fn stop(mut self) {
            self.stop.store(true, Ordering::Release);
            self.log.notify.wake();
            self.done.take().unwrap().join().unwrap().unwrap();
        }
    }

    fn collect(t: &Tailer, after: u64, n: usize) -> Vec<Record> {
        let mut f = Follower::start(t, after);
        let records = f.take(n);
        f.stop();
        records
    }

    fn seqs(records: &[Record]) -> Vec<u64> {
        records.iter().map(|r| r.seq).collect()
    }

    fn first_seq(path: &std::path::Path) -> u64 {
        let data = std::fs::read(path).unwrap();
        seq_of(data.split(|&b| b == b'\n').next().unwrap()).unwrap()
    }

    #[test]
    fn frames_and_serves_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = open(&dir, DEFAULT_LOG_CAP);
        t.write_raw(Stream::Stdout, "a\nb\n");
        t.write_raw(Stream::Stderr, "err1\n");
        t.write_raw(Stream::Stdout, "partial");
        t.poll().unwrap();
        let records = collect(&t, 0, 3);
        assert_eq!(seqs(&records), [1, 2, 3]);
        assert_eq!(records.iter().map(|r| r.line.as_str()).collect::<Vec<_>>(), ["a", "b", "err1"]);
        assert_eq!(records[2].stream, Stream::Stderr);
        assert_eq!(records[0].container, "kernel");
        assert!(!records[0].gap);
        t.write_raw(Stream::Stdout, " line\n");
        t.poll().unwrap();
        let records = collect(&t, 3, 1);
        assert_eq!((records[0].seq, records[0].line.as_str(), records[0].gap), (4, "partial line", false));
    }

    #[test]
    fn closed_log_ends_stream() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = open(&dir, DEFAULT_LOG_CAP);
        t.write_raw(Stream::Stdout, "a\n");
        t.poll().unwrap();
        let mut f = Follower::start(&t, 0);
        assert_eq!(f.next().line, "a");
        t.write_raw(Stream::Stdout, "last");
        t.finish().unwrap();
        t.log().close();
        assert_eq!(f.next().line, "last");
        assert_eq!(f.records.read_line(&mut String::new()).unwrap(), 0, "stream ends at the last record");
        f.done.take().unwrap().join().unwrap().unwrap();
        // a follower that connects after the close gets the rest and ends too
        let mut late = Follower::start(&t, 1);
        assert_eq!(late.next().line, "last");
        assert_eq!(late.records.read_line(&mut String::new()).unwrap(), 0);
    }

    #[test]
    fn finish_frames_unterminated_tail_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = open(&dir, DEFAULT_LOG_CAP);
        t.write_raw(Stream::Stdout, "a\npanicked: oops");
        t.write_raw(Stream::Stderr, "e");
        t.poll().unwrap();
        t.finish().unwrap();
        let records = collect(&t, 0, 3);
        let lines: Vec<_> = records.iter().map(|r| (r.stream, r.line.as_str())).collect();
        assert_eq!(lines, [(Stream::Stdout, "a"), (Stream::Stdout, "panicked: oops"), (Stream::Stderr, "e")]);
        // the offsets it saved cover the tail, so a restart doesn't frame it again
        let mut t2 = open(&dir, DEFAULT_LOG_CAP);
        t2.write_raw(Stream::Stdout, "next\n");
        t2.poll().unwrap();
        let records = collect(&t2, 3, 1);
        assert_eq!((records[0].seq, records[0].line.as_str()), (4, "next"));
    }

    #[test]
    fn restart_resumes_seq_and_offsets() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = open(&dir, DEFAULT_LOG_CAP);
        t.write_raw(Stream::Stdout, "one\ntwo\n");
        t.poll().unwrap();
        // written after the last poll, then a crash
        t.write_raw(Stream::Stdout, "three\n");
        t.write_raw(Stream::Stderr, "e\n");
        let mut t2 = open(&dir, DEFAULT_LOG_CAP);
        t2.poll().unwrap();
        let records = collect(&t2, 2, 2);
        assert_eq!(seqs(&records), [3, 4]);
        assert_eq!((records[0].line.as_str(), records[1].line.as_str()), ("three", "e"));
        assert!(!records[0].gap);
        assert_eq!(seqs(&collect(&t2, 0, 4)), [1, 2, 3, 4]);
    }

    #[test]
    fn failed_append_keeps_records() {
        let dir = tempfile::tempdir().unwrap();
        let framed = dir.path().join("kernel.jsonl");
        let mut t = open(&dir, DEFAULT_LOG_CAP);
        t.write_raw(Stream::Stdout, "a\n");
        t.poll().unwrap();
        let size = std::fs::metadata(&framed).unwrap().len();

        t.set_writable(false);
        t.write_raw(Stream::Stdout, "b\nc\n");
        t.poll().unwrap_err();
        t.write_raw(Stream::Stderr, "d\n");
        t.poll().unwrap_err();
        assert_eq!(std::fs::metadata(&framed).unwrap().len(), size, "nothing lands while appends fail");

        t.set_writable(true);
        t.poll().unwrap();
        let data = std::fs::read(&framed).unwrap();
        let records: Vec<Record> =
            data.split(|&b| b == b'\n').filter(|l| !l.is_empty()).map(|l| serde_json::from_slice(l).unwrap()).collect();
        assert_eq!(seqs(&records), [1, 2, 3, 4]);
        assert_eq!(records.iter().map(|r| r.line.as_str()).collect::<Vec<_>>(), ["a", "b", "c", "d"]);
    }

    #[test]
    fn rotation_sets_gap() {
        const TOTAL: u64 = 60;
        let dir = tempfile::tempdir().unwrap();
        let mut t = open(&dir, TEST_CAP);
        for _ in 0..TOTAL {
            t.write_raw(Stream::Stdout, format!("{}\n", "x".repeat(20)));
            t.poll().unwrap();
        }
        let oldest = first_seq(&dir.path().join("kernel.jsonl.1"));
        assert!(oldest > 1);
        let retained = usize::try_from(TOTAL - oldest + 1).unwrap();
        let records = collect(&t, 0, retained);
        assert!(records[0].gap, "first record after a rotated-out range carries gap");
        assert_eq!(records[0].seq, oldest);
        assert!(!records[1].gap);
        assert_eq!(seqs(&records), (oldest..=TOTAL).collect::<Vec<_>>());
        assert!(!collect(&t, oldest - 1, retained)[0].gap, "asking for exactly the oldest retained is not a gap");
        let records = collect(&t, oldest + 2, retained - 3);
        assert_eq!((records[0].seq, records[0].gap), (oldest + 3, false));
    }

    #[test]
    fn burst_rotates_within_one_poll() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = open(&dir, TEST_CAP);
        let line = format!("{}\n", "b".repeat(1000));
        for _ in 0..3 * FLUSH_BYTES / line.len() {
            t.write_raw(Stream::Stdout, &line);
        }
        t.poll().unwrap();
        let size = std::fs::metadata(dir.path().join("kernel.jsonl")).unwrap().len();
        assert!(size < TEST_CAP + FLUSH_BYTES as u64, "rotation runs per flush, not per poll");
        assert!(first_seq(&dir.path().join("kernel.jsonl.1")) > 1, "seq 1 rotated out mid-burst");
    }

    #[test]
    fn follower_survives_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = open(&dir, TEST_CAP);
        t.write_raw(Stream::Stdout, "first\n");
        t.poll().unwrap();
        let mut f = Follower::start(&t, 0);
        assert_eq!(f.next().seq, 1);
        // paced so the follower keeps up, since it has to switch files on every rotation
        for seq in 2..42 {
            t.write_raw(Stream::Stdout, format!("{}\n", "y".repeat(30)));
            t.poll().unwrap();
            let r = f.next();
            assert_eq!((r.seq, r.gap), (seq, false));
        }
        f.stop();
    }

    #[test]
    fn stalled_follower_sees_gap() {
        const LAST: u64 = 41;
        let dir = tempfile::tempdir().unwrap();
        let mut t = open(&dir, TEST_CAP);
        t.write_raw(Stream::Stdout, "first\n");
        t.poll().unwrap();
        let mut f = Follower::start(&t, 0);
        assert_eq!(f.next().seq, 1);
        for _ in 1..LAST {
            t.write_raw(Stream::Stdout, format!("{}\n", "y".repeat(30)));
            t.poll().unwrap();
        }
        let (mut prev, mut gaps) = (1, 0);
        while prev < LAST {
            let r = f.next();
            assert!(r.seq > prev, "never reordered or repeated");
            assert_eq!(r.gap, r.seq != prev + 1, "gap iff a range was lost");
            gaps += usize::from(r.gap);
            prev = r.seq;
        }
        assert_eq!(gaps, 1);
        f.stop();
    }

    #[test]
    fn long_line_is_force_emitted() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = open(&dir, DEFAULT_LOG_CAP);
        t.write_raw(Stream::Stdout, "z".repeat(MAX_LOG_LINE + 10));
        t.poll().unwrap();
        assert_eq!(collect(&t, 0, 1)[0].line.len(), MAX_LOG_LINE);
        t.write_raw(Stream::Stdout, "\n");
        t.poll().unwrap();
        assert_eq!(collect(&t, 1, 1)[0].line, "z".repeat(10));
    }

    #[test]
    fn long_escaped_line_across_read_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = open(&dir, DEFAULT_LOG_CAP);
        t.write_raw(Stream::Stdout, format!("prefix\n{}\n", "\x01".repeat(2 * MAX_LOG_LINE)));
        t.poll().unwrap();
        let records = collect(&t, 0, 3);
        assert_eq!(records[0].line, "prefix");
        for r in &records[1..] {
            assert_eq!(r.line.len(), MAX_LOG_LINE);
            assert!(serde_json::to_vec(r).unwrap().len() < MAX_LOG_RECORD);
        }
    }

    #[test]
    fn line_at_limit_is_one_record() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = open(&dir, DEFAULT_LOG_CAP);
        t.write_raw(Stream::Stdout, format!("{}\nnext\n", "a".repeat(MAX_LOG_LINE)));
        t.poll().unwrap();
        let records = collect(&t, 0, 2);
        assert_eq!(records[0].line.len(), MAX_LOG_LINE);
        assert_eq!(records[1].line, "next", "no empty record for the newline");
    }

    #[test]
    fn split_keeps_chars_whole() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = open(&dir, DEFAULT_LOG_CAP);
        // the odd prefix puts a two-byte character across the limit
        t.write_raw(Stream::Stdout, format!("x{}\n", "я".repeat(MAX_LOG_LINE / 2)));
        t.poll().unwrap();
        let records = collect(&t, 0, 2);
        assert_eq!(records[0].line, format!("x{}", "я".repeat(MAX_LOG_LINE / 2 - 1)));
        assert_eq!(records[1].line, "я");
    }

    #[test]
    fn invalid_utf8_stays_within_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = open(&dir, DEFAULT_LOG_CAP);
        t.write_raw(Stream::Stdout, [vec![0xFF; MAX_LOG_LINE], b"\n".to_vec()].concat());
        t.poll().unwrap();
        // each invalid byte decodes to a 3-byte U+FFFD
        let records = collect(&t, 0, (3 * MAX_LOG_LINE).div_ceil(MAX_LOG_LINE - 1));
        assert!(records.iter().all(|r| r.line.len() <= MAX_LOG_LINE));
        assert_eq!(records.iter().map(|r| r.line.as_str()).collect::<String>(), "\u{FFFD}".repeat(MAX_LOG_LINE));
    }

    #[test]
    fn trim_punches_consumed_raw_blocks() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let mut t = open(&dir, 2 * 4096);
        let line = format!("{}\n", "r".repeat(99));
        for _ in 0..100 {
            t.write_raw(Stream::Stdout, &line);
        }
        t.poll().unwrap();
        let st = std::fs::metadata(dir.path().join("kernel.out.log")).unwrap();
        assert_eq!(st.size(), 100 * line.len() as u64);
        assert!(st.blocks() * 512 < st.size(), "punched blocks are freed while the size stays");
        t.write_raw(Stream::Stdout, "after\n");
        t.poll().unwrap();
        assert_eq!(collect(&t, 100, 1)[0].line, "after");
    }
}
