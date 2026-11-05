//! Firecracker's log and metrics. It writes them to FIFOs that roost drains. The writes are nonblocking, so a full
//! pipe drops them and bumps the `missed_*` metrics.

use std::collections::HashMap;
use std::os::unix::fs::chown;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use fcapi::{InstanceActionInfo, InstanceActionInfoActionType, Logger, LoggerLevel, Metrics};
use nix::sys::stat::Mode;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::unix::pipe;
use tracing::Level;

use super::Driver;
use super::api::Api;
use super::metrics::Metrics as Counters;
use crate::Instance;

const LOG_NAME: &str = "fc.log";
const METRICS_NAME: &str = "fc-metrics";
const METRICS_MAX_LINE: u64 = 1 << 20;
const LOG_MAX_LINE: u64 = 64 << 10;
const BLOB_START: &str = r#"{"utc_timestamp_ms""#;
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// A file in the vm's run dir, next to its API socket, owned by the vm's uid.
pub fn run_file(inst: &Instance, name: &str) -> PathBuf {
    inst.api_sock.with_file_name(name)
}

pub fn run_file_in_vm(inst: &Instance, name: &str) -> String {
    inst.sandbox.path_in_vm(&run_file(inst, name), &format!("run/{name}"))
}

impl Driver {
    /// Hooks up before the devices are configured so boot errors make it into the log.
    pub(super) async fn attach_telemetry(&self, api: &Api, inst: &Instance) -> Result<()> {
        let uid = crate::Driver::uid(self, inst);
        for name in [LOG_NAME, METRICS_NAME] {
            let path = run_file(inst, name);
            nix::unistd::mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).with_context(|| format!("mkfifo {}", path.display()))?;
            if uid != 0 {
                chown(&path, Some(uid), Some(uid)).with_context(|| format!("chown fifo {}", path.display()))?;
            }
        }
        api.send(&Logger {
            // Info just adds per-request API lines, and roost already traces those as spans
            level: LoggerLevel::Warning,
            log_path: Some(run_file_in_vm(inst, LOG_NAME)),
            module: None,
            show_level: true,
            show_log_origin: false,
        })
        .await?;
        api.send(&Metrics { emit_id: false, metrics_path: run_file_in_vm(inst, METRICS_NAME), properties: HashMap::default() }).await?;
        self.adopt_fifos(inst)
    }

    /// Drains queued and future FIFO data until the vmm closes its end.
    pub(super) fn adopt_fifos(&self, inst: &Instance) -> Result<()> {
        // opening the read end doesn't wait for a writer
        let open = |name| pipe::OpenOptions::new().open_receiver(run_file(inst, name)).with_context(|| format!("open fifo {name}"));
        let (log, metrics) = (open(LOG_NAME)?, open(METRICS_NAME)?);
        tokio::spawn(pump_log(inst.name.clone(), BufReader::new(log)));
        tokio::spawn(pump_metrics(inst.name.clone(), Arc::clone(&self.metrics), BufReader::new(metrics)));
        Ok(())
    }

    /// Asks for one last metrics flush before the kill. A guest that never finished booting might refuse.
    pub(super) async fn flush_metrics(&self, inst: &Instance) {
        if !crate::Driver::alive(self, inst) {
            return;
        }
        let flush = InstanceActionInfo { action_type: InstanceActionInfoActionType::FlushMetrics };
        let result = tokio::time::timeout(FLUSH_TIMEOUT, Api::new(&inst.api_sock).send(&flush)).await;
        if let Err(err) = result.map_err(|_| anyhow!("timed out")).and_then(|r| r) {
            tracing::debug!(name = inst.name, error = format!("{err:#}"), "flush fc metrics");
        }
    }
}

async fn pump_log(session: String, mut fifo: impl AsyncBufRead + Unpin) {
    let mut line = Vec::new();
    loop {
        let truncated = match read_line_bounded(&mut fifo, &mut line, LOG_MAX_LINE).await {
            Ok(Line::Eof) => return,
            Ok(Line::Whole) => false,
            Ok(Line::Long) => true,
            Err(err) => {
                tracing::warn!(session, component = "firecracker", error = %err, "fc log drain ended");
                return;
            }
        };
        // one bad byte shouldn't stop the drain. Firecracker's writes are nonblocking, so once nobody's reading the
        // FIFO every line after that gets dropped
        let line = String::from_utf8_lossy(&line);
        let (level, msg) = parse_log_line(line.trim_end());
        match level {
            Level::ERROR => tracing::error!(session, component = "firecracker", truncated, "{msg}"),
            Level::WARN => tracing::warn!(session, component = "firecracker", truncated, "{msg}"),
            Level::INFO => tracing::info!(session, component = "firecracker", truncated, "{msg}"),
            _ => tracing::debug!(session, component = "firecracker", truncated, "{msg}"),
        }
    }
}

/// Splits a line like `2026-09-06T20:01:02.123 [s0-g1:fc_api:WARN] msg` into its level and message.
fn parse_log_line(line: &str) -> (Level, &str) {
    let Some((open, close)) = line.find('[').and_then(|open| Some((open, open + line[open..].find(']')?))) else {
        return (Level::INFO, line);
    };
    let msg = line[close + 1..].trim();
    let level = match line[open + 1..close].split(':').nth(2) {
        Some("ERROR") => Level::ERROR,
        Some("WARN") => Level::WARN,
        Some("DEBUG" | "TRACE") => Level::DEBUG,
        _ => Level::INFO,
    };
    (level, msg)
}

async fn pump_metrics(session: String, counters: Arc<Counters>, mut fifo: impl AsyncBufRead + Unpin) {
    let mut line = Vec::new();
    loop {
        match read_line_bounded(&mut fifo, &mut line, METRICS_MAX_LINE).await {
            Ok(Line::Eof) => return,
            Ok(Line::Long) => {
                tracing::warn!(session, component = "firecracker", "fc metrics line over {METRICS_MAX_LINE} bytes, skipped");
            }
            Ok(Line::Whole) => match parse_blob(&line) {
                Ok((blob, salvaged)) => {
                    if salvaged {
                        tracing::warn!(session, component = "firecracker", "fc metrics blob salvaged from a truncated write");
                    }
                    counters.record(&session, &blob);
                }
                Err(err) => tracing::warn!(session, component = "firecracker", error = format!("{err:#}"), "fc metrics blob unparsable"),
            },
            Err(err) => {
                tracing::warn!(session, component = "firecracker", error = %err, "fc metrics drain ended");
                return;
            }
        }
    }
}

#[derive(Debug, PartialEq)]
enum Line {
    Eof,
    Whole,
    /// Too long. The buffer has the first bytes and the rest got skipped.
    Long,
}

/// Reads one line into `buf`, keeping at most `max` bytes. The rest of a long line gets thrown away instead of
/// coming back as more lines, since a mid-line fragment has no header and parses as garbage.
async fn read_line_bounded(fifo: &mut (impl AsyncBufRead + Unpin), buf: &mut Vec<u8>, max: u64) -> std::io::Result<Line> {
    buf.clear();
    let n = (&mut *fifo).take(max).read_until(b'\n', buf).await?;
    if n == 0 {
        return Ok(Line::Eof);
    }
    if buf.last() != Some(&b'\n') && n as u64 == max {
        skip_line(fifo).await?;
        return Ok(Line::Long);
    }
    Ok(Line::Whole)
}

async fn skip_line(fifo: &mut (impl AsyncBufRead + Unpin)) -> std::io::Result<()> {
    loop {
        let buf = fifo.fill_buf().await?;
        if buf.is_empty() {
            return Ok(());
        }
        if let Some(i) = buf.iter().position(|&b| b == b'\n') {
            fifo.consume(i + 1);
            return Ok(());
        }
        let n = buf.len();
        fifo.consume(n);
    }
}

pub type Blob = serde_json::Map<String, serde_json::Value>;

/// A full FIFO can glue a truncated blob onto the next one, so a bad line falls back to its last complete blob. The
/// bool says whether that happened.
fn parse_blob(line: &[u8]) -> Result<(Blob, bool)> {
    let err = match serde_json::from_slice(line) {
        Ok(blob) => return Ok((blob, false)),
        Err(err) => err,
    };
    let start = line.windows(BLOB_START.len()).rposition(|w| w == BLOB_START.as_bytes()).filter(|&start| start > 0);
    let Some(start) = start else { return Err(anyhow::Error::new(err).context("parse fc metrics")) };
    Ok((serde_json::from_slice(&line[start..]).context("parse fc metrics")?, true))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;

    #[rstest]
    #[case::warn(
        "2026-09-06T20:01:02.123 [s0-g1:fc_api:WARN] Failed to write metrics: EAGAIN",
        Level::WARN,
        "Failed to write metrics: EAGAIN"
    )]
    #[case::error_from_a_spaced_thread(
        "2026-09-06T20:01:02.123 [s0-g1:fc_vcpu 0:ERROR] Shutting down VM after intercepting a bad syscall (57).",
        Level::ERROR,
        "Shutting down VM after intercepting a bad syscall (57)."
    )]
    #[case::brackets_in_the_message(
        "2026-09-06T20:01:02.123 [s0-g1:main:INFO] Guest-boot-time = 1s [x]",
        Level::INFO,
        "Guest-boot-time = 1s [x]"
    )]
    #[case::debug("2026-09-06T20:01:02.123 [s0-g1:main:DEBUG] noise", Level::DEBUG, "noise")]
    #[case::short_header("2026-09-06T20:01:02.123 [short] header", Level::INFO, "header")]
    #[case::no_header("garbage without a header", Level::INFO, "garbage without a header")]
    fn log_lines_carry_their_level(#[case] line: &str, #[case] level: Level, #[case] msg: &str) {
        assert_eq!(parse_log_line(line), (level, msg));
    }

    #[test]
    fn truncated_blobs_are_salvaged() {
        let clean = r#"{"utc_timestamp_ms":2,"seccomp":{"num_faults":0}}"#;
        let (blob, salvaged) = parse_blob(clean.as_bytes()).unwrap();
        assert!(!salvaged);
        assert!(blob.contains_key("seccomp"));

        // a write that hit a full pipe, glued to the next good one
        let (blob, salvaged) = parse_blob(format!(r#"{{"utc_timestamp_ms":1,"api_server":{{"proc{clean}"#).as_bytes()).unwrap();
        assert!(salvaged);
        assert_eq!(blob["seccomp"], json!({"num_faults": 0}));

        assert!(parse_blob(br#"{"utc_timestamp_ms":1,"api_server":{"proc"#).is_err());
    }

    #[tokio::test]
    async fn bounded_lines_survive_long_and_invalid_input() {
        let mut input = b"head".to_vec();
        input.extend(std::iter::repeat_n(b'x', 100));
        input.extend_from_slice(b"\nbad \xff byte\nfine\n");
        let mut fifo = BufReader::new(input.as_slice());
        let mut line = Vec::new();

        assert_eq!(read_line_bounded(&mut fifo, &mut line, 16).await.unwrap(), Line::Long);
        assert_eq!(line, b"headxxxxxxxxxxxx", "keeps the start, where the level header is");
        assert_eq!(read_line_bounded(&mut fifo, &mut line, 16).await.unwrap(), Line::Whole);
        assert_eq!(String::from_utf8_lossy(&line), "bad \u{fffd} byte\n");
        assert_eq!(read_line_bounded(&mut fifo, &mut line, 16).await.unwrap(), Line::Whole);
        assert_eq!(line, b"fine\n");
        assert_eq!(read_line_bounded(&mut fifo, &mut line, 16).await.unwrap(), Line::Eof);
    }
}
