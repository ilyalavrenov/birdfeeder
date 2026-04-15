//! Serves a restored Firecracker guest's memory over the userfaultfd Firecracker hands us.
//! roost starts one per restored VM, next to its jailer, running as the VM's uid.

// the formats and fetcher build anywhere so their tests run on a Mac too. only Linux serves.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod extents;
mod fetch;
mod layout;
mod manifest;
mod working_set;

#[cfg(target_os = "linux")]
mod handler;
#[cfg(target_os = "linux")]
mod handshake;
#[cfg(target_os = "linux")]
mod mem_file;
#[cfg(target_os = "linux")]
mod remote;
#[cfg(target_os = "linux")]
mod stats;
#[cfg(target_os = "linux")]
mod sys;
#[cfg(target_os = "linux")]
mod uffd;

use std::process::ExitCode;

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("uffd-handler needs linux");
    ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    use clap::Parser;

    let options = Args::parse().into_options();
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_target(false)
        .with_current_span(false)
        .with_span_list(false)
        .with_writer(std::io::stderr)
        .init();
    match handler::serve(&options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(err = format!("{err:#}"), "uffd handler failed");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(clap::Parser)]
#[command(about)]
struct Args {
    /// Unix socket Firecracker connects to (`mem_backend.backend_path`).
    #[arg(long)]
    socket: std::path::PathBuf,
    /// Snapshot memory file.
    #[arg(long, required_unless_present = "mem_url", conflicts_with = "mem_url")]
    mem: Option<std::path::PathBuf>,
    /// URL serving the memory file's byte ranges, instead of --mem.
    #[arg(long, requires = "manifest")]
    mem_url: Option<String>,
    /// The remote memory file's size and data extents.
    #[arg(long, requires = "mem_url")]
    manifest: Option<std::path::PathBuf>,
    /// Bytes per remote fetch, rounded up to whole guest pages.
    #[arg(long, default_value_t = remote::DEFAULT_CHUNK)]
    chunk: std::num::NonZeroU64,
    /// Concurrent remote fetches.
    #[arg(long, default_value_t = remote::DEFAULT_FETCHERS)]
    fetchers: std::num::NonZeroUsize,
    /// Populate every page right after the handshake, then exit.
    #[arg(long, conflicts_with_all = ["prefetch", "record"])]
    fault_all: bool,
    /// Working set to populate right after the handshake.
    #[arg(long)]
    prefetch: Option<std::path::PathBuf>,
    /// With --mem-url, a URL serving the working set's pages packed in its order.
    #[arg(long, requires = "mem_url", requires = "prefetch")]
    prefetch_url: Option<String>,
    /// On SIGUSR1, write the pages faulted so far here and stop recording.
    #[arg(long, conflicts_with = "mem_url")]
    record: Option<std::path::PathBuf>,
    /// With --record, also write those pages' contents here, packed in the same order.
    #[arg(long, requires = "record")]
    record_pack: Option<std::path::PathBuf>,
    /// Log cumulative fault counters this often; 0s disables.
    #[arg(long, default_value = "5s", value_parser = humantime::parse_duration)]
    stats_every: std::time::Duration,
}

#[cfg(target_os = "linux")]
impl Args {
    fn into_options(self) -> handler::Options {
        let source = match (self.mem, self.mem_url, self.manifest) {
            (Some(path), _, _) => handler::Source::Local(path),
            (None, Some(url), Some(manifest)) => {
                handler::Source::Remote { url, manifest, pack_url: self.prefetch_url, chunk_size: self.chunk, fetchers: self.fetchers }
            }
            _ => unreachable!("clap requires --mem, or --mem-url with --manifest"),
        };
        let mode = if self.fault_all {
            handler::Mode::FaultAll
        } else {
            handler::Mode::Serve {
                prefetch: self.prefetch,
                record: self.record.map(|working_set| handler::Record { working_set, pack: self.record_pack }),
            }
        };
        handler::Options { socket: self.socket, source, mode, stats_every: self.stats_every }
    }
}
