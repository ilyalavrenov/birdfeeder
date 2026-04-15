//! The guest's init. Boots whatever workload roost put in MMDS and serves its telemetry over
//! vsock. busybox init runs it once, and the guest reboots when it returns.

// the MMDS client, bundle and stats code build anywhere, so their tests run on a Mac too.
// only Linux actually boots a guest.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod bundle;
mod mmds;
mod stats;

#[cfg(target_os = "linux")]
mod logs;
#[cfg(target_os = "linux")]
mod runtime;
#[cfg(target_os = "linux")]
mod server;
#[cfg(target_os = "linux")]
mod stream;
#[cfg(target_os = "linux")]
mod sys;

use std::process::ExitCode;

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("birdfeeder-init needs linux");
    ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_target(false)
        .with_current_span(false)
        .with_span_list(false)
        .with_writer(std::io::stderr)
        .init();
    let Err(err) = runtime::run();
    tracing::error!(err = format!("{err:#}"), "guest stopped");
    // the guest goes down whenever init returns, so any return is a failure.
    ExitCode::FAILURE
}
