//! roost: the per-host agent that keeps warm pools of Firecracker guests and hands them out as sessions over gRPC. If
//! roost restarts, the new one picks up the guests the old one left running.

// the manager builds everywhere so its tests run on a Mac, but only Linux actually serves.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, Result, ensure};
use clap::Parser;
use service::telemetry::GuestLogs;

pub mod config;
mod host;
mod manager;
mod metrics;
mod server;
mod snapshots;
mod state;
#[cfg(test)]
mod testing;

pub use config::Config;
pub use host::Host;
pub use manager::Manager;

/// Keeps warm pools of Firecracker guests on this host and serves them as sessions.
#[derive(Parser, Debug)]
#[command(version)]
pub struct Args {
    /// roost's JSON config
    #[arg(long, default_value = "/etc/birdfeeder/roost.json")]
    pub config: PathBuf,
}

/// Serves until SIGINT or SIGTERM, and leaves the guests running for the next roost to adopt. With `guest_logs` set, it
/// relays every guest container's logs there.
pub async fn run(args: Args, guest_logs: Option<GuestLogs>) -> Result<()> {
    let shutdown = service::rpc::shutdown_signal().context("install signal handlers")?;
    let cfg = Config::load(&args.config)?;
    serve(cfg, guest_logs, shutdown).await
}

#[cfg(not(target_os = "linux"))]
#[expect(clippy::unused_async, reason = "the Linux serve's signature")]
async fn serve(_: Config, _: Option<GuestLogs>, _: impl Future<Output = ()>) -> Result<()> {
    anyhow::bail!("roost runs guests on Linux only")
}

#[cfg(target_os = "linux")]
async fn serve(cfg: Config, guest_logs: Option<GuestLogs>, shutdown: impl Future<Output = ()>) -> Result<()> {
    use std::time::Duration;

    use roost_api::v1::roost_service_server::RoostServiceServer;
    use tonic::service::Routes;

    const MAX_REQUEST_BYTES: usize = 1 << 20;
    const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

    let meter = opentelemetry::global::meter("roost");
    let driver = vmm::firecracker::Driver::new(cfg.driver(), &meter);
    let listen = cfg.listen_addr;
    let manager = Manager::start(cfg, driver, host::Kernel::new()?, &meter).await?;
    let relay = match guest_logs {
        Some(logs) => Some(start_relay(&manager, logs).await?),
        None => None,
    };
    let listener = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("listen on {listen}"))?;
    tracing::info!(addr = %listen, "roost listening");
    let routes = Routes::new(RoostServiceServer::new(server::Api(Arc::clone(&manager))).max_decoding_message_size(MAX_REQUEST_BYTES));
    let served = service::rpc::serve(listener, routes, meter, shutdown, SHUTDOWN_TIMEOUT).await;
    // stop the relay here so its last records and cursors land before main returns and telemetry shuts down.
    if let Some(relay) = relay {
        relay.stop().await;
    }
    // a golden boot's snapshot upload doesn't stop for shutdown. If it gets abandoned, the next roost just rebuilds it.
    if tokio::time::timeout(SHUTDOWN_TIMEOUT, manager.shutdown()).await.is_err() {
        tracing::warn!("manager tasks still running at shutdown");
    }
    served
}

/// Relays every pooled and claimed guest's container logs, with a stream per container.
async fn start_relay<D: vmm::Driver + 'static, H: Host>(manager: &Arc<Manager<D, H>>, logs: GuestLogs) -> Result<relay::Relay> {
    let cfg = manager.config();
    // reserve enough streams for any mix we'd admit, including adopted sessions whose template isn't configured
    // anymore.
    let required = cfg.max_sessions * manager.max_containers();
    ensure!(required <= cfg.guest_log_max_streams, "guest_log_max_streams must be at least {required} for host capacity");
    let targets = Arc::clone(manager);
    let relay = relay::start(cfg.state_dir.join("log-cursors"), move || targets.log_targets(), move |attrs| logs.logger(attrs)).await;
    relay.context("start guest log relay")
}
