//! The dispatcher: one gRPC endpoint for the session API in front of a bunch of roost hosts. It polls each host's
//! status, sends claims to whichever host has the most pooled guests for the template, and routes session RPCs to
//! the host that owns the session. No durable state.

use std::{net::SocketAddr, num::NonZeroU32, time::Duration};

use anyhow::{Context as _, bail};
use clap::Parser;
use roost_api::v1::roost_service_server::RoostServiceServer;
use tokio::{
    net::TcpListener,
    task::JoinSet,
    time::{Instant, Interval, MissedTickBehavior},
};
use tonic::service::Routes;

use registry::{Host, Registry};
use routing::Dispatcher;

mod registry;
mod routing;
#[cfg(test)]
mod tests;

const MAX_REQUEST_BYTES: usize = 1 << 20;
const ROOST_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Routes birdfeeder's session API across roost hosts.
#[derive(Parser, Debug)]
#[command(version)]
pub struct Config {
    /// roost hosts to route across, as comma-separated host:port
    #[arg(long, env = "BIRDFEEDER_HOSTS", value_delimiter = ',', required = true)]
    hosts: Vec<Host>,
    #[arg(long, env = "BIRDFEEDER_DISPATCHER_LISTEN_ADDR", default_value = "127.0.0.1:8080")]
    listen_addr: SocketAddr,
    /// how often to poll each host's status, which is also how long one poll may take
    #[arg(long, env = "BIRDFEEDER_POLL_INTERVAL", default_value = "10s", value_parser = positive_duration)]
    poll_interval: Duration,
    /// how often to rebuild the session index from every host's sessions
    #[arg(long, env = "BIRDFEEDER_SWEEP_INTERVAL", default_value = "60s", value_parser = positive_duration)]
    sweep_interval: Duration,
    /// how long one claim attempt on a host may take
    #[arg(long, env = "BIRDFEEDER_CLAIM_TIMEOUT", default_value = "60s", value_parser = positive_duration)]
    claim_timeout: Duration,
    /// failed polls in a row before a host is suspect and gets no traffic
    #[arg(long, env = "BIRDFEEDER_SUSPECT_AFTER", default_value = "3")]
    suspect_after: NonZeroU32,
}

fn positive_duration(s: &str) -> anyhow::Result<Duration> {
    let duration = humantime::parse_duration(s)?;
    if duration.is_zero() {
        bail!("must be longer than zero");
    }
    Ok(duration)
}

/// Serves until SIGINT/SIGTERM, then gives in-flight calls up to ten seconds to finish.
pub async fn run(config: Config) -> anyhow::Result<()> {
    let shutdown = service::rpc::shutdown_signal().context("install signal handlers")?;
    let meter = opentelemetry::global::meter("dispatcher");
    let registry = Registry::new(config.hosts, config.poll_interval, config.suspect_after.get(), &meter)?;
    let dispatcher = Dispatcher::new(registry.clone(), config.claim_timeout, ROOST_REQUEST_TIMEOUT, &meter);

    // dropping the set on return stops both loops.
    let mut background = JoinSet::new();
    let mut polls = ticker(config.poll_interval, Instant::now());
    let polled = registry.clone();
    background.spawn(async move {
        loop {
            polls.tick().await;
            polled.poll().await;
        }
    });
    let mut sweeps = ticker(config.sweep_interval, Instant::now() + config.sweep_interval);
    let swept = dispatcher.clone();
    background.spawn(async move {
        loop {
            sweeps.tick().await;
            swept.sweep().await;
        }
    });

    let listener = TcpListener::bind(config.listen_addr).await.with_context(|| format!("listen on {}", config.listen_addr))?;
    tracing::info!(addr = %config.listen_addr, "dispatcher listening");
    let routes = Routes::new(RoostServiceServer::from_arc(dispatcher).max_decoding_message_size(MAX_REQUEST_BYTES));
    service::rpc::serve(listener, routes, meter, shutdown, SHUTDOWN_TIMEOUT).await
}

/// Ticks at `start` and then every `period`. If a tick's work runs long, the next one waits instead of piling up.
fn ticker(period: Duration, start: Instant) -> Interval {
    let mut ticks = tokio::time::interval_at(start, period);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticks
}
