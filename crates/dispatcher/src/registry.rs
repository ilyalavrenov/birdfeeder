//! The roost hosts the dispatcher routes across, and how healthy each looked at the last poll. None of it's
//! durable. A restarted dispatcher just relearns it from the hosts.

use std::{
    fmt,
    str::FromStr,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use anyhow::{Context as _, bail};
use futures_util::future::join_all;
use http::uri::Authority;
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Meter, ObservableGauge},
};
use roost_api::v1::{HostStatusRequest, HostStatusResponse, roost_service_client::RoostServiceClient};
use service::rpc::{Trace, TraceLayer, code_name};
use tonic::{
    Request,
    transport::{Channel, Endpoint},
};
use tower_layer::Layer as _;

pub type Client = RoostServiceClient<Trace<Channel>>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
// every claim miss and listing fans out to all hosts.
const MAX_HOSTS: usize = 128;

/// A host's identity: its endpoint as listed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostId(Arc<str>);

impl fmt::Display for HostId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A roost to route to, at a `host:port` with a non-zero port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    pub id: HostId,
    pub endpoint: Authority,
}

impl Host {
    #[must_use]
    pub fn new(id: &str, endpoint: Authority) -> Self {
        Self { id: HostId(id.into()), endpoint }
    }
}

impl FromStr for Host {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        let endpoint: Authority = s.parse().with_context(|| format!("{s:?} is not host:port"))?;
        // an authority may also carry userinfo or leave out the host or port, none of which name a roost.
        if endpoint.host().is_empty() || s.contains('@') || endpoint.port_u16().is_none_or(|p| p == 0) {
            bail!("{s:?} is not host:port");
        }
        Ok(Self::new(s, endpoint))
    }
}

enum State {
    /// hasn't had a good poll yet, but hasn't failed enough to be suspect either.
    Launching,
    /// with what its last poll reported.
    Ready(Arc<HostStatusResponse>),
    /// failed its last `suspect_after` polls.
    Suspect,
}

impl State {
    fn name(&self) -> &'static str {
        match self {
            Self::Launching => "launching",
            Self::Ready(_) => "ready",
            Self::Suspect => "suspect",
        }
    }
}

/// A host whose last poll succeeded, with what it reported.
#[derive(Clone)]
pub struct ReadyHost {
    pub id: HostId,
    pub status: Arc<HostStatusResponse>,
    pub client: Client,
    /// its latest poll failed, though not yet `suspect_after` in a row.
    pub failing: bool,
}

struct Health {
    state: State,
    failures: u32,
}

struct Entry {
    host: Host,
    client: Client,
    health: Mutex<Health>,
}

pub struct Registry {
    // sorted by id, so every listing comes out in host order.
    entries: Vec<Entry>,
    poll_timeout: Duration,
    suspect_after: u32,
    transitions: Counter<u64>,
    _hosts: ObservableGauge<i64>,
}

impl Registry {
    /// Connects to each host lazily. A host isn't ready until a [`Registry::poll`] reaches it. Each poll waits up to
    /// `poll_timeout` per host.
    pub fn new(mut hosts: Vec<Host>, poll_timeout: Duration, suspect_after: u32, meter: &Meter) -> anyhow::Result<Arc<Self>> {
        if hosts.is_empty() || hosts.len() > MAX_HOSTS {
            bail!("{} hosts listed; the dispatcher routes across 1 to {MAX_HOSTS}", hosts.len());
        }
        hosts.sort_by(|a, b| a.id.cmp(&b.id));
        if let Some(pair) = hosts.windows(2).find(|pair| pair[0].id == pair[1].id) {
            bail!("host {} is listed twice", pair[0].id);
        }
        let entries = hosts
            .into_iter()
            .map(|host| {
                let channel = Endpoint::from_shared(format!("http://{}", host.endpoint))
                    .with_context(|| format!("host {}", host.id))?
                    .connect_timeout(CONNECT_TIMEOUT)
                    .connect_lazy();
                let client = RoostServiceClient::new(TraceLayer::client(meter, &host.endpoint).layer(channel));
                let health = Mutex::new(Health { state: State::Launching, failures: 0 });
                Ok(Entry { host, client, health })
            })
            .collect::<anyhow::Result<_>>()?;
        let transitions = meter.u64_counter("birdfeeder.dispatcher.host.transitions").build();
        Ok(Arc::new_cyclic(|registry: &Weak<Self>| {
            let registry = registry.clone();
            let hosts = meter
                .i64_observable_gauge("birdfeeder.dispatcher.hosts")
                .with_description("discovered roost hosts by health state")
                .with_callback(move |observer| {
                    let Some(registry) = registry.upgrade() else { return };
                    for entry in &registry.entries {
                        let state = entry.health.lock().unwrap().state.name();
                        observer.observe(1, &[KeyValue::new("host.id", entry.host.id.to_string()), state_attribute(state)]);
                    }
                })
                .build();
            Self { entries, poll_timeout, suspect_after, transitions, _hosts: hosts }
        }))
    }

    /// Asks every host for its status at once and records what each answered.
    pub async fn poll(&self) {
        join_all(self.entries.iter().map(|entry| async move {
            let mut request = Request::new(HostStatusRequest {});
            request.set_timeout(self.poll_timeout);
            let polled = entry.client.clone().host_status(request).await;
            let mut health = entry.health.lock().unwrap();
            match polled {
                Ok(status) => {
                    health.failures = 0;
                    self.transition(entry, &mut health, State::Ready(Arc::new(status.into_inner())));
                }
                Err(status) => {
                    health.failures += 1;
                    let (host, failures) = (&entry.host.id, health.failures);
                    let (code, message) = (code_name(status.code()), status.message());
                    if failures < self.suspect_after {
                        tracing::debug!(%host, code, message, failures, "host poll failed");
                    } else {
                        if !matches!(health.state, State::Suspect) {
                            tracing::warn!(%host, code, message, failures, "host poll failed; marking it suspect");
                        }
                        self.transition(entry, &mut health, State::Suspect);
                    }
                }
            }
        }))
        .await;
    }

    fn transition(&self, entry: &Entry, health: &mut Health, to: State) {
        let (from, name) = (health.state.name(), to.name());
        health.state = to;
        if from != name {
            tracing::info!(host = %entry.host.id, from, to = name, "host state changed");
            self.transitions.add(1, &[KeyValue::new("host.id", entry.host.id.to_string()), state_attribute(name)]);
        }
    }

    /// The ready hosts in id order.
    #[must_use]
    pub fn ready_hosts(&self) -> Vec<ReadyHost> {
        self.all_hosts_ready().unwrap_or_else(|partial| partial.ready)
    }

    /// Every host in id order, or [`NotAllReady`] if any isn't ready.
    pub fn all_hosts_ready(&self) -> Result<Vec<ReadyHost>, NotAllReady> {
        let mut ready = Vec::with_capacity(self.entries.len());
        let mut unavailable = Vec::new();
        for entry in &self.entries {
            let health = entry.health.lock().unwrap();
            if let State::Ready(status) = &health.state {
                let failing = health.failures > 0;
                ready.push(ReadyHost { id: entry.host.id.clone(), status: status.clone(), client: entry.client.clone(), failing });
            } else {
                unavailable.push(entry.host.id.clone());
            }
        }
        if unavailable.is_empty() { Ok(ready) } else { Err(NotAllReady { ready, unavailable }) }
    }
}

/// Some hosts weren't ready, so an answer from just the rest could miss whatever those hold.
pub struct NotAllReady {
    /// the hosts that were, in id order, all taken in the same pass as `unavailable`.
    pub ready: Vec<ReadyHost>,
    pub unavailable: Vec<HostId>,
}

impl From<NotAllReady> for tonic::Status {
    fn from(err: NotAllReady) -> Self {
        let ids: Vec<String> = err.unavailable.iter().map(ToString::to_string).collect();
        Self::unavailable(format!("hosts unavailable: {}", ids.join(", ")))
    }
}

fn state_attribute(state: &'static str) -> KeyValue {
    KeyValue::new("birdfeeder.host.state", state)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::ipv4("10.1.0.1:7443", "10.1.0.1:7443")]
    #[case::padded(" roost-a:7443 ", "roost-a:7443")]
    #[case::ipv6("[::1]:7443", "[::1]:7443")]
    fn hosts_parse_as_host_port(#[case] listed: &str, #[case] endpoint: &str) {
        assert_eq!(listed.parse::<Host>().unwrap(), Host::new(endpoint, endpoint.parse().unwrap()));
    }

    #[rstest]
    #[case::no_port("roost-a")]
    #[case::no_host(":7443")]
    #[case::port_zero("roost-a:0")]
    #[case::port_too_big("roost-a:65536")]
    #[case::named_port("roost-a:http")]
    #[case::userinfo("admin@roost-a:7443")]
    #[case::empty("")]
    fn hosts_must_be_host_port(#[case] bad: &str) {
        assert!(bad.parse::<Host>().is_err());
    }
}
