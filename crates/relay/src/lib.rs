//! Relays each guest container's logs from birdfeeder-init's `LOGS` stream to OTel. Each stream resumes from its own
//! cursor, so a restarted roost doesn't drop or repeat anything it already exported.

use std::{
    collections::{HashMap, HashSet},
    fmt, io,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use opentelemetry::{KeyValue, logs::Logger};
use sha2::{Digest as _, Sha256};
use tokio::{task::JoinHandle, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;

mod cursor;
mod stream;

const RECONCILE_EVERY: Duration = Duration::from_secs(1);

/// One container's log stream in one guest generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host_id: String,
    pub session_id: String,
    pub template_id: String,
    pub container: String,
    /// The guest's hybrid vsock.
    pub socket: PathBuf,
    pub generation: u64,
}

/// A stream's identity. It names the cursor file and prefixes record ids, and shows as lowercase hex.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct StreamKey([u8; 32]);

impl fmt::Display for StreamKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for StreamKey {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut key = [0; 32];
        hex::decode_to_slice(s, &mut key)?;
        Ok(Self(key))
    }
}

impl Target {
    /// Hashes the generation in, so a replaced guest's records are fenced off from its predecessor's.
    fn key(&self) -> StreamKey {
        let Self { host_id, session_id, generation, container, .. } = self;
        StreamKey(Sha256::digest(format!("{host_id}\0{session_id}\0{generation}\0{container}")).into())
    }

    fn attributes(&self) -> Vec<KeyValue> {
        let key = self.key().to_string();
        vec![
            KeyValue::new("service.instance.id", key.clone()),
            KeyValue::new("container.id", key),
            KeyValue::new("container.name", self.container.clone()),
            KeyValue::new("birdfeeder.host.id", self.host_id.clone()),
            KeyValue::new("birdfeeder.session.id", self.session_id.clone()),
            KeyValue::new("birdfeeder.session.generation", self.generation.to_string()),
            KeyValue::new("birdfeeder.template.id", self.template_id.clone()),
        ]
    }
}

/// The running relay. Call [`Relay::stop`] before shutting down the loggers' provider, so its last records and cursors
/// make it out.
#[must_use = "stop the relay to save its cursors"]
pub struct Relay {
    cancel: CancellationToken,
    supervisor: JoinHandle<()>,
}

/// Relays every target `source` lists, checking once a second. A stream starts when its target shows up and stops when
/// it goes away. `loggers` builds each stream's logger from the target's resource attributes. Callers have to bound the
/// number of targets, since each one is a connection and a task.
pub async fn start<L: Logger + Send + Sync + 'static>(
    dir: PathBuf,
    source: impl Fn() -> Vec<Target> + Send + Sync + 'static,
    loggers: impl Fn(Vec<KeyValue>) -> L + Send + Sync + 'static,
) -> io::Result<Relay> {
    cursor::create_dir(&dir).await?;
    let cancel = CancellationToken::new();
    let supervisor = Supervisor { dir, workers: HashMap::new() };
    let supervisor = tokio::spawn(supervisor.run(source, loggers, cancel.clone()));
    Ok(Relay { cancel, supervisor })
}

impl Relay {
    /// Stops every stream and waits for their cursors to save.
    pub async fn stop(self) {
        self.cancel.cancel();
        if let Err(err) = self.supervisor.await {
            tracing::warn!(error = %err, "guest log relay");
        }
    }
}

struct Worker {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

/// Cancels every worker before waiting on any, so they all wind down together.
async fn stop(workers: impl IntoIterator<Item = Worker>) {
    let tasks: Vec<_> = workers
        .into_iter()
        .map(|w| {
            w.cancel.cancel();
            w.task
        })
        .collect();
    for task in tasks {
        if let Err(err) = task.await {
            tracing::warn!(error = %err, "guest log stream");
        }
    }
}

struct Supervisor {
    dir: PathBuf,
    workers: HashMap<StreamKey, Worker>,
}

impl Supervisor {
    async fn run<L: Logger + Send + Sync + 'static>(
        mut self,
        source: impl Fn() -> Vec<Target> + Sync,
        loggers: impl Fn(Vec<KeyValue>) -> L + Sync,
        cancel: CancellationToken,
    ) {
        let mut tick = tokio::time::interval(RECONCILE_EVERY);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // the first tick fires right away, and resume stands in for it.
        tick.tick().await;
        self.resume(source(), &loggers, &cancel).await;
        while cancel.run_until_cancelled(tick.tick()).await.is_some() {
            self.reconcile(source(), &loggers, &cancel).await;
        }
        stop(self.workers.into_values()).await;
    }

    /// Starts the first streams. Before that it removes cursors of streams that ended while the relay was down, since
    /// there's no worker left to retire them.
    async fn resume<L: Logger + Send + Sync + 'static>(
        &mut self,
        current: Vec<Target>,
        loggers: impl Fn(Vec<KeyValue>) -> L + Sync,
        cancel: &CancellationToken,
    ) {
        let live: HashSet<StreamKey> = current.iter().map(Target::key).collect();
        cursor::prune(&self.dir, |key| live.contains(key)).await;
        self.reconcile(current, loggers, cancel).await;
    }

    async fn reconcile<L: Logger + Send + Sync + 'static>(
        &mut self,
        current: Vec<Target>,
        loggers: impl Fn(Vec<KeyValue>) -> L + Sync,
        cancel: &CancellationToken,
    ) {
        let targets: HashMap<StreamKey, Target> = current.into_iter().map(|t| (t.key(), t)).collect();
        let (live, retired): (HashMap<_, _>, HashMap<_, _>) =
            std::mem::take(&mut self.workers).into_iter().partition(|(key, _)| targets.contains_key(key));
        self.workers = live;
        let retired_keys: Vec<StreamKey> = retired.keys().copied().collect();
        // a retired stream's last checkpoint has to land before its cursor goes.
        stop(retired.into_values()).await;
        for key in &retired_keys {
            cursor::remove(&self.dir, key).await;
        }
        for (key, target) in targets {
            if self.workers.contains_key(&key) {
                continue;
            }
            let cancel = cancel.child_token();
            let logger = loggers(target.attributes());
            let path = self.dir.join(format!("{key}.cursor"));
            let task = tokio::spawn(stream::follow(target, key, path, logger, cancel.clone()));
            self.workers.insert(key, Worker { cancel, task });
        }
    }
}

#[cfg(test)]
mod tests;
