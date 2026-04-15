//! The session API spread across hosts. Claims go to the host with the most pooled guests for the template, and
//! session RPCs go to whichever host owns the session. A claim with an idempotency key asks every host about the
//! key first, so a retry lands where the first attempt did.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use futures_util::future::join_all;
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Meter},
};
use roost_api::{
    v1::{
        ClaimSessionRequest, ClaimSessionResponse, DeleteSessionRequest, DeleteSessionResponse, GetSessionRequest, GetSessionResponse,
        HostStatusRequest, HostStatusResponse, ListSessionsRequest, ListSessionsResponse, PoolFill, Session, SetSessionExpiryRequest,
        SetSessionExpiryResponse, roost_service_server::RoostService,
    },
    validate_claim, validate_expiry, validate_get, validate_list,
};
use tonic::{Code, ConnectError, Request, Response, Status, TimeoutExpired};
use tracing::Instrument as _;

use crate::registry::{Client, HostId, ReadyHost, Registry};

/// Routes session RPCs using an index from session name to host. The index is just a cache. Claims and sweeps fill
/// it, and on a miss we ask every ready host.
pub struct Dispatcher {
    registry: Arc<Registry>,
    claim_timeout: Duration,
    request_timeout: Duration,
    claims: Counter<u64>,
    index: Mutex<HashMap<String, HostId>>,
    keys: KeyLocks,
    /// Lets a keyed claim outlive its call, which only borrows the dispatcher.
    me: Weak<Self>,
}

impl Dispatcher {
    /// Each claim attempt on a host waits up to `claim_timeout`; every other call to a host waits up to
    /// `request_timeout`.
    #[must_use]
    pub fn new(registry: Arc<Registry>, claim_timeout: Duration, request_timeout: Duration, meter: &Meter) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            registry,
            claim_timeout,
            request_timeout,
            claims: meter.u64_counter("birdfeeder.dispatcher.claims").build(),
            index: Mutex::default(),
            keys: KeyLocks::default(),
            me: me.clone(),
        })
    }

    /// Rebuilds the index from every ready host's sessions. A host that fails to list gets skipped. Its sessions
    /// turn up again on a later miss.
    pub async fn sweep(&self) {
        let ready = self.registry.ready_hosts();
        let listed = join_all(ready.into_iter().map(|host| async move {
            match ask(&host, "list sessions", self.request_timeout, ListSessionsRequest::default(), async |c, r| c.list_sessions(r).await)
                .await
            {
                Ok(list) => list.sessions.into_iter().map(|s| (s.name, host.id.clone())).collect(),
                Err(err) => {
                    tracing::warn!(host = %host.id, error = %err.message(), "sweep list failed");
                    Vec::new()
                }
            }
        }))
        .await;
        *self.index.lock().unwrap() = listed.into_iter().flatten().collect();
    }

    fn remember(&self, name: &str, host: &HostId) {
        self.index.lock().unwrap().insert(name.to_owned(), host.clone());
    }

    async fn claim(&self, msg: ClaimSessionRequest) -> (ClaimOutcome, Result<ClaimSessionResponse, Status>) {
        if let Err(err) = validate_claim(&msg) {
            return (ClaimOutcome::Invalid, Err(err.into()));
        }
        if msg.idempotency_key.is_empty() {
            return self.place(msg).await;
        }
        let me = self.me.upgrade().expect("dispatcher is alive while serving");
        // detached, so the key stays locked until this attempt is done even if its caller hangs up and retries.
        let attempt = tokio::spawn(
            async move {
                let _turn = me.keys.lock(&msg.idempotency_key).await;
                me.claim_keyed(msg).await
            }
            .instrument(tracing::Span::current()),
        );
        attempt.await.unwrap_or_else(|err| (ClaimOutcome::Canceled, Err(Status::internal(err.to_string()))))
    }

    /// Repeats a keyed claim on the host that has its key, or else places it like any claim.
    async fn claim_keyed(&self, msg: ClaimSessionRequest) -> (ClaimOutcome, Result<ClaimSessionResponse, Status>) {
        let found = match self.find_key(&msg.idempotency_key).await {
            Ok(found) => found,
            Err(status) => return (ClaimOutcome::LookupFailed, Err(status)),
        };
        let Some((host, _)) = found else { return self.place(msg).await };
        let resp = ask(&host, "claim", self.claim_timeout, msg, async |c, r| c.claim_session(r).await).await;
        let outcome = match &resp {
            Ok(resp) => {
                if let Some(session) = &resp.session {
                    self.remember(&session.name, &host.id);
                }
                ClaimOutcome::Replayed
            }
            Err(status) if status.code() == Code::FailedPrecondition => ClaimOutcome::KeyConflict,
            Err(_) => ClaimOutcome::Ambiguous,
        };
        (outcome, resp)
    }

    /// The host holding `key` and the session it answers for it. Every host must answer: one that didn't may hold it.
    async fn find_key(&self, key: &str) -> Result<Option<(ReadyHost, Session)>, Status> {
        let ready = self.registry.all_hosts_ready()?;
        let answers = join_all(ready.iter().map(|host| async move {
            let msg = GetSessionRequest { idempotency_key: key.to_owned(), ..GetSessionRequest::default() };
            ask(host, "look up idempotency key", self.request_timeout, msg, async |c, r| c.get_session(r).await).await
        }))
        .await;
        let mut found = None;
        for (host, answer) in ready.into_iter().zip(answers) {
            match answer {
                Ok(resp) => found = found.or(resp.session.map(|s| (host, s))),
                Err(status) if status.code() == Code::NotFound => {}
                Err(status) => return Err(status),
            }
        }
        Ok(found)
    }

    /// Claims on the host with the most pooled guests, failing over only where a failure proves nothing was claimed.
    async fn place(&self, msg: ClaimSessionRequest) -> (ClaimOutcome, Result<ClaimSessionResponse, Status>) {
        let ready = self.registry.ready_hosts();
        if conflicting_definitions(&ready, &msg.template_id) {
            let status = Status::failed_precondition(format!("conflicting definitions for template {:?}", msg.template_id));
            return (ClaimOutcome::Conflict, Err(status));
        }
        let candidates = candidates(ready, &msg.template_id);
        if candidates.is_empty() {
            let status = Status::resource_exhausted(format!("no ready host with template {:?}", msg.template_id));
            return (ClaimOutcome::NoCandidates, Err(status));
        }
        let mut refusals = Vec::new();
        for (attempt, host) in candidates.iter().enumerate() {
            match try_ask(host, "claim", self.claim_timeout, msg.clone(), async |c, r| c.claim_session(r).await).await {
                Ok(resp) => {
                    if let Some(session) = &resp.session {
                        self.remember(&session.name, &host.id);
                    }
                    return (if attempt == 0 { ClaimOutcome::Ok } else { ClaimOutcome::FailedOver }, Ok(resp));
                }
                // only exhaustion, or a request that never went out, proves the host didn't claim anything. anything
                // else might have claimed a session.
                Err(failed) if failed.unsent || failed.status.code() == Code::ResourceExhausted => {
                    refusals.push(format!("{}: {}", host.id, failed.status.message()));
                }
                Err(failed) => return (ClaimOutcome::Ambiguous, Err(failed.status)),
            }
        }
        let status =
            Status::resource_exhausted(format!("claim failed on all {} candidate hosts: {}", candidates.len(), refusals.join("; ")));
        (ClaimOutcome::AllFailed, Err(status))
    }

    /// Finds the ready host that owns `name`: from the index, or else by asking every ready host.
    async fn locate(&self, name: &str) -> Result<ReadyHost, Status> {
        let (ready, complete) = match self.registry.all_hosts_ready() {
            Ok(all) => (all, true),
            Err(partial) => (partial.ready, false),
        };
        let indexed = self.index.lock().unwrap().get(name).cloned();
        if let Some(id) = &indexed
            && let Some(host) = ready.iter().find(|h| &h.id == id)
        {
            return Ok(host.clone());
        }
        let answers = join_all(ready.iter().map(|host| async move {
            let msg = GetSessionRequest { name: name.to_owned(), ..GetSessionRequest::default() };
            ask(host, "get session", self.request_timeout, msg, async |c, r| c.get_session(r).await).await
        }))
        .await;
        let mut failed = false;
        for (host, answer) in ready.iter().zip(answers) {
            match answer {
                Ok(_) => {
                    self.remember(name, &host.id);
                    return Ok(host.clone());
                }
                Err(status) if status.code() == Code::NotFound => {}
                Err(_) => failed = true,
            }
        }
        // a session can only be called missing when every host that could own it said so.
        if indexed.is_some() || !complete || failed {
            return Err(Status::unavailable("session owner is unavailable"));
        }
        Err(Status::not_found(format!("session {name:?} not found on any ready host")))
    }
}

#[tonic::async_trait]
impl RoostService for Dispatcher {
    async fn claim_session(&self, req: Request<ClaimSessionRequest>) -> Result<Response<ClaimSessionResponse>, Status> {
        let mut counted = Outcome::new(&self.claims);
        let (outcome, result) = self.claim(req.into_inner()).await;
        counted.set(outcome);
        result.map(Response::new)
    }

    async fn get_session(&self, req: Request<GetSessionRequest>) -> Result<Response<GetSessionResponse>, Status> {
        let msg = req.into_inner();
        validate_get(&msg)?;
        if !msg.idempotency_key.is_empty() {
            // waits out a claim with the key in flight here, which may not have reached its host yet
            let _turn = self.keys.lock(&msg.idempotency_key).await;
            let (_, session) =
                self.find_key(&msg.idempotency_key).await?.ok_or_else(|| Status::not_found("no session has this idempotency key"))?;
            return Ok(Response::new(GetSessionResponse { session: Some(session) }));
        }
        let host = self.locate(&msg.name).await?;
        ask(&host, "get session", self.request_timeout, msg, async |c, r| c.get_session(r).await).await.map(Response::new)
    }

    async fn delete_session(&self, req: Request<DeleteSessionRequest>) -> Result<Response<DeleteSessionResponse>, Status> {
        let msg = req.into_inner();
        let host = self.locate(&msg.name).await?;
        let name = msg.name.clone();
        let resp = ask(&host, "delete session", self.request_timeout, msg, async |c, r| c.delete_session(r).await).await?;
        self.index.lock().unwrap().remove(&name);
        Ok(Response::new(resp))
    }

    async fn set_session_expiry(&self, req: Request<SetSessionExpiryRequest>) -> Result<Response<SetSessionExpiryResponse>, Status> {
        let msg = req.into_inner();
        validate_expiry(msg.expires_at_ms)?;
        let host = self.locate(&msg.name).await?;
        ask(&host, "set session expiry", self.request_timeout, msg, async |c, r| c.set_session_expiry(r).await).await.map(Response::new)
    }

    async fn list_sessions(&self, req: Request<ListSessionsRequest>) -> Result<Response<ListSessionsResponse>, Status> {
        let msg = req.into_inner();
        validate_list(&msg)?;
        // a partial list could lead callers to discard sessions on a host that is only unreachable.
        let ready = self.registry.all_hosts_ready()?;
        let lists = join_all(ready.iter().map(|host| {
            let msg = msg.clone();
            async move { ask(host, "list sessions", self.request_timeout, msg, async |c, r| c.list_sessions(r).await).await }
        }))
        .await;
        let mut merged = ListSessionsResponse::default();
        for list in lists {
            merged.sessions.extend(list?.sessions);
        }
        Ok(Response::new(merged))
    }

    /// Sums the ready hosts' last polled status, without calling them.
    async fn host_status(&self, _: Request<HostStatusRequest>) -> Result<Response<HostStatusResponse>, Status> {
        let ready = self.registry.ready_hosts();
        let mut total = HostStatusResponse::default();
        let mut pools: BTreeMap<String, PoolFill> = BTreeMap::new();
        for host in &ready {
            let s = &host.status;
            total.capacity += s.capacity;
            total.running += s.running;
            total.max_vcpus += s.max_vcpus;
            total.reserved_vcpus += s.reserved_vcpus;
            total.max_memory_mib += s.max_memory_mib;
            total.reserved_memory_mib += s.reserved_memory_mib;
            for p in &s.pools {
                let pool = pools.entry(p.template_id.clone()).or_insert_with(|| PoolFill {
                    template_id: p.template_id.clone(),
                    fingerprint: p.fingerprint.clone(),
                    ..PoolFill::default()
                });
                if pool.fingerprint != p.fingerprint {
                    return Err(Status::failed_precondition(format!("conflicting template {:?}", p.template_id)));
                }
                pool.ready += p.ready;
                pool.target += p.target;
            }
        }
        total.pools = pools.into_values().collect();
        Ok(Response::new(total))
    }
}

/// Serializes calls that share an idempotency key, holding an entry only while a key is in use.
#[derive(Default)]
struct KeyLocks(Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>);

struct KeyTurn<'a> {
    locks: &'a KeyLocks,
    key: String,
    turn: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl KeyLocks {
    async fn lock(&self, key: &str) -> KeyTurn<'_> {
        let lock = Arc::clone(self.0.lock().unwrap().entry(key.to_owned()).or_default());
        KeyTurn { locks: self, key: key.to_owned(), turn: Some(lock.lock_owned().await) }
    }
}

impl Drop for KeyTurn<'_> {
    fn drop(&mut self) {
        let lock = self.turn.take().map(|turn| Arc::clone(tokio::sync::OwnedMutexGuard::mutex(&turn)));
        let mut locks = self.locks.0.lock().unwrap();
        // the map's reference and this one are all that's left once nobody else waits.
        if lock.is_some_and(|lock| Arc::strong_count(&lock) == 2) {
            locks.remove(&self.key);
        }
    }
}

/// How a claim ended, as the claims counter labels it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaimOutcome {
    /// the first candidate host claimed.
    Ok,
    /// a later candidate claimed after earlier ones provably didn't.
    FailedOver,
    /// a keyed claim went back to the host holding its key, which answered it.
    Replayed,
    Invalid,
    /// a keyed claim couldn't find out which host holds its key.
    LookupFailed,
    /// the host holding the key refused the claim as a different request under the same key.
    KeyConflict,
    /// the host may or may not have claimed.
    Ambiguous,
    /// hosts define the template differently.
    Conflict,
    NoCandidates,
    AllFailed,
    /// the caller hung up first.
    Canceled,
}

impl ClaimOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::FailedOver => "failed_over",
            Self::Replayed => "replayed",
            Self::Invalid => "invalid",
            Self::LookupFailed => "lookup_failed",
            Self::KeyConflict => "key_conflict",
            Self::Ambiguous => "ambiguous",
            Self::Conflict => "conflict",
            Self::NoCandidates => "no_candidates",
            Self::AllFailed => "all_failed",
            Self::Canceled => "canceled",
        }
    }
}

/// Counts a claim once, with whatever outcome it ended on. If it's dropped before that, the caller cancelled it.
struct Outcome<'a> {
    claims: &'a Counter<u64>,
    outcome: ClaimOutcome,
}

impl<'a> Outcome<'a> {
    fn new(claims: &'a Counter<u64>) -> Self {
        Self { claims, outcome: ClaimOutcome::Canceled }
    }

    fn set(&mut self, outcome: ClaimOutcome) {
        self.outcome = outcome;
    }
}

impl Drop for Outcome<'_> {
    fn drop(&mut self) {
        self.claims.add(1, &[KeyValue::new("birdfeeder.operation.outcome", self.outcome.as_str())]);
    }
}

/// Calls `host` with `msg` and asks it to answer within `limit`. The host's own errors pass straight through. A
/// failure that never reached it gets labelled with the call and host. A timeout becomes `deadline_exceeded`,
/// because tonic's `cancelled` looks to callers like they cancelled.
async fn ask<M, T>(
    host: &ReadyHost,
    what: &str,
    limit: Duration,
    msg: M,
    call: impl AsyncFnOnce(&mut Client, Request<M>) -> Result<Response<T>, Status>,
) -> Result<T, Status> {
    try_ask(host, what, limit, msg, call).await.map_err(|failed| failed.status)
}

/// A call that failed, and whether the request provably never reached the host.
struct Failed {
    status: Status,
    /// the connection, or its TLS, failed before any of the request was sent, so the host did nothing.
    unsent: bool,
}

/// [`ask`], telling a request that never left apart from one the host may have acted on.
async fn try_ask<M, T>(
    host: &ReadyHost,
    what: &str,
    limit: Duration,
    msg: M,
    call: impl AsyncFnOnce(&mut Client, Request<M>) -> Result<Response<T>, Status>,
) -> Result<T, Failed> {
    let mut request = Request::new(msg);
    request.set_timeout(limit);
    let mut client = host.client.clone();
    let status = match call(&mut client, request).await {
        Ok(response) => return Ok(response.into_inner()),
        Err(status) => status,
    };
    let reached_host = std::error::Error::source(&status).is_none();
    let mut causes = std::iter::successors(std::error::Error::source(&status), |e| e.source());
    let timed_out = causes.clone().any(<dyn std::error::Error>::is::<TimeoutExpired>);
    // tonic only wraps the TCP connect and TLS handshake in ConnectError, and both happen before the request is
    // written. a connection that drops after that is a hyper error, and then the outcome's unknown.
    let unsent = !timed_out && causes.any(<dyn std::error::Error>::is::<ConnectError>);
    let status = if timed_out {
        Status::deadline_exceeded(format!("{what} on host {}: no answer within {limit:?}", host.id))
    } else if reached_host {
        Status::new(status.code(), status.message())
    } else {
        Status::new(status.code(), format!("{what} on host {}: {}", host.id, status.message()))
    };
    Err(Failed { status, unsent })
}

fn conflicting_definitions(ready: &[ReadyHost], template_id: &str) -> bool {
    let mut fingerprints = ready.iter().flat_map(|h| &h.status.pools).filter(|p| p.template_id == template_id).map(|p| &p.fingerprint);
    let Some(first) = fingerprints.next() else { return false };
    fingerprints.any(|f| f != first)
}

/// Hosts with pooled guests for the template, fullest first, with every host whose latest poll succeeded ahead of
/// the rest. A host that just stopped answering is probably gone, and a claim that times out there can't fail over.
fn candidates(ready: Vec<ReadyHost>, template_id: &str) -> Vec<ReadyHost> {
    let pooled =
        |h: &ReadyHost| -> i64 { h.status.pools.iter().filter(|p| p.template_id == template_id).map(|p| i64::from(p.ready)).sum() };
    let mut candidates: Vec<_> = ready.into_iter().filter(|h| pooled(h) > 0).collect();
    // ready hosts arrive in id order and the sort is stable, so ties go to the lower id.
    candidates.sort_by_key(|h| (h.failing, std::cmp::Reverse(pooled(h))));
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn key_locks_serialize_and_clean_up() {
        let locks = KeyLocks::default();
        let first = locks.lock("k").await;
        let _other = locks.lock("j").await;
        let second = locks.lock("k");
        tokio::pin!(second);
        assert!(futures_util::poll!(second.as_mut()).is_pending());
        drop(first);
        let second = second.await;
        assert_eq!(locks.0.lock().unwrap().len(), 2);
        drop(second);
        assert_eq!(locks.0.lock().unwrap().keys().collect::<Vec<_>>(), ["j"]);
    }
}
