use std::{fmt, io, process::ExitCode};

use tonic::{Code, Status};

use super::{SERVER_ENV, Stopped};

/// A command failed. Each variant gets its own exit code (listed in the usage text) so scripts can branch on it.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0}")]
    Usage(String),
    #[error("invalid request: {}", .0.message())]
    InvalidRequest(Status),
    #[error("{what} not found")]
    NotFound { what: String },
    #[error("session {session:?} has no endpoint {want:?} (it has: {})", .have.join(", "))]
    NoSuchEndpoint { session: String, want: String, have: Vec<String> },
    #[error("session {0:?} has no endpoints")]
    NoEndpoints(String),
    #[error("{what}: {}", .status.message())]
    Stale { what: String, status: Status },
    #[error("session {name:?} is no longer at generation {generation}: it was replaced; 'birdfeeder get {name}' shows the current one")]
    Replaced { name: String, generation: u64 },
    #[error("session {name:?} was replaced while this ran; run the command again")]
    ReplacedWhileRunning { name: String },
    #[error("{what}: {}", .status.message())]
    NoCapacity { what: String, status: Status },
    #[error("no ready guest for template {template:?}: its pools are empty or every host's budget is spent; retry later")]
    NoReadyGuest { template: String },
    #[error("the claim may or may not have succeeded ({}: {}); {reconcile}", code_name(.status.code()), .status.message())]
    ClaimOutcomeUnknown { status: Status, reconcile: Reconcile },
    #[error("cannot reach {server} (set --server or {SERVER_ENV})")]
    Unreachable {
        server: String,
        #[source]
        source: tonic::transport::Error,
    },
    #[error("cannot reach {server}: {stopped} (set --server or {SERVER_ENV})")]
    StoppedConnecting { server: String, stopped: Stopped },
    #[error("{what}: timed out; raise --timeout")]
    TimedOut { what: String },
    #[error("{what}: {}: {}", code_name(.status.code()), .status.message())]
    Rpc { what: String, status: Status },
    #[error("{0}")]
    Stopped(Stopped),
    #[error("listen for signals")]
    Signals(#[source] io::Error),
    #[error("write output")]
    Output(#[source] io::Error),
    /// every failure already got printed as it happened. this just exits with the first one's code.
    #[error("some sessions weren't deleted")]
    NotAllDeleted { first: Box<CliError> },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl CliError {
    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from(match self {
            _ if self.is_usage() => 2,
            Self::NotFound { .. } | Self::NoSuchEndpoint { .. } | Self::NoEndpoints(_) => 3,
            Self::Stale { .. } | Self::Replaced { .. } | Self::ReplacedWhileRunning { .. } => 4,
            Self::NoCapacity { .. } | Self::NoReadyGuest { .. } => 5,
            Self::ClaimOutcomeUnknown { .. } => 6,
            Self::NotAllDeleted { first } => return first.exit_code(),
            _ => 1,
        })
    }

    pub fn is_usage(&self) -> bool {
        match self {
            Self::Usage(_) | Self::InvalidRequest(_) => true,
            Self::NotAllDeleted { first } => first.is_usage(),
            _ => false,
        }
    }

    /// The message plus its causes, like `{:#}` prints an `anyhow::Error`.
    pub fn report(&self) -> Report<'_> {
        Report(self)
    }
}

pub struct Report<'a>(&'a CliError);

impl fmt::Display for Report<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut shown = String::new();
        for e in std::iter::successors(Some(self.0 as &dyn std::error::Error), |e| e.source()) {
            let text = e.to_string();
            // hyper's connect errors just repeat their cause's message.
            if shown.ends_with(&text) {
                continue;
            }
            if !shown.is_empty() {
                f.write_str(": ")?;
            }
            f.write_str(&text)?;
            shown = text;
        }
        Ok(())
    }
}

/// What to do when we can't tell if a claim went through. Without a key a claim isn't idempotent, so retrying
/// could grab a second guest (see docs/runtime.md, "claims and retries").
#[derive(Debug)]
pub enum Reconcile {
    SameKey,
    ListTemplate(String),
}

impl fmt::Display for Reconcile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameKey => f.write_str("claim again with the same --idempotency-key to get its session"),
            Self::ListTemplate(t) => {
                write!(f, "run 'birdfeeder ls --template {t}' and delete any session you don't hold before claiming again")
            }
        }
    }
}

/// How an API call failed.
#[derive(Debug)]
pub enum CallError {
    /// never connected, so the request can't have done anything.
    NotConnected(tonic::transport::Error),
    /// the command bailed before connecting, so same deal.
    StoppedConnecting(Stopped),
    Status(Status),
}

/// The gRPC name for a code. Shorter than tonic's description.
fn code_name(code: Code) -> &'static str {
    match code {
        Code::Ok => "ok",
        Code::Cancelled => "canceled",
        Code::Unknown => "unknown",
        Code::InvalidArgument => "invalid_argument",
        Code::DeadlineExceeded => "deadline_exceeded",
        Code::NotFound => "not_found",
        Code::AlreadyExists => "already_exists",
        Code::PermissionDenied => "permission_denied",
        Code::ResourceExhausted => "resource_exhausted",
        Code::FailedPrecondition => "failed_precondition",
        Code::Aborted => "aborted",
        Code::OutOfRange => "out_of_range",
        Code::Unimplemented => "unimplemented",
        Code::Internal => "internal",
        Code::Unavailable => "unavailable",
        Code::DataLoss => "data_loss",
        Code::Unauthenticated => "unauthenticated",
    }
}

/// Figures out what kind of API error this is. `what` is the thing the request was about, for messages.
pub fn rpc_error(err: CallError, server: &str, what: &str) -> CliError {
    let status = match err {
        CallError::NotConnected(source) => return CliError::Unreachable { server: server.to_owned(), source },
        CallError::StoppedConnecting(stopped) => return CliError::StoppedConnecting { server: server.to_owned(), stopped },
        CallError::Status(s) => s,
    };
    let what = what.to_owned();
    match status.code() {
        Code::NotFound => CliError::NotFound { what },
        Code::FailedPrecondition => CliError::Stale { what, status },
        Code::InvalidArgument => CliError::InvalidRequest(status),
        Code::ResourceExhausted => CliError::NoCapacity { what, status },
        Code::DeadlineExceeded => CliError::TimedOut { what },
        _ => CliError::Rpc { what, status },
    }
}

/// `rpc_error` for claims. If the error doesn't prove the claim failed, it says how to reconcile and doesn't
/// suggest a retry.
pub fn claim_error(err: CallError, server: &str, template: &str, key: Option<&str>) -> CliError {
    match err {
        CallError::Status(s) if s.code() == Code::ResourceExhausted => CliError::NoReadyGuest { template: template.to_owned() },
        CallError::Status(status) if !matches!(status.code(), Code::InvalidArgument | Code::FailedPrecondition) => {
            let reconcile = if key.is_some() { Reconcile::SameKey } else { Reconcile::ListTemplate(template.to_owned()) };
            CliError::ClaimOutcomeUnknown { status, reconcile }
        }
        err => rpc_error(err, server, "claim"),
    }
}

/// A mutation error, worded for when a newer generation replaced the session.
pub fn mutation_error(err: CallError, server: &str, name: &str, generation: u64, explicit: bool) -> CliError {
    match err {
        CallError::Status(s) if s.code() == Code::FailedPrecondition => {
            let name = name.to_owned();
            if explicit { CliError::Replaced { name, generation } } else { CliError::ReplacedWhileRunning { name } }
        }
        err => rpc_error(err, server, &format!("session {name:?}")),
    }
}
