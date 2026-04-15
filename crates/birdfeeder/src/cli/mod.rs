//! Argument parsing, and one method per command.

mod errors;
mod output;
#[cfg(test)]
mod tests;

use std::{collections::BTreeMap, ffi::OsString, fmt, future::Future, io::Write, path::PathBuf, process::ExitCode, time::Duration};

use chrono::{DateTime, FixedOffset, SecondsFormat};
use clap::{
    Arg, ArgAction, ArgGroup, ArgMatches, CommandFactory as _, FromArgMatches, Parser, Subcommand,
    builder::{StringValueParser, TypedValueParser},
};
use roost_api::v1::{
    ClaimSessionRequest, DeleteSessionRequest, EgressPolicy, GetSessionRequest, GetSessionResponse, HostStatusRequest, ListSessionsRequest,
    SessionState, SetSessionExpiryRequest, roost_service_client::RoostServiceClient,
};
use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    time::Instant,
};
use tonic::{
    Request, Response, Status,
    transport::{Channel, ClientTlsConfig, Endpoint},
};

use self::{
    errors::{CallError, CliError, claim_error, mutation_error, rpc_error},
    output::Output,
};
use crate::ociimage::{self, Platform};

pub const SERVER_ENV: &str = "BIRDFEEDER_SERVER";
const DEFAULT_SERVER: &str = "http://127.0.0.1:8080";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

const AFTER_HELP: &str = "\
exit status: 0 success, 1 failure, 2 usage, 3 not found, 4 stale generation,
5 no ready guest, 6 claim outcome unknown.

run 'birdfeeder help COMMAND' for a command's flags.";

/// birdfeeder is a client for the birdfeeder session API, served by the dispatcher and by roost.
/// it also packs registry images and unpacked bundles into the blobs templates run.
#[derive(Debug, Parser)]
#[command(name = "birdfeeder", after_help = AFTER_HELP, arg_required_else_help = true)]
struct Args {
    #[arg(
        long,
        global = true,
        value_name = "ADDRESS",
        help = "roost or dispatcher address, host:port or an http(s) URL [env: BIRDFEEDER_SERVER] [default: http://127.0.0.1:8080]"
    )]
    server: Option<String>,
    /// output format
    #[arg(short, long, global = true, value_enum, default_value_t = Output::Table, value_name = "FORMAT")]
    output: Output,
    /// give up after this duration, such as 90s or 2m 30s; 0 waits indefinitely [default: 60s, none for convert and pack]
    #[arg(long, global = true, value_name = "DURATION", value_parser = humantime::parse_duration)]
    timeout: Option<Duration>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// claim a ready guest from a template's pool
    Claim(Claim),
    /// show one session
    Get {
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// list sessions
    Ls(Ls),
    /// print a session's endpoint address, for use in scripts
    Endpoint {
        #[arg(value_name = "NAME")]
        name: String,
        /// which endpoint, when the session has several
        #[arg(value_name = "ENDPOINT")]
        endpoint: Option<String>,
    },
    /// set or clear a session's expiry
    Expire(Expire),
    /// delete sessions
    Rm(Rm),
    /// show capacity and pool fill
    Status,
    /// convert a registry image into a template blob (needs mksquashfs 4.6+)
    Convert(Convert),
    /// pack a trusted, unpacked OCI bundle directory into a template blob (needs mksquashfs)
    Pack(Pack),
}

#[derive(Debug, clap::Args)]
struct Claim {
    #[arg(value_name = "TEMPLATE")]
    template: String,
    /// attach a label; repeatable
    #[arg(long = "label", value_name = "KEY=VALUE", value_parser = parse_label)]
    labels: Vec<(String, String)>,
    /// allow egress to a domain (*.example.com for subdomains); repeatable or comma-separated
    #[arg(long = "allow-fqdn", value_name = "DOMAIN", value_delimiter = ',', value_parser = trimmed())]
    fqdns: Vec<String>,
    /// allow egress to an IP range (0.0.0.0/0 for the internet); repeatable or comma-separated
    #[arg(long = "allow-cidr", value_name = "RANGE", value_delimiter = ',', value_parser = trimmed())]
    cidrs: Vec<String>,
    /// allow outbound SMTP to the allowed destinations
    #[arg(long)]
    allow_smtp: bool,
    /// delete the session this long after the claim [default: never]
    #[arg(long, value_name = "DURATION", value_parser = idle_timeout)]
    idle_timeout: Option<Duration>,
    /// make the claim safe to retry: the same claim with the same key answers the session it claimed
    #[arg(long, value_name = "KEY")]
    idempotency_key: Option<String>,
}

#[derive(Debug, clap::Args)]
struct Ls {
    /// only sessions with this label; repeatable
    #[arg(long = "label", value_name = "KEY=VALUE", value_parser = parse_label)]
    labels: Vec<(String, String)>,
    /// only sessions of this template
    #[arg(long)]
    template: Option<String>,
    /// only sessions in this state: booting, pooled, claimed, or stopping
    #[arg(long, value_parser = parse_state)]
    state: Option<SessionState>,
    /// only sessions on this host
    #[arg(long)]
    host: Option<String>,
}

#[derive(Debug, clap::Args)]
struct Expire {
    #[arg(value_name = "NAME")]
    name: String,
    #[command(flatten)]
    when: Expiry,
    /// fail unless the session is at this generation [default: its current one]
    #[arg(long)]
    generation: Option<u64>,
}

#[derive(Debug, clap::Args)]
struct Rm {
    #[arg(value_name = "NAME", required = true)]
    names: Vec<String>,
    /// fail unless the session is at this generation, so a replacement with the same name is never deleted [default: its current one]
    #[arg(long)]
    generation: Option<u64>,
}

#[derive(Debug, clap::Args)]
struct Convert {
    #[arg(value_name = "IMAGE")]
    image: String,
    // not `output`, that'd shadow the global -o.
    #[arg(value_name = "OUTPUT")]
    dest: PathBuf,
    /// image os[/arch[/variant]] to select from a multi-platform index
    #[arg(long, value_name = "PLATFORM", default_value_t)]
    platform: Platform,
    /// reach this registry (host[:port], as in IMAGE) over plain HTTP, sending any credentials in the clear; loopback
    /// registries always are. repeatable
    #[arg(long = "insecure-registry", value_name = "REGISTRY")]
    insecure_registries: Vec<String>,
}

#[derive(Debug, clap::Args)]
struct Pack {
    /// a directory holding config.json and rootfs/
    #[arg(value_name = "BUNDLE")]
    bundle: PathBuf,
    #[arg(value_name = "OUTPUT")]
    dest: PathBuf,
}

fn parse_label(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_owned(), v.to_owned())),
        _ => Err("want key=value".into()),
    }
}

fn parse_state(s: &str) -> Result<SessionState, String> {
    SessionState::from_str_name(&format!("SESSION_STATE_{}", s.to_uppercase()))
        .filter(|&st| st != SessionState::Unspecified)
        .ok_or_else(|| "want booting, pooled, claimed, or stopping".into())
}

/// Lets `--allow-fqdn 'a, b'` mean the same as `--allow-fqdn a --allow-fqdn b`.
fn trimmed() -> impl TypedValueParser<Value = String> {
    StringValueParser::new().map(|s| s.trim().to_owned())
}

fn idle_timeout(s: &str) -> Result<Duration, String> {
    let d = humantime::parse_duration(s).map_err(|e| e.to_string())?;
    // the API counts whole milliseconds, where 0 means no timeout.
    if d < Duration::from_millis(1) {
        return Err("must be at least 1ms".into());
    }
    Ok(d)
}

/// When a session expires, from exactly one of --in, --at, and --never.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expiry {
    In(Duration),
    At(DateTime<FixedOffset>),
    Never,
}

// clap only derives `Args` for structs, so picking one of several flags has to be done by hand.
impl FromArgMatches for Expiry {
    fn from_arg_matches(m: &ArgMatches) -> Result<Self, clap::Error> {
        // the group makes you pass one of the three, and --in/--at parse straight into their variants.
        Ok(["in", "at"].into_iter().find_map(|id| m.get_one::<Self>(id)).copied().unwrap_or(Self::Never))
    }

    fn update_from_arg_matches(&mut self, m: &ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(m)?;
        Ok(())
    }
}

impl clap::Args for Expiry {
    fn augment_args(cmd: clap::Command) -> clap::Command {
        let after = |s: &str| match humantime::parse_duration(s) {
            Ok(d) if d.is_zero() => Err("must be positive".to_owned()),
            Ok(d) => Ok(Self::In(d)),
            Err(e) => Err(e.to_string()),
        };
        let at = |s: &str| DateTime::parse_from_rfc3339(s).map(Self::At);
        cmd.arg(Arg::new("in").long("in").value_name("DURATION").value_parser(after).help("expire this duration from now"))
            .arg(Arg::new("at").long("at").value_name("TIME").value_parser(at).help("expire at this RFC 3339 time"))
            .arg(Arg::new("never").long("never").action(ArgAction::SetTrue).help("clear the expiry"))
            .group(ArgGroup::new("when").required(true).args(["in", "at", "never"]))
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
        Self::augment_args(cmd)
    }
}

/// Everything the command reads from or writes to its process.
pub struct Env<'a> {
    pub stdout: &'a mut dyn Write,
    pub stderr: &'a mut dyn Write,
    pub server: Option<String>,
    pub now: DateTime<FixedOffset>,
}

/// Executes a command line (with the program name first) and returns the process exit code.
pub async fn run(args: impl IntoIterator<Item = impl Into<OsString> + Clone>, env: Env<'_>) -> ExitCode {
    let parsed = Args::command().try_get_matches_from(args).and_then(|m| Ok((Args::from_arg_matches(&m)?, m)));
    let (args, matches) = match parsed {
        Ok(parsed) => parsed,
        Err(e) => {
            let w = if e.use_stderr() { env.stderr } else { env.stdout };
            let _ = write!(w, "{e}");
            return ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(2));
        }
    };
    let name = matches.subcommand_name().expect("clap requires a command");
    let result = match Runner::new(&args, env.server, env.stdout, &mut *env.stderr, env.now) {
        Ok(mut r) => r.execute(args.command).await,
        Err(e) => Err(e),
    };
    let Err(e) = result else { return ExitCode::SUCCESS };
    let _ = writeln!(env.stderr, "birdfeeder {name}: {}", e.report());
    if e.is_usage() {
        let _ = writeln!(env.stderr, "run 'birdfeeder help {name}' for usage");
    }
    e.exit_code()
}

/// Takes a bare host:port or a URL. Both services speak plain HTTP by default.
fn server_url(server: &str) -> Result<String, CliError> {
    let full = if server.contains("://") { server.to_owned() } else { format!("http://{server}") };
    let uri: http::Uri = full.parse().map_err(|e| CliError::Usage(format!("invalid server address {full:?}: {e}")))?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none_or(|a| a.host().is_empty()) {
        return Err(CliError::Usage(format!("invalid server address {full:?}: want host:port or an http(s) URL")));
    }
    Ok(full.trim_end_matches('/').to_owned())
}

#[derive(Debug, Clone, Copy)]
enum Stopped {
    Timeout,
    Interrupted,
}

impl Stopped {
    fn status(self) -> Status {
        match self {
            Self::Timeout => Status::deadline_exceeded("timed out"),
            Self::Interrupted => Status::cancelled("interrupted"),
        }
    }
}

impl fmt::Display for Stopped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Timeout => "timed out; raise --timeout",
            Self::Interrupted => "interrupted",
        })
    }
}

/// Cuts a command short at its deadline or on SIGINT/SIGTERM. We listen from the start so a signal can't kill us
/// halfway through a claim and leave its outcome unreported.
struct Stop {
    deadline: Option<Instant>,
    signals: Vec<Signal>,
}

impl Stop {
    fn new(timeout: Option<Duration>) -> Result<Self, CliError> {
        let signals = [SignalKind::interrupt(), SignalKind::terminate()].into_iter().map(signal).collect::<std::io::Result<_>>();
        Ok(Self { deadline: timeout.filter(|t| !t.is_zero()).map(|t| Instant::now() + t), signals: signals.map_err(CliError::Signals)? })
    }

    fn expired(&self) -> bool {
        self.deadline.is_some_and(|d| d <= Instant::now())
    }

    fn remaining(&self) -> Option<Duration> {
        self.deadline.map(|d| d.saturating_duration_since(Instant::now()))
    }

    async fn wait(&mut self) -> Stopped {
        let deadline = async {
            match self.deadline {
                Some(d) => tokio::time::sleep_until(d).await,
                None => std::future::pending().await,
            }
        };
        let signals = futures_util::future::select_all(self.signals.iter_mut().map(|s| Box::pin(s.recv())));
        tokio::select! {
            () = deadline => Stopped::Timeout,
            _ = signals => Stopped::Interrupted,
        }
    }
}

type Client = RoostServiceClient<Channel>;

struct Runner<'a> {
    server: String,
    output: Output,
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
    now: DateTime<FixedOffset>,
    stop: Stop,
    client: Option<Client>,
}

impl<'a> Runner<'a> {
    fn new(
        args: &Args,
        server_env: Option<String>,
        stdout: &'a mut dyn Write,
        stderr: &'a mut dyn Write,
        now: DateTime<FixedOffset>,
    ) -> Result<Self, CliError> {
        let server = args.server.clone().or(server_env.filter(|s| !s.is_empty())).unwrap_or_else(|| DEFAULT_SERVER.into());
        // these don't hit the API, so the default timeout (sized for an API call) doesn't apply.
        let local = matches!(args.command, Command::Convert(_) | Command::Pack(_));
        let timeout = args.timeout.or((!local).then_some(DEFAULT_TIMEOUT));
        Ok(Self { server: server_url(&server)?, output: args.output, stdout, stderr, now, stop: Stop::new(timeout)?, client: None })
    }

    async fn execute(&mut self, command: Command) -> Result<(), CliError> {
        match command {
            Command::Claim(c) => self.claim(c).await,
            Command::Get { name } => self.get(&name).await,
            Command::Ls(l) => self.ls(l).await,
            Command::Endpoint { name, endpoint } => self.endpoint(&name, endpoint.as_deref()).await,
            Command::Expire(e) => self.expire(e).await,
            Command::Rm(r) => self.rm(r).await,
            Command::Status => self.status().await,
            Command::Convert(c) => self.convert(c).await,
            Command::Pack(p) => self.pack(p).await,
        }
    }

    async fn connect(&mut self) -> Result<Client, CallError> {
        if let Some(c) = &self.client {
            return Ok(c.clone());
        }
        let mut endpoint = Endpoint::from_shared(self.server.clone()).map_err(CallError::NotConnected)?;
        if self.server.starts_with("https://") {
            endpoint = endpoint.tls_config(ClientTlsConfig::new().with_native_roots()).map_err(CallError::NotConnected)?;
        }
        // connect first, so we can tell a request that never went out from one whose outcome is unknown.
        let channel = tokio::select! {
            r = endpoint.connect() => r.map_err(CallError::NotConnected)?,
            why = self.stop.wait() => return Err(CallError::StoppedConnecting(why)),
        };
        let client = RoostServiceClient::new(channel);
        self.client = Some(client.clone());
        Ok(client)
    }

    /// Sends one request, bounded by the command's deadline and signals.
    async fn call<Req, Res, F, Fut>(&mut self, req: Req, send: F) -> Result<Res, CallError>
    where
        F: FnOnce(Client, Request<Req>) -> Fut,
        Fut: Future<Output = Result<Response<Res>, Status>>,
    {
        let client = self.connect().await?;
        let mut req = Request::new(req);
        if let Some(left) = self.stop.remaining() {
            req.set_timeout(left);
        }
        let res = tokio::select! {
            r = send(client, req) => r.map(Response::into_inner),
            why = self.stop.wait() => Err(why.status()),
        };
        // tonic enforces the timeout itself and reports it as cancelled.
        res.map_err(|s| CallError::Status(if self.stop.expired() { Stopped::Timeout.status() } else { s }))
    }

    async fn claim(&mut self, c: Claim) -> Result<(), CliError> {
        let mut labels = BTreeMap::new();
        for (k, v) in c.labels {
            if labels.insert(k.clone(), v).is_some() {
                return Err(CliError::Usage(format!("label {k:?} given twice")));
            }
        }
        // a trailing comma or an empty flag adds nothing.
        let allowlist = |values: Vec<String>| values.into_iter().filter(|v| !v.is_empty()).collect();
        let egress = EgressPolicy { fqdn_allowlist: allowlist(c.fqdns), cidr_allowlist: allowlist(c.cidrs), smtp_allowed: c.allow_smtp };
        let has_egress = !egress.fqdn_allowlist.is_empty() || !egress.cidr_allowlist.is_empty() || egress.smtp_allowed;
        let req = ClaimSessionRequest {
            template_id: c.template.clone(),
            labels,
            egress: has_egress.then_some(egress),
            idle_timeout_ms: c.idle_timeout.map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX)),
            idempotency_key: c.idempotency_key.clone().unwrap_or_default(),
        };
        roost_api::validate_claim(&req).map_err(|e| CliError::Usage(e.to_string()))?;
        let res = self
            .call(req, |mut c, r| async move { c.claim_session(r).await })
            .await
            .map_err(|e| claim_error(e, &self.server, &c.template, c.idempotency_key.as_deref()))?;
        output::sessions(self.stdout, self.output, &res, res.session.as_ref()).map_err(CliError::Output)
    }

    async fn get_session(&mut self, name: &str) -> Result<GetSessionResponse, CliError> {
        let req = GetSessionRequest { name: name.into(), ..GetSessionRequest::default() };
        self.call(req, |mut c, r| async move { c.get_session(r).await })
            .await
            .map_err(|e| rpc_error(e, &self.server, &format!("session {name:?}")))
    }

    async fn get(&mut self, name: &str) -> Result<(), CliError> {
        let res = self.get_session(name).await?;
        output::sessions(self.stdout, self.output, &res, res.session.as_ref()).map_err(CliError::Output)
    }

    async fn ls(&mut self, l: Ls) -> Result<(), CliError> {
        let req = ListSessionsRequest { labels: l.labels.into_iter().collect() };
        roost_api::validate_list(&req).map_err(|e| CliError::Usage(e.to_string()))?;
        let mut res = self
            .call(req, |mut c, r| async move { c.list_sessions(r).await })
            .await
            .map_err(|e| rpc_error(e, &self.server, "list sessions"))?;
        res.sessions.retain(|s| {
            l.template.as_ref().is_none_or(|t| &s.template_id == t)
                && l.state.is_none_or(|st| s.state == st as i32)
                && l.host.as_ref().is_none_or(|h| &s.host_id == h)
        });
        res.sessions.sort_by(|a, b| a.name.cmp(&b.name));
        let printed = if res.sessions.is_empty() && self.output == Output::Table {
            writeln!(self.stderr, "no sessions")
        } else {
            output::sessions(self.stdout, self.output, &res, &res.sessions)
        };
        printed.map_err(CliError::Output)
    }

    async fn endpoint(&mut self, name: &str, endpoint: Option<&str>) -> Result<(), CliError> {
        let res = self.get_session(name).await?;
        let endpoints = res.session.map(|s| s.endpoints).unwrap_or_default();
        let names = || endpoints.keys().cloned().collect::<Vec<_>>();
        let addr = match (endpoint, endpoints.len()) {
            (Some(want), _) => endpoints.get(want).ok_or_else(|| CliError::NoSuchEndpoint {
                session: name.to_owned(),
                want: want.to_owned(),
                have: names(),
            })?,
            (None, 1) => endpoints.values().next().expect("one endpoint"),
            (None, 0) => return Err(CliError::NoEndpoints(name.to_owned())),
            (None, _) => {
                return Err(CliError::Usage(format!("session {name:?} has several endpoints; name one of: {}", names().join(", "))));
            }
        };
        writeln!(self.stdout, "{addr}").map_err(CliError::Output)
    }

    async fn expire(&mut self, e: Expire) -> Result<(), CliError> {
        let expires = match e.when {
            Expiry::In(d) => Some(
                chrono::Duration::from_std(d)
                    .ok()
                    .and_then(|d| self.now.checked_add_signed(d))
                    .ok_or_else(|| CliError::Usage("--in is too long".into()))?,
            ),
            Expiry::At(t) => Some(t),
            Expiry::Never => None,
        };
        let expires_at_ms = expires.map_or(0, |t| t.timestamp_millis().max(1));
        roost_api::validate_expiry(expires_at_ms).map_err(|err| CliError::Usage(err.to_string()))?;
        let generation = self.generation(&e.name, e.generation).await?;
        let req = SetSessionExpiryRequest { name: e.name.clone(), generation, expires_at_ms };
        self.call(req.clone(), |mut c, r| async move { c.set_session_expiry(r).await })
            .await
            .map_err(|err| mutation_error(err, &self.server, &e.name, generation, e.generation.is_some()))?;
        let printed = match (self.output, expires) {
            // the response is empty. the request is what tells us what changed.
            (Output::Json, _) => output::json(self.stdout, &req),
            (Output::Name, _) => writeln!(self.stdout, "{}", e.name),
            (Output::Table, None) => writeln!(self.stdout, "{} (generation {generation}) no longer expires", e.name),
            (Output::Table, Some(t)) => {
                writeln!(self.stdout, "{} (generation {generation}) expires at {}", e.name, t.to_rfc3339_opts(SecondsFormat::Secs, true))
            }
        };
        printed.map_err(CliError::Output)
    }

    async fn rm(&mut self, r: Rm) -> Result<(), CliError> {
        if r.generation.is_some() && r.names.len() > 1 {
            return Err(CliError::Usage("--generation applies to a single session".into()));
        }
        let [name] = &r.names[..] else { return self.rm_several(&r.names).await };
        self.delete(name, r.generation).await
    }

    /// Deletes what can be deleted, reports every failure, and exits with the first one's code.
    async fn rm_several(&mut self, names: &[String]) -> Result<(), CliError> {
        let mut first = None;
        for name in names {
            if let Err(e) = self.delete(name, None).await {
                writeln!(self.stderr, "birdfeeder rm: {}", e.report()).map_err(CliError::Output)?;
                first.get_or_insert(e);
            }
        }
        match first {
            Some(first) => Err(CliError::NotAllDeleted { first: Box::new(first) }),
            None => Ok(()),
        }
    }

    async fn delete(&mut self, name: &str, explicit: Option<u64>) -> Result<(), CliError> {
        let generation = self.generation(name, explicit).await?;
        let req = DeleteSessionRequest { name: name.into(), generation };
        self.call(req.clone(), |mut c, r| async move { c.delete_session(r).await })
            .await
            .map_err(|e| mutation_error(e, &self.server, name, generation, explicit.is_some()))?;
        let printed = match self.output {
            // the response is empty. the request is what tells us what got deleted.
            Output::Json => output::json(self.stdout, &req),
            Output::Name => writeln!(self.stdout, "{name}"),
            Output::Table => writeln!(self.stdout, "deleted {name} (generation {generation})"),
        };
        printed.map_err(CliError::Output)
    }

    /// explicit if set, otherwise the session's current generation. if you only name a session, you mean whatever
    /// session has that name right now.
    async fn generation(&mut self, name: &str, explicit: Option<u64>) -> Result<u64, CliError> {
        if let Some(g) = explicit {
            return Ok(g);
        }
        let res = self.get_session(name).await?;
        res.session.map(|s| s.generation).ok_or_else(|| CliError::NotFound { what: format!("session {name:?}") })
    }

    async fn status(&mut self) -> Result<(), CliError> {
        let res = self
            .call(HostStatusRequest {}, |mut c, r| async move { c.host_status(r).await })
            .await
            .map_err(|e| rpc_error(e, &self.server, "host status"))?;
        output::status(self.stdout, self.output, &res).map_err(CliError::Output)
    }

    async fn convert(&mut self, c: Convert) -> Result<(), CliError> {
        let res = tokio::select! {
            r = ociimage::convert(&c.image, &c.platform, &c.insecure_registries, &c.dest) => r?,
            why = self.stop.wait() => return Err(CliError::Stopped(why)),
        };
        let printed = match self.output {
            Output::Json => output::json(self.stdout, &res),
            // a template's blob_sha256 wants this digest.
            Output::Name => writeln!(self.stdout, "{}", res.sha256),
            Output::Table => {
                output::rows(self.stdout, &[["image", &res.image], ["path", &res.path.display().to_string()], ["sha256", &res.sha256]])
            }
        };
        printed.map_err(CliError::Output)
    }

    async fn pack(&mut self, p: Pack) -> Result<(), CliError> {
        let res = tokio::select! {
            r = ociimage::pack_dir(&p.bundle, &p.dest) => r?,
            why = self.stop.wait() => return Err(CliError::Stopped(why)),
        };
        let printed = match self.output {
            Output::Json => output::json(self.stdout, &res),
            Output::Name => writeln!(self.stdout, "{}", res.sha256),
            Output::Table => output::rows(self.stdout, &[["path", &res.path.display().to_string()], ["sha256", &res.sha256]]),
        };
        printed.map_err(CliError::Output)
    }
}
