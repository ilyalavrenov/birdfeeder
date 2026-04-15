use std::io::{self, Write};

use roost_api::v1::{HostStatusResponse, Session, SessionState};
use serde::Serialize;
use tabwriter::TabWriter;

/// fingerprints are sha256 hex; a prefix tells templates apart in a table.
const FINGERPRINT_PREFIX: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Output {
    Table,
    Json,
    Name,
}

/// Writes msg as protobuf JSON, same as gRPC tools like buf curl print it. Empty lists and zero values stay in so
/// scripts can index into them.
pub fn json(w: &mut dyn Write, msg: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *w, msg)?;
    writeln!(w)
}

fn table(w: &mut dyn Write) -> TabWriter<&mut dyn Write> {
    TabWriter::new(w).minwidth(0).padding(2)
}

/// Writes res in JSON, or sessions as names or a table.
pub fn sessions<'a>(
    w: &mut dyn Write,
    output: Output,
    res: &impl Serialize,
    sessions: impl IntoIterator<Item = &'a Session>,
) -> io::Result<()> {
    match output {
        Output::Json => json(w, res),
        Output::Name => sessions.into_iter().try_for_each(|s| writeln!(w, "{}", s.name)),
        Output::Table => {
            let mut t = table(w);
            writeln!(t, "NAME\tGENERATION\tSTATE\tTEMPLATE\tHOST\tENDPOINTS")?;
            for s in sessions {
                let endpoints: Vec<String> = s.endpoints.iter().map(|(name, addr)| format!("{name}={addr}")).collect();
                writeln!(
                    t,
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    s.name,
                    s.generation,
                    state_name(s.state),
                    dash(&s.template_id),
                    dash(&s.host_id),
                    dash(&endpoints.join(" "))
                )?;
            }
            t.flush()
        }
    }
}

pub fn status(w: &mut dyn Write, output: Output, res: &HostStatusResponse) -> io::Result<()> {
    match output {
        Output::Json => json(w, res),
        Output::Name => res.pools.iter().try_for_each(|p| writeln!(w, "{}", p.template_id)),
        Output::Table => {
            let mut t = table(w);
            writeln!(t, "sessions\t{} running of {}", res.running, res.capacity)?;
            writeln!(t, "vcpus\t{} reserved of {}", res.reserved_vcpus, res.max_vcpus)?;
            writeln!(t, "memory\t{} MiB reserved of {} MiB", res.reserved_memory_mib, res.max_memory_mib)?;
            if !res.pools.is_empty() {
                writeln!(t, "\nTEMPLATE\tREADY\tTARGET\tFINGERPRINT")?;
                for p in &res.pools {
                    let fp: String = p.fingerprint.chars().take(FINGERPRINT_PREFIX).collect();
                    writeln!(t, "{}\t{}\t{}\t{}", p.template_id, p.ready, p.target, dash(&fp))?;
                }
            }
            t.flush()
        }
    }
}

/// Writes key-value rows as an aligned table.
pub fn rows(w: &mut dyn Write, rows: &[[&str; 2]]) -> io::Result<()> {
    let mut t = table(w);
    for [k, v] in rows {
        writeln!(t, "{k}\t{v}")?;
    }
    t.flush()
}

/// A session state as the CLI shows and accepts it: `SESSION_STATE_CLAIMED` is "claimed".
pub fn state_name(state: i32) -> String {
    SessionState::try_from(state)
        .map_or_else(|_| state.to_string(), |s| s.as_str_name().trim_start_matches("SESSION_STATE_").to_lowercase())
}

fn dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}
