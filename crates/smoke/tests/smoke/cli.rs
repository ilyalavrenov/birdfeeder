//! The birdfeeder command against the dispatcher.

use std::time::Duration;

use roost_api::v1::{self, SessionState};

use crate::harness::{DISPATCHER_ADDR, Harness, bin, eventually, get, sessions};

/// Claims, lists, extends, and deletes a session with the CLI, then waits until only pooled guests remain so the
/// rest of the test starts from a full pool.
pub async fn check(h: &Harness, template: &str, expected: &str) {
    let out =
        cli(&["claim", template, "--label", "smoke=cli", "--allow-cidr", "198.18.0.0/30", "--idle-timeout", "10m", "-o", "json"]).await;
    let claimed: v1::ClaimSessionResponse = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
    let session = claimed.session.expect("claim printed a session");
    assert_eq!(session.state(), SessionState::Claimed);
    assert_eq!(session.template_id, template);
    let listed = cli(&["ls", "--state", "claimed", "--template", template, "-o", "name"]).await;
    assert!(listed.split_whitespace().any(|name| name == session.name), "{listed}");
    assert_eq!(cli(&["endpoint", &session.name]).await.trim(), session.endpoints["http"]);
    assert_eq!(get(&session, "/", 200).await, expected.as_bytes());

    cli(&["expire", &session.name, "--in", "1h", "--generation", &session.generation.to_string()]).await;
    // without --generation, rm deletes the session's current generation, which is still the claimed one.
    assert_eq!(cli(&["rm", &session.name, "-o", "name"]).await, format!("{}\n", session.name));
    eventually("teardown of the session the CLI deleted", async || {
        let sessions = sessions(h.host()).await?;
        Ok(!sessions.is_empty() && sessions.iter().all(|s| s.state() == SessionState::Pooled))
    })
    .await;
    eventually("warm pool after the CLI checks", async || h.ready().await).await;
}

async fn cli(args: &[&str]) -> String {
    let mut cmd = tokio::process::Command::new(bin("birdfeeder"));
    cmd.args(args).env("BIRDFEEDER_SERVER", DISPATCHER_ADDR).kill_on_drop(true);
    let out = tokio::time::timeout(Duration::from_secs(30), cmd.output()).await.expect("birdfeeder finished").expect("run birdfeeder");
    assert!(out.status.success(), "birdfeeder {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).expect("utf-8 output")
}
