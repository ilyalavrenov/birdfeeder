//! Reads the workload from Firecracker's metadata service (MMDS v2).

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use ureq::Agent;
use ureq::http::Response;

use guestapi::workload::Metadata;

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: u64 = 64 << 10;

pub fn fetch(base: &str) -> Result<Metadata> {
    let agent: Agent =
        Agent::config_builder().timeout_global(Some(TIMEOUT)).proxy(None).max_redirects(0).http_status_as_error(false).build().into();
    let token = read(
        agent
            .put(format!("{base}/latest/api/token"))
            .header("Accept", "application/json")
            .header("X-metadata-token-ttl-seconds", "60")
            .send_empty(),
        "/latest/api/token",
    )?;
    let token = String::from_utf8(token).context("MMDS token is not text")?;
    let body = read(agent.get(format!("{base}/")).header("Accept", "application/json").header("X-metadata-token", &token).call(), "/")?;
    let md: Metadata = serde_json::from_slice(&body).context("decode MMDS")?;
    md.validate()?;
    Ok(md)
}

fn read(res: Result<Response<ureq::Body>, ureq::Error>, path: &str) -> Result<Vec<u8>> {
    let mut res = res.context("query MMDS")?;
    ensure!(res.status() == 200, "MMDS {path}: status {}", res.status().as_u16());
    res.body_mut().with_config().limit(MAX_RESPONSE_BYTES).read_to_vec().with_context(|| format!("read MMDS {path}"))
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;
    use guestapi::workload::{Container, Identifier, Manifest, Probe, ProbeTarget};

    /// Fakes MMDS: hands out a token on PUT, then returns `body` to a GET that sends it back.
    fn mmds(body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        thread::spawn(move || {
            for conn in listener.incoming() {
                let conn = conn.unwrap();
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                let mut out = conn;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let mut headers = Vec::new();
                    loop {
                        let mut h = String::new();
                        reader.read_line(&mut h).unwrap();
                        if h.trim().is_empty() {
                            break;
                        }
                        headers.push(h.trim().to_ascii_lowercase());
                    }
                    let has = |h: &str| headers.iter().any(|x| x == h);
                    let reply = if line.starts_with("PUT /latest/api/token ") && has("x-metadata-token-ttl-seconds: 60") {
                        "test-token".to_owned()
                    } else if line.starts_with("GET / ") && has("x-metadata-token: test-token") && has("accept: application/json") {
                        body.clone()
                    } else {
                        write!(out, "HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n").unwrap();
                        continue;
                    };
                    write!(out, "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{reply}", reply.len()).unwrap();
                }
            }
        });
        url
    }

    #[test]
    fn fetches_with_a_session_token() {
        let id = |s: &str| s.parse::<Identifier>().unwrap();
        let md = Metadata {
            version: 1,
            template_id: id("web-v1"),
            blobs: vec![id("app")],
            manifest: Manifest {
                containers: vec![Container::new(id("web"), id("app"))],
                readiness: vec![Probe { name: id("http"), target: ProbeTarget::Tcp(8080.try_into().unwrap()) }],
                ..Manifest::default()
            },
        };
        assert_eq!(fetch(&mmds(serde_json::to_string(&md).unwrap())).unwrap(), md);
    }

    #[test]
    fn rejects_invalid_and_oversized_metadata() {
        assert!(fetch(&mmds(r#"{"version":2}"#.into())).is_err());
        assert!(fetch(&mmds(format!(r#"{{"template_id":"{}"}}"#, "x".repeat(64 << 10)))).is_err());
    }
}
