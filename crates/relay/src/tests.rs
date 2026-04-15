use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use opentelemetry::{
    InstrumentationScope,
    logs::{AnyValue, LoggerProvider as _},
};
use opentelemetry_sdk::logs::{InMemoryLogExporter, SdkLoggerProvider, in_memory_exporter::LogDataWithResource};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::UnixListener,
    sync::mpsc,
    time::timeout,
};

use super::*;

const WAIT: Duration = Duration::from_secs(5);

async fn eventually<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    timeout(WAIT, async {
        loop {
            if let Some(value) = check() {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

/// Plays Firecracker and birdfeeder-init: each connection gets one record after the cursor it asks for. The first
/// connection's record is as long as a record can get, then it hangs up. Later ones stay open until the relay closes.
fn guest(listener: UnixListener) -> mpsc::UnboundedReceiver<u64> {
    let (requests, received) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        for connection in 0.. {
            let (conn, _) = listener.accept().await.unwrap();
            let mut conn = BufReader::new(conn);
            let mut line = String::new();
            conn.read_line(&mut line).await.unwrap();
            assert_eq!(line, "CONNECT 5000\n");
            conn.write_all(b"OK 5000\n").await.unwrap();
            line.clear();
            conn.read_line(&mut line).await.unwrap();
            let after: u64 = line.strip_prefix("LOGS web ").and_then(|s| s.trim_end().parse().ok()).unwrap();
            requests.send(after).unwrap();
            // escaped control chars push the longest line close to the record limit. only send it once, since the rate
            // limit would hold a second one back for seconds.
            let line = if connection == 0 { "\0".repeat(64 << 10) } else { "hello".into() };
            let record = serde_json::json!({
                "seq": after + 1, "ts": humantime::format_rfc3339_nanos(std::time::SystemTime::now()).to_string(),
                "container": "web", "stream": "stderr", "line": line,
            });
            conn.write_all(format!("{record}\n").as_bytes()).await.unwrap();
            if connection != 0 {
                let _ = conn.read_to_end(&mut Vec::new()).await;
            }
        }
    });
    received
}

#[tokio::test]
async fn streams_resume_and_retire() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("vsock");
    let mut requests = guest(UnixListener::bind(&socket).unwrap());
    let target = Target {
        host_id: "host".into(),
        session_id: "vm".into(),
        template_id: "tpl".into(),
        container: "web".into(),
        socket,
        generation: 1,
    };
    let live = Arc::new(AtomicBool::new(true));
    let exporter = InMemoryLogExporter::default();
    let provider = SdkLoggerProvider::builder().with_simple_exporter(exporter.clone()).build();
    let cursors = dir.path().join("log-cursors");
    let start = || {
        let (target, live, provider) = (target.clone(), Arc::clone(&live), provider.clone());
        let source = move || if live.load(Ordering::Relaxed) { vec![target.clone()] } else { vec![] };
        let loggers = move |attrs| provider.logger_with_scope(InstrumentationScope::builder("guest").with_attributes(attrs).build());
        start(cursors.clone(), source, loggers)
    };
    let records = |n: usize| {
        let exporter = exporter.clone();
        move || Some(exporter.get_emitted_logs().unwrap()).filter(|logs| logs.len() >= n)
    };
    let next = async |requests: &mut mpsc::UnboundedReceiver<u64>| timeout(WAIT, requests.recv()).await.unwrap().unwrap();

    let relay = start().await.unwrap();
    assert_eq!(next(&mut requests).await, 0);
    assert_eq!(next(&mut requests).await, 1, "a dropped stream reconnects from the last record");
    let logs: Vec<LogDataWithResource> = eventually("two records", records(2)).await;
    let record = &logs[0].record;
    assert_eq!(record.severity_number(), None, "guest stderr carries no severity");
    assert!(matches!(record.body(), Some(AnyValue::String(body)) if body.as_str().len() == 64 << 10));
    let record = &logs[1].record;
    let key = target.key();
    let scope: Vec<_> = logs[1].instrumentation.attributes().map(|kv| (kv.key.as_str().to_owned(), kv.value.to_string())).collect();
    assert!(scope.contains(&("container.id".into(), key.to_string())), "{scope:?}");
    let uid = record.attributes_iter().find(|(k, _)| k.as_str() == "log.record.uid").map(|(_, v)| v.clone());
    assert_eq!(uid, Some(AnyValue::String(format!("{key}:2").into())));
    relay.stop().await;
    let cursor = cursors.join(format!("{key}.cursor"));
    assert_eq!(cursor::load(&cursor).await.unwrap(), 2, "stopping saves the cursor");

    let relay = start().await.unwrap();
    assert_eq!(next(&mut requests).await, 2, "a restarted relay resumes from its cursor");
    eventually("the resumed record", records(3)).await;
    live.store(false, Ordering::Relaxed);
    eventually("the retired cursor to go", || (!cursor.exists()).then_some(())).await;
    relay.stop().await;
}

#[test]
fn generations_fence_cursors_and_record_ids() {
    let target = Target {
        host_id: "h".into(),
        session_id: "s".into(),
        template_id: "t".into(),
        container: "c".into(),
        socket: "/v.sock".into(),
        generation: 1,
    };
    // sha256 of "h\0s\01\0c", pinned: changing the key orphans a host's cursors and its guests' logs replay.
    assert_eq!(target.key().to_string(), "5d37c74d382b76d7f790721516bbe14b86c0079d2e32ec2a39550b59697a271b");
    let next = Target { generation: 2, ..target.clone() };
    assert_ne!(next.key(), target.key());
}

#[tokio::test]
async fn startup_sweeps_dead_cursors_once() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = |c: char| dir.path().join(format!("{}.cursor", c.to_string().repeat(64)));
    std::fs::write(cursor('a'), 1u64.to_be_bytes()).unwrap();
    let provider = SdkLoggerProvider::builder().build();
    let loggers = |attrs| provider.logger_with_scope(InstrumentationScope::builder("guest").with_attributes(attrs).build());
    let cancel = CancellationToken::new();
    let mut supervisor = Supervisor { dir: dir.path().to_owned(), workers: HashMap::new() };

    supervisor.resume(vec![], &loggers, &cancel).await;
    assert!(!cursor('a').exists(), "a stream that ended while the relay was down loses its cursor at startup");
    std::fs::write(cursor('b'), 1u64.to_be_bytes()).unwrap();
    supervisor.reconcile(vec![], &loggers, &cancel).await;
    assert!(cursor('b').exists(), "later ticks don't sweep the directory");
}
