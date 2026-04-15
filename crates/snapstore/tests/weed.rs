//! Uploads to weed's S3 API and reads the objects back by range, like a restored guest's handler does.
//! dev/run-linux.sh runs it with weed on the PATH and the credentials below in the environment.

use std::{
    fs,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime},
};

use snapstore::{Config, Store};

const ACCESS_KEY: &str = "snapstore-test";
const SECRET_KEY: &str = "snapstore-test-secret";
const S3_PORT: u16 = 28333;

/// Kills weed instead of waiting on its slow shutdown, and cleans up the sockets it leaves in /tmp.
struct Weed {
    child: Child,
    started: SystemTime,
}

impl Drop for Weed {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for entry in fs::read_dir("/tmp").into_iter().flatten().flatten() {
            let name = entry.file_name();
            let ours = entry.metadata().and_then(|m| m.modified()).is_ok_and(|modified| modified >= self.started);
            if name.to_string_lossy().starts_with("seaweedfs-") && name.to_string_lossy().ends_with(".sock") && ours {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

fn weed(dir: &std::path::Path) -> Weed {
    let identities = serde_json::json!({"identities": [{"name": "test", "credentials": [{"accessKey": ACCESS_KEY, "secretKey": SECRET_KEY}], "actions": ["Admin", "Read", "Write", "List"]}]});
    fs::write(dir.join("s3.json"), identities.to_string()).unwrap();
    let started = SystemTime::now();
    let log = fs::File::create(dir.join("weed.log")).unwrap();
    let child = Command::new("weed")
        .args(["mini", "-ip", "127.0.0.1", "-ip.bind", "127.0.0.1", "-admin.ui=false"])
        .args(["-master.port", "29333", "-volume.port", "28089", "-filer.port", "28888"])
        .arg(format!("-s3.port={S3_PORT}"))
        .arg(format!("-dir={}", dir.display()))
        .arg(format!("-s3.config={}", dir.join("s3.json").display()))
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .stdin(Stdio::null())
        .spawn()
        .expect("weed on the PATH");
    let weed = Weed { child, started };
    // weed 4.20's mini has no -bucket. the shell waits for the cluster to come up.
    let status = Command::new("sh")
        .args(["-c", "echo 's3.bucket.create -name snapshots' | weed shell -master=127.0.0.1:29333"])
        .stdout(Stdio::null())
        .status()
        .expect("run weed shell");
    assert!(status.success(), "weed shell: {status}");
    weed
}

fn get(url: &str, range: &str) -> Vec<u8> {
    let mut response = ureq::get(url).header("Range", range).call().unwrap();
    assert_eq!(response.status(), 206, "{range}");
    response.body_mut().read_to_vec().unwrap()
}

#[tokio::test]
#[ignore = "needs weed and its credentials"]
async fn uploads_read_back_by_range() {
    assert_eq!(std::env::var("AWS_ACCESS_KEY_ID").as_deref(), Ok(ACCESS_KEY), "run with the test's credentials");
    let dir = tempfile::tempdir().unwrap();
    let _weed = weed(dir.path());
    let config = Config {
        endpoint: Some(format!("http://127.0.0.1:{S3_PORT}")),
        region: "us-east-1".into(),
        bucket: "snapshots".into(),
        prefix: "test".into(),
        path_style: true,
        presign_ttl: Duration::from_mins(15),
    };
    let store = Store::new(&config).await.unwrap();

    let small = dir.path().join("small");
    fs::write(&small, b"probe").unwrap();
    let key = store.key(&["host", "tpl", "probe"]);
    // the bucket shows up a bit after the S3 port opens.
    let deadline = Instant::now() + Duration::from_mins(1);
    while let Err(err) = store.put(&key, &small).await {
        assert!(
            Instant::now() < deadline,
            "weed never took an upload: {err:#}\n{}",
            fs::read_to_string(dir.path().join("weed.log")).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(get(&store.url(&key).await.unwrap(), "bytes=1-3"), b"rob");

    // three parts, the last one short.
    let memory: Vec<u8> = (0..(16 << 20) + 3).map(|i: u32| (i % 251) as u8).collect();
    let mem = dir.path().join("mem");
    fs::write(&mem, &memory).unwrap();
    let key = store.key(&["host", "tpl", "mem"]);
    store.put(&key, &mem).await.unwrap();
    let url = store.url(&key).await.unwrap();
    let boundary = 8 << 20;
    assert_eq!(get(&url, &format!("bytes={}-{}", boundary - 2, boundary + 1)), memory[boundary - 2..boundary + 2]);
    assert_eq!(get(&url, &format!("bytes={}-", memory.len() - 5)), memory[memory.len() - 5..]);
}
