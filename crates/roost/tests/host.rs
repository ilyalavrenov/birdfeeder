//! What a host needs before roost can run guests on it. dev/run-linux.sh's integration suite runs these.

use std::path::Path;
use std::process::Command;

#[test]
#[ignore = "checks the host's KVM setup"]
fn host_prerequisites() {
    for path in ["/dev/net/tun", "/sys/fs/cgroup/cgroup.controllers"] {
        assert!(Path::new(path).exists(), "{path} is missing");
    }
    for tool in ["nft", "ip", "jailer"] {
        let found = Command::new("sh").args(["-c", &format!("command -v {tool}")]).status().unwrap();
        assert!(found.success(), "{tool} isn't on PATH");
    }
    let out = Command::new("firecracker").arg("--version").output().expect("run firecracker");
    let version = String::from_utf8_lossy(&out.stdout);
    assert!(
        version.contains(&format!("Firecracker {}", fcapi::FIRECRACKER_TAG)),
        "Firecracker differs from the version its API types were generated from: {version}"
    );
}
