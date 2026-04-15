//! Checks that a host can run roost's guests: KVM works, and no forward chain drops their egress by default.

use std::process::{Command, ExitCode};

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;

fn main() -> ExitCode {
    for check in [check_kvm, check_forward_policy] {
        match check() {
            Ok(passed) => println!("{passed}"),
            Err(e) => {
                eprintln!("{e:#}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

#[cfg(target_os = "linux")]
fn check_kvm() -> Result<String> {
    use std::{
        fs::OpenOptions,
        io,
        os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd},
    };

    const GET_API_VERSION: libc::Ioctl = 0xae00;
    const CREATE_VM: libc::Ioctl = 0xae01;
    const CREATE_VCPU: libc::Ioctl = 0xae41;
    // the KVM API docs require refusing any other version.
    const API_VERSION: libc::c_int = 12;

    fn ioctl(fd: BorrowedFd<'_>, request: libc::Ioctl) -> io::Result<libc::c_int> {
        // SAFETY: each of these KVM ioctls takes an integer argument, 0 here, and reads or writes no caller memory.
        let r = unsafe { libc::ioctl(fd.as_raw_fd(), request, 0 as libc::c_ulong) };
        if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
    }
    fn create(fd: BorrowedFd<'_>, request: libc::Ioctl) -> io::Result<OwnedFd> {
        let fd = ioctl(fd, request)?;
        // SAFETY: a successful create ioctl returns a new descriptor that nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    let kvm = OpenOptions::new().read(true).write(true).open("/dev/kvm").context("KVM device")?;
    let version = ioctl(kvm.as_fd(), GET_API_VERSION).context("KVM API version")?;
    if version != API_VERSION {
        bail!("unexpected KVM API version: {version}");
    }
    let vm = create(kvm.as_fd(), CREATE_VM).context("create KVM VM")?;
    create(vm.as_fd(), CREATE_VCPU).context("create KVM vCPU")?;
    Ok("KVM API, VM, and vCPU creation passed".into())
}

#[cfg(not(target_os = "linux"))]
fn check_kvm() -> Result<String> {
    bail!("KVM needs Linux")
}

/// An accept in roost's table doesn't override a drop from another table at the same hook, so a dropping forward
/// policy (Docker sets one) silently blocks granted guest egress.
fn check_forward_policy() -> Result<String> {
    if !is_root() {
        return Ok("forward policy check skipped: reading nftables needs root".into());
    }
    let out = Command::new("nft").args(["-j", "list", "chains"]).output().context("list nftables chains")?;
    if !out.status.success() {
        bail!("list nftables chains: {}: {}", out.status, String::from_utf8_lossy(&out.stderr).trim());
    }
    forward_drop_chain(&out.stdout)?;
    Ok("no forward chain drops by default".into())
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and can't fail.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(target_os = "linux"))]
fn is_root() -> bool {
    false
}

fn forward_drop_chain(chains: &[u8]) -> Result<()> {
    #[derive(Deserialize)]
    struct Ruleset {
        nftables: Vec<Item>,
    }
    #[derive(Deserialize)]
    struct Item {
        chain: Option<Chain>,
    }
    #[derive(Deserialize)]
    struct Chain {
        family: String,
        table: String,
        name: String,
        hook: Option<String>,
        policy: Option<String>,
    }
    let ruleset: Ruleset = serde_json::from_slice(chains).context("decode nftables chains")?;
    for c in ruleset.nftables.into_iter().filter_map(|i| i.chain) {
        if c.hook.as_deref() == Some("forward") && c.policy.as_deref() == Some("drop") && matches!(c.family.as_str(), "ip" | "inet") {
            bail!("forward chain {} {} {} drops by default; guest egress needs a forward policy of accept", c.family, c.table, c.name);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::forward_drop_chain;

    fn chain(family: &str, hook: &str, policy: &str) -> String {
        format!(
            r#"{{"chain":{{"family":"{family}","table":"filter","name":"FORWARD","handle":1,"type":"filter","hook":"{hook}","prio":0,"policy":"{policy}"}}}}"#
        )
    }

    fn ruleset(items: &[String]) -> Vec<u8> {
        let meta = r#"{"metainfo":{"version":"1.1.1","json_schema_version":1}}"#;
        // a regular chain has no hook or policy.
        let regular = r#"{"chain":{"family":"ip","table":"filter","name":"DOCKER","handle":2}}"#;
        format!(r#"{{"nftables":[{meta},{regular},{}]}}"#, items.join(",")).into_bytes()
    }

    #[test]
    fn finds_dropping_forward_chains() {
        let ignored = ruleset(&[chain("ip", "forward", "accept"), chain("ip6", "forward", "drop"), chain("ip", "input", "drop")]);
        forward_drop_chain(&ignored).unwrap();
        let err = forward_drop_chain(&ruleset(&[chain("ip", "forward", "drop")])).unwrap_err();
        assert!(err.to_string().contains("forward chain ip filter FORWARD drops by default"), "{err}");
        assert!(forward_drop_chain(&ruleset(&[chain("inet", "forward", "drop")])).is_err());
    }
}
