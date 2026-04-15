//! What the manager needs from the host kernel besides the vmm: session networks, nftables, and probing guests. It's
//! behind a trait so the manager's tests can run without root, and on a Mac.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use guestnet::Slot;

/// Where guest traffic leaves the host. guestnet has its own, but it's Linux-only and the manager builds everywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uplink {
    pub iface: String,
    /// The interface's source address, when it has one.
    pub source: Option<Ipv4Addr>,
}

pub trait Host: Send + Sync + 'static {
    fn enable_forwarding(&self) -> Result<()>;
    fn uplink(&self) -> impl Future<Output = Result<Uplink>> + Send;
    fn apply_ruleset(&self, ruleset: String) -> impl Future<Output = Result<()>> + Send;
    /// Builds the slot's namespace with a tap `owner` can open.
    fn create_session(&self, slot: Slot, owner: u32) -> impl Future<Output = Result<()>> + Send;
    fn delete_session(&self, slot: Slot) -> impl Future<Output = Result<()>> + Send;
    /// Re-pins a live session's namespace. A restart loses the pin along with roost's mount namespace.
    fn attach_netns(&self, slot: Slot, pid: u32) -> Result<()>;
    /// Removes session-looking taps and namespaces that aren't in `owned`.
    fn sweep_networks(&self, owned: &[Slot]) -> impl Future<Output = ()> + Send;
    /// Kills unjailed `firecracker_bin` vmms serving a session under `run_dir` that isn't in `owned`. Jailed vmms get
    /// swept through their cgroup instead.
    fn kill_stray_vmms(&self, firecracker_bin: &Path, run_dir: &Path, owned: &[u32]);
    /// Whether a TCP connection to `addr` opens within `within`.
    fn accepts(&self, addr: SocketAddr, within: Duration) -> impl Future<Output = bool> + Send;
}

#[cfg(target_os = "linux")]
pub use linux::Kernel;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::path::PathBuf;

    use anyhow::Context as _;

    use super::{Duration, Host, Path, Result, Slot, SocketAddr, Uplink, unjailed_command};

    /// The real host, through rtnetlink and nft.
    pub struct Kernel {
        net: guestnet::Net,
    }

    impl Kernel {
        /// Needs a tokio runtime to drive the rtnetlink connection.
        pub fn new() -> Result<Self> {
            Ok(Self { net: guestnet::Net::new()? })
        }
    }

    impl Host for Kernel {
        fn enable_forwarding(&self) -> Result<()> {
            guestnet::enable_ip_forward()
        }

        async fn uplink(&self) -> Result<Uplink> {
            let guestnet::Uplink { iface, source } = self.net.uplink().await?;
            Ok(Uplink { iface, source })
        }

        async fn apply_ruleset(&self, ruleset: String) -> Result<()> {
            guestnet::apply_ruleset(&ruleset).await
        }

        async fn create_session(&self, slot: Slot, owner: u32) -> Result<()> {
            // uid 0 from the driver means an unjailed vmm, which runs as root.
            self.net.create_session(&slot, (owner != 0).then_some(nix::unistd::Uid::from_raw(owner))).await
        }

        async fn delete_session(&self, slot: Slot) -> Result<()> {
            self.net.delete_session(&slot).await
        }

        fn attach_netns(&self, slot: Slot, pid: u32) -> Result<()> {
            guestnet::attach_netns(&slot, pid)
        }

        async fn sweep_networks(&self, owned: &[Slot]) {
            let taps: BTreeSet<_> = owned.iter().map(Slot::tap).collect();
            let namespaces: BTreeSet<_> = owned.iter().map(Slot::netns).collect();
            match self.net.list_taps().await {
                Ok(found) => {
                    for tap in found.into_iter().filter(|t| !taps.contains(t)) {
                        tracing::info!(tap, "deleting orphan tap");
                        if let Err(err) = self.net.delete_tap(&tap).await {
                            tracing::error!(tap, error = format!("{err:#}"), "delete orphan tap");
                        }
                    }
                }
                Err(err) => tracing::error!(error = format!("{err:#}"), "list taps"),
            }
            // unpinning a namespace unmounts it, and that syscall blocks.
            let swept = tokio::task::spawn_blocking(move || match guestnet::list_netns() {
                Ok(found) => {
                    for netns in found.into_iter().filter(|n| !namespaces.contains(n)) {
                        tracing::info!(netns, "deleting orphan netns");
                        if let Err(err) = guestnet::delete_netns(&netns) {
                            tracing::error!(netns, error = format!("{err:#}"), "delete orphan netns");
                        }
                    }
                }
                Err(err) => tracing::error!(error = %err, "list netns"),
            });
            if let Err(err) = swept.await {
                tracing::error!(error = %err, "sweep orphan netns");
            }
        }

        fn kill_stray_vmms(&self, firecracker_bin: &Path, run_dir: &Path, owned: &[u32]) {
            let Ok(binary) = fs::metadata(firecracker_bin) else { return };
            let Ok(procs) = fs::read_dir("/proc") else { return };
            for pid in procs.flatten().filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok()) {
                if owned.contains(&pid) {
                    continue;
                }
                let proc = PathBuf::from(format!("/proc/{pid}"));
                // for an unjailed vmm, both the binary and our exact socket and id args have to match.
                let ours = || {
                    use std::os::unix::fs::MetadataExt as _;
                    fs::metadata(proc.join("exe")).is_ok_and(|exe| exe.dev() == binary.dev() && exe.ino() == binary.ino())
                        && fs::read(proc.join("cmdline")).is_ok_and(|cmdline| unjailed_command(&cmdline, run_dir))
                };
                if ours()
                    && let Err(err) = kill_matched(pid, ours)
                {
                    tracing::error!(pid, error = format!("{err:#}"), "kill orphan vmm");
                }
            }
        }

        async fn accepts(&self, addr: SocketAddr, within: Duration) -> bool {
            tokio::time::timeout(within, tokio::net::TcpStream::connect(addr)).await.is_ok_and(|conn| conn.is_ok())
        }
    }

    /// Signals `pid` only if `ours` still holds after a pidfd pins it, so pid reuse can't make us kill the wrong
    /// process.
    fn kill_matched(pid: u32, ours: impl Fn() -> bool) -> Result<()> {
        // SAFETY: pidfd_open takes a pid and flags and returns a new descriptor or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::pid_t::try_from(pid)?, 0) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return if err.raw_os_error() == Some(libc::ESRCH) { Ok(()) } else { Err(err).context("pidfd open") };
        }
        // SAFETY: pidfd_open just returned this descriptor, which nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        if !ours() {
            return Ok(());
        }
        // SAFETY: the descriptor is a live pidfd, and a null siginfo with no flags is the plain kill form.
        let sent = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, fd.as_raw_fd(), libc::SIGKILL, std::ptr::null::<()>(), 0) };
        let err = std::io::Error::last_os_error();
        if sent < 0 && err.raw_os_error() != Some(libc::ESRCH) {
            return Err(err).context("pidfd send sigkill");
        }
        Ok(())
    }
}

/// Whether a NUL-separated command line is exactly the one an unjailed session's vmm runs with:
/// `<bin> --api-sock <run_dir>/<id>.<generation>/fc.sock --id <id>`.
fn unjailed_command(cmdline: &[u8], run_dir: &Path) -> bool {
    let Ok(cmdline) = std::str::from_utf8(cmdline) else { return false };
    let args: Vec<&str> = cmdline.strip_suffix('\0').unwrap_or(cmdline).split('\0').collect();
    let [_, "--api-sock", sock, "--id", id] = args[..] else { return false };
    if id.is_empty() || id.contains('/') {
        return false;
    }
    let Some(generation) = Path::new(sock).parent().and_then(Path::file_name).and_then(|d| d.to_str()?.strip_prefix(&format!("{id}.")))
    else {
        return false;
    };
    generation.parse::<u64>().is_ok_and(|g| g > 0 && Path::new(sock) == run_dir.join(format!("{id}.{g}")).join("fc.sock"))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::ours(b"/usr/bin/firecracker\0--api-sock\0/run/birdfeeder/h-0.3/fc.sock\0--id\0h-0\0", true)]
    #[case::generation_zero(b"/usr/bin/firecracker\0--api-sock\0/run/birdfeeder/h-0.0/fc.sock\0--id\0h-0\0", false)]
    #[case::other_id(b"/usr/bin/firecracker\0--api-sock\0/run/birdfeeder/h-0.3/fc.sock\0--id\0h-1\0", false)]
    #[case::other_run_dir(b"/usr/bin/firecracker\0--api-sock\0/tmp/h-0.3/fc.sock\0--id\0h-0\0", false)]
    #[case::padded_generation(b"/usr/bin/firecracker\0--api-sock\0/run/birdfeeder/h-0.03/fc.sock\0--id\0h-0\0", false)]
    #[case::other_command(b"/bin/sh\0-c\0echo /run/birdfeeder/h-0.3/fc.sock\0", false)]
    #[case::extra_arg(b"/usr/bin/firecracker\0--api-sock\0/run/birdfeeder/h-0.3/fc.sock\0--id\0h-0\0--extra\0", false)]
    fn unjailed_command_matches_exactly(#[case] cmdline: &[u8], #[case] ours: bool) {
        assert_eq!(unjailed_command(cmdline, Path::new("/run/birdfeeder")), ours);
    }
}
