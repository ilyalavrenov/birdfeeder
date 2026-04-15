//! Persistent taps. The kernel can't create one over rtnetlink, so this does the same `/dev/net/tun` ioctl dance as `ip
//! tuntap add`.

use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd as _;

use anyhow::Context as _;
use nix::unistd::Uid;

/// Creates a persistent tap in the calling thread's namespace, owned by `owner` if given, otherwise root. Like `ip
/// tuntap` there's no packet-info header, which is how Firecracker reopens it.
pub(super) fn create(name: &str, owner: Option<Uid>) -> anyhow::Result<()> {
    let tun = OpenOptions::new().read(true).write(true).open("/dev/net/tun").context("open /dev/net/tun")?;
    let fd = tun.as_raw_fd();

    // SAFETY: ifreq is plain old data, and all-zero is a valid (empty) request.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    anyhow::ensure!(name.len() < req.ifr_name.len(), "tap name {name:?} too long");
    for (dst, src) in req.ifr_name.iter_mut().zip(name.bytes()) {
        *dst = libc::c_char::from_ne_bytes([src]);
    }
    req.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;

    // SAFETY: TUNSETIFF reads and writes an ifreq, which req is and outlives the call.
    check(unsafe { libc::ioctl(fd, libc::TUNSETIFF, &raw mut req) }).with_context(|| format!("create tap {name}"))?;
    if let Some(owner) = owner.map(Uid::as_raw) {
        // SAFETY: TUNSETOWNER and TUNSETGROUP take the id by value.
        check(unsafe { libc::ioctl(fd, libc::TUNSETOWNER, libc::c_ulong::from(owner)) }).context("set tap owner")?;
        // SAFETY: as above.
        check(unsafe { libc::ioctl(fd, libc::TUNSETGROUP, libc::c_ulong::from(owner)) }).context("set tap group")?;
    }
    // SAFETY: TUNSETPERSIST takes a flag by value.
    check(unsafe { libc::ioctl(fd, libc::TUNSETPERSIST, libc::c_ulong::from(true)) }).context("persist tap")
}

fn check(ret: libc::c_int) -> io::Result<()> {
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}
