use std::fs;
use std::io::IoSliceMut;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use nix::poll::PollFlags;
use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};

use crate::sys::PollSet;

const MAX_BYTES: usize = 64 << 10;
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Accepts the one VMM this handler serves, then closes the listener.
pub fn accept(sock: &Path) -> Result<UnixStream> {
    // bind creates the path before listen, and roost waits on the path. so listen under a temp
    // name and rename it, that way the path only shows up once connect will work.
    let mut tmp = sock.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = Path::new(&tmp);
    let listener = UnixListener::bind(tmp).with_context(|| format!("listen {}", tmp.display()))?;
    fs::rename(tmp, sock).context("publish handshake socket")?;
    let accepted = accept_within(&listener, ACCEPT_TIMEOUT).with_context(|| format!("accept on {}", sock.display()));
    let _ = fs::remove_file(sock);
    accepted
}

fn accept_within(listener: &UnixListener, timeout: Duration) -> Result<UnixStream> {
    let mut fds = PollSet::default();
    let listening = fds.add(listener.as_fd(), PollFlags::POLLIN);
    fds.wait(timeout)?;
    ensure!(fds.ready(listening), "no vmm connected within {timeout:?}");
    Ok(listener.accept()?.0)
}

/// Reads Firecracker's handshake: the guest memory layout as JSON, plus the userfaultfd.
pub fn receive(conn: &UnixStream) -> Result<(Vec<u8>, OwnedFd)> {
    let mut body = vec![0; MAX_BYTES];
    let mut cmsg = nix::cmsg_space!(std::os::fd::RawFd);
    let mut iov = [IoSliceMut::new(&mut body)];
    let msg = recvmsg::<()>(conn.as_raw_fd(), &mut iov, Some(&mut cmsg), MsgFlags::MSG_CMSG_CLOEXEC).context("read handshake")?;
    ensure!(!msg.flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC), "handshake truncated (flags {:?})", msg.flags);
    let n = msg.bytes;
    let mut fds = Vec::new();
    for c in msg.cmsgs().context("parse control message")? {
        if let ControlMessageOwned::ScmRights(raw) = c {
            // SAFETY: SCM_RIGHTS just put these fds in our process and nobody else owns them.
            fds.extend(raw.into_iter().map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }));
        }
    }
    body.truncate(n);
    let Some(uffd) = fds.into_iter().next() else {
        bail!("handshake carried no uffd: {:?}", String::from_utf8_lossy(&body));
    };
    Ok((body, uffd))
}
