use std::os::fd::BorrowedFd;
use std::time::Duration;

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout};

/// Fds to poll. Read each one back through the slot `add` handed out, not by position.
#[derive(Default)]
pub struct PollSet<'fd>(Vec<PollFd<'fd>>);

#[derive(Clone, Copy)]
pub struct Slot(usize);

impl<'fd> PollSet<'fd> {
    pub fn add(&mut self, fd: BorrowedFd<'fd>, events: PollFlags) -> Slot {
        self.0.push(PollFd::new(fd, events));
        Slot(self.0.len() - 1)
    }

    /// Waits up to `timeout` for any of the fds. A signal interrupting it looks like a timeout:
    /// no events.
    pub fn wait(&mut self, timeout: Duration) -> Result<()> {
        let timeout = PollTimeout::try_from(timeout).expect("poll timeouts fit in an int of milliseconds");
        match nix::poll::poll(&mut self.0, timeout) {
            Ok(_) | Err(Errno::EINTR) => Ok(()),
            Err(e) => Err(e).context("poll"),
        }
    }

    /// Whether `slot` saw anything: what it asked for, or an error or hangup.
    pub fn ready(&self, slot: Slot) -> bool {
        // nix gives None for a bit it has no flag for, but that's still an event
        self.0[slot.0].revents().is_none_or(|r| !r.is_empty())
    }

    pub fn readable(&self, slot: Slot) -> bool {
        self.0[slot.0].revents().is_some_and(|r| r.contains(PollFlags::POLLIN))
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn sees_a_peer_hang_up() {
        let (conn, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let mut fds = PollSet::default();
        let slot = fds.add(conn.as_fd(), PollFlags::POLLIN);
        fds.wait(Duration::ZERO).unwrap();
        assert!(fds.ready(slot));
        assert!(fds.readable(slot), "EOF reads as readable");
    }

    #[test]
    fn counts_a_flag_nix_lacks_as_ready() {
        let (conn, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let mut fds = PollSet::default();
        let slot = fds.add(conn.as_fd(), PollFlags::from_bits_retain(libc::POLLRDHUP));
        fds.wait(Duration::ZERO).unwrap();
        assert!(fds.ready(slot));
    }
}
