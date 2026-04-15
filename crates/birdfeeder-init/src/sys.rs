use std::fs::File;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

use nix::fcntl::{FallocateFlags, fallocate};
use nix::sys::statfs::statfs;
use nix::sys::time::TimeSpec;
use nix::time::{ClockId, clock_settime};

use crate::stats::Disk;

/// Sets a restored guest's wall clock to the host's. The monotonic clock stays on the snapshot's timeline.
pub fn set_realtime(since_epoch: Duration) -> io::Result<()> {
    Ok(clock_settime(ClockId::CLOCK_REALTIME, TimeSpec::from_duration(since_epoch))?)
}

/// Frees `[off, off+len)` of `file` in place. The size and every offset after the hole stay put.
pub fn punch_hole(file: &File, off: u64, len: u64) -> io::Result<()> {
    let (off, len) = (i64::try_from(off).map_err(io::Error::other)?, i64::try_from(len).map_err(io::Error::other)?);
    Ok(fallocate(file, FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_KEEP_SIZE, off, len)?)
}

/// Reserves `[off, off+len)` of `file` without changing its size, so a write there can't run out of space.
pub fn reserve(file: &File, off: u64, len: u64) -> io::Result<()> {
    let (off, len) = (i64::try_from(off).map_err(io::Error::other)?, i64::try_from(len).map_err(io::Error::other)?);
    Ok(fallocate(file, FallocateFlags::FALLOC_FL_KEEP_SIZE, off, len)?)
}

/// The rootfs is read-only, so the scratch disk is the only writable space that can fill up.
pub fn disk_stats(path: &Path) -> Option<Disk> {
    let st = statfs(path).ok()?;
    #[allow(clippy::useless_conversion, reason = "f_bsize is signed in glibc and unsigned in musl")]
    let block = u64::try_from(st.block_size()).ok()?;
    Some(Disk { total_bytes: st.blocks().checked_mul(block)?, free_bytes: st.blocks_free().checked_mul(block)? })
}

/// An fd that polls readable once the child exits. Unlike a pid it can't end up pointing at
/// another process, and it leaves reaping to whoever owns the child.
pub fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes a pid and flags and returns a new descriptor or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::pid_t::try_from(pid).map_err(io::Error::other)?, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = i32::try_from(fd).map_err(io::Error::other)?;
    // SAFETY: the syscall just returned fd, which nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
