//! userfaultfd ioctls and messages, copied from uapi/linux/userfaultfd.h. libc only has the
//! syscall number.

use std::fmt;
use std::ops::Range;
use std::os::fd::{AsRawFd, BorrowedFd};

use nix::errno::Errno;

pub const MSG_SIZE: usize = 32;
const EVENT_PAGEFAULT: u8 = 0x12;
const EVENT_REMOVE: u8 = 0x15;
const PAGEFAULT_ADDR: usize = 16;
const REMOVE_START: usize = 8;
const REMOVE_END: usize = 16;

#[repr(C)]
struct UffdioCopy {
    dst: u64,
    src: u64,
    len: u64,
    mode: u64,
    copy: i64,
}

nix::ioctl_readwrite!(uffdio_copy, 0xAA, 0x03, UffdioCopy);

pub enum Event {
    Pagefault(u64),
    Remove(Range<u64>),
    Other(u8),
}

impl Event {
    pub fn parse(msg: &[u8; MSG_SIZE]) -> Self {
        let word = |at: usize| u64::from_ne_bytes(*msg[at..].first_chunk().expect("fields lie inside the message"));
        match msg[0] {
            EVENT_PAGEFAULT => Self::Pagefault(word(PAGEFAULT_ADDR)),
            EVENT_REMOVE => Self::Remove(word(REMOVE_START)..word(REMOVE_END)),
            other => Self::Other(other),
        }
    }
}

/// Why `UFFDIO_COPY` stopped short.
#[derive(Debug, PartialEq, Eq)]
pub enum CopyErr {
    /// The first page is already in, so nothing was copied.
    Exists,
    /// Pending remove events block the copy until we read them. `copied` bytes made it in first.
    /// The kernel reports every partial copy this way, no matter what stopped it.
    Again {
        copied: u64,
    },
    /// The VMM's memory is gone. Exit tears down the mm before closing files, so this can show up
    /// before the handshake socket's EOF.
    VmmGone,
    Other(Errno),
}

impl fmt::Display for CopyErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exists => f.write_str("page already populated"),
            Self::Again { copied } => write!(f, "blocked by pending events after {copied} bytes"),
            Self::VmmGone => f.write_str("vmm exited"),
            Self::Other(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for CopyErr {}

/// Copies `src` to the guest at `dst`, retrying when a signal interrupts it.
pub fn copy(uffd: BorrowedFd<'_>, dst: u64, src: &[u8]) -> Result<(), CopyErr> {
    let len = src.len() as u64;
    loop {
        let mut arg = UffdioCopy { dst, src: src.as_ptr() as u64, len, mode: 0, copy: 0 };
        // SAFETY: arg is a live uffdio_copy for the whole call and src is readable for len bytes.
        // the kernel only writes arg.copy.
        let res = unsafe { uffdio_copy(uffd.as_raw_fd(), &raw mut arg) };
        // a negative copy is the errno and means nothing landed. only a partial copy reports EAGAIN
        // with bytes copied, so an interrupted one copied nothing and we can just retry
        return match res {
            Ok(_) => Ok(()),
            Err(Errno::EINTR) => continue,
            Err(Errno::EEXIST) => Err(CopyErr::Exists),
            Err(Errno::EAGAIN) => Err(CopyErr::Again { copied: u64::try_from(arg.copy).unwrap_or(0) }),
            Err(Errno::ESRCH) => Err(CopyErr::VmmGone),
            Err(e) => Err(CopyErr::Other(e)),
        };
    }
}
