//! What roost and birdfeeder-init agree on: the workload roost puts in MMDS, and the vsock API the guest serves on
//! [`PORT`], which the host reaches through Firecracker's hybrid vsock. The host's client needs the `client` feature.
//! The guest only uses the types.

#[cfg(feature = "client")]
mod client;
pub mod protocol;
pub mod stats;
pub mod workload;

#[cfg(feature = "client")]
pub use client::{connect, set_clock, stats};

/// The guest port birdfeeder-init listens on.
pub const PORT: u32 = 5000;

/// Longest line a guest log record carries, in UTF-8 bytes. birdfeeder-init splits anything longer.
pub const MAX_LOG_LINE: usize = 64 << 10;
/// Longest guest log record, not counting the newline. JSON escaping can blow a max-length line up to 6x.
pub const MAX_LOG_RECORD: usize = 8 * MAX_LOG_LINE;
