//! A working set is the memory-file offsets a restored guest faulted on, in first-touch order, as
//! little-endian u64s. Offsets, not addresses, since each VMM maps guest memory somewhere else.

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result, ensure};

const WORD: usize = 8;
/// Caps a working set file at 1 TiB worth of 4 KiB pages.
const MAX_BYTES: u64 = 2 << 30;
/// Batches 4 KiB pages into fewer writes. Hugepages are big enough to write directly.
const WRITE_BUFFER: usize = 1 << 20;

pub fn encode(offsets: &[u64]) -> Vec<u8> {
    offsets.iter().copied().flat_map(u64::to_le_bytes).collect()
}

pub fn decode(data: &[u8]) -> Result<Vec<u64>> {
    ensure!(data.len().is_multiple_of(WORD), "working set isn't a whole number of offsets");
    Ok(data.as_chunks::<WORD>().0.iter().map(|&w| u64::from_le_bytes(w)).collect())
}

pub fn read(path: &Path) -> Result<Vec<u64>> {
    let size = fs::metadata(path).context("stat working set")?.len();
    ensure!(size <= MAX_BYTES, "working set is {size} bytes");
    decode(&fs::read(path).context("read working set")?)
}

/// Replaces `path` so a reader never sees half of `data`.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    write_atomic_with(path, |w| w.write_all(data))
}

/// Like [`write_atomic`], streaming the contents from `write`.
pub fn write_atomic_with(path: &Path, write: impl FnOnce(&mut BufWriter<File>) -> io::Result<()>) -> Result<()> {
    let name = path.file_name().context("no file name")?.to_string_lossy();
    let tmp = path.with_file_name(format!(".{name}.{}", std::process::id()));
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|f| {
            let mut w = BufWriter::with_capacity(WRITE_BUFFER, f);
            write(&mut w)?;
            w.flush()
        })
        .and_then(|()| fs::rename(&tmp, path));
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written.with_context(|| format!("write {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_in_first_touch_order() {
        let offsets = [0x3000, 0, 0x1000];
        assert_eq!(decode(&encode(&offsets)).unwrap(), offsets);
        assert!(decode(&[1, 2, 3]).is_err());
    }

    #[test]
    fn write_atomic_replaces_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ws");
        fs::write(&path, b"old").unwrap();
        write_atomic(&path, &encode(&[7])).unwrap();
        assert_eq!(read(&path).unwrap(), [7]);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1, "no temporary file left behind");
    }

    #[test]
    fn write_atomic_with_keeps_the_old_file_when_writing_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pack");
        fs::write(&path, b"old").unwrap();
        let failed = write_atomic_with(&path, |w| {
            w.write_all(&vec![1; WRITE_BUFFER + 1])?;
            Err(io::Error::other("disk full"))
        });
        assert!(failed.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1, "no temporary file left behind");

        write_atomic_with(&path, |w| (0..3u8).try_for_each(|i| w.write_all(&[i; 4096]))).unwrap();
        let data = fs::read(&path).unwrap();
        assert_eq!((data.len(), data[0], data[4096], data[8191 + 4096]), (3 * 4096, 0, 1, 2));
    }
}
