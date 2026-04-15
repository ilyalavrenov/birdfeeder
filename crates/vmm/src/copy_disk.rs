use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use tracing_opentelemetry::OpenTelemetrySpanExt;

#[derive(Debug, thiserror::Error)]
pub enum CopyDiskError {
    /// Separate from target failures so callers can tell a missing base from a full target.
    #[error("unreadable base disk {}", path.display())]
    UnreadableBase {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{op} {}", path.display())]
    Target {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Reflinks `base` to `dst` if the filesystem supports it, otherwise copies its allocated extents. Overwrites an
/// existing `dst` and keeps its mode, like cp.
pub async fn copy_disk(base: &Path, dst: &Path) -> anyhow::Result<()> {
    let (base, dst) = (base.to_owned(), dst.to_owned());
    let cloned = tokio::task::spawn_blocking(move || copy(&base, &dst)).await??;
    tracing::Span::current().set_attribute("birdfeeder.disk.reflink", cloned);
    Ok(())
}

fn copy(base: &Path, dst: &Path) -> Result<bool, CopyDiskError> {
    let unreadable = |source| CopyDiskError::UnreadableBase { path: base.to_owned(), source };
    let target = |op| move |source| CopyDiskError::Target { op, path: dst.to_owned(), source };
    let src = File::open(base).map_err(unreadable)?;
    let meta = src.metadata().map_err(unreadable)?;
    let out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(meta.permissions().mode() & 0o7777)
        .open(dst)
        .map_err(target("create"))?;
    let cloned = sys::reflink(&src, &out).map_err(target("clone into"))?;
    if !cloned {
        sys::sparse_copy(&src, &out, meta.len()).map_err(target("copy into"))?;
    }
    Ok(cloned)
}

#[cfg(target_os = "linux")]
mod sys {
    use std::fs::File;
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;

    use nix::errno::Errno;
    use nix::unistd::{Whence, lseek};

    /// Whether `dst` now shares `src`'s extents. False means the filesystem can't do it and we need to copy.
    pub fn reflink(src: &File, dst: &File) -> io::Result<bool> {
        // SAFETY: FICLONE takes the source descriptor as its argument; both stay open for the call.
        match Errno::result(unsafe { libc::ioctl(dst.as_raw_fd(), libc::FICLONE, src.as_raw_fd()) }) {
            Ok(_) => Ok(true),
            Err(Errno::EOPNOTSUPP | Errno::EXDEV | Errno::EINVAL | Errno::ENOSYS | Errno::ENOTTY) => Ok(false),
            Err(errno) => Err(errno.into()),
        }
    }

    pub fn sparse_copy(mut src: &File, mut dst: &File, size: u64) -> io::Result<()> {
        let mut off = 0_u64;
        while off < size {
            // a file's offsets fit in an off_t
            let data = match lseek(src, off.cast_signed(), Whence::SeekData) {
                Err(Errno::ENXIO) => break, // only a hole left
                data => data?,
            };
            let hole = lseek(src, data, Whence::SeekHole)?;
            let (data, hole) = (data.cast_unsigned(), hole.cast_unsigned());
            src.seek(SeekFrom::Start(data))?;
            dst.seek(SeekFrom::Start(data))?;
            io::copy(&mut src.take(hole - data), &mut dst)?;
            off = hole;
        }
        dst.flush()?;
        // a trailing hole never gets written, so set the size by hand
        dst.set_len(size)
    }
}

#[cfg(not(target_os = "linux"))]
mod sys {
    use std::fs::File;
    use std::io::{self, Seek, SeekFrom};

    #[expect(clippy::unnecessary_wraps, reason = "Linux's can fail")]
    pub fn reflink(_: &File, _: &File) -> io::Result<bool> {
        Ok(false)
    }

    pub fn sparse_copy(mut src: &File, mut dst: &File, size: u64) -> io::Result<()> {
        src.seek(SeekFrom::Start(0))?;
        io::copy(&mut src, &mut dst)?;
        dst.set_len(size)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{FileExt, MetadataExt};

    use super::*;

    const MIB: u64 = 1 << 20;

    #[tokio::test]
    async fn copies_keep_holes_and_an_existing_mode() {
        let dir = tempfile::tempdir().unwrap();
        let (base, dst) = (dir.path().join("base.ext4"), dir.path().join("guest.ext4"));
        let f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&base).unwrap();
        f.write_all_at(&b"head".repeat(1024), 0).unwrap();
        f.write_all_at(&b"tail".repeat(1024), 64 * MIB).unwrap();
        f.set_len(65 * MIB).unwrap();
        drop(f);

        copy_disk(&base, &dst).await.unwrap();
        assert_eq!(fs::read(&base).unwrap(), fs::read(&dst).unwrap());
        let (src_meta, dst_meta) = (fs::metadata(&base).unwrap(), fs::metadata(&dst).unwrap());
        assert_eq!(dst_meta.mode() & 0o777, 0o600);
        // only Linux copies sparsely
        if cfg!(target_os = "linux") && src_meta.blocks() * 512 < src_meta.len() {
            assert!(dst_meta.blocks() * 512 < src_meta.len() / 8, "holes survive the copy");
        }

        fs::write(&dst, b"stale".repeat(3 * MIB as usize)).unwrap();
        fs::set_permissions(&dst, fs::Permissions::from_mode(0o644)).unwrap();
        copy_disk(&base, &dst).await.unwrap();
        assert_eq!(fs::read(&base).unwrap(), fs::read(&dst).unwrap());
        assert_eq!(fs::metadata(&dst).unwrap().mode() & 0o777, 0o644, "cp keeps an existing dst's mode");
    }

    #[test]
    fn a_missing_base_names_itself() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("nope");
        let err = copy(&base, &dir.path().join("dst")).unwrap_err();
        assert!(
            matches!(&err, CopyDiskError::UnreadableBase { path, source } if *path == base && source.kind() == io::ErrorKind::NotFound),
            "{err:?}"
        );
        assert!(crate::base_unreadable(&anyhow::Error::new(err).context("boot")));
    }

    #[test]
    fn an_unwritable_target_isnt_the_bases_fault() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base");
        fs::write(&base, "disk").unwrap();
        let err = anyhow::Error::new(copy(&base, &dir.path().join("missing-dir/dst")).unwrap_err());
        assert!(format!("{err:#}").contains("create "), "{err:#}");
        assert!(!crate::base_unreadable(&err));
    }
}
