use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};
use memmap2::{Mmap, MmapOptions};
use nix::errno::Errno;
use nix::unistd::{Whence, lseek};

use crate::extents::Extents;
use crate::layout::PageSize;

/// A local snapshot memory file, mapped read-only, plus which extents hold data.
pub struct MemFile {
    map: Mmap,
    pub data: Extents,
}

impl MemFile {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).context("open memory file")?;
        let size = file.metadata().context("stat memory file")?.len();
        let data = data_extents(&file, size)?;
        // SAFETY: roost writes a snapshot once, before any restore maps it, and never changes it after.
        let map = unsafe { MmapOptions::new().map_copy_read_only(&file) }.context("mmap memory file")?;
        Ok(Self { map, data })
    }

    pub fn size(&self) -> u64 {
        self.map.len() as u64
    }

    /// The page at `off`, or `None` when it's a hole and reads as zeros.
    pub fn page(&self, off: u64, ps: PageSize) -> Option<&[u8]> {
        if !self.data.overlaps(off..off + ps.get()) {
            return None;
        }
        let start = usize::try_from(off).expect("the file is mapped, so its offsets fit");
        Some(&self.map[start..start + ps.bytes()])
    }
}

fn data_extents(file: &File, size: u64) -> Result<Extents> {
    let offset = |o: u64| i64::try_from(o).expect("file offsets fit in off_t");
    let mut out = Vec::new();
    let mut off = 0;
    while off < size {
        let data = match lseek(file, offset(off), Whence::SeekData) {
            Ok(data) => data.cast_unsigned(),
            Err(Errno::ENXIO) => break,
            Err(e) => return Err(e).with_context(|| format!("seek data at {off}")),
        };
        let hole = lseek(file, offset(data), Whence::SeekHole).with_context(|| format!("seek hole at {data}"))?.cast_unsigned();
        out.push(data..hole);
        off = hole;
    }
    Ok(Extents(out))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::FileExt;

    use super::*;

    #[test]
    fn reads_holes_as_zeros() {
        let ps = PageSize::new(4096).unwrap();
        let page = ps.get();
        let f = tempfile::NamedTempFile::new().unwrap();
        f.as_file().write_at(&[7], page).unwrap();
        f.as_file().set_len(4 * page).unwrap();

        let m = MemFile::open(f.path()).unwrap();
        assert_eq!(m.size(), 4 * page);
        assert!(m.page(0, ps).is_none(), "page 0 is a hole");
        assert_eq!(m.page(page, ps).map(|p| p[0]), Some(7), "page 1 holds data");
        assert!(m.page(3 * page, ps).is_none(), "the truncated tail is a hole");
    }
}
