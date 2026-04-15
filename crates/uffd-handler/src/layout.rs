use std::collections::HashSet;
use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

/// A guest memory region and its offset in the snapshot file, as Firecracker's handshake sends it.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub struct Mapping {
    pub base_host_virt_addr: u64,
    pub size: u64,
    pub offset: u64,
    pub page_size: u64,
}

/// A guest page size. It's a power of two that fits in both u64 and usize, so converting either
/// way needs no check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageSize(usize);

impl PageSize {
    pub fn new(bytes: u64) -> Option<Self> {
        usize::try_from(bytes).ok().filter(|b| b.is_power_of_two()).map(Self)
    }

    pub fn get(self) -> u64 {
        self.0 as u64
    }

    pub fn bytes(self) -> usize {
        self.0
    }

    /// The start of the page holding `addr`.
    pub fn align_down(self, addr: u64) -> u64 {
        addr & !(self.get() - 1)
    }
}

/// The parsed handshake: regions sorted by host address, one page size for all.
#[derive(Clone, Debug)]
pub struct Layout {
    pub regions: Vec<Mapping>,
    pub page_size: PageSize,
}

impl Layout {
    /// Decodes Firecracker's handshake and checks it against the memory file size.
    pub fn parse(data: &[u8], mem_size: u64) -> Result<Self> {
        let mut regions: Vec<Mapping> =
            serde_json::from_slice(data).with_context(|| format!("parse mappings {:?}", String::from_utf8_lossy(data)))?;
        ensure!(!regions.is_empty(), "no memory regions in handshake");
        regions.sort_by_key(|r| r.base_host_virt_addr);
        let page_size = regions[0].page_size;
        let Some(valid) = PageSize::new(page_size) else { bail!("page size {page_size} is not a power of two") };

        // the handshake comes from the jailed VMM, so don't trust it. release builds don't check
        // overflow, and a wrapped sum would sneak past these bounds and fault later.
        let mut prev_end = 0;
        for r in &regions {
            if r.page_size != page_size {
                bail!("mixed page sizes {page_size} and {}", r.page_size);
            }
            if r.size == 0 || r.size % page_size != 0 || r.base_host_virt_addr % page_size != 0 || r.offset % page_size != 0 {
                bail!("region {:#x}+{:#x} at file offset {:#x} not aligned to {page_size}", r.base_host_virt_addr, r.size, r.offset);
            }
            if r.base_host_virt_addr < prev_end {
                bail!("region {:#x} overlaps the previous one ending at {prev_end:#x}", r.base_host_virt_addr);
            }
            let Some(end) = r.base_host_virt_addr.checked_add(r.size) else {
                bail!("region {:#x}+{:#x} wraps the address space", r.base_host_virt_addr, r.size);
            };
            if r.offset.checked_add(r.size).is_none_or(|end| end > mem_size) {
                bail!("region at file offset {:#x}+{:#x} exceeds the {mem_size} byte memory file", r.offset, r.size);
            }
            prev_end = end;
        }

        // non-overlapping in-bounds file ranges can't add up past the file size, and if they add up
        // to it they tile the file. so every file page maps back to exactly one host address.
        let mut by_offset: Vec<_> = regions.iter().map(|r| (r.offset, r.offset + r.size)).collect();
        by_offset.sort_unstable();
        for pair in by_offset.windows(2) {
            let ((start, end), (next, _)) = (pair[0], pair[1]);
            ensure!(next >= end, "file range {start:#x}..{end:#x} overlaps the one at {next:#x}");
        }
        let total: u64 = regions.iter().map(|r| r.size).sum();
        ensure!(total == mem_size, "regions cover {total} bytes, memory file has {mem_size}");
        Ok(Self { regions, page_size: valid })
    }

    /// The aligned host address and file offset of the page holding `addr`, for a whole-page copy.
    pub fn locate(&self, addr: u64) -> Option<(u64, u64)> {
        let page = self.page_size.align_down(addr);
        self.regions
            .iter()
            .find(|r| (r.base_host_virt_addr..r.base_host_virt_addr + r.size).contains(&page))
            .map(|r| (page, r.offset + (page - r.base_host_virt_addr)))
    }

    /// Maps a page-aligned file offset back to its host address in this VMM.
    pub fn address(&self, off: u64) -> Option<u64> {
        if !off.is_multiple_of(self.page_size.get()) {
            return None;
        }
        self.regions.iter().find(|r| (r.offset..r.offset + r.size).contains(&off)).map(|r| r.base_host_virt_addr + (off - r.offset))
    }

    /// The guest memory in bytes.
    pub fn size(&self) -> u64 {
        self.regions.iter().map(|r| r.size).sum()
    }
}

/// Pages the guest removed. These have to fault back in as zeros, not snapshot data.
#[derive(Debug)]
pub struct PageSet {
    page_size: PageSize,
    pages: HashSet<u64>,
}

impl PageSet {
    pub fn new(page_size: PageSize) -> Self {
        Self { page_size, pages: HashSet::new() }
    }

    /// Marks every page touching `range`.
    pub fn remove(&mut self, range: Range<u64>) {
        let first = self.page_size.align_down(range.start);
        self.pages.extend((first..range.end).step_by(self.page_size.bytes()));
    }

    pub fn has(&self, page: u64) -> bool {
        self.pages.contains(&page)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    const HUGE: u64 = 2 << 20;
    const GIB: u64 = 1 << 30;

    fn region(base: u64, size: u64, offset: u64, page_size: u64) -> Mapping {
        Mapping { base_host_virt_addr: base, size, offset, page_size }
    }

    #[test]
    fn parses_firecracker_handshakes() {
        // what Firecracker 1.16 sends, including the deprecated duplicate field.
        let fc = br#"[{"base_host_virt_addr":139637976727552,"size":1073741824,"offset":0,"page_size":2097152,"page_size_kib":2097152}]"#;
        let l = Layout::parse(fc, GIB).unwrap();
        assert_eq!((l.page_size.get(), l.size(), l.regions.len()), (HUGE, GIB, 1));

        // x86 guests above 3.5 GiB come as two regions. unsorted input gets sorted by host address
        let two = br#"[{"base_host_virt_addr":8589934592,"size":2097152,"offset":1073741824,"page_size":2097152},
            {"base_host_virt_addr":4294967296,"size":1073741824,"offset":0,"page_size":2097152}]"#;
        let l = Layout::parse(two, GIB + HUGE).unwrap();
        assert_eq!(l.regions[0].base_host_virt_addr, 4_294_967_296);
        assert_eq!(l.size(), GIB + HUGE);
    }

    fn one(base: u64, size: u64, page: u64) -> String {
        format!(r#"[{{"base_host_virt_addr":{base},"size":{size},"offset":0,"page_size":{page}}}]"#)
    }

    #[rstest]
    #[case::garbage("nope".to_owned(), GIB)]
    #[case::empty("[]".to_owned(), GIB)]
    #[case::page_size_not_pow2(one(0, GIB, 3 * HUGE / 2), GIB)]
    #[case::unaligned_base(one(4096, GIB, HUGE), GIB)]
    #[case::unaligned_size(one(0, GIB + 4096, HUGE), GIB + 4096)]
    #[case::file_too_small(one(0, GIB, HUGE), GIB - HUGE)]
    #[case::file_too_big(one(0, GIB, HUGE), GIB + HUGE)]
    #[case::overlap(
        r#"[{"base_host_virt_addr":0,"size":4194304,"offset":0,"page_size":2097152},
            {"base_host_virt_addr":2097152,"size":2097152,"offset":4194304,"page_size":2097152}]"#.to_owned(),
        3 * HUGE,
    )]
    #[case::mixed_page_sizes(
        r#"[{"base_host_virt_addr":0,"size":2097152,"offset":0,"page_size":2097152},
            {"base_host_virt_addr":4194304,"size":4096,"offset":2097152,"page_size":4096}]"#.to_owned(),
        HUGE + 4096,
    )]
    #[case::file_ranges_overlap(
        r#"[{"base_host_virt_addr":0,"size":4194304,"offset":0,"page_size":2097152},
            {"base_host_virt_addr":8388608,"size":2097152,"offset":2097152,"page_size":2097152}]"#.to_owned(),
        3 * HUGE,
    )]
    #[case::unaligned_offset(r#"[{"base_host_virt_addr":0,"size":2097152,"offset":4096,"page_size":2097152}]"#.to_owned(), HUGE)]
    // each would pass the bounds checks if the sum wrapped
    #[case::offset_wraps(
        format!(r#"[{{"base_host_virt_addr":0,"size":{HUGE},"offset":{},"page_size":{HUGE}}}]"#, u64::MAX - HUGE + 1),
        HUGE,
    )]
    #[case::address_wraps(one(u64::MAX - HUGE + 1, 2 * HUGE, HUGE), 2 * HUGE)]
    fn rejects_bad_handshakes(#[case] body: String, #[case] mem_size: u64) {
        assert!(Layout::parse(body.as_bytes(), mem_size).is_err());
    }

    #[test]
    fn locate_rounds_to_pages_across_regions() {
        let l = Layout {
            page_size: PageSize::new(HUGE).unwrap(),
            regions: vec![region(0x1000_0000, 4 * HUGE, 0, HUGE), region(0x4000_0000, 2 * HUGE, 4 * HUGE, HUGE)],
        };
        assert_eq!(l.locate(0x1000_0000 + HUGE + 12345), Some((0x1000_0000 + HUGE, HUGE)), "rounds down to its huge page");
        assert_eq!(
            l.locate(0x4000_0000 + 2 * HUGE - 1),
            Some((0x4000_0000 + HUGE, 5 * HUGE)),
            "the second region follows the first in the file"
        );
        assert_eq!(l.locate(0x4000_0000 + 2 * HUGE), None, "one past the end of the last region");
        assert_eq!(l.locate(0x1000_0000 + 4 * HUGE), None, "the gap between regions");
    }

    #[test]
    fn address_inverts_locate() {
        let l = Layout {
            page_size: PageSize::new(4096).unwrap(),
            regions: vec![region(0x10000, 0x2000, 0, 4096), region(0x80000, 0x1000, 0x2000, 4096)],
        };
        for addr in [0x10000, 0x11000, 0x80000] {
            let (page, off) = l.locate(addr + 7).unwrap();
            assert_eq!(l.address(off), Some(page));
        }
        assert_eq!(l.address(0x3000), None, "past the last region");
        assert_eq!(l.address(0x1001), None, "unaligned");
    }

    #[test]
    fn page_set_marks_whole_pages() {
        let mut s = PageSet::new(PageSize::new(HUGE).unwrap());
        assert!(!s.has(0));
        // a 4k remove inside a huge page marks the whole page. an end mid-page marks that page too
        s.remove(HUGE + 4096..HUGE + 8192);
        assert!(s.has(HUGE) && !s.has(0) && !s.has(2 * HUGE));
        s.remove(4 * HUGE..6 * HUGE + 1);
        assert!(s.has(4 * HUGE) && s.has(5 * HUGE) && s.has(6 * HUGE) && !s.has(7 * HUGE));
        assert_eq!(s.pages.len(), 4);
        s.remove(4 * HUGE..5 * HUGE);
        assert_eq!(s.pages.len(), 4, "idempotent");
    }
}
