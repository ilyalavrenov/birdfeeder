//! A manifest keeps what a remote copy of a memory file loses: its size and which extents hold
//! data. It's little-endian u64s: the size, then start and end for each extent. vmm writes it when
//! roost exports a snapshot.

use anyhow::{Result, bail, ensure};

use crate::extents::Extents;

const WORD: usize = 8;

/// The memory file's size and data extents, which must be sorted, disjoint and inside the file.
pub fn decode(b: &[u8]) -> Result<(u64, Extents)> {
    ensure!(b.len() >= WORD && (b.len() - WORD).is_multiple_of(2 * WORD), "manifest isn't a size followed by start, end pairs");
    let mut words = b.as_chunks::<WORD>().0.iter().map(|&w| u64::from_le_bytes(w));
    let size = words.next().expect("the length check guarantees a size");
    let mut data = Vec::with_capacity((b.len() - WORD) / (2 * WORD));
    let mut prev_end = 0;
    while let (Some(start), Some(end)) = (words.next(), words.next()) {
        if start >= end || start < prev_end || end > size {
            bail!("manifest extent {start:#x}-{end:#x} after {prev_end:#x} in a {size} byte file");
        }
        data.push(start..end);
        prev_end = end;
    }
    Ok((size, Extents(data)))
}

#[cfg(test)]
pub fn encode(size: u64, data: &[std::ops::Range<u64>]) -> Vec<u8> {
    std::iter::once(size).chain(data.iter().flat_map(|e| [e.start, e.end])).flat_map(u64::to_le_bytes).collect()
}

#[cfg(test)]
#[expect(clippy::single_range_in_vec_init, reason = "a list of extents, which are ranges")]
mod tests {
    use rstest::rstest;

    use super::*;

    #[test]
    fn round_trips() {
        let data = vec![0..4096, 8192..16384];
        assert_eq!(decode(&encode(16384, &data)).unwrap(), (16384, Extents(data)));
        assert_eq!(decode(&encode(4096, &[])).unwrap(), (4096, Extents::default()), "an all-hole file has no extents");
    }

    #[rstest]
    #[case::empty(vec![])]
    #[case::half_an_extent(encode(8192, &[0..4096])[..2 * WORD].to_vec())]
    #[case::empty_extent(encode(8192, &[4096..4096]))]
    #[case::unsorted(encode(8192, &[4096..8192, 0..4096]))]
    #[case::overlapping(encode(8192, &[0..6000, 4096..8192]))]
    #[case::past_the_end(encode(4096, &[0..8192]))]
    fn rejects_malformed_manifests(#[case] input: Vec<u8>) {
        assert!(decode(&input).is_err());
    }
}
