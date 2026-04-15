use std::ops::Range;

/// Sorted, non-overlapping byte ranges of a memory file that hold data. Everything else reads as
/// zeros.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extents(pub Vec<Range<u64>>);

impl Extents {
    /// Whether any byte of `range` holds data.
    pub fn overlaps(&self, range: Range<u64>) -> bool {
        let i = self.0.partition_point(|e| e.end <= range.start);
        self.0.get(i).is_some_and(|e| e.start < range.end)
    }

    pub fn bytes(&self) -> u64 {
        self.0.iter().map(|e| e.end - e.start).sum()
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn two() -> Extents {
        Extents(vec![4096..8192, 16384..20480])
    }

    #[rstest]
    #[case::before_the_first(0..4096, false)]
    #[case::inside_the_first(4096..8192, true)]
    #[case::straddles_the_first_start(2048..6144, true)]
    #[case::between(8192..16384, false)]
    #[case::inside_the_last(16384..20480, true)]
    #[case::after_the_last(20480..24576, false)]
    fn overlaps_only_ranges_holding_data(#[case] range: Range<u64>, #[case] want: bool) {
        assert_eq!(two().overlaps(range), want);
    }

    #[test]
    fn no_extents_means_all_zeros() {
        assert!(!Extents::default().overlaps(0..4096));
    }
}
