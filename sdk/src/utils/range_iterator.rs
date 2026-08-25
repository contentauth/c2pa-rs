use std::ops::Range;

struct SubRanges {
    start: usize,
    end: usize,
    size: usize,
}

impl Iterator for SubRanges {
    type Item = Range<usize>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.start >= self.end {
            return None;
        }
        let next = (self.start + self.size).min(self.end);
        let chunk = self.start..next;
        self.start = next;
        Some(chunk)
    }
}


/// Splits `range` into consecutive sub-ranges of at most `size` elements.
///
/// Every sub-range has exactly `size` elements except possibly the last,
/// which holds the remainder. Yields nothing for an empty range.
///
/// # Panics
/// Panics if `size == 0`.
fn sub_ranges(range: Range<usize>, size: usize) -> impl Iterator<Item = Range<usize>> {
    let Range { mut start, end } = range;
    std::iter::from_fn(move || {
        if start >= end {
            return None;
        }
        let next = (start + size).min(end);
        let chunk = start..next;
        start = next;
        Some(chunk)
    })
}