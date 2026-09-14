// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! A segment cache of asset byte ranges.
//!
//! Holds non-overlapping byte segments keyed by start offset, coalescing adjacent
//! segments on insert and evicting least-recently-used segments once a byte budget
//! is exceeded.
//!
//! The coalesce is capped at `max_cached`: a run of touching segments that would
//! exceed the budget is left as separate segments rather than merged into one, so a
//! forward sequential read (the pattern a hash pass produces) leaves evictable
//! segments behind instead of one immortal segment that defeats the budget.

use std::collections::BTreeMap;

struct Segment {
    data: Vec<u8>,
    /// LRU clock value at last access; the smallest is evicted first.
    last_used: u64,
}

/// A least-recently-used cache of non-overlapping asset byte segments.
pub(crate) struct RangeCache {
    segments: BTreeMap<u64, Segment>,
    total: u64,
    max_cached: u64,
    clock: u64,
}

impl RangeCache {
    /// Creates a cache that evicts once cached bytes exceed `max_cached`.
    pub(crate) fn new(max_cached: u64) -> Self {
        Self {
            segments: BTreeMap::new(),
            total: 0,
            max_cached,
            clock: 0,
        }
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// Copies contiguous cached bytes starting at `offset` into `buf`, returning how
    /// many bytes were copied (0 if `offset` is not cached).
    ///
    /// A partial copy is not a driver miss: [`super::driver::PrefetchStream`] treats
    /// only a zero-length copy as a miss and re-reads from the returned offset, so a
    /// seam left by a capped insert (see [`RangeCache::insert`]) costs at most an extra
    /// `read` call, never a retry attempt. Walking across adjacent segments here would
    /// be dead code under the current eviction policy: two byte-adjacent segments can
    /// never both be resident, since adjacency within budget always coalesces and a
    /// capped split leaves `total` over budget, which `evict` immediately trims to one.
    pub(crate) fn copy_into(&mut self, offset: u64, buf: &mut [u8]) -> usize {
        let Some((&start, seg)) = self.segments.range(..=offset).next_back() else {
            return 0;
        };
        let end = start + seg.data.len() as u64;
        if offset >= end {
            return 0;
        }
        let seg_pos = (offset - start) as usize;
        let available = seg.data.len() - seg_pos;
        let n = available.min(buf.len());
        buf[..n].copy_from_slice(&seg.data[seg_pos..seg_pos + n]);
        let clock = self.tick();
        // Re-borrow mutably to record the access.
        if let Some(seg) = self.segments.get_mut(&start) {
            seg.last_used = clock;
        }
        n
    }

    /// Inserts `data` at `offset`, coalescing with overlapping or adjacent segments
    /// while the merged span stays within the byte budget, then evicting until within
    /// budget.
    ///
    /// If merging would exceed `max_cached`, `data` is inserted as its own segment
    /// (trimmed to not overlap a neighbour) and the neighbours are left in place, so
    /// the map stays non-overlapping and a long sequential read remains evictable.
    pub(crate) fn insert(&mut self, offset: u64, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        let mut lo = offset;
        let mut hi = offset + data.len() as u64;

        // Segments overlapping or touching [lo, hi): start <= hi and end >= lo.
        let overlapping: Vec<u64> = self
            .segments
            .range(..=hi)
            .filter(|(&start, seg)| start + seg.data.len() as u64 >= lo)
            .map(|(&start, _)| start)
            .collect();

        for &start in &overlapping {
            let seg = &self.segments[&start];
            lo = lo.min(start);
            hi = hi.max(start + seg.data.len() as u64);
        }

        // Cap the coalesce. A span over budget, or one that cannot be addressed as a
        // `usize` on this target (32-bit wasm), takes the own-segment path instead of
        // merging into a single unbounded, unaddressable buffer.
        let span = hi - lo;
        match usize::try_from(span) {
            Ok(span_len) if span <= self.max_cached => {
                let mut merged = vec![0u8; span_len];
                for &start in &overlapping {
                    // `start` came from the map above, so the segment is present.
                    if let Some(seg) = self.segments.remove(&start) {
                        self.total -= seg.data.len() as u64;
                        let at = (start - lo) as usize;
                        merged[at..at + seg.data.len()].copy_from_slice(&seg.data);
                    }
                }
                let at = (offset - lo) as usize;
                merged[at..at + data.len()].copy_from_slice(&data);

                self.total += merged.len() as u64;
                let clock = self.tick();
                self.segments.insert(
                    lo,
                    Segment {
                        data: merged,
                        last_used: clock,
                    },
                );
            }
            _ => self.insert_capped(offset, data),
        }

        self.evict();
    }

    /// Inserts `data` as its own segment, trimming any bytes that overlap an existing
    /// neighbour so the map stays non-overlapping. Neighbours are left in place.
    fn insert_capped(&mut self, offset: u64, data: Vec<u8>) {
        let mut start = offset;
        let end = offset + data.len() as u64;

        // Trim the front against a segment that covers `start`.
        if let Some((&s, seg)) = self.segments.range(..=start).next_back() {
            let s_end = s + seg.data.len() as u64;
            if s_end > start {
                start = s_end;
            }
        }
        // Stop before the next segment that starts within (start, end).
        let end = match self.segments.range(start..end).next() {
            Some((&next_start, _)) => end.min(next_start),
            None => end,
        };
        if end <= start {
            return;
        }
        let from = (start - offset) as usize;
        let to = (end - offset) as usize;
        let piece = data[from..to].to_vec();
        self.total += piece.len() as u64;
        let clock = self.tick();
        self.segments.insert(
            start,
            Segment {
                data: piece,
                last_used: clock,
            },
        );
    }

    /// Evicts least-recently-used segments while over budget, always keeping at
    /// least one segment (a single segment larger than the budget is kept, since a
    /// read in progress needs it).
    fn evict(&mut self) {
        while self.total > self.max_cached && self.segments.len() > 1 {
            let victim = self
                .segments
                .iter()
                .min_by_key(|(_, seg)| seg.last_used)
                .map(|(&start, _)| start);
            let Some(start) = victim else { break };
            if let Some(seg) = self.segments.remove(&start) {
                self.total -= seg.data.len() as u64;
            }
        }
    }

    #[cfg(test)]
    fn segment_count(&self) -> usize {
        self.segments.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn copy_into_returns_zero_when_uncached() {
        let mut cache = RangeCache::new(1024);
        let mut buf = [0u8; 8];
        assert_eq!(cache.copy_into(0, &mut buf), 0);
    }

    #[test]
    fn copy_into_reads_cached_bytes() {
        let mut cache = RangeCache::new(1024);
        cache.insert(10, vec![1, 2, 3, 4]);
        let mut buf = [0u8; 4];
        assert_eq!(cache.copy_into(10, &mut buf), 4);
        assert_eq!(buf, [1, 2, 3, 4]);
        // Partial read from the middle of a segment.
        let mut buf = [0u8; 8];
        assert_eq!(cache.copy_into(12, &mut buf), 2);
        assert_eq!(&buf[..2], &[3, 4]);
    }

    #[test]
    fn adjacent_inserts_coalesce_into_one_segment() {
        let mut cache = RangeCache::new(1024);
        cache.insert(0, vec![1, 2, 3]);
        cache.insert(3, vec![4, 5, 6]);
        assert_eq!(cache.segment_count(), 1);
        let mut buf = [0u8; 6];
        assert_eq!(cache.copy_into(0, &mut buf), 6);
        assert_eq!(buf, [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn overlapping_inserts_coalesce() {
        let mut cache = RangeCache::new(1024);
        cache.insert(0, vec![1, 2, 3, 4]);
        cache.insert(2, vec![3, 4, 5, 6]);
        assert_eq!(cache.segment_count(), 1);
        let mut buf = [0u8; 6];
        assert_eq!(cache.copy_into(0, &mut buf), 6);
        assert_eq!(buf, [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn disjoint_inserts_stay_separate() {
        let mut cache = RangeCache::new(1024);
        cache.insert(0, vec![1, 2]);
        cache.insert(100, vec![9, 9]);
        assert_eq!(cache.segment_count(), 2);
    }

    #[test]
    fn eviction_drops_least_recently_used() {
        // Budget holds only ~2 of the 4-byte segments.
        let mut cache = RangeCache::new(8);
        cache.insert(0, vec![0; 4]);
        cache.insert(100, vec![0; 4]);
        // Touch the first segment so the second becomes least-recently-used.
        let mut buf = [0u8; 4];
        assert_eq!(cache.copy_into(0, &mut buf), 4);
        cache.insert(200, vec![0; 4]);
        // Segment at 100 was LRU and should be gone; 0 and 200 remain.
        assert!(cache.total <= 8);
        let mut buf = [0u8; 4];
        assert_eq!(cache.copy_into(100, &mut buf), 0);
        assert_eq!(cache.copy_into(0, &mut buf), 4);
        assert_eq!(cache.copy_into(200, &mut buf), 4);
    }

    // --- R2: `max_cached` must bound memory on a sequential read ---

    #[test]
    fn sequential_run_stays_within_budget() {
        // A forward pass of touching windows totalling far more than the budget.
        // Before the coalesce cap this merged into one never-evicted segment and
        // `total` grew without bound; the assertion is the defect stated directly.
        let window = 64u64;
        let max_cached = 4 * window;
        let mut cache = RangeCache::new(max_cached);
        for i in 0..64u64 {
            cache.insert(i * window, vec![0u8; window as usize]);
            assert!(
                cache.total <= max_cached,
                "total {} exceeded budget {} at window {}",
                cache.total,
                max_cached,
                i
            );
        }
    }
}
