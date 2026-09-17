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

/// One past the last byte of `len` bytes at `offset`, clamped to `u64::MAX`.
///
/// A transport reports the object length, so an offset can sit anywhere in the range
/// and `offset + len` can leave it. Saturating keeps the end ordered after the start,
/// which is what the overlap comparisons need; the clamped byte is past any real
/// object and is never addressed.
fn segment_end(offset: u64, len: usize) -> u64 {
    offset.saturating_add(len as u64)
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

    /// Bytes currently held across every segment.
    #[cfg(test)]
    pub(crate) fn cached_bytes(&self) -> u64 {
        self.total
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// Copies contiguous cached bytes starting at `offset` into `buf`, returning how
    /// many bytes were copied (0 if `offset` is not cached).
    ///
    /// A partial copy is not a miss. Only a zero-length copy is, so a short segment left
    /// by a capped insert (see [`RangeCache::insert`]) costs at most an extra `read`
    /// call. The async driver re-reads from the returned offset instead of spending a
    /// retry attempt on it.
    ///
    /// Adjacent segments are never both resident: coalescing on insert merges them
    /// within budget, and eviction trims an over-budget split immediately. So a walk
    /// across segments here would never run.
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
        let mut hi = segment_end(offset, data.len());

        // Segments overlapping or touching [lo, hi): start <= hi and end >= lo.
        let overlapping: Vec<u64> = self
            .segments
            .range(..=hi)
            .filter(|(&start, seg)| segment_end(start, seg.data.len()) >= lo)
            .map(|(&start, _)| start)
            .collect();

        for &start in &overlapping {
            let seg = &self.segments[&start];
            lo = lo.min(start);
            hi = hi.max(segment_end(start, seg.data.len()));
        }

        // Cap the coalesce. A span over budget, or one that cannot be addressed as a
        // `usize` on this target (32-bit wasm), takes the own-segment path instead of
        // merging into a single unbounded, unaddressable buffer. A span that reached
        // `u64::MAX` was clamped and no longer covers the data, so it takes that path
        // too rather than merging into a buffer too short to hold it.
        let span = hi - lo;
        match usize::try_from(span) {
            Ok(span_len) if span <= self.max_cached && hi < u64::MAX => {
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
        let end = segment_end(offset, data.len());

        // Trim the front against a segment that covers `start`.
        if let Some((&s, seg)) = self.segments.range(..=start).next_back() {
            let s_end = segment_end(s, seg.data.len());
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

}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // A transport reports the object length, so it decides which offsets a read
    // reaches. An offset whose end leaves `u64` must not take the arithmetic with it.
    #[test]
    fn an_offset_near_the_end_of_the_range_does_not_overflow() {
        let mut cache = RangeCache::new(4096);

        cache.insert(u64::MAX - 10, vec![7u8; 64]);
        cache.insert(u64::MAX - 200, vec![9u8; 64]);
        cache.insert(u64::MAX, vec![1u8; 8]);

        // The clamped tail is stored short rather than wrapping to the front of the
        // object: a read at the low offset must not see those bytes.
        let mut buf = [0u8; 16];
        assert_eq!(cache.copy_into(0, &mut buf), 0);
        assert!(cache.cached_bytes() <= 4096);
    }
}
