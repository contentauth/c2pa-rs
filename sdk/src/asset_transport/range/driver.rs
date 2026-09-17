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

//! Runs the synchronous parser over an [`AsyncRangeTransport`] by restarting it.
//!
//! The parser cannot await, so it never performs I/O here. It reads through a
//! [`PrefetchStream`], which serves cached bytes and aborts on anything absent. The
//! driver awaits the missing range, caches it, and runs the parse again from the top.
//! The cache outlives each attempt, so every attempt resolves at least one more miss.

use std::{
    io::{self, Cursor, Read, Seek, SeekFrom},
    num::NonZeroUsize,
};

use super::{
    cache::RangeCache, fetch_len, seek_to, AsyncRangeTransport, ObjectVersion, RangeConfig,
};
use crate::{
    asset_transport::AssetTransportError,
    utils::hash_utils::{build_hash_ranges, HashRange, Hasher},
};

/// Marks the error a [`PrefetchStream`] raises when the parse reads absent bytes.
///
/// The parse sees an ordinary [`io::Error`], so a handler that maps or wraps I/O errors
/// still propagates it. The driver matches on this payload rather than on a message.
#[derive(Debug)]
struct CacheMiss {
    offset: u64,
    len: u64,
}

impl std::fmt::Display for CacheMiss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "range not resident: {} bytes at {}", self.len, self.offset)
    }
}

impl std::error::Error for CacheMiss {}

/// What one attempt recorded.
struct MissRecord {
    offset: u64,
    len: u64,
}

/// A `Read + Seek` view over a [`RangeCache`] that performs no I/O.
///
/// A read of resident bytes succeeds. A read of absent bytes records what was wanted
/// and fails, which aborts the attempt. Seeks only move the cursor, so the seek-heavy
/// discovery a format handler performs costs nothing until it reads.
pub(crate) struct PrefetchStream<'a> {
    cache: &'a mut RangeCache,
    miss: &'a mut Option<MissRecord>,
    config: &'a RangeConfig,
    len: u64,
    offset: u64,
}

impl<'a> PrefetchStream<'a> {
    fn new(
        cache: &'a mut RangeCache,
        miss: &'a mut Option<MissRecord>,
        config: &'a RangeConfig,
        len: u64,
    ) -> Self {
        Self {
            cache,
            miss,
            config,
            len,
            offset: 0,
        }
    }
}

impl Read for PrefetchStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.offset >= self.len {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.len - self.offset) as usize;
        if want == 0 {
            return Ok(0);
        }

        let got = self.cache.copy_into(self.offset, &mut buf[..want]);
        if got == 0 {
            // Ask for the same span `RangeStream` would, so a driven parse and a
            // blocking one fetch the same windows.
            let fetch = fetch_len(want as u64, self.len - self.offset, self.config);
            *self.miss = Some(MissRecord {
                offset: self.offset,
                len: fetch,
            });
            return Err(io::Error::other(CacheMiss {
                offset: self.offset,
                len: fetch,
            }));
        }

        self.offset += got as u64;
        Ok(got)
    }
}

impl Seek for PrefetchStream<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_offset = seek_to(self.offset, pos, || Ok(self.len))?;
        self.offset = new_offset;
        Ok(new_offset)
    }
}

/// Ranges already fetched, so the driver can tell a first miss from a re-read.
#[derive(Default)]
struct Fetched {
    spans: Vec<(u64, u64)>,
    bytes: u64,
}

impl Fetched {
    /// Whether `offset` falls inside a span already fetched.
    ///
    /// A hit means the cache dropped those bytes, so the working set is over budget.
    /// Only the offset is compared: the parse restarts at 0 each attempt and asks for
    /// the same span, so the start position identifies the window.
    fn contains(&self, offset: u64) -> bool {
        self.spans
            .iter()
            .any(|(start, len)| offset >= *start && offset < start + len)
    }

    fn record(&mut self, offset: u64, len: u64) {
        self.spans.push((offset, len));
        self.bytes += len;
    }
}

/// What a completed drive reports besides the parse's own value.
#[derive(Debug)]
pub(crate) struct DriveReport {
    /// Attempts made, which equals distinct cache misses plus the final clean pass.
    pub(crate) attempts: u32,
    /// Bytes fetched across every attempt.
    pub(crate) bytes_fetched: u64,
}

/// Runs `parse` over an async range transport, restarting it on each cache miss.
///
/// `parse` must be side-effect-free and restartable: it runs once per distinct miss,
/// and every attempt begins at byte 0. It must not mutate a `StatusTracker`, write a
/// file, or advance any external cursor.
///
/// Three terminal conditions, none of which retries. A re-read of an already-fetched
/// range means the cache evicted it, so the working set exceeds `max_cached`. A version
/// change means the object moved underneath the read. Holding both versions is the
/// splice `ObjectVersion` exists to prevent. A transport error is a network failure
/// and propagates without consuming an attempt.
pub(crate) async fn drive_async<T, F>(
    transport: &dyn AsyncRangeTransport,
    config: &RangeConfig,
    format: &str,
    mut parse: F,
) -> Result<(T, DriveReport), AssetTransportError>
where
    F: FnMut(&mut PrefetchStream<'_>) -> io::Result<T>,
{
    // A fetch larger than the budget becomes a segment `evict` cannot drop, which
    // would make the ceiling below unprovable.
    let config = config.clamped();

    let info = transport.info_async().await?;
    let mut version = info.version.clone();

    // `max_cached / window`, plus two attempts of headroom for the re-miss detection
    // to fire before this ceiling does. See `RangeConfig::clamped` for why.
    let ceiling = (config.max_cached() / config.window()).saturating_add(2) as u32;

    let mut cache = RangeCache::new(config.max_cached());
    let mut miss: Option<MissRecord>;
    let mut fetched = Fetched::default();
    let mut attempts: u32 = 0;

    loop {
        attempts += 1;
        miss = None;

        let outcome = {
            let mut stream = PrefetchStream::new(&mut cache, &mut miss, &config, info.len);
            parse(&mut stream)
        };
        // A parse that swallows read errors can report success on a truncated view.
        // `bmff_io::build_bmff_tree` does exactly that: a header it cannot read ends
        // the walk as if the asset had trailing data. So a recorded miss outranks a
        // reported success.
        let err = match outcome {
            Ok(value) if miss.is_none() => {
                return Ok((
                    value,
                    DriveReport {
                        attempts,
                        bytes_fetched: fetched.bytes,
                    },
                ))
            }
            Ok(_) => io::Error::other("parse completed on a truncated view"),
            Err(err) => err,
        };

        let Some(record) = miss.take() else {
            // A parse failure of its own, not a miss.
            return Err(AssetTransportError::Io(err));
        };

        if fetched.contains(record.offset) {
            return Err(AssetTransportError::WorkingSetTooLarge {
                format: format.to_owned(),
                windows: fetched.spans.len(),
                bytes: fetched.bytes,
                max_cached: config.max_cached(),
            });
        }

        if attempts >= ceiling {
            return Err(AssetTransportError::AttemptsExhausted {
                format: format.to_owned(),
                attempts,
                ceiling,
                max_cached: config.max_cached(),
                window: config.window(),
            });
        }

        // A transport error propagates here, spending no attempt, and `VersionChanged`
        // aborts with the cache dropped rather than retrying.
        let bytes = fetch_piece(transport, record.offset, record.len, &mut version).await?;
        fetched.record(record.offset, bytes.len() as u64);
        cache.insert(record.offset, bytes);
    }
}

/// Fetches `len` bytes at `offset`, rejecting an empty response and adopting the
/// version when the caller has not anchored on one yet.
///
/// A transport that returns nothing while bytes remain has short-read, not reached the
/// end: the object length came from `info`, so the caller knows more bytes are there.
async fn fetch_piece(
    transport: &dyn AsyncRangeTransport,
    offset: u64,
    len: u64,
    version: &mut Option<ObjectVersion>,
) -> Result<Vec<u8>, AssetTransportError> {
    let chunk = fetch_versioned_async(transport, offset, len, version.as_ref()).await?;
    if chunk.bytes.is_empty() {
        return Err(AssetTransportError::ShortRead {
            offset,
            expected: len,
            got: 0,
        });
    }
    if version.is_none() {
        *version = chunk.version;
    }
    Ok(chunk.bytes)
}

/// The asynchronous twin of `fetch_versioned`: same placement, length and version
/// checks, so a driven read rejects what a blocking one rejects.
pub(crate) async fn fetch_versioned_async(
    transport: &dyn AsyncRangeTransport,
    offset: u64,
    len: u64,
    expect: Option<&ObjectVersion>,
) -> Result<super::RangeChunk, AssetTransportError> {
    let chunk = transport.read_range_async(offset, len, expect).await?;
    super::reject_misplaced(offset, chunk.offset)?;
    super::reject_overlong(offset, len, chunk.bytes.len())?;
    super::check_version(expect, chunk.version.as_ref())?;
    Ok(chunk)
}

/// Bytes the whole-object rung reserves up front. Past this the buffer grows as it
/// fills, so a transport that reports an impossible length fails on its own short read
/// rather than aborting the process on a reservation.
const MAX_PREALLOC: usize = 64 * 1024 * 1024;

/// Reads an entire object into memory, for a parse that ranges cannot serve.
///
/// A handler that reads its input to end (JPEG) re-reads everything on every attempt,
/// so driving it is quadratic for no benefit. `max_whole_object` bounds this rung: a
/// runtime with a hard memory ceiling sets it low, or `None` to refuse every read.
///
/// The object still arrives over the network in `max_request` pieces, one ranged
/// request each, so an intermediary that streams bounded chunks (a CORS proxy) serves
/// this. Only the assembled buffer is whole.
pub(crate) async fn read_whole_async(
    transport: &dyn AsyncRangeTransport,
    config: &RangeConfig,
    reference: &str,
) -> Result<Cursor<Vec<u8>>, AssetTransportError> {
    let info = transport.info_async().await?;
    match config.max_whole_object() {
        Some(cap) if info.len <= cap => {}
        _ => {
            return Err(AssetTransportError::WholeObjectTooLarge {
                reference: reference.to_owned(),
                len: info.len,
            })
        }
    }

    let mut bytes = Vec::new();
    bytes.try_reserve(usize::try_from(info.len).unwrap_or(0).min(MAX_PREALLOC))
        .map_err(|_| AssetTransportError::WholeObjectTooLarge {
            reference: reference.to_owned(),
            len: info.len,
        })?;
    let mut version = info.version.clone();
    let mut offset = 0u64;
    while offset < info.len {
        let want = fetch_len(config.max_request(), info.len - offset, config);
        let piece = fetch_piece(transport, offset, want, &mut version).await?;
        offset += piece.len() as u64;
        bytes.extend_from_slice(&piece);
    }

    Ok(Cursor::new(bytes))
}

/// Hashes an asset over an async transport, holding one `max_hash_buf` buffer at a time.
///
/// The hash itself stays synchronous. Only byte acquisition awaits, so peak memory is
/// the buffer rather than the object. `hash_range` and `is_exclusion` have the meaning
/// they carry in [`hash_stream_by_alg`], and coverage comes from the same
/// `build_hash_ranges` the blocking hasher uses, so the two agree by construction.
///
/// `progress(step, total)` fires once per buffer, matching the blocking hasher's ticks.
///
/// [`hash_stream_by_alg`]: crate::utils::hash_utils::hash_stream_by_alg
pub(crate) async fn hash_ranges_async<F>(
    alg: &str,
    transport: &dyn AsyncRangeTransport,
    config: &RangeConfig,
    hash_range: Option<Vec<HashRange>>,
    is_exclusion: bool,
    max_hash_buf: NonZeroUsize,
    progress: &mut F,
) -> Result<Vec<u8>, AssetTransportError>
where
    F: FnMut(u32, u32) -> crate::Result<()>,
{
    let info = transport.info_async().await?;
    if info.len < 1 {
        return Err(AssetTransportError::Other {
            source: "no data to hash".into(),
        });
    }

    let mut hasher = Hasher::new(alg).map_err(|_| AssetTransportError::Other {
        source: format!("unsupported hash algorithm: {alg}").into(),
    })?;

    let (ranges, bmff_v2_starts) = build_hash_ranges(hash_range, is_exclusion, info.len)
        .map_err(|e| AssetTransportError::Other {
            source: e.to_string().into(),
        })?;

    let buf = max_hash_buf.get() as u64;
    let total: u32 = ranges
        .iter()
        .map(|r| u32::try_from((r.end() - r.start() + 1).div_ceil(buf)).unwrap_or(u32::MAX))
        .sum();
    let mut step: u32 = 0;
    let mut version = info.version.clone();

    for r in &ranges {
        step += 1;
        progress(step, total).map_err(|e| AssetTransportError::Other {
            source: e.to_string().into(),
        })?;

        let start = *r.start();
        let end = *r.end();

        // A BMFF V2 offset contributes its position, not the byte at it.
        if bmff_v2_starts.contains(&start) && end == start {
            hasher.update(&start.to_be_bytes());
            continue;
        }

        let mut left = end - start + 1;
        let mut offset = start;
        while left > 0 {
            let want = left.min(buf);
            let bytes =
                read_exact_async(transport, config, offset, want, &mut version).await?;
            hasher.update(&bytes);
            offset += want;
            left -= want;

            if left > 0 {
                step += 1;
                progress(step, total).map_err(|e| AssetTransportError::Other {
                    source: e.to_string().into(),
                })?;
            }
        }
    }

    Ok(Hasher::finalize(hasher))
}

/// Fills `len` bytes at `offset`, issuing as many `max_request` pieces as it takes.
///
/// The network stays chunked even when the hash buffer is larger than one request, and
/// the object version is pinned across every piece so a splice cannot go unnoticed.
async fn read_exact_async(
    transport: &dyn AsyncRangeTransport,
    config: &RangeConfig,
    offset: u64,
    len: u64,
    version: &mut Option<ObjectVersion>,
) -> Result<Vec<u8>, AssetTransportError> {
    let mut out = Vec::with_capacity(usize::try_from(len).unwrap_or(usize::MAX));
    while (out.len() as u64) < len {
        let at = offset + out.len() as u64;
        let want = fetch_len(config.max_request(), len - out.len() as u64, config);
        let piece = fetch_piece(transport, at, want, version).await?;
        out.extend_from_slice(&piece);
    }
    out.truncate(usize::try_from(len).unwrap_or(usize::MAX));
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]
    use std::num::NonZeroU64;

    use super::*;
    use crate::asset_transport::range::{RangeChunk, RangeInfo};

    fn config(window: u64, max_cached: u64) -> RangeConfig {
        let window = NonZeroU64::new(window).unwrap();
        RangeConfig::default()
            .with_window(window)
            .with_max_request(window)
            .with_max_cached(NonZeroU64::new(max_cached).unwrap())
    }

    /// Under an unbounded cap there is no length left to refuse. A transport reporting
    /// an impossible length still fails by name, without a reservation that would abort
    /// the process trying to satisfy it.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn an_unbounded_whole_object_read_fails_by_name_not_by_abort() {
        struct Huge;

        #[async_trait::async_trait]
        impl AsyncRangeTransport for Huge {
            async fn info_async(&self) -> Result<RangeInfo, AssetTransportError> {
                Ok(RangeInfo::new(u64::MAX))
            }
            async fn read_range_async(
                &self,
                offset: u64,
                _len: u64,
                _expect: Option<&ObjectVersion>,
            ) -> Result<RangeChunk, AssetTransportError> {
                // No bytes to give: the reported length was a lie.
                Ok(RangeChunk::new(offset, Vec::new()))
            }
        }

        let unbounded = config(1024, 65536).with_unbounded_whole_object();
        let err = read_whole_async(&Huge, &unbounded, "https://x/huge")
            .await
            .unwrap_err();

        assert!(
            matches!(err, AssetTransportError::ShortRead { .. }),
            "expected ShortRead, got {err:?}"
        );
    }

}
