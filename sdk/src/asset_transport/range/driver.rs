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
    add_signed, cache::RangeCache, fetch_len, AsyncRangeTransport, ObjectVersion, RangeConfig,
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
        let new_offset = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::Current(delta) => add_signed(self.offset, delta)?,
            SeekFrom::End(delta) => add_signed(self.len, delta)?,
        };
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
/// splice `ObjectVersion` exists to prevent. A transport error is a network failure,
/// not a parse miss, so it propagates without consuming an attempt.
pub(crate) async fn drive_async<T, F>(
    transport: &dyn AsyncRangeTransport,
    config: &RangeConfig,
    format: &str,
    mut parse: F,
) -> Result<(T, DriveReport), AssetTransportError>
where
    F: FnMut(&mut PrefetchStream<'_>) -> io::Result<T>,
{
    // Match `RangeStream::new`: a fetch larger than the budget becomes a segment
    // `evict` cannot drop, which would make the ceiling below unprovable.
    let config = config
        .with_max_request(config.max_request().min(config.max_cached()))
        .unwrap_or(*config);

    let info = transport.info_async().await?;
    let mut version = info.version.clone();

    // Each successful attempt caches at least `min(window, remaining)` new bytes.
    // The cache holds at most `max_cached` before evicting. So `max_cached / window`
    // attempts fill the budget. One more attempt evicts, and the attempt after that
    // re-reads what was dropped. That is where re-miss detection fires with the
    // actionable error. The ceiling has to leave room for both, or it pre-empts the
    // better diagnosis. It exists only for a parse that reads different ranges each
    // time and so never re-misses at all.
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
        let chunk =
            fetch_versioned_async(transport, record.offset, record.len, version.as_ref()).await?;
        if chunk.bytes.is_empty() {
            return Err(AssetTransportError::ShortRead {
                offset: record.offset,
                expected: record.len,
                got: 0,
            });
        }
        if version.is_none() {
            version = chunk.version.clone();
        }
        fetched.record(record.offset, chunk.bytes.len() as u64);
        cache.insert(record.offset, chunk.bytes);
    }
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
/// runtime with a hard memory ceiling sets it low, or `None` to refuse outright.
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

    // An unbounded cap can name a length no allocation can serve. Reserving it up front
    // aborts the process, so the buffer grows as bytes arrive and an oversized object
    // fails on the transport's own short read instead.
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
        let chunk = fetch_versioned_async(transport, offset, want, version.as_ref()).await?;
        if chunk.bytes.is_empty() {
            return Err(AssetTransportError::ShortRead {
                offset,
                expected: want,
                got: 0,
            });
        }
        if version.is_none() {
            version = chunk.version.clone();
        }
        offset += chunk.bytes.len() as u64;
        bytes.extend_from_slice(&chunk.bytes);
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
        let chunk = fetch_versioned_async(transport, at, want, version.as_ref()).await?;
        if chunk.bytes.is_empty() {
            return Err(AssetTransportError::ShortRead {
                offset: at,
                expected: want,
                got: 0,
            });
        }
        if version.is_none() {
            *version = chunk.version.clone();
        }
        out.extend_from_slice(&chunk.bytes);
    }
    out.truncate(usize::try_from(len).unwrap_or(usize::MAX));
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };

    use super::*;
    use crate::asset_transport::range::{RangeChunk, RangeInfo};

    /// An in-memory async transport that counts its reads and can change version
    /// after a chosen number of them.
    struct MemAsync {
        data: Vec<u8>,
        reads: Arc<AtomicU64>,
        version: Option<String>,
        /// Reports a second version from this read onwards, simulating an object
        /// replaced underneath the drive.
        change_version_after: Option<u64>,
    }

    impl MemAsync {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                reads: Arc::new(AtomicU64::new(0)),
                version: None,
                change_version_after: None,
            }
        }

        fn with_version(mut self, version: &str) -> Self {
            self.version = Some(version.to_owned());
            self
        }

        fn changing_after(mut self, reads: u64) -> Self {
            self.change_version_after = Some(reads);
            self
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl AsyncRangeTransport for MemAsync {
        async fn info_async(&self) -> Result<RangeInfo, AssetTransportError> {
            let info = RangeInfo::new(self.data.len() as u64);
            Ok(match &self.version {
                Some(v) => info.with_version(v.clone()),
                None => info,
            })
        }

        async fn read_range_async(
            &self,
            offset: u64,
            len: u64,
            _expect: Option<&ObjectVersion>,
        ) -> Result<RangeChunk, AssetTransportError> {
            let n = self.reads.fetch_add(1, Ordering::SeqCst);
            let start = offset as usize;
            let end = (offset + len).min(self.data.len() as u64) as usize;
            let chunk = RangeChunk::new(offset, self.data[start..end].to_vec());
            let version = match (&self.version, self.change_version_after) {
                (Some(_), Some(after)) if n >= after => Some("v2".to_owned()),
                (Some(v), _) => Some(v.clone()),
                (None, _) => None,
            };
            Ok(match version {
                Some(v) => chunk.with_version(v),
                None => chunk,
            })
        }
    }

    /// Reads the whole object, which needs one attempt per window.
    fn read_all(stream: &mut PrefetchStream<'_>) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        stream.read_to_end(&mut out)?;
        Ok(out)
    }

    fn config(window: u64, max_cached: u64) -> RangeConfig {
        RangeConfig::default()
            .with_window(window)
            .unwrap()
            .with_max_request(window)
            .unwrap()
            .with_max_cached(max_cached)
            .unwrap()
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn drives_a_parse_to_completion_one_attempt_per_window() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let transport = MemAsync::new(data.clone());
        let reads = transport.reads.clone();

        // 4096 bytes in 1024-byte windows is four misses, then a clean pass.
        let (bytes, report) = drive_async(&transport, &config(1024, 65536), "test", read_all)
            .await
            .unwrap();

        assert_eq!(bytes, data);
        assert_eq!(report.attempts, 5);
        assert_eq!(reads.load(Ordering::SeqCst), 4);
        assert_eq!(report.bytes_fetched, 4096);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn seeks_alone_never_fetch() {
        // Discovery seeks far more than it reads. A seek past the end must not cost
        // a fetch, or a box-header walk would fetch the whole object.
        let transport = MemAsync::new(vec![7u8; 8192]);
        let reads = transport.reads.clone();

        let (pos, report) = drive_async(&transport, &config(1024, 65536), "test", |stream| {
            stream.seek(SeekFrom::Start(4096))?;
            stream.seek(SeekFrom::End(-16))?;
            stream.seek(SeekFrom::Current(-100))?;
            stream.stream_position()
        })
        .await
        .unwrap();

        assert_eq!(pos, 8076);
        assert_eq!(report.attempts, 1);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn a_working_set_over_budget_reports_the_budget() {
        // 8 KiB read in 1 KiB windows against a 4 KiB budget: the cache evicts, the
        // restarted parse re-reads window 0, and that re-read is the error.
        let transport = MemAsync::new(vec![3u8; 8192]);

        let err = drive_async(&transport, &config(1024, 4096), "video/mp4", read_all)
            .await
            .unwrap_err();

        match err {
            AssetTransportError::WorkingSetTooLarge {
                format, max_cached, ..
            } => {
                assert_eq!(format, "video/mp4");
                assert_eq!(max_cached, 4096);
            }
            other => panic!("expected WorkingSetTooLarge, got {other:?}"),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn a_version_change_mid_drive_is_terminal() {
        // The object is replaced after the first fetch. Caching bytes from both
        // versions is the splice ObjectVersion exists to prevent, so this never retries.
        let transport = MemAsync::new(vec![1u8; 4096])
            .with_version("v1")
            .changing_after(1);

        let err = drive_async(&transport, &config(1024, 65536), "test", read_all)
            .await
            .unwrap_err();

        assert!(
            matches!(err, AssetTransportError::VersionChanged { .. }),
            "expected VersionChanged, got {err:?}"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn a_parse_that_never_re_misses_hits_the_ceiling() {
        // Reads a different window each attempt, so it never re-reads a fetched range
        // and re-miss detection cannot fire. The ceiling is the only thing that stops it.
        let transport = MemAsync::new(vec![5u8; 1024 * 1024]);
        let attempt = std::cell::Cell::new(0u64);

        let err = drive_async(&transport, &config(1024, 8192), "test", |stream| {
            let n = attempt.get();
            attempt.set(n + 1);
            stream.seek(SeekFrom::Start(n * 4096))?;
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf)?;
            Ok(())
        })
        .await
        .unwrap_err();

        match err {
            AssetTransportError::AttemptsExhausted {
                attempts, ceiling, ..
            } => {
                assert_eq!(ceiling, 10); // 8192 / 1024 + 2
                assert_eq!(attempts, 10);
            }
            other => panic!("expected AttemptsExhausted, got {other:?}"),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn the_whole_object_rung_refuses_an_object_over_the_cap() {
        let transport = MemAsync::new(vec![9u8; 4096]);

        let under = read_whole_async(
            &transport,
            &config(1024, 65536).with_max_whole_object(Some(8192)),
            "u",
        )
        .await
        .unwrap();
        assert_eq!(under.into_inner().len(), 4096);

        let over = read_whole_async(
            &transport,
            &config(1024, 65536).with_max_whole_object(Some(1024)),
            "https://x/y",
        )
        .await
        .unwrap_err();
        assert!(matches!(
            over,
            AssetTransportError::WholeObjectTooLarge { len: 4096, .. }
        ));

        // `None` disables the rung outright, which is what a memory-capped Worker sets.
        let disabled = read_whole_async(
            &transport,
            &config(1024, 65536).with_max_whole_object(None),
            "https://x/y",
        )
        .await
        .unwrap_err();
        assert!(matches!(
            disabled,
            AssetTransportError::WholeObjectTooLarge { .. }
        ));
    }

    /// Under an unbounded cap there is no length left to refuse, so a transport
    /// reporting an impossible length must fail by name rather than abort the process
    /// on a reservation it can never satisfy.
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

    /// The unbounded cap admits an object the default 256 MiB cap would refuse.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn the_unbounded_cap_admits_an_object_over_the_default() {
        let transport = MemAsync::new(vec![7u8; 4096]);

        let refused = read_whole_async(
            &transport,
            &config(1024, 65536).with_max_whole_object(Some(1024)),
            "https://x/y",
        )
        .await
        .unwrap_err();
        assert!(matches!(
            refused,
            AssetTransportError::WholeObjectTooLarge { .. }
        ));

        let admitted = read_whole_async(
            &transport,
            &config(1024, 65536).with_unbounded_whole_object(),
            "https://x/y",
        )
        .await
        .unwrap();
        assert_eq!(admitted.into_inner().len(), 4096);
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod hash_equivalence_tests {
    #![allow(clippy::panic, clippy::unwrap_used)]
    use std::{io::Cursor, num::NonZeroUsize};

    use super::*;
    use crate::utils::hash_utils::hash_stream_by_alg;

    struct Mem(Vec<u8>);

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl AsyncRangeTransport for Mem {
        async fn info_async(&self) -> Result<super::super::RangeInfo, AssetTransportError> {
            Ok(super::super::RangeInfo::new(self.0.len() as u64))
        }
        async fn read_range_async(
            &self,
            offset: u64,
            len: u64,
            _expect: Option<&ObjectVersion>,
        ) -> Result<super::super::RangeChunk, AssetTransportError> {
            let start = (offset as usize).min(self.0.len());
            let end = start.saturating_add(len as usize).min(self.0.len());
            Ok(super::super::RangeChunk::new(
                offset,
                self.0[start..end].to_vec(),
            ))
        }
    }

    async fn both(data: &[u8], exclusions: Option<Vec<HashRange>>, chunk: usize) -> (Vec<u8>, Vec<u8>) {
        let blocking =
            hash_stream_by_alg("sha256", &mut Cursor::new(data.to_vec()), exclusions.clone(), true)
                .unwrap();
        let transport = Mem(data.to_vec());
        let driven = hash_ranges_async(
            "sha256",
            &transport,
            &RangeConfig::default(),
            exclusions,
            true,
            NonZeroUsize::new(chunk).unwrap(),
            &mut |_, _| Ok(()),
        )
        .await
        .unwrap();
        (blocking, driven)
    }

    #[tokio::test]
    async fn the_async_hash_matches_the_blocking_hash() {
        let data: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();

        let (a, b) = both(&data, None, 512).await;
        assert_eq!(a, b, "no exclusions");

        let one = vec![HashRange::new(100, 50)];
        let (a, b) = both(&data, Some(one), 512).await;
        assert_eq!(a, b, "one exclusion");

        let two = vec![HashRange::new(100, 50), HashRange::new(4000, 200)];
        let (a, b) = both(&data, Some(two), 512).await;
        assert_eq!(a, b, "two exclusions");
    }
}
