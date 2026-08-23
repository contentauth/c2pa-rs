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

//! COntrols a synchronous parse over an asynchronous byte source.
//!
//! The C2PA parse path is synchronous `Read + Seek`. To read it over a
//! non-blocking transport without making the whole parser async, a synchronous
//! parse closure is run over a [`PrefetchStream`] that never performs I/O: a read
//! of uncached bytes aborts the closure with a [`AssetSourceError::RangeMiss`]
//! naming the wanted range. [`drive_async`] awaits that range, inserts it
//! into the cache, and re-runs the closure. The cache persists across attempts, so
//! every attempt makes strict progress.
//!
//! Only side-effect-free, restartable work may be driven this way.

use std::io::{self, Read, Seek, SeekFrom};

use super::{cache::RangeCache, AsyncRangeReader, RangeConfig};
use crate::{
    asset_source::AssetSourceError,
    context::Context,
    error::Result,
};

/// Aborts a driven closure after this many attempts.
const MAX_ATTEMPTS: u32 = 64;

/// A synchronous `Read + Seek` view over a [`RangeCache`] that performs no I/O.
///
/// A read of bytes not resident in the cache records the wanted range in a side
/// channel and returns an error to abort the read. The range is recorded in the
/// side channel rather than only in the error, so a miss is detected even when the
/// parser reclassifies the error.
/// Seeks never fail on missing bytes (they only move the cursor).
pub(crate) struct PrefetchStream<'a> {
    cache: &'a mut RangeCache,
    len: u64,
    offset: u64,
    config: RangeConfig,
    miss: &'a mut Option<(u64, u64)>,
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
            let remaining = self.len - self.offset;
            let fetch_len = (want as u64)
                .max(self.config.window)
                .min(self.config.max_request)
                .min(remaining);
            *self.miss = Some((self.offset, fetch_len));
            return Err(io::Error::other(AssetSourceError::RangeMiss {
                offset: self.offset,
                len: fetch_len,
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

fn add_signed(base: u64, delta: i64) -> io::Result<u64> {
    let result = base as i128 + delta as i128;
    if result < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "seek to a negative position",
        ));
    }
    Ok(result as u64)
}

/// Runs a synchronous parse closure over an asynchronous byte source.
///
/// Each cache miss aborts `op`, the missing range is awaited and inserted, and `op`
/// is re-run over the warmed cache.
/// Aborts with a "prefetch stalled" error if the closure re-requests a resident range or exceeds
/// [`MAX_ATTEMPTS`], and checks the context cancellation flag before each attempt.
pub(crate) async fn drive_async<T, F>(
    reader: &dyn AsyncRangeReader,
    context: &Context,
    config: RangeConfig,
    mut op: F,
) -> Result<T>
where
    F: FnMut(&mut PrefetchStream<'_>) -> Result<T>,
{
    let len = reader.info_async().await?.len;
    let mut cache = RangeCache::new(config.max_cached);
    let mut miss: Option<(u64, u64)> = None;
    let mut attempts: u32 = 0;

    loop {
        if context.is_cancelled() {
            return Err(AssetSourceError::Cancelled.into());
        }
        attempts += 1;
        if attempts > MAX_ATTEMPTS {
            return Err(AssetSourceError::Other(
                "prefetch stalled: exceeded maximum attempts".into(),
            )
            .into());
        }

        miss = None;
        let result = {
            let mut stream = PrefetchStream {
                cache: &mut cache,
                len,
                offset: 0,
                config,
                miss: &mut miss,
            };
            op(&mut stream)
        };

        // A miss during this attempt means the parse ran on incomplete bytes, so the
        // result is discarded regardless of whether `op` returned Ok or Err.
        let Some((offset, fetch_len)) = miss.take() else {
            return result;
        };

        // A range that is already resident cannot legitimately miss again:
        // that means the closure is not converging.
        let mut probe = [0u8; 1];
        if cache.copy_into(offset, &mut probe) > 0 {
            return Err(AssetSourceError::Other(
                "prefetch stalled: re-requested a cached range".into(),
            )
            .into());
        }
        let data = reader.read_range_async(offset, fetch_len).await?;
        if data.is_empty() {
            return Err(AssetSourceError::ShortRead {
                offset,
                expected: fetch_len,
                got: 0,
            }
            .into());
        }
        cache.insert(offset, data);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use super::*;
    use crate::asset_source::range::RangeInfo;
    use crate::error::Error;

    struct AsyncMem {
        data: Vec<u8>,
        calls: Arc<AtomicUsize>,
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl AsyncRangeReader for AsyncMem {
        async fn info_async(&self) -> std::result::Result<RangeInfo, AssetSourceError> {
            Ok(RangeInfo {
                len: self.data.len() as u64,
            })
        }
        async fn read_range_async(
            &self,
            offset: u64,
            len: u64,
        ) -> std::result::Result<Vec<u8>, AssetSourceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let start = offset as usize;
            let end = (offset + len).min(self.data.len() as u64) as usize;
            Ok(self.data[start..end].to_vec())
        }
    }

    // A tiny synchronous parser that reads the whole stream.
    fn read_all(stream: &mut PrefetchStream<'_>) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        stream.read_to_end(&mut out)?;
        Ok(out)
    }

    #[tokio::test]
    async fn drives_a_sync_parser_over_async_source_with_no_blocking() {
        let data: Vec<u8> = (0..250u8).collect();
        let reader = AsyncMem {
            data: data.clone(),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let context = Context::new();
        let config = RangeConfig {
            window: 32,
            max_request: 64,
            max_cached: 4 * 1024 * 1024,
            ..Default::default()
        };
        let out = drive_async(&reader, &context, config, read_all).await.unwrap();
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn cancellation_is_reported() {
        let reader = AsyncMem {
            data: vec![0u8; 1000],
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let context = Context::new();
        context.cancel();
        let config = RangeConfig::default();
        let err = drive_async(&reader, &context, config, read_all)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::AssetSource(AssetSourceError::Cancelled)));
    }

    struct NeverSatisfies;

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl AsyncRangeReader for NeverSatisfies {
        async fn info_async(&self) -> std::result::Result<RangeInfo, AssetSourceError> {
            Ok(RangeInfo { len: 1000 })
        }
        async fn read_range_async(
            &self,
            offset: u64,
            len: u64,
        ) -> std::result::Result<Vec<u8>, AssetSourceError> {
            // Serves only one byte per request, forcing many fetches.
            let _ = len;
            if offset >= 1000 {
                return Ok(Vec::new());
            }
            Ok(vec![0u8; 1])
        }
    }

    #[tokio::test]
    async fn non_converging_closure_reports_stall() {
        let reader = NeverSatisfies;
        let context = Context::new();
        let config = RangeConfig {
            window: 1,
            max_request: 1,
            max_cached: 4 * 1024 * 1024,
            ..Default::default()
        };
        // Reading the whole 1000-byte object one byte per fetch exceeds the attempt cap.
        let err = drive_async(&reader, &context, config, read_all)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::AssetSource(AssetSourceError::Other(_))));
    }

    #[tokio::test]
    async fn miss_detected_when_parser_reclassifies_the_abort_error() {
        // The BMFF reader wraps a read error into a non-io error...
        let data: Vec<u8> = (0..250u8).collect();
        let reader = AsyncMem {
            data: data.clone(),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let context = Context::new();
        let config = RangeConfig {
            window: 32,
            max_request: 64,
            max_cached: 4 * 1024 * 1024,
            ..Default::default()
        };
        let out = drive_async(&reader, &context, config, |stream| {
            let mut out = Vec::new();
            stream
                .read_to_end(&mut out)
                .map_err(|e| Error::BadParam(format!("reclassified: {e}")))?;
            Ok(out)
        })
        .await
        .unwrap();
        assert_eq!(out, data);
    }
}
