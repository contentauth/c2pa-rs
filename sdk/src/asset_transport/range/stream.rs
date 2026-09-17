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

//! A synchronous `Read + Seek` view over a [`SyncRangeTransport`] and its window cache.

use std::io::{self, Read, Seek, SeekFrom};

use super::{
    cache::RangeCache, fetch_len, seek_to, ObjectVersion, RangeConfig, SyncRangeTransport,
};
use crate::asset_transport::AssetTransportError;

/// A seekable stream that fetches asset bytes on demand through a
/// [`SyncRangeTransport`], caching fetched segments so seek-heavy access does not
/// re-request bytes it already holds.
///
/// The object length is discovered lazily on the first read, not in the constructor.
pub(crate) struct RangeStream {
    transport: Box<dyn SyncRangeTransport>,
    cache: RangeCache,
    config: RangeConfig,
    offset: u64,
    len: Option<u64>,
    /// The object version this stream is reading, adopted from the first response
    /// that reports one. Every later response must agree, so a stream cannot
    /// silently splice together two versions of an object.
    version: Option<ObjectVersion>,
}

impl RangeStream {
    pub(crate) fn new(transport: Box<dyn SyncRangeTransport>, config: RangeConfig) -> Self {
        let config = config.clamped();
        Self {
            cache: RangeCache::new(config.max_cached()),
            transport,
            config,
            offset: 0,
            len: None,
            version: None,
        }
    }

    /// Discovers and caches the object length, adopting the reported version if the
    /// stream has not already anchored on one.
    fn resolved_len(&mut self) -> io::Result<u64> {
        if let Some(len) = self.len {
            return Ok(len);
        }
        let info = self.transport.info().map_err(to_io)?;
        self.len = Some(info.len);
        if self.version.is_none() {
            self.version = info.version;
        }
        Ok(info.len)
    }
}

impl Read for RangeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.resolved_len()?;
        if self.offset >= len {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(len - self.offset) as usize;
        if want == 0 {
            return Ok(0);
        }

        let mut got = self.cache.copy_into(self.offset, &mut buf[..want]);
        if got == 0 {
            let remaining = len - self.offset;
            let fetch = fetch_len(want as u64, remaining, &self.config);
            let chunk = super::fetch_versioned(
                self.transport.as_ref(),
                self.offset,
                fetch,
                self.version.as_ref(),
            )
            .map_err(to_io)?;
            if chunk.bytes.is_empty() {
                // Bytes remain but the source returned nothing: a short read, not EOF.
                return Err(to_io(AssetTransportError::ShortRead {
                    offset: self.offset,
                    expected: fetch,
                    got: 0,
                }));
            }
            // Anchor on the first version seen; `fetch_versioned` has already
            // rejected any later response that disagrees with it.
            if self.version.is_none() {
                self.version = chunk.version;
            }
            self.cache.insert(self.offset, chunk.bytes);
            got = self.cache.copy_into(self.offset, &mut buf[..want]);
        }

        self.offset += got as u64;
        Ok(got)
    }
}

impl Seek for RangeStream {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_offset = seek_to(self.offset, pos, || self.resolved_len())?;
        self.offset = new_offset;
        Ok(new_offset)
    }
}

fn to_io(err: AssetTransportError) -> io::Error {
    match err {
        AssetTransportError::Io(e) => e,
        other => io::Error::other(other),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::num::NonZeroU64;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use super::*;
    use crate::asset_transport::range::{RangeChunk, RangeInfo};

    struct MemReader {
        data: Vec<u8>,
        calls: Arc<AtomicUsize>,
        short: bool,
    }

    impl SyncRangeTransport for MemReader {
        fn info(&self) -> Result<RangeInfo, AssetTransportError> {
            Ok(RangeInfo::new(self.data.len() as u64))
        }

        fn read_range(
            &self,
            offset: u64,
            len: u64,
            _expect: Option<&ObjectVersion>,
        ) -> Result<RangeChunk, AssetTransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.short {
                return Ok(RangeChunk::new(offset, Vec::new()));
            }
            let start = offset as usize;
            let end = (offset + len).min(self.data.len() as u64) as usize;
            Ok(RangeChunk::new(offset, self.data[start..end].to_vec()))
        }
    }

    fn reader(data: Vec<u8>) -> (Box<MemReader>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let reader = Box::new(MemReader {
            data,
            calls: calls.clone(),
            short: false,
        });
        (reader, calls)
    }

    #[test]
    fn reads_full_object() {
        let data: Vec<u8> = (0..200u8).collect();
        let (mem, _calls) = reader(data.clone());
        let mut stream = RangeStream::new(mem, RangeConfig::default());
        let mut out = Vec::new();
        stream.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn seek_backwards_reuses_cache() {
        let data: Vec<u8> = (0..100u8).collect();
        let (mem, calls) = reader(data.clone());
        let mut stream = RangeStream::new(mem, RangeConfig::default());

        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &data[..10]);

        stream.seek(SeekFrom::Start(0)).unwrap();
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &data[..10]);

        // The default window covers this object in one request, so the re-read after
        // seeking back is served from cache.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_fetch_never_exceeds_the_eviction_budget() {
        // `max_request` above `max_cached` produces one segment `evict` cannot drop,
        // since it keeps the last segment whatever the budget. `RangeStream::new` caps
        // the request at the budget, so `max_cached` is the real peak.
        let max_cached = NonZeroU64::new(1024).unwrap();
        let config = RangeConfig::default()
            .with_window(NonZeroU64::new(64).unwrap())
            .with_max_cached(max_cached)
            .with_max_request(max_cached.saturating_mul(NonZeroU64::new(8).unwrap()));

        let (mem, _calls) = reader(vec![0u8; 16 * 1024]);
        let mut stream = RangeStream::new(mem, config);

        // A read larger than the budget: `want` alone would ask for 8 KiB.
        let mut buf = vec![0u8; 8 * 1024];
        stream.read_exact(&mut buf).unwrap();

        assert!(
            stream.cache.cached_bytes() <= max_cached.get(),
            "cached {} exceeded budget {max_cached}",
            stream.cache.cached_bytes()
        );
    }

    #[test]
    fn a_disabled_whole_object_rung_is_distinct_from_a_zero_tunable() {
        // Zero is meaningful here, unlike the three `NonZeroU64` tunables: it means the
        // whole-object rung is off, not that a size was left unset.
        assert_eq!(
            RangeConfig::default()
                .with_max_whole_object(None)
                .max_whole_object(),
            None
        );
    }

    #[test]
    fn short_read_surfaces_as_error() {
        let mem = MemReader {
            data: vec![0u8; 100],
            calls: Arc::new(AtomicUsize::new(0)),
            short: true,
        };
        let mut stream = RangeStream::new(Box::new(mem), RangeConfig::default());
        let mut buf = [0u8; 10];
        let err = stream.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    // `SeekFrom::End` is the one arm that has to discover the object length, and it
    // costs a request to do so. The other arms must not pay for it.
    #[test]
    fn seeking_from_the_end_resolves_the_length_and_other_arms_do_not() {
        let data: Vec<u8> = (0..100u8).collect();
        let (mem, calls) = reader(data.clone());
        let mut stream = RangeStream::new(mem, RangeConfig::default());

        stream.seek(SeekFrom::Start(10)).unwrap();
        stream.seek(SeekFrom::Current(5)).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        assert_eq!(stream.seek(SeekFrom::End(-10)).unwrap(), 90);
        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &data[90..]);
    }

    #[test]
    fn read_past_end_returns_zero() {
        let (mem, _calls) = reader(vec![1, 2, 3]);
        let mut stream = RangeStream::new(mem, RangeConfig::default());
        stream.seek(SeekFrom::Start(10)).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }
}
