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

//! A synchronous `Read + Seek` view over a [`SyncRangeReader`] and its window cache.

use std::io::{self, Read, Seek, SeekFrom};

use super::{cache::RangeCache, ObjectVersion, RangeChunk, RangeConfig, SyncRangeReader};
use crate::asset_source::AssetSourceError;

/// A seekable stream that fetches asset bytes on demand through a
/// [`SyncRangeReader`], caching fetched segments so seek-heavy access does not
/// re-request bytes it already holds.
///
/// The object length is discovered lazily on the first read, not in the constructor.
pub struct RangeStream {
    reader: Box<dyn SyncRangeReader>,
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
    pub(crate) fn new(reader: Box<dyn SyncRangeReader>, config: RangeConfig) -> Self {
        Self {
            cache: RangeCache::new(config.max_cached),
            reader,
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
        let info = self.reader.info().map_err(to_io)?;
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
            let fetch_len = (want as u64)
                .max(self.config.window)
                .min(self.config.max_request)
                .min(remaining);
            let chunk = super::fetch_versioned(
                self.reader.as_ref(),
                self.offset,
                fetch_len,
                self.version.as_ref(),
            )
            .map_err(to_io)?;
            if chunk.bytes.is_empty() {
                // Bytes remain but the source returned nothing: a short read, not EOF.
                return Err(to_io(AssetSourceError::ShortRead {
                    offset: self.offset,
                    expected: fetch_len,
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
        let new_offset = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::Current(delta) => add_signed(self.offset, delta)?,
            SeekFrom::End(delta) => {
                let len = self.resolved_len()?;
                add_signed(len, delta)?
            }
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

fn to_io(err: AssetSourceError) -> io::Error {
    match err {
        AssetSourceError::Io(e) => e,
        other => io::Error::other(other),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::asset_source::range::RangeInfo;

    struct MemReader {
        data: Vec<u8>,
        calls: AtomicUsize,
        short: bool,
    }

    impl SyncRangeReader for MemReader {
        fn info(&self) -> Result<RangeInfo, AssetSourceError> {
            Ok(RangeInfo::new(self.data.len() as u64))
        }

        fn read_range(
            &self,
            offset: u64,
            len: u64,
            expect: Option<&ObjectVersion>,
        ) -> Result<RangeChunk, AssetSourceError> {
            let _ = expect;
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.short {
                return Ok(RangeChunk::new(Vec::new()));
            }
            let start = offset as usize;
            let end = (offset + len).min(self.data.len() as u64) as usize;
            Ok(RangeChunk::new(self.data[start..end].to_vec()))
        }
    }

    fn reader(data: Vec<u8>) -> Box<MemReader> {
        Box::new(MemReader {
            data,
            calls: AtomicUsize::new(0),
            short: false,
        })
    }

    #[test]
    fn reads_full_object() {
        let data: Vec<u8> = (0..200u8).collect();
        let mut stream = RangeStream::new(reader(data.clone()), RangeConfig::default());
        let mut out = Vec::new();
        stream.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn seek_backwards_reuses_cache() {
        let data: Vec<u8> = (0..100u8).collect();
        let mem = reader(data.clone());
        let calls_ref: *const AtomicUsize = &mem.calls;
        let mut stream = RangeStream::new(mem, RangeConfig::default());

        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &data[..10]);

        stream.seek(SeekFrom::Start(0)).unwrap();
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &data[..10]);

        // Default window (64 KiB) fetched the whole object in one request; the
        // re-read after seeking back is served from cache.
        let calls = unsafe { (*calls_ref).load(Ordering::SeqCst) };
        assert_eq!(calls, 1);
    }

    #[test]
    fn short_read_surfaces_as_error() {
        let mut mem = MemReader {
            data: vec![0u8; 100],
            calls: AtomicUsize::new(0),
            short: true,
        };
        mem.short = true;
        let mut stream = RangeStream::new(Box::new(mem), RangeConfig::default());
        let mut buf = [0u8; 10];
        let err = stream.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn read_past_end_returns_zero() {
        let mut stream = RangeStream::new(reader(vec![1, 2, 3]), RangeConfig::default());
        stream.seek(SeekFrom::Start(10)).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }
}
