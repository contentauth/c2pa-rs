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

