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

//! Random-access byte sources and a shared window cache.
//!
//! A binding implements one method [`SyncRangeReader::read_range`] (or its async
//! twin) and gets segment caching, coalescing, short-read handling, and length
//! discovery from [`RangeStream`].

mod cache;
mod driver;
mod stream;

pub(crate) use driver::drive_async;
pub use stream::RangeStream;

use crate::{
    asset_source::{AssetRequest, AssetSourceError, ResolvedAsset, SyncAssetSource},
    maybe_send_sync::{MaybeSend, MaybeSync},
};

/// What a [`SyncRangeReader`]/[`AsyncRangeReader`] reports about the object it serves.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RangeInfo {
    /// Total length of the object in bytes.
    pub len: u64,
}

impl RangeInfo {
    /// Reports an object of `len` bytes.
    pub fn new(len: u64) -> Self {
        Self { len }
    }
}

/// Tunables for the window cache layered over a range reader.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RangeConfig {
    /// Minimum bytes to fetch per cache miss (read-ahead).
    pub window: u64,
    /// Upper bound on a single range request.
    pub max_request: u64,
    /// Eviction budget for cached bytes.
    pub max_cached: u64,
    /// Bytes held at once while hashing an asset for verification over an async source.
    /// Verification hashes the whole asset, so this bounds peak memory for the
    /// read: one chunk is fetched, hashed, and dropped before the next.
    pub hash_chunk: u64,
}

impl Default for RangeConfig {
    fn default() -> Self {
        Self {
            window: 64 * 1024,
            max_request: 8 * 1024 * 1024,
            max_cached: 4 * 1024 * 1024,
            hash_chunk: 4 * 1024 * 1024,
        }
    }
}

/// A random-access byte source read synchronously.
pub trait SyncRangeReader: MaybeSend + MaybeSync {
    /// Reports the object length.
    fn info(&self) -> Result<RangeInfo, AssetSourceError>;

    /// Reads up to `len` bytes at `offset`. May return fewer bytes than requested;
    /// [`RangeStream`] treats a short read as [`AssetSourceError::ShortRead`], never
    /// as end-of-file.
    fn read_range(&self, offset: u64, len: u64) -> Result<Vec<u8>, AssetSourceError>;
}

/// A random-access byte source read asynchronously, for non-blocking transports.
///
/// Driven by the async read path (the retry-on-miss driver); the synchronous parse
/// path cannot use it directly.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait AsyncRangeReader: MaybeSend + MaybeSync {
    /// Reports the object length.
    async fn info_async(&self) -> Result<RangeInfo, AssetSourceError>;

    /// Reads up to `len` bytes at `offset`.
    async fn read_range_async(
        &self,
        offset: u64,
        len: u64,
    ) -> Result<Vec<u8>, AssetSourceError>;
}

/// An [`SyncAssetSource`] that maps each request to a [`SyncRangeReader`], wrapping
/// it in the shared window cache.
///
/// The factory is called once per open and returns a reader for that reference.
pub struct RangeAssetSource<F> {
    factory: F,
    config: RangeConfig,
}

impl<F, R> RangeAssetSource<F>
where
    F: Fn(&AssetRequest<'_>) -> Result<R, AssetSourceError> + MaybeSend + MaybeSync,
    R: SyncRangeReader + 'static,
{
    /// Builds a range-backed asset source from a reader factory.
    pub fn new(factory: F) -> Self {
        Self {
            factory,
            config: RangeConfig::default(),
        }
    }

    /// Sets the window-cache configuration.
    pub fn with_config(mut self, config: RangeConfig) -> Self {
        self.config = config;
        self
    }
}

impl<F, R> SyncAssetSource for RangeAssetSource<F>
where
    F: Fn(&AssetRequest<'_>) -> Result<R, AssetSourceError> + MaybeSend + MaybeSync,
    R: SyncRangeReader + 'static,
{
    fn open(&self, request: &AssetRequest<'_>) -> Result<ResolvedAsset, AssetSourceError> {
        let reader = (self.factory)(request)?;
        Ok(ResolvedAsset::from_ranges(Box::new(reader)).with_range_config(self.config))
    }
}
