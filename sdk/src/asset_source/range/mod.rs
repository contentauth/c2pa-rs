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

pub(crate) use driver::{drive_async, drive_async_versioned};
pub use stream::RangeStream;

use crate::{
    asset_source::{AssetRequest, AssetSourceError, ResolvedAsset, SyncAssetSource},
    maybe_send_sync::{MaybeSend, MaybeSync},
};

/// An opaque token identifying one version of an object.
///
/// A range-backed read fetches the same object many times, and the bytes must all
/// come from one version of it.
/// The token is compared for equality and never interpreted. What it contains is
/// the transport's choice. A transport that cannot identify versions,
/// or judges its own token unfit for this purpose, reports `None` instead, and the
/// read proceeds without the guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectVersion(String);

impl ObjectVersion {
    /// Wraps a transport's version token.
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }
}

impl std::fmt::Display for ObjectVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a [`SyncRangeReader`]/[`AsyncRangeReader`] reports about the object it serves.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RangeInfo {
    /// Total length of the object in bytes.
    pub len: u64,
    /// Identifies the version of the object being served, when the transport can.
    ///
    /// `None` means the source cannot express object identity, so a read spanning
    /// several requests cannot be confirmed to have seen one consistent version.
    pub version: Option<ObjectVersion>,
}

impl RangeInfo {
    /// Reports an object of `len` bytes whose version cannot be identified.
    pub fn new(len: u64) -> Self {
        Self { len, version: None }
    }

    /// Records the version of the object being served.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(ObjectVersion::new(version));
        self
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

impl RangeConfig {
    /// Sets the bytes held at once while hashing for verification.
    ///
    /// This struct is `#[non_exhaustive]`, so a caller outside the crate cannot
    /// build one field-by-field; chain from [`Default`] instead:
    ///
    /// ```
    /// # use c2pa::RangeConfig;
    /// let config = RangeConfig::default().with_hash_chunk(1024 * 1024);
    /// ```
    pub fn with_hash_chunk(mut self, hash_chunk: u64) -> Self {
        self.hash_chunk = hash_chunk;
        self
    }
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

/// Bytes from one range request, and which version of the object served them.
///
/// `version` is `None` when the transport cannot identify object versions. The
/// read then proceeds without the guarantee that every byte came from one version,
/// and the caller records that in the validation results.
#[derive(Debug, Clone)]
pub struct RangeChunk {
    /// The bytes served. May be shorter than requested.
    pub bytes: Vec<u8>,
    /// The version that served them, when the transport can identify one.
    pub version: Option<ObjectVersion>,
}

impl RangeChunk {
    /// Bytes served by a transport that cannot identify object versions.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            version: None,
        }
    }

    /// Bytes served by a known version of the object.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(ObjectVersion::new(version));
        self
    }
}

/// A random-access byte source read synchronously.
pub trait SyncRangeReader: MaybeSend + MaybeSync {
    /// Reports the object length, and its version when the transport knows one.
    ///
    /// Called at most once per read. Prefer letting [`read_range`](Self::read_range)
    /// establish the version where the transport can, so the read anchors on a
    /// response whose bytes are actually used.
    fn info(&self) -> Result<RangeInfo, AssetSourceError>;

    /// Reads up to `len` bytes at `offset`, reporting which version served them.
    ///
    /// May return fewer bytes than requested; [`RangeStream`] treats a short read as
    /// [`AssetSourceError::ShortRead`], never as end-of-file.
    ///
    /// `expect` carries the version established earlier in this read, when one is
    /// known. A transport able to enforce it server-side should do so and report a
    /// mismatch as [`AssetSourceError::VersionChanged`]; the caller compares the
    /// returned version too, so a transport that cannot enforce it is still caught
    /// one round trip later.
    fn read_range(
        &self,
        offset: u64,
        len: u64,
        expect: Option<&ObjectVersion>,
    ) -> Result<RangeChunk, AssetSourceError>;
}

/// A random-access byte source read asynchronously, for non-blocking transports.
///
/// Driven by the async read path (the retry-on-miss driver); the synchronous parse
/// path cannot use it directly.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait AsyncRangeReader: MaybeSend + MaybeSync {
    /// Reports the object length, and its version when the transport knows one.
    async fn info_async(&self) -> Result<RangeInfo, AssetSourceError>;

    /// Reads up to `len` bytes at `offset`, reporting which version served them.
    ///
    /// The asynchronous twin of [`SyncRangeReader::read_range`], with the same
    /// contract: enforce `expect` where the transport can, and report what was
    /// served so the caller can compare.
    async fn read_range_async(
        &self,
        offset: u64,
        len: u64,
        expect: Option<&ObjectVersion>,
    ) -> Result<RangeChunk, AssetSourceError>;
}

/// Fetches a range and confirms it came from the expected version of the object.
///
/// Returns [`AssetSourceError::VersionChanged`] when the source reports a different
/// version than the read began with.
pub(crate) async fn fetch_versioned_async(
    reader: &dyn AsyncRangeReader,
    offset: u64,
    len: u64,
    expect: Option<&ObjectVersion>,
) -> Result<Vec<u8>, AssetSourceError> {
    let chunk = reader.read_range_async(offset, len, expect).await?;
    check_version(expect, chunk.version.as_ref())?;
    Ok(chunk.bytes)
}

/// The synchronous twin of [`fetch_versioned_async`].
///
/// Returns the bytes and the version that served them, so a caller reading an
/// object across several requests can adopt the first version it sees and hold
/// every later response to it.
pub(crate) fn fetch_versioned(
    reader: &dyn SyncRangeReader,
    offset: u64,
    len: u64,
    expect: Option<&ObjectVersion>,
) -> Result<RangeChunk, AssetSourceError> {
    let chunk = reader.read_range(offset, len, expect)?;
    check_version(expect, chunk.version.as_ref())?;
    Ok(chunk)
}

/// Compares an observed object version against the one a read began with.
///
/// Only a disagreement between two known versions is an error: if either side has
/// nothing to report, there is no guarantee to break.
pub(crate) fn check_version(
    expect: Option<&ObjectVersion>,
    observed: Option<&ObjectVersion>,
) -> Result<(), AssetSourceError> {
    match (expect, observed) {
        (Some(expected), Some(got)) if expected != got => Err(AssetSourceError::VersionChanged {
            expected: expected.to_string(),
            got: got.to_string(),
        }),
        _ => Ok(()),
    }
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
