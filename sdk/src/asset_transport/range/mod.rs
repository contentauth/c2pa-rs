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

//! Random-access byte transport source and a shared window cache.
//!
//! A binding implements one method [`SyncRangeTransport::read_range`] (or its async
//! twin) and gets segment caching, coalescing, short-read handling, and length
//! discovery from `RangeStream`.
//!
//! The synchronous path is complete here: a [`SyncRangeTransport`] wrapped in a
//! `RangeStream` is read by the ordinary synchronous parse, which discovers and
//! verifies the manifest over ranges. The asynchronous path is served by the
//! retry-on-miss driver and forward-only hashing added alongside verification; until
//! then [`AsyncRangeTransport`] is defined for callers to implement, but reading an
//! async range source returns
//! [`AsyncOnlyAsset`](AssetTransportError::AsyncOnlyAsset).
//!
//! HTTP transports do not have to reinvent object identity and status handling:
//! [`ObjectVersion::from_http_validators`] carries the `ETag`/`Last-Modified` version
//! rule, and the [`http_range`] module the status, `Range` and `Content-Range` rules
//! every HTTP range transport needs. They are pure functions over values a fetch already
//! produced, so they pull in no HTTP client and are available in any build.

mod cache;
mod driver;
pub mod http_range;
mod stream;

pub(crate) use driver::{drive_async, hash_ranges_async, read_whole_async};
pub(crate) use stream::RangeStream;

use crate::{
    asset_transport::{
        AssetRequest, AssetTransportError, AsyncAssetTransport, ResolvedAsset, SyncAssetTransport,
    },
    maybe_send_sync::{MaybeSend, MaybeSync},
};

/// An opaque token identifying one version of an object.
///
/// A range-backed read fetches the same object many times, and the bytes must all
/// come from one version of it.
/// The token is compared for equality and never interpreted. Its contents are the
/// transport's choice. A transport that cannot identify versions, or whose token is
/// unfit for this purpose, reports `None` instead, and the read proceeds without
/// the guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectVersion(String);

impl ObjectVersion {
    /// Wraps a transport's version token.
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    /// Derives a version token from HTTP validators, preferring a strong `ETag`.
    ///
    /// A weak `ETag` (`W/`-prefixed) is rejected: RFC 9110 says weak validators may
    /// compare equal across byte-different representations, which is exactly the
    /// guarantee a range read needs and a weak tag does not give. `Last-Modified` is
    /// the fallback. Returns `None` when neither yields a usable token, so the read
    /// proceeds unversioned rather than pinned to a token that cannot hold.
    ///
    /// The tag must be quoted: RFC 9110 8.8.3 defines `opaque-tag` as a quoted string,
    /// so a bare `abc` is malformed and falls through to `Last-Modified`. Quotes are
    /// kept, because 8.8.3.2 compares strong validators character by character.
    pub fn from_http_validators(
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Option<ObjectVersion> {
        if let Some(etag) = etag {
            let etag = etag.trim();
            if etag.starts_with('"') && etag.len() > 1 && etag.ends_with('"') {
                return Some(ObjectVersion::new(etag));
            }
        }
        last_modified
            .map(str::trim)
            .filter(|lm| !lm.is_empty())
            .map(ObjectVersion::new)
    }
}

impl From<String> for ObjectVersion {
    fn from(token: String) -> Self {
        ObjectVersion(token)
    }
}

impl From<&str> for ObjectVersion {
    fn from(token: &str) -> Self {
        ObjectVersion(token.to_string())
    }
}

impl std::fmt::Display for ObjectVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a [`SyncRangeTransport`]/[`AsyncRangeTransport`] reports about the object it
/// serves.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RangeInfo {
    /// Total length of the object in bytes.
    /// Discovered on the first read.
    /// [`ResolvedAsset::size`](crate::asset_transport::ResolvedAsset::size) is a hint.
    pub len: u64,
    /// Identifies the version of the object being served, when the transport can.
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
    pub fn with_version(mut self, version: impl Into<ObjectVersion>) -> Self {
        self.version = Some(version.into());
        self
    }
}

/// Tunables for the window cache layered over a range transport.
///
/// Fields are private and set through the `with_*` builders, which reject a zero where
/// zero has no meaning. Chain from [`Default`]:
///
/// ```
/// # use c2pa::asset_transport::RangeConfig;
/// # fn main() -> Result<(), c2pa::asset_transport::AssetTransportError> {
/// let config = RangeConfig::default().with_window(32 * 1024)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RangeConfig {
    /// Minimum bytes to fetch per cache miss (read-ahead).
    window: u64,
    /// Upper bound on a single range request.
    max_request: u64,
    /// Eviction budget for cached bytes.
    max_cached: u64,
    /// Largest object read whole when ranges cannot serve the read: a verified async
    /// read, or a handler that slurps. `None` disables that rung.
    max_whole_object: Option<u64>,
}

impl RangeConfig {
    /// Sets the read-ahead floor for a cache miss.
    ///
    /// A miss fetches at least this much. Smaller windows suit a format whose discovery
    /// walks box headers, where the working set is one window per header. Returns
    /// [`AssetTransportError::Other`] for zero, which would make every fetch empty.
    pub fn with_window(mut self, window: u64) -> Result<Self, AssetTransportError> {
        self.window = nonzero("window", window)?;
        Ok(self)
    }

    /// Sets the upper bound on one range request.
    ///
    /// [`RangeStream`] lowers this to `max_cached` when it is larger, so a single fetch
    /// can never exceed the eviction budget. Returns [`AssetTransportError::Other`] for
    /// zero.
    pub fn with_max_request(mut self, max_request: u64) -> Result<Self, AssetTransportError> {
        self.max_request = nonzero("max_request", max_request)?;
        Ok(self)
    }

    /// Sets the eviction budget for cached bytes.
    ///
    /// This is the peak memory a ranged read uses, and it also caps `max_request`.
    /// Returns [`AssetTransportError::Other`] for zero.
    pub fn with_max_cached(mut self, max_cached: u64) -> Result<Self, AssetTransportError> {
        self.max_cached = nonzero("max_cached", max_cached)?;
        Ok(self)
    }

    /// Sets the largest object the whole-object fallback will read.
    ///
    /// `None` disables the fallback, which is the setting for a runtime that cannot hold
    /// an arbitrary object, such as a Worker isolate.
    pub fn with_max_whole_object(mut self, max_whole_object: Option<u64>) -> Self {
        self.max_whole_object = max_whole_object;
        self
    }

    /// Lets the whole-object fallback read an object of any size.
    ///
    /// This suits a host that can hold the object, such as a desktop browser tab. The
    /// rung still fetches in [`max_request`](Self::max_request) pieces, and the caller
    /// holds the assembled object for the length of the read.
    pub fn with_unbounded_whole_object(mut self) -> Self {
        self.max_whole_object = Some(u64::MAX);
        self
    }

    /// Read-ahead floor for a cache miss.
    pub fn window(&self) -> u64 {
        self.window
    }

    /// Upper bound on one range request, before [`RangeStream`] caps it at
    /// [`max_cached`](Self::max_cached).
    pub fn max_request(&self) -> u64 {
        self.max_request
    }

    /// Eviction budget for cached bytes.
    pub fn max_cached(&self) -> u64 {
        self.max_cached
    }

    /// Largest object the whole-object fallback will read, or `None` when that fallback
    /// is disabled.
    pub fn max_whole_object(&self) -> Option<u64> {
        self.max_whole_object
    }
}

/// Rejects a zero for a tunable that has no meaning at zero.
fn nonzero(field: &str, value: u64) -> Result<u64, AssetTransportError> {
    if value == 0 {
        return Err(AssetTransportError::Other {
            source: format!("RangeConfig::{field} must be greater than zero").into(),
        });
    }
    Ok(value)
}

impl Default for RangeConfig {
    fn default() -> Self {
        Self {
            window: 16 * 1024,
            max_request: 8 * 1024 * 1024,
            max_cached: 4 * 1024 * 1024,
            // Verification reads the whole object, so a default of `None` would refuse
            // every async verified read. This fits a browser tab and a Node process; a
            // Worker isolate, capped near 128 MiB, lowers it or disables the rung.
            max_whole_object: Some(256 * 1024 * 1024),
        }
    }
}

/// Bytes from one range request, and which version of the object served them.
///
/// `version` is `None` when the transport cannot identify object versions. The
/// read then proceeds without the guarantee that every byte came from one version,
/// and the caller records that in the validation results.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RangeChunk {
    /// Where the response says these bytes start in the object.
    ///
    /// The offset the response *reported*, not the one requested. A transport that
    /// echoes the request here makes the caller's placement check pass unconditionally.
    /// An HTTP
    /// transport reads it from `Content-Range`.
    pub offset: u64,
    /// The bytes served. May be shorter than requested.
    pub bytes: Vec<u8>,
    /// The version that served them, when the transport can identify one.
    pub version: Option<ObjectVersion>,
}

impl RangeChunk {
    /// Bytes served by a transport that cannot identify object versions.
    pub fn new(offset: u64, bytes: Vec<u8>) -> Self {
        Self {
            offset,
            bytes,
            version: None,
        }
    }

    /// Bytes served by a known version of the object.
    pub fn with_version(mut self, version: impl Into<ObjectVersion>) -> Self {
        self.version = Some(version.into());
        self
    }
}

/// A random-access byte source read synchronously.
pub trait SyncRangeTransport: MaybeSend + MaybeSync {
    /// Reports the object length, and its version when the transport knows one.
    ///
    /// Called at most once per read. [`read_range`](Self::read_range) also reports a
    /// version, which anchors the read on a response whose bytes are used.
    fn info(&self) -> Result<RangeInfo, AssetTransportError>;

    /// Reads up to `len` bytes at `offset`, reporting which version served them.
    ///
    /// May return fewer bytes than requested. `RangeStream` accepts a short response and
    /// reads again from where it ended, so there is no need to pad. Only an empty
    /// response with bytes still outstanding is
    /// [`AssetTransportError::ShortRead`]. Returning *more* than `len` bytes is rejected
    /// by the caller: it is the signature of a server that ignored the range request and
    /// returned the whole object.
    ///
    /// The bytes must be unencoded. RFC 9110 14.1.2 defines ranges over the encoded
    /// bytes, so a `gzip` response makes every offset meaningless. This trait cannot see
    /// headers, so the transport checks its own `Content-Encoding` (see
    /// [`http_range::content_encoding_ok`](super::range::http_range::content_encoding_ok)).
    ///
    /// `expect` carries the version established earlier in this read, when one is
    /// known. The caller compares the returned version against what it expected, and
    /// that comparison is what holds a read to one object.
    ///
    /// A transport may additionally ask the far end to reject a changed object — an
    /// HTTP one can send `If-Range` — and report the refusal as
    /// [`AssetTransportError::VersionChanged`]. RFC 9110 13.1.1 permits any cache or
    /// intermediary to ignore a conditional header meant for an origin, so behind a
    /// CDN it may not be evaluated. A transport must always report the version it
    /// observed.
    fn read_range(
        &self,
        offset: u64,
        len: u64,
        expect: Option<&ObjectVersion>,
    ) -> Result<RangeChunk, AssetTransportError>;
}

/// A range transport behind a shared pointer, e.g. one owned across an FFI boundary.
impl<T: SyncRangeTransport + ?Sized> SyncRangeTransport for std::sync::Arc<T> {
    fn info(&self) -> Result<RangeInfo, AssetTransportError> {
        (**self).info()
    }

    fn read_range(
        &self,
        offset: u64,
        len: u64,
        expect: Option<&ObjectVersion>,
    ) -> Result<RangeChunk, AssetTransportError> {
        (**self).read_range(offset, len, expect)
    }
}

/// A random-access byte source read asynchronously, for non-blocking transports.
///
/// Driven by the async read path (the retry-on-miss driver); the synchronous parse
/// path cannot use it directly.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait AsyncRangeTransport: MaybeSend + MaybeSync {
    /// Reports the object length, and its version when the transport knows one.
    async fn info_async(&self) -> Result<RangeInfo, AssetTransportError>;

    /// Reads up to `len` bytes at `offset`, reporting which version served them.
    ///
    /// The asynchronous twin of [`SyncRangeTransport::read_range`], with the same
    /// contract: always report the version that served the bytes, never return more
    /// than `len` bytes, and optionally ask the far end to reject a changed object.
    async fn read_range_async(
        &self,
        offset: u64,
        len: u64,
        expect: Option<&ObjectVersion>,
    ) -> Result<RangeChunk, AssetTransportError>;
}

/// A range transport behind a shared pointer, e.g. one owned across an FFI boundary.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<T: AsyncRangeTransport + ?Sized> AsyncRangeTransport for std::sync::Arc<T> {
    async fn info_async(&self) -> Result<RangeInfo, AssetTransportError> {
        (**self).info_async().await
    }

    async fn read_range_async(
        &self,
        offset: u64,
        len: u64,
        expect: Option<&ObjectVersion>,
    ) -> Result<RangeChunk, AssetTransportError> {
        (**self).read_range_async(offset, len, expect).await
    }
}

/// Fetches a range and confirms it matches the request: right offset, right version,
/// not longer than asked.
///
/// Returns the bytes and the version that served them, so a caller reading an object
/// across several requests can adopt the first version it sees and hold every later
/// response to it. Returns [`AssetTransportError::VersionChanged`] when the source
/// reports a different version than the read began with, and rejects a response longer
/// than `len`, which is the signature of a server that ignored `Range` and returned the
/// whole object, whose bytes would otherwise be cached at the wrong offset.
pub(crate) fn fetch_versioned(
    reader: &dyn SyncRangeTransport,
    offset: u64,
    len: u64,
    expect: Option<&ObjectVersion>,
) -> Result<RangeChunk, AssetTransportError> {
    let chunk = reader.read_range(offset, len, expect)?;
    reject_misplaced(offset, chunk.offset)?;
    reject_overlong(offset, len, chunk.bytes.len())?;
    check_version(expect, chunk.version.as_ref())?;
    Ok(chunk)
}

/// Rejects a range response that starts somewhere other than the requested offset.
///
/// A correctly-sized response from the wrong position passes every length check and
/// still feeds the parser bytes from elsewhere in the object. Content delivery networks
/// realign ranges to block boundaries, proxies rewrite them, and service workers
/// substitute bodies.
fn reject_misplaced(requested: u64, served: u64) -> Result<(), AssetTransportError> {
    if served != requested {
        return Err(AssetTransportError::Other {
            source: format!(
                "range response starts at {served}, not the requested {requested} \
                 (the response was served from the wrong position)"
            )
            .into(),
        });
    }
    Ok(())
}

/// Rejects a range response longer than requested.
///
/// A response longer than `len` means the far end ignored the range request. Its
/// bytes are the object from position 0, not from `offset`, so caching them at
/// `offset` would feed the parser wrong bytes. Reject rather than truncate.
fn reject_overlong(offset: u64, len: u64, got: usize) -> Result<(), AssetTransportError> {
    if got as u64 > len {
        return Err(AssetTransportError::Other {
            source: format!(
                "range response at offset {offset} is longer than requested: \
                 expected at most {len}, got {got} (server may have ignored Range)"
            )
            .into(),
        });
    }
    Ok(())
}

/// Compares an observed object version against the one a read began with.
///
/// A disagreement between two known versions is an error. If either side reports no
/// version, the comparison passes.
pub(crate) fn check_version(
    expect: Option<&ObjectVersion>,
    observed: Option<&ObjectVersion>,
) -> Result<(), AssetTransportError> {
    match (expect, observed) {
        (Some(expected), Some(got)) if expected != got => {
            Err(AssetTransportError::VersionChanged {
                expected: expected.to_string(),
                got: got.to_string(),
            })
        }
        _ => Ok(()),
    }
}

/// Bytes to fetch for a cache miss: at least a full window, capped by the single
/// request limit and by what remains of the object.
pub(crate) fn fetch_len(want: u64, remaining: u64, config: &RangeConfig) -> u64 {
    want.max(config.window())
        .min(config.max_request())
        .min(remaining)
}

/// Adds a signed delta to an unsigned base, erroring on under- or overflow.
///
/// Used by the `RangeStream` and driver seek arithmetic.
pub(crate) fn add_signed(base: u64, delta: i64) -> std::io::Result<u64> {
    base.checked_add_signed(delta).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "seek to an invalid position",
        )
    })
}

/// A [`SyncAssetTransport`] that maps each request to a [`SyncRangeTransport`],
/// wrapping it in the shared window cache.
///
/// The factory is called once per open and returns a transport for that reference.
pub struct SyncRangeAssetTransport<F> {
    factory: F,
    config: RangeConfig,
}

impl<F, R> SyncRangeAssetTransport<F>
where
    F: Fn(&AssetRequest<'_>) -> Result<R, AssetTransportError> + MaybeSend + MaybeSync,
    R: SyncRangeTransport + 'static,
{
    /// Builds a range-backed asset source from a transport factory.
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

impl<F, R> SyncAssetTransport for SyncRangeAssetTransport<F>
where
    F: Fn(&AssetRequest<'_>) -> Result<R, AssetTransportError> + MaybeSend + MaybeSync,
    R: SyncRangeTransport + 'static,
{
    fn open(&self, request: AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError> {
        let reader = (self.factory)(&request)?;
        Ok(ResolvedAsset::from_ranges(reader, self.config))
    }
}

/// An [`AsyncAssetTransport`] that maps each request to an [`AsyncRangeTransport`],
/// for a runtime with no blocking read. The reader drives the parse over it.
///
/// The twin of [`SyncRangeAssetTransport`], and the reason a binding with an async
/// range transport does not write the [`AsyncAssetTransport`] boilerplate by hand.
pub struct AsyncRangeAssetTransport<F> {
    factory: F,
    config: RangeConfig,
}

impl<F, R> AsyncRangeAssetTransport<F>
where
    F: Fn(&AssetRequest<'_>) -> Result<R, AssetTransportError> + MaybeSend + MaybeSync,
    R: AsyncRangeTransport + 'static,
{
    /// Builds an async range-backed asset source from a transport factory.
    ///
    /// The factory is synchronous because opening a transport is cheap: it records a
    /// reference, and the first network round trip happens in
    /// [`AsyncRangeTransport::info_async`], which is awaited at most once per read.
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

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<F, R> AsyncAssetTransport for AsyncRangeAssetTransport<F>
where
    F: Fn(&AssetRequest<'_>) -> Result<R, AssetTransportError> + MaybeSend + MaybeSync,
    R: AsyncRangeTransport + 'static,
{
    async fn open_async(
        &self,
        request: AssetRequest<'_>,
    ) -> Result<ResolvedAsset, AssetTransportError> {
        let reader = (self.factory)(&request)?;
        Ok(ResolvedAsset::from_ranges_async(reader, self.config))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };

    use super::*;

    /// A transport double that returns exactly what it is told to, so tests can
    /// exercise the guards in the core fetch path.
    struct FakeTransport {
        bytes: Vec<u8>,
        version: Option<String>,
        calls: Arc<AtomicU64>,
    }

    impl SyncRangeTransport for FakeTransport {
        fn info(&self) -> Result<RangeInfo, AssetTransportError> {
            Ok(RangeInfo::new(self.bytes.len() as u64))
        }

        fn read_range(
            &self,
            offset: u64,
            _len: u64,
            _expect: Option<&ObjectVersion>,
        ) -> Result<RangeChunk, AssetTransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let chunk = RangeChunk::new(offset, self.bytes.clone());
            Ok(match &self.version {
                Some(v) => chunk.with_version(v.clone()),
                None => chunk,
            })
        }
    }

    #[test]
    fn fetch_versioned_rejects_an_overlong_response() {
        // A transport that ignored Range and returned more than requested. Caching
        // those bytes at the requested offset would feed the parser wrong bytes.
        let calls = Arc::new(AtomicU64::new(0));
        let transport = FakeTransport {
            bytes: vec![0u8; 100],
            version: None,
            calls: calls.clone(),
        };
        let err = fetch_versioned(&transport, 0, 10, None).unwrap_err();
        assert!(
            matches!(err, AssetTransportError::Other { .. }),
            "expected an over-length rejection, got {err:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fetch_versioned_allows_a_short_response() {
        // Short reads are contractual ("reads up to len"); only over-length is wrong.
        let transport = FakeTransport {
            bytes: vec![0u8; 4],
            version: None,
            calls: Arc::new(AtomicU64::new(0)),
        };
        let chunk = fetch_versioned(&transport, 0, 10, None).unwrap();
        assert_eq!(chunk.bytes.len(), 4);
    }

    #[test]
    fn fetch_versioned_detects_a_changed_version() {
        let transport = FakeTransport {
            bytes: vec![0u8; 4],
            version: Some("v2".to_string()),
            calls: Arc::new(AtomicU64::new(0)),
        };
        let expected = ObjectVersion::new("v1");
        let err = fetch_versioned(&transport, 0, 4, Some(&expected)).unwrap_err();
        assert!(matches!(err, AssetTransportError::VersionChanged { .. }));
    }

    #[test]
    fn fetch_versioned_rejects_a_response_from_the_wrong_offset() {
        // A content delivery network that realigns the range to a block boundary returns
        // the right number of bytes from the wrong position. Every length check passes
        // and the parser reads bytes from elsewhere in the object.
        struct RealignedTransport;
        impl SyncRangeTransport for RealignedTransport {
            fn info(&self) -> Result<RangeInfo, AssetTransportError> {
                Ok(RangeInfo::new(8192))
            }

            fn read_range(
                &self,
                offset: u64,
                len: u64,
                _expect: Option<&ObjectVersion>,
            ) -> Result<RangeChunk, AssetTransportError> {
                Ok(RangeChunk::new(offset + 512, vec![0u8; len as usize]))
            }
        }

        let err = fetch_versioned(&RealignedTransport, 1024, 256, None).unwrap_err();
        assert!(
            matches!(err, AssetTransportError::Other { .. }),
            "expected a misplaced-response rejection, got {err:?}"
        );
    }

    #[test]
    fn object_version_prefers_strong_etag_then_last_modified() {
        assert_eq!(
            ObjectVersion::from_http_validators(
                Some("\"abc\""),
                Some("Mon, 01 Jan 2026 00:00:00 GMT")
            ),
            Some(ObjectVersion::new("\"abc\""))
        );
        // A weak ETag is rejected; fall back to Last-Modified.
        assert_eq!(
            ObjectVersion::from_http_validators(Some("W/\"abc\""), Some("some-date")),
            Some(ObjectVersion::new("some-date"))
        );
        // RFC 9110 8.8.3 makes an unquoted tag malformed. Fall back to Last-Modified.
        assert_eq!(
            ObjectVersion::from_http_validators(Some("abc"), Some("some-date")),
            Some(ObjectVersion::new("some-date"))
        );
        // A lone quote is not a tag either.
        assert_eq!(
            ObjectVersion::from_http_validators(Some("\""), Some("some-date")),
            Some(ObjectVersion::new("some-date"))
        );
        // Neither usable.
        assert_eq!(
            ObjectVersion::from_http_validators(Some("W/\"abc\""), Some("  ")),
            None
        );
        assert_eq!(ObjectVersion::from_http_validators(None, None), None);
    }

    #[test]
    fn add_signed_bounds_both_ends() {
        assert_eq!(add_signed(10, 5).unwrap(), 15);
        assert_eq!(add_signed(10, -5).unwrap(), 5);
        assert!(add_signed(0, -1).is_err());
        assert!(add_signed(u64::MAX, 1).is_err());
    }
}
