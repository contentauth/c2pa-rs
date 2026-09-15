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
//! rule, and [`validate_range_status`]/[`content_range_total`] the `206`/`412` status
//! rules and `Content-Range` total parsing that every HTTP range transport needs.
//! They are pure functions over values a fetch already produced, so they pull in no
//! HTTP client and are available in any build.

mod cache;
mod stream;

pub(crate) use stream::RangeStream;

use crate::{
    asset_transport::{AssetRequest, AssetTransportError, ResolvedAsset, SyncAssetTransport},
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
    pub fn from_http_validators(
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Option<ObjectVersion> {
        if let Some(etag) = etag {
            let etag = etag.trim();
            if !etag.is_empty() && !etag.starts_with("W/") {
                return Some(ObjectVersion::new(etag));
            }
        }
        last_modified
            .map(str::trim)
            .filter(|lm| !lm.is_empty())
            .map(ObjectVersion::new)
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
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(ObjectVersion::new(version));
        self
    }
}

/// Tunables for the window cache layered over a range transport.
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
    /// # use c2pa::asset_transport::RangeConfig;
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
pub trait SyncRangeTransport: MaybeSend + MaybeSync {
    /// Reports the object length, and its version when the transport knows one.
    ///
    /// Called at most once per read. [`read_range`](Self::read_range) also reports a
    /// version, which anchors the read on a response whose bytes are used.
    fn info(&self) -> Result<RangeInfo, AssetTransportError>;

    /// Reads up to `len` bytes at `offset`, reporting which version served them.
    ///
    /// May return fewer bytes than requested; `RangeStream` treats a short read as
    /// [`AssetTransportError::ShortRead`], never as end-of-file. Returning *more* than
    /// `len` bytes is rejected by the caller: it is the signature of a server that
    /// ignored the range request and returned the whole object.
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

/// Checks an HTTP range response's status against the range contract, so an HTTP
/// range transport does not reinvent this rule.
///
/// - `206 Partial Content` is the success case.
/// - `200 OK` with a validator that differs from `expect` means the object changed
///   and the whole body was returned; reported as
///   [`AssetTransportError::VersionChanged`].
/// - `412 Precondition Failed` means the origin rejected the `If-Range`; also
///   [`AssetTransportError::VersionChanged`].
/// - `416 Range Not Satisfiable` means the range lies outside the object; reported as
///   [`AssetTransportError::RangeNotSatisfiable`].
/// - Any other status means the far end did not honor `Range`.
///
/// A `200` whose validator matches `expect` (or where no version is known) still
/// fails as "did not honor Range": a whole-body response cannot be trusted to sit at
/// the requested offset. The length backstop in the core fetch path catches it too,
/// but failing here names the cause.
///
/// Pure over values a fetch already produced — no I/O, no HTTP client.
pub fn validate_range_status(
    status: u16,
    reference: &str,
    expect: Option<&ObjectVersion>,
    served: Option<&ObjectVersion>,
) -> Result<(), AssetTransportError> {
    match status {
        206 => Ok(()),
        416 => Err(AssetTransportError::RangeNotSatisfiable {
            reference: reference.to_string(),
        }),
        412 => Err(AssetTransportError::VersionChanged {
            expected: expect.map(ObjectVersion::to_string).unwrap_or_default(),
            got: "rejected by origin (412 Precondition Failed)".to_string(),
        }),
        200 => {
            if let (Some(expected), Some(got)) = (expect, served) {
                if expected != got {
                    return Err(AssetTransportError::VersionChanged {
                        expected: expected.to_string(),
                        got: got.to_string(),
                    });
                }
            }
            Err(AssetTransportError::Other {
                source: "expected 206 Partial Content, got 200 (server did not honor Range)".into(),
            })
        }
        other => Err(AssetTransportError::Other {
            source: format!(
                "expected 206 Partial Content, got {other} (server may not honor Range)"
            )
            .into(),
        }),
    }
}

/// Parses the total object length from a `Content-Range` header value.
///
/// `bytes 0-1023/4096` yields `Some(4096)`; an unknown total (`*/`) or an
/// unparseable value yields `None`. Pure over the header value — no I/O.
pub fn content_range_total(value: &str) -> Option<u64> {
    let total = value.rsplit_once('/')?.1.trim();
    if total == "*" {
        return None;
    }
    total.parse().ok()
}

/// Fetches a range and confirms it matches the request: right version, not longer
/// than asked.
///
/// Returns the bytes and the version that served them, so a caller reading an object
/// across several requests can adopt the first version it sees and hold every later
/// response to it. Returns [`AssetTransportError::VersionChanged`] when the source
/// reports a different version than the read began with, and rejects a response longer
/// than `len` — the signature of a server that ignored `Range` and returned the whole
/// object, whose bytes would otherwise be cached at the wrong offset.
pub(crate) fn fetch_versioned(
    reader: &dyn SyncRangeTransport,
    offset: u64,
    len: u64,
    expect: Option<&ObjectVersion>,
) -> Result<RangeChunk, AssetTransportError> {
    let chunk = reader.read_range(offset, len, expect)?;
    reject_overlong(offset, len, chunk.bytes.len())?;
    check_version(expect, chunk.version.as_ref())?;
    Ok(chunk)
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
    want.max(config.window)
        .min(config.max_request)
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
pub struct RangeTransportSource<F> {
    factory: F,
    config: RangeConfig,
}

impl<F, R> RangeTransportSource<F>
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

impl<F, R> SyncAssetTransport for RangeTransportSource<F>
where
    F: Fn(&AssetRequest<'_>) -> Result<R, AssetTransportError> + MaybeSend + MaybeSync,
    R: SyncRangeTransport + 'static,
{
    fn open(&self, request: AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError> {
        let reader = (self.factory)(&request)?;
        Ok(ResolvedAsset::from_ranges(reader, self.config))
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
            _offset: u64,
            _len: u64,
            _expect: Option<&ObjectVersion>,
        ) -> Result<RangeChunk, AssetTransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let chunk = RangeChunk::new(self.bytes.clone());
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
        // Neither usable.
        assert_eq!(
            ObjectVersion::from_http_validators(Some("W/\"abc\""), Some("  ")),
            None
        );
        assert_eq!(ObjectVersion::from_http_validators(None, None), None);
    }

    #[test]
    fn validate_range_status_enforces_the_range_contract() {
        assert!(validate_range_status(206, "s3://bucket/key", None, None).is_ok());

        // 200 with a differing validator is a changed object.
        let v1 = ObjectVersion::new("v1");
        let v2 = ObjectVersion::new("v2");
        assert!(matches!(
            validate_range_status(200, "s3://bucket/key", Some(&v1), Some(&v2)),
            Err(AssetTransportError::VersionChanged { .. })
        ));
        // 200 without a version mismatch still fails: a whole body is not a range.
        assert!(matches!(
            validate_range_status(200, "s3://bucket/key", None, None),
            Err(AssetTransportError::Other { .. })
        ));

        assert!(matches!(
            validate_range_status(412, "s3://bucket/key", Some(&v1), None),
            Err(AssetTransportError::VersionChanged { .. })
        ));
        assert!(matches!(
            validate_range_status(416, "s3://bucket/key", None, None),
            Err(AssetTransportError::RangeNotSatisfiable { reference })
                if reference == "s3://bucket/key"
        ));
        assert!(matches!(
            validate_range_status(500, "s3://bucket/key", None, None),
            Err(AssetTransportError::Other { .. })
        ));
    }

    #[test]
    fn content_range_total_parses_the_suffix() {
        assert_eq!(content_range_total("bytes 0-1023/4096"), Some(4096));
        assert_eq!(content_range_total("bytes 0-1023/*"), None);
        assert_eq!(content_range_total("garbage"), None);
    }

    #[test]
    fn add_signed_bounds_both_ends() {
        assert_eq!(add_signed(10, 5).unwrap(), 15);
        assert_eq!(add_signed(10, -5).unwrap(), 5);
        assert!(add_signed(0, -1).is_err());
        assert!(add_signed(u64::MAX, 1).is_err());
    }
}
