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

//! Layer recovering read asset bytes through some transport (e.g. filesystem, network, ...).
//! Extension points `SyncAssetTransport` and `AsyncAssetTransport` lets determine
//! where and how asset bytes are read from.
//! Custom transports can be registered on [`Context`](crate::Context).

mod error;
mod local;
mod range;

pub use error::AssetTransportError;
#[cfg(feature = "file_io")]
pub use local::LocalAssetTransport;
pub use local::UnconfiguredAssetTransport;
use range::RangeStream;
pub use range::{
    content_range_total, validate_range_status, AsyncRangeTransport, ObjectVersion, RangeChunk,
    RangeConfig, RangeInfo, RangeTransportSource, SyncRangeTransport,
};

use crate::{
    maybe_send_sync::{MaybeSend, MaybeSync},
    read_seek::ReadSeek,
};

/// What the transport opens:
/// filepath (filesystem), URI, or something the transport handler defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssetRef<'a> {
    /// A filesystem path.
    Path(&'a std::path::Path),
    /// An absolute URI.
    Uri(&'a str),
    /// Location/type defined by the handler, opaque, so untrusted.
    /// The handler is expected to check for path traversals etc.
    Custom(&'a str),
}

/// A generic request to open an asset (through an AssetRef).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AssetRequest<'a> {
    /// Reference to open.
    pub reference: AssetRef<'a>,
}

impl<'a> AssetRequest<'a> {
    /// Build a request to open an [`AssetRef`].
    pub fn new(reference: AssetRef<'a>) -> Self {
        Self { reference }
    }

    /// Build a request to open an [`AssetRef`] from a string.
    /// Supports URIs (if recognized as URI), considered an opaque ref otherwise.
    pub fn from_reference(reference: &'a str) -> Self {
        let reference = if has_uri_scheme(reference) {
            AssetRef::Uri(reference)
        } else {
            AssetRef::Custom(reference)
        };
        Self::new(reference)
    }
}

/// Determines if an asset reference fits a URI scheme.
/// Matches any URI format (e.g. s3://bucket/key).
fn has_uri_scheme(reference: &str) -> bool {
    let Some((scheme, _)) = reference.split_once("://") else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Result of opening request: bytes + transport info.
#[non_exhaustive]
pub struct ResolvedAsset {
    bytes: AssetBytes,
    format: Option<String>,
}

/// How a resolved asset's bytes are backed: a ready seekable stream, or a
/// random-access range source fetched on demand.
enum AssetBytes {
    Stream(Box<dyn ReadSeek>),
    Ranges(RangeSource),
}

/// A range transport plus the window-cache configuration to read it with.
struct RangeSource {
    transport: RangeTransportKind,
    config: RangeConfig,
}

/// A range transport, synchronous or non-blocking.
enum RangeTransportKind {
    Sync(Box<dyn SyncRangeTransport>),
    // Constructed by `from_ranges_async` and refused by the synchronous accessors with
    // `NoSyncTransport`. The transport itself is read by the retry-on-miss driver that
    // lands with asynchronous verification; until then it is intentionally only stored.
    #[allow(dead_code)]
    Async(Box<dyn AsyncRangeTransport>),
}

impl ResolvedAsset {
    /// Creates a seekable stream set at the beginning of an asset.
    pub fn new(stream: impl ReadSeek + 'static) -> Self {
        Self {
            bytes: AssetBytes::Stream(Box::new(stream)),
            format: None,
        }
    }

    /// Serves the asset in byte ranges through a synchronous [`SyncRangeTransport`].
    ///
    /// The transport is wrapped in a window cache and presented to the parse as an
    /// ordinary seekable stream, so a synchronous read verifies over ranges with no
    /// separate driver.
    pub fn from_ranges(transport: impl SyncRangeTransport + 'static) -> Self {
        Self {
            bytes: AssetBytes::Ranges(RangeSource {
                transport: RangeTransportKind::Sync(Box::new(transport)),
                config: RangeConfig::default(),
            }),
            format: None,
        }
    }

    /// Serves the asset in byte ranges through a non-blocking [`AsyncRangeTransport`],
    /// for a runtime with no blocking read (a service worker, a Cloudflare Worker).
    ///
    /// The synchronous parse path cannot read this directly; the reader drives it.
    pub fn from_ranges_async(transport: impl AsyncRangeTransport + 'static) -> Self {
        Self {
            bytes: AssetBytes::Ranges(RangeSource {
                transport: RangeTransportKind::Async(Box::new(transport)),
                config: RangeConfig::default(),
            }),
            format: None,
        }
    }

    /// Format hint for the asset (bytes) transport.
    pub fn with_format(mut self, format: impl Into<String>) -> Self {
        self.format = Some(format.into());
        self
    }

    /// Sets the window-cache configuration for a range-backed asset.
    ///
    /// Returns an error on a stream asset: there is no range source to configure, and
    /// silently discarding the configuration would hide the mistake.
    pub fn with_range_config(mut self, config: RangeConfig) -> Result<Self, AssetTransportError> {
        match &mut self.bytes {
            AssetBytes::Ranges(source) => {
                source.config = config;
                Ok(self)
            }
            AssetBytes::Stream(_) => Err(AssetTransportError::Other {
                source: "with_range_config called on a stream asset (no range source to configure)"
                    .into(),
            }),
        }
    }

    /// Format hint for the asset (bytes) transport, as declared by the transport.
    /// Hint, since e.g. a `Content-Type` hint wouldn't override magic bytes determined type.
    pub fn advisory_format(&self) -> Option<&str> {
        self.format.as_deref()
    }

    /// Turns the transported asset bytes into a blocking seekable stream.
    ///
    /// A stream asset returns its stream; a synchronous range asset is wrapped so it
    /// fetches on demand. An asynchronous range asset has no blocking view and returns
    /// [`AssetTransportError::NoSyncTransport`]; use the async read path for it.
    pub fn try_into_read_seek(self) -> Result<Box<dyn ReadSeek>, AssetTransportError> {
        match self.bytes {
            AssetBytes::Stream(stream) => Ok(stream),
            AssetBytes::Ranges(source) => match source.transport {
                RangeTransportKind::Sync(transport) => {
                    Ok(Box::new(RangeStream::new(transport, source.config)))
                }
                RangeTransportKind::Async(_) => Err(AssetTransportError::NoSyncTransport),
            },
        }
    }
}

/// Extension point: transport that can open an asset synchronously.
/// The surface is read-only today; a write path would arrive as further methods.
pub trait SyncAssetTransport: MaybeSend + MaybeSync {
    /// Opens the requested asset, returns seekable bytes (position is at the start).
    fn open(&self, request: &AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError>;
}

/// Transport that can open an asset synchronously.
impl<T: SyncAssetTransport + ?Sized> SyncAssetTransport for std::sync::Arc<T> {
    fn open(&self, request: &AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError> {
        (**self).open(request)
    }
}

/// Extension point: transport that can open an asset asynchronously (non-blocking only).
/// The surface is read-only today; a write path would arrive as further methods.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait AsyncAssetTransport: MaybeSend + MaybeSync {
    /// Opens the requested asset, returns seekable bytes (position is at the start).
    async fn open_async(
        &self,
        request: &AssetRequest<'_>,
    ) -> Result<ResolvedAsset, AssetTransportError>;
}

/// Transport that can open an asset asynchronously (non-blocking only).
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<T: AsyncAssetTransport + ?Sized> AsyncAssetTransport for std::sync::Arc<T> {
    async fn open_async(
        &self,
        request: &AssetRequest<'_>,
    ) -> Result<ResolvedAsset, AssetTransportError> {
        (**self).open_async(request).await
    }
}
