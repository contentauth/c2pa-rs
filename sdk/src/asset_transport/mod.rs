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

//! Abstraction over where asset bytes are read from (filesystem, network, ...).
//! `SyncAssetTransport` and `AsyncAssetTransport` let callers plug in custom transports,
//! registered on [`Context`](crate::Context).

mod error;
mod local;
mod range;

pub use error::AssetTransportError;
#[cfg(feature = "file_io")]
pub use local::LocalAssetTransport;
pub use local::UnconfiguredAssetTransport;
pub(crate) use range::{drive_async, hash_ranges_async, read_whole_async};
use range::RangeStream;
pub use range::{
    http_range, AsyncRangeAssetTransport, AsyncRangeTransport, ObjectVersion, RangeChunk,
    RangeConfig, RangeInfo, SyncRangeAssetTransport, SyncRangeTransport,
};

use crate::{
    maybe_send_sync::{MaybeSend, MaybeSync},
    read_seek::ReadSeek,
};

/// What the transport opens: a filesystem path, a URI, or a handler-defined reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssetRef<'a> {
    /// A filesystem path.
    Path(&'a std::path::Path),
    /// An absolute URI.
    Uri(&'a str),
    /// A reference whose shape only the handler understands, so it is untrusted.
    /// The handler must guard against path traversal.
    Custom(&'a str),
}

impl AssetRef<'_> {
    /// Copy this reference into an owned [`OwnedAssetRef`].
    pub fn into_owned(self) -> OwnedAssetRef {
        match self {
            AssetRef::Path(p) => OwnedAssetRef::Path(p.to_path_buf()),
            AssetRef::Uri(u) => OwnedAssetRef::Uri(u.to_owned()),
            AssetRef::Custom(s) => OwnedAssetRef::Custom(s.to_owned()),
        }
    }
}

/// Owned form of [`AssetRef`], for a transport that keeps a reference past a borrow.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OwnedAssetRef {
    /// A filesystem path.
    Path(std::path::PathBuf),
    /// An absolute URI.
    Uri(String),
    /// A handler-defined reference (see [`AssetRef::Custom`]).
    Custom(String),
}

impl OwnedAssetRef {
    /// Borrow as an [`AssetRef`]. Not named `as_ref`: that reads as the [`AsRef`] trait,
    /// which returns a reference, while this returns a fresh borrowing value.
    pub fn as_asset_ref(&self) -> AssetRef<'_> {
        match self {
            OwnedAssetRef::Path(p) => AssetRef::Path(p),
            OwnedAssetRef::Uri(u) => AssetRef::Uri(u),
            OwnedAssetRef::Custom(s) => AssetRef::Custom(s),
        }
    }
}

impl std::fmt::Display for AssetRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetRef::Path(p) => write!(f, "{}", p.display()),
            AssetRef::Uri(u) => f.write_str(u),
            AssetRef::Custom(s) => f.write_str(s),
        }
    }
}

/// Whether a request targets the primary asset or its sidecar manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AssetRequestKind {
    /// The primary asset.
    #[default]
    Asset,
    /// A sidecar manifest (`.c2pa`). A transport that cannot serve sidecars returns
    /// [`AssetTransportError::UnsupportedReference`], which the reader reads as no manifest.
    Sidecar,
}

/// A generic request to read an asset (through an AssetRef).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AssetRequest<'a> {
    /// Reference to open.
    pub reference: AssetRef<'a>,
    /// Whether this targets the primary asset or its sidecar manifest.
    pub kind: AssetRequestKind,
}

impl<'a> AssetRequest<'a> {
    /// Build a request to open an [`AssetRef`].
    pub fn new(reference: AssetRef<'a>) -> Self {
        Self {
            reference,
            kind: AssetRequestKind::Asset,
        }
    }

    /// Set whether this targets the (primary) asset or its sidecar manifest.
    pub fn with_kind(mut self, kind: AssetRequestKind) -> Self {
        self.kind = kind;
        self
    }

    /// Build a request from a string: a recognized URI scheme becomes
    /// [`AssetRef::Uri`], otherwise [`AssetRef::Custom`].
    pub fn from_reference(reference: &'a str) -> Self {
        let reference = if has_uri_scheme(reference) {
            AssetRef::Uri(reference)
        } else {
            AssetRef::Custom(reference)
        };
        Self::new(reference)
    }
}

/// True if `reference` has a URI scheme (e.g. `s3://bucket/key`).
fn has_uri_scheme(reference: &str) -> bool {
    let Some((scheme, _)) = reference.split_once("://") else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Result of a request: the resolved asset and metadata about it.
pub struct ResolvedAsset {
    bytes: AssetBytes,
    format: Option<String>,
}

/// How a resolved asset's bytes come in: a ready seekable stream, or a
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
    Async(Box<dyn AsyncRangeTransport>),
}

/// How a caller must read a resolved asset: an ordinary stream, or a transport to drive.
///
/// Synchronous ranges collapse into `Stream`, since [`RangeStream`] already presents
/// them as blocking bytes and driving them would only be slower.
pub(crate) enum ReadTarget {
    /// Blocking bytes: a stream asset, or a sync range transport wrapped in a cache.
    Stream(Box<dyn ReadSeek>),
    /// A non-blocking range transport, and the config to drive it with.
    AsyncRanges {
        transport: Box<dyn AsyncRangeTransport>,
        config: RangeConfig,
    },
}

impl ResolvedAsset {
    /// Creates a seekable stream set at the beginning of an asset.
    pub fn new(stream: impl ReadSeek + 'static) -> Self {
        Self::from_boxed(Box::new(stream))
    }

    /// Like [`new`](Self::new), for an already-boxed stream (no double box).
    pub fn from_boxed(stream: Box<dyn ReadSeek>) -> Self {
        Self {
            bytes: AssetBytes::Stream(stream),
            format: None,
        }
    }

    /// Serves the asset in byte ranges through a synchronous [`SyncRangeTransport`].
    ///
    /// The transport is wrapped in a window cache and presented to the parse as an
    /// ordinary seekable stream, so a synchronous read verifies over ranges with no
    /// separate driver.
    pub fn from_ranges(transport: impl SyncRangeTransport + 'static, config: RangeConfig) -> Self {
        Self {
            bytes: AssetBytes::Ranges(RangeSource {
                transport: RangeTransportKind::Sync(Box::new(transport)),
                config,
            }),
            format: None,
        }
    }

    /// Serves the asset in byte ranges through a non-blocking [`AsyncRangeTransport`],
    /// for a runtime with no blocking read (a service worker, a Cloudflare Worker).
    ///
    /// The synchronous parse path cannot read this directly; the reader drives it.
    pub fn from_ranges_async(
        transport: impl AsyncRangeTransport + 'static,
        config: RangeConfig,
    ) -> Self {
        Self {
            bytes: AssetBytes::Ranges(RangeSource {
                transport: RangeTransportKind::Async(Box::new(transport)),
                config,
            }),
            format: None,
        }
    }

    /// Format hint for the asset bytes: a MIME type or an extension
    /// Detected magic bytes and the path extension win over it.
    /// An unrecognized format hint is ignored.
    pub fn with_format_hint(mut self, format: impl Into<String>) -> Self {
        self.format = Some(format.into());
        self
    }

    /// Format hint declared by the transport (e.g. `Content-Type`).
    /// Detected magic bytes take precedence.
    pub fn format_hint(&self) -> Option<&str> {
        self.format.as_deref()
    }

    /// Whether this asset's bytes are already a plain stream, or need a transport driven.
    ///
    /// Read the format hint and size before calling this, since it consumes `self`.
    pub(crate) fn into_read_target(self) -> ReadTarget {
        match self.bytes {
            AssetBytes::Stream(stream) => ReadTarget::Stream(stream),
            AssetBytes::Ranges(source) => match source.transport {
                RangeTransportKind::Sync(transport) => {
                    ReadTarget::Stream(Box::new(RangeStream::new(transport, source.config)))
                }
                RangeTransportKind::Async(transport) => ReadTarget::AsyncRanges {
                    transport,
                    config: source.config,
                },
            },
        }
    }

    /// Turns the transported asset bytes into a blocking seekable stream.
    ///
    /// A stream asset returns its stream; a synchronous range asset is wrapped so it
    /// fetches on demand. An asynchronous range asset has no blocking view and returns
    /// [`AssetTransportError::AsyncOnlyAsset`]; use the async read path for it.
    pub fn try_into_read_seek(self) -> Result<Box<dyn ReadSeek>, AssetTransportError> {
        match self.into_read_target() {
            ReadTarget::Stream(stream) => Ok(stream),
            ReadTarget::AsyncRanges { .. } => Err(AssetTransportError::AsyncOnlyAsset),
        }
    }
}

/// Extension point: transport that can open an asset synchronously.
/// The surface is read-only today. A write path would arrive as further methods.
pub trait SyncAssetTransport: MaybeSend + MaybeSync {
    /// Opens the requested asset, returns seekable bytes (position is at the start).
    fn open(&self, request: AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError>;
}

/// Delegates to the inner transport.
impl<T: SyncAssetTransport + ?Sized> SyncAssetTransport for std::sync::Arc<T> {
    fn open(&self, request: AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError> {
        (**self).open(request)
    }
}

/// Extension point: transport that can open an asset asynchronously (non-blocking only).
/// The surface is read-only today. A write path would arrive as further methods.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait AsyncAssetTransport: MaybeSend + MaybeSync {
    /// Opens the requested asset, returns seekable bytes (position is at the start).
    async fn open_async(
        &self,
        request: AssetRequest<'_>,
    ) -> Result<ResolvedAsset, AssetTransportError>;
}

/// Delegates to the inner transport.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<T: AsyncAssetTransport + ?Sized> AsyncAssetTransport for std::sync::Arc<T> {
    async fn open_async(
        &self,
        request: AssetRequest<'_>,
    ) -> Result<ResolvedAsset, AssetTransportError> {
        (**self).open_async(request).await
    }
}

