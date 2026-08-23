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

//! Where asset bytes come from.
//!
//! An [`SyncAssetSource`] / [`AsyncAssetSource`] is the extension seam for *where
//! asset bytes come from*, kept separate from [`AssetIO`](crate::asset_io::AssetIO)
//! (which decides *how* a format is parsed). The SDK ships [`LocalAssetSource`] as
//! the default; register a custom source on a [`Context`](crate::Context) to pull
//! bytes from a network range-reader, an object store, or any custom transport
//! while leaving parsing and validation unchanged.
//!
//! There are two capability traits — a source implements whichever it can serve —
//! and a [`Context`](crate::Context) holds exactly one of them in an
//! [`AssetSourceSlot`]. A synchronous open against an async-only source returns
//! [`AssetSourceError::SyncUnsupported`] instead of falling through to a different
//! source, so a filesystem API can never silently become a network API.

mod error;
mod fragment;
mod local;
pub mod range;

pub use error::AssetSourceError;
pub use fragment::FragmentSource;
#[cfg(feature = "file_io")]
pub(crate) use fragment::SourcePathFragments;
pub(crate) use fragment::SourceRefFragments;
#[cfg(feature = "file_io")]
pub use local::LocalAssetSource;
pub use local::NoAssetSource;

use std::sync::Arc;

use crate::{
    asset_io::CAIRead,
    asset_source::range::{RangeConfig, RangeStream, SyncRangeReader},
    maybe_send_sync::{MaybeSend, MaybeSync},
};

/// What to open. Modelled as a type so a filesystem API never silently becomes a
/// network API and non-UTF-8 paths survive intact.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AssetRef<'a> {
    /// A filesystem path.
    #[cfg(feature = "file_io")]
    Path(&'a std::path::Path),
    /// An absolute URI (`http`, `https`, `s3`, `file`, custom scheme, ...).
    Uri(&'a str),
    /// A source-defined opaque identifier (object key, blob handle, fixture name).
    Opaque(&'a str),
}

/// A request to open an asset: the reference plus an optional caller format hint.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AssetRequest<'a> {
    /// What to open.
    pub reference: AssetRef<'a>,
    /// Caller's format hint (extension or MIME), if any.
    pub format_hint: Option<&'a str>,
}

impl<'a> AssetRequest<'a> {
    /// Builds a request from an explicit [`AssetRef`].
    pub fn new(reference: AssetRef<'a>, format_hint: Option<&'a str>) -> Self {
        Self {
            reference,
            format_hint,
        }
    }

    /// Builds a request from an untyped reference string.
    ///
    /// A string containing `://` is treated as an [`AssetRef::Uri`]; anything else is
    /// [`AssetRef::Opaque`]. This is what keeps an `http://…` string from being
    /// opened as a relative filesystem path — a URI reaches the source as a `Uri`,
    /// which [`LocalAssetSource`] rejects unless it is a `file:` URI.
    pub fn from_reference(reference: &'a str, format_hint: Option<&'a str>) -> Self {
        let reference = if reference.contains("://") {
            AssetRef::Uri(reference)
        } else {
            AssetRef::Opaque(reference)
        };
        Self {
            reference,
            format_hint,
        }
    }
}

/// The bytes an [`SyncAssetSource`]/[`AsyncAssetSource`] hands back.
#[non_exhaustive]
pub enum AssetBytes {
    /// A ready seekable stream (files, in-memory, caller-managed transports).
    Stream(Box<dyn CAIRead>),
    /// A random-access byte source the SDK wraps in its own window cache. This is
    /// what unlocks the shared caching and the async retry-on-miss read path.
    Ranges(RangeSource),
}

/// A random-access byte source plus its window-cache configuration.
pub struct RangeSource {
    reader: RangeReaderKind,
    config: RangeConfig,
}

enum RangeReaderKind {
    Sync(Box<dyn SyncRangeReader>),
    Async(Box<dyn range::AsyncRangeReader>),
}

/// How the reader should consume a [`ResolvedAsset`]: either a ready synchronous
/// stream, or an asynchronous range source that the async read path drives.
pub(crate) enum ReadTarget {
    Stream(Box<dyn CAIRead>),
    AsyncRanges {
        reader: Box<dyn range::AsyncRangeReader>,
        config: RangeConfig,
    },
}

/// The result of opening an asset: its bytes plus advisory transport metadata.
#[non_exhaustive]
pub struct ResolvedAsset {
    bytes: AssetBytes,
    format: Option<String>,
}

impl ResolvedAsset {
    /// Wraps a ready seekable stream.
    pub fn from_stream(stream: Box<dyn CAIRead>) -> Self {
        Self {
            bytes: AssetBytes::Stream(stream),
            format: None,
        }
    }

    /// Wraps a synchronous random-access byte source; the SDK layers its window
    /// cache over it.
    pub fn from_ranges(reader: Box<dyn SyncRangeReader>) -> Self {
        Self {
            bytes: AssetBytes::Ranges(RangeSource {
                reader: RangeReaderKind::Sync(reader),
                config: RangeConfig::default(),
            }),
            format: None,
        }
    }

    /// Wraps an asynchronous random-access byte source, read by the async path.
    pub fn from_ranges_async(reader: Box<dyn range::AsyncRangeReader>) -> Self {
        Self {
            bytes: AssetBytes::Ranges(RangeSource {
                reader: RangeReaderKind::Async(reader),
                config: RangeConfig::default(),
            }),
            format: None,
        }
    }

    /// Overrides the window-cache configuration for a range-backed asset. No effect
    /// on a stream-backed asset.
    pub fn with_range_config(mut self, config: RangeConfig) -> Self {
        if let AssetBytes::Ranges(source) = &mut self.bytes {
            source.config = config;
        }
        self
    }

    /// Sets the transport-reported format (advisory only — see [`advisory_format`]).
    ///
    /// [`advisory_format`]: Self::advisory_format
    pub fn with_format(mut self, format: impl Into<String>) -> Self {
        self.format = Some(format.into());
        self
    }

    /// The transport-reported format, if any.
    ///
    /// Advisory only: it is consulted as a format hint at exactly one site, and only
    /// when the caller passed no hint and magic-byte sniffing returned nothing. A
    /// server-declared `Content-Type` must never override magic-byte detection.
    pub fn advisory_format(&self) -> Option<&str> {
        self.format.as_deref()
    }

    /// Converts the resolved asset into a seekable [`CAIRead`] stream for the parser.
    ///
    /// A synchronous range source is wrapped in a [`RangeStream`]. An asynchronous
    /// range source has no synchronous view and returns
    /// [`AssetSourceError::SyncUnsupported`]; it is read through the async path.
    pub fn into_cai_read(self) -> Result<Box<dyn CAIRead>, AssetSourceError> {
        match self.bytes {
            AssetBytes::Stream(stream) => Ok(stream),
            AssetBytes::Ranges(source) => match source.reader {
                RangeReaderKind::Sync(reader) => {
                    Ok(Box::new(RangeStream::new(reader, source.config)))
                }
                RangeReaderKind::Async(_) => Err(AssetSourceError::SyncUnsupported),
            },
        }
    }

    /// Classifies the asset for the async read path: a ready stream (including a
    /// synchronous range source wrapped in a [`RangeStream`]), or an asynchronous
    /// range source the driver reads without blocking.
    pub(crate) fn into_read_target(self) -> ReadTarget {
        match self.bytes {
            AssetBytes::Stream(stream) => ReadTarget::Stream(stream),
            AssetBytes::Ranges(source) => match source.reader {
                RangeReaderKind::Sync(reader) => {
                    ReadTarget::Stream(Box::new(RangeStream::new(reader, source.config)))
                }
                RangeReaderKind::Async(reader) => ReadTarget::AsyncRanges {
                    reader,
                    config: source.config,
                },
            },
        }
    }
}

/// A source that can open an asset synchronously.
pub trait SyncAssetSource: MaybeSend + MaybeSync {
    /// Open `request` and return its bytes, positioned at the start.
    fn open(&self, request: &AssetRequest<'_>) -> Result<ResolvedAsset, AssetSourceError>;
}

/// A source that can open an asset asynchronously, for non-blocking transports.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait AsyncAssetSource: MaybeSend + MaybeSync {
    /// Open `request` and return its bytes, positioned at the start.
    async fn open_async(
        &self,
        request: &AssetRequest<'_>,
    ) -> Result<ResolvedAsset, AssetSourceError>;
}

/// The single asset-source slot held by a [`Context`](crate::Context).
///
/// A context holds one capability, never both, so a sync call against an
/// async-only source is a typed [`AssetSourceError::SyncUnsupported`] rather than a
/// silent fallback to the default filesystem source.
#[derive(Clone)]
pub enum AssetSourceSlot {
    /// A synchronous source.
    Sync(Arc<dyn SyncAssetSource>),
    /// An asynchronous source.
    Async(Arc<dyn AsyncAssetSource>),
}

impl AssetSourceSlot {
    /// Opens synchronously. An async-only source returns
    /// [`AssetSourceError::SyncUnsupported`].
    pub fn open(&self, request: &AssetRequest<'_>) -> Result<ResolvedAsset, AssetSourceError> {
        match self {
            AssetSourceSlot::Sync(source) => source.open(request),
            AssetSourceSlot::Async(_) => Err(AssetSourceError::SyncUnsupported),
        }
    }

    /// Opens asynchronously. A sync source is driven directly.
    pub async fn open_async(
        &self,
        request: &AssetRequest<'_>,
    ) -> Result<ResolvedAsset, AssetSourceError> {
        match self {
            AssetSourceSlot::Sync(source) => source.open(request),
            AssetSourceSlot::Async(source) => source.open_async(request).await,
        }
    }
}

impl From<Arc<dyn SyncAssetSource>> for AssetSourceSlot {
    fn from(source: Arc<dyn SyncAssetSource>) -> Self {
        AssetSourceSlot::Sync(source)
    }
}

impl From<Arc<dyn AsyncAssetSource>> for AssetSourceSlot {
    fn from(source: Arc<dyn AsyncAssetSource>) -> Self {
        AssetSourceSlot::Async(source)
    }
}
