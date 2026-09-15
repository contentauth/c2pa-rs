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

pub use error::AssetTransportError;
#[cfg(feature = "file_io")]
pub use local::LocalAssetTransport;
pub use local::UnconfiguredAssetTransport;

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
    /// A reference whose shape only the handler understands, so it is untrusted;
    /// the handler must guard against path traversal.
    Custom(&'a str),
}

/// Whether a request targets the primary asset or its sidecar manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AssetRequestKind {
    /// The primary asset.
    #[default]
    Asset,
    /// A sidecar manifest (`.c2pa`).
    Sidecar,
}

/// A generic request to open an asset (through an AssetRef).
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Set whether this targets the primary asset or its sidecar manifest.
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

/// Result of an open request: the resolved asset plus metadata about it.
pub struct ResolvedAsset {
    stream: Box<dyn ReadSeek>,
    format: Option<String>,
    size: Option<u64>,
}

impl ResolvedAsset {
    /// Creates a seekable stream set at the beginning of an asset.
    pub fn new(stream: impl ReadSeek + 'static) -> Self {
        Self {
            stream: Box::new(stream),
            format: None,
            size: None,
        }
    }

    /// Format hint for the asset (bytes) transport.
    pub fn with_format(mut self, format: impl Into<String>) -> Self {
        self.format = Some(format.into());
        self
    }

    /// Total size of the asset, if the transport knows it.
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// Format hint declared by the transport (e.g. `Content-Type`). A hint only.
    /// Detected magic bytes take precedence.
    pub fn advisory_format(&self) -> Option<&str> {
        self.format.as_deref()
    }

    /// The size the transport reported, if any.
    pub fn size(&self) -> Option<u64> {
        self.size
    }

    /// Turn the transported asset bytes into a seekable stream.
    pub fn into_read_seek(self) -> Box<dyn ReadSeek> {
        self.stream
    }
}

/// Extension point: transport that can open an asset synchronously.
/// The surface is read-only today. A write path would arrive as further methods.
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
/// The surface is read-only today. A write path would arrive as further methods.
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn resolved_asset_carries_optional_size() {
        let unknown = ResolvedAsset::new(Cursor::new(vec![1u8, 2, 3]));
        assert_eq!(unknown.size(), None);

        let known = ResolvedAsset::new(Cursor::new(vec![1u8, 2, 3])).with_size(3);
        assert_eq!(known.size(), Some(3));
    }

    #[test]
    fn asset_request_kind_defaults_to_asset() {
        let request = AssetRequest::new(AssetRef::Uri("s3://b/k"));
        assert_eq!(request.kind, AssetRequestKind::Asset);

        let sidecar = request.with_kind(AssetRequestKind::Sidecar);
        assert_eq!(sidecar.kind, AssetRequestKind::Sidecar);
    }
}
