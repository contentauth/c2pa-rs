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

//! Error type for the [`asset_source`](crate::asset_source) module.

/// Errors produced while resolving or reading an asset through an
/// [`SyncAssetSource`](crate::asset_source::SyncAssetSource) or
/// [`AsyncAssetSource`](crate::asset_source::AsyncAssetSource).
///
/// Distinguishing these from a malformed-asset error lets a caller tell
/// "the transport refused the request" apart from "the bytes are not valid C2PA".
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AssetSourceError {
    /// The reference does not name anything the source can serve.
    #[error("asset not found: {reference}")]
    NotFound { reference: String },

    /// The source found the asset but refused access to it.
    #[error("permission denied: {reference}")]
    PermissionDenied { reference: String },

    /// The source does not understand this kind of [`AssetRef`](crate::asset_source::AssetRef)
    /// (e.g. an `http:` URI handed to a filesystem-only source).
    #[error("this asset source does not support that reference kind")]
    UnsupportedReference,

    /// A synchronous open was attempted against a source that only implements the asynchronous path.
    #[error("this asset source has no synchronous implementation")]
    SyncUnsupported,

    /// No asset source is registered on the [`Context`](crate::Context).
    #[error(
        "no asset source is configured; register one with Context::with_sync_asset_source or \
         Context::with_async_asset_source"
    )]
    NotConfigured,

    /// The source can only serve whole objects, but a range read was required.
    #[error("source does not support range requests")]
    RangeNotSupported,

    /// A range request returned fewer bytes than asked for while more were expected.
    #[error("range {offset}+{expected} returned only {got} bytes")]
    ShortRead { offset: u64, expected: u64, got: u64 },

    /// The object changed while it was being read.
    ///
    /// A range-backed read fetches an object many times.
    /// Every byte must come from one version of it.
    /// Raised when a later request serves a different version
    /// than the read started with, whether the source detected that itself or the
    /// version it reported no longer matches.
    #[error("object changed while being read: expected version {expected}, got {got}")]
    VersionChanged { expected: String, got: String },

    /// The requested range is not resident in the prefetch cache.
    /// Carried out of a synchronous parse pass so the async driver can fetch
    /// the range and retry.
    #[error("range {offset}+{len} not resident in cache")]
    RangeMiss { offset: u64, len: u64 },

    /// A transport-level failure.
    /// HTTP status (if any) lives inside `source`, so the variant stays transport-agnostic.
    #[error("transport error")]
    Transport {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The read was cancelled via the [`Context`](crate::Context) cancellation flag.
    #[error("asset read cancelled")]
    Cancelled,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl AssetSourceError {
    /// Maps a filesystem [`std::io::Error`] to the most specific variant,
    /// tagging it with `reference` so the message names what failed to open.
    #[cfg(feature = "file_io")]
    pub(crate) fn from_io(err: std::io::Error, reference: &str) -> Self {
        match err.kind() {
            std::io::ErrorKind::NotFound => AssetSourceError::NotFound {
                reference: reference.to_string(),
            },
            std::io::ErrorKind::PermissionDenied => AssetSourceError::PermissionDenied {
                reference: reference.to_string(),
            },
            _ => AssetSourceError::Io(err),
        }
    }
}
