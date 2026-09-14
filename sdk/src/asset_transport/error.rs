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

//! Error types for the [`asset_transport`](crate::asset_transport) module.

/// Errors happening through the asset transport.
/// The errors let a caller determine if the transport rejected the request,
/// or the bytes transported were somehow not valid.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AssetTransportError {
    /// The asset reference can't be found.
    #[error("asset not found: {reference}")]
    NotFound { reference: String },

    /// Access to the asset was refused.
    #[error("permission denied: {reference}")]
    PermissionDenied { reference: String },

    /// The transport can't handle/understand this asset (reference).
    #[error("asset reference not supported by transport")]
    UnsupportedReference,

    /// The asset reference is outside the configured sandbox root.
    #[error("asset reference is outside configured root: {reference}")]
    OutsideRoot { reference: String },

    /// Only an async transport is registered, so the sync path can't be served.
    #[error("the configured asset transport is async-only")]
    NoSyncTransport,

    /// No asset transport available on the Context to serve asset bytes.
    #[error("no asset transport configured on the Context")]
    NotConfigured,

    /// A range read returned fewer bytes than required and the caller did not expect a
    /// partial response.
    #[error("short read at offset {offset}: expected {expected} bytes, got {got}")]
    ShortRead {
        offset: u64,
        expected: u64,
        got: u64,
    },

    /// The object changed underneath a range read: a response came from a different
    /// version than the read began with.
    #[error("object version changed during read: expected {expected}, got {got}")]
    VersionChanged { expected: String, got: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl AssetTransportError {
    /// A custom transport may raise its own errors.
    pub fn other(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        AssetTransportError::Other {
            source: Box::new(source),
        }
    }

    /// Detailed errors parsed from I/O errors, to distinguish NotFound/PermissionDenied.
    pub fn from_io(err: std::io::Error, reference: &str) -> Self {
        match err.kind() {
            std::io::ErrorKind::NotFound => AssetTransportError::NotFound {
                reference: reference.to_string(),
            },
            std::io::ErrorKind::PermissionDenied => AssetTransportError::PermissionDenied {
                reference: reference.to_string(),
            },
            _ => AssetTransportError::Io(err),
        }
    }
}
