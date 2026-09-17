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

/// Errors from the asset transport.
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

    /// No blocking sync transport configured.
    #[error("asset is served by an async range transport")]
    AsyncOnlyAsset,

    /// No asset transport available on the Context to serve asset bytes.
    #[error("no asset transport configured on the Context")]
    NotConfigured,

    /// The transport could not satisfy the requested byte range.
    ///
    /// `total` is the object length when the transport learned it, which for HTTP comes
    /// from `Content-Range: bytes */total`. An `offset` below a known `total` means the
    /// range was satisfiable and the transport refused it for another reason, such as an
    /// unsupported range unit.
    #[error("requested range not satisfiable at offset {offset}: {reference}")]
    RangeNotSatisfiable {
        /// The reference that was read.
        reference: String,
        /// The offset the failed request asked for.
        offset: u64,
        /// The object length, when the transport learned it.
        total: Option<u64>,
    },

    /// A range read returned fewer bytes than required,
    /// and the caller did not expect a partial response.
    #[error("short read at offset {offset}: expected {expected} bytes, got {got}")]
    ShortRead {
        offset: u64,
        expected: u64,
        got: u64,
    },

    /// The object changed underneath a range read:
    /// a response came from a different version than the read began with.
    #[error("object version changed during read: expected {expected}, got {got}")]
    VersionChanged { expected: String, got: String },

    /// A driven parse asked again for bytes it had already fetched, so the cache
    /// evicted them and the parse needs more resident at once than `max_cached` allows.
    ///
    /// Raise `max_cached`, lower `window`, or allow the whole-object fallback through
    /// [`RangeConfig::with_max_whole_object`](crate::asset_transport::RangeConfig::with_max_whole_object).
    #[error(
        "working set exceeds the cache budget for {format}: re-read {windows} windows \
         ({bytes} bytes) against max_cached {max_cached}"
    )]
    WorkingSetTooLarge {
        /// The asset format being parsed.
        format: String,
        /// Distinct windows fetched before the re-read.
        windows: usize,
        /// Bytes fetched before the re-read.
        bytes: u64,
        /// The eviction budget the parse exceeded.
        max_cached: u64,
    },

    /// A driven parse hit the attempt ceiling, so it is not resolving one miss per
    /// attempt. A parse that reads different ranges each time never re-misses and
    /// arrives here instead.
    #[error(
        "parse did not converge for {format}: {attempts} attempts against ceiling \
         {ceiling} (max_cached {max_cached}, window {window})"
    )]
    AttemptsExhausted {
        /// The asset format being parsed.
        format: String,
        /// Attempts made.
        attempts: u32,
        /// The ceiling, `max_cached / window + 2`.
        ceiling: u32,
        /// The eviction budget in force.
        max_cached: u64,
        /// The window size in force.
        window: u64,
    },

    /// The whole-object fallback was needed but the object is larger than
    /// [`RangeConfig::max_whole_object`](crate::asset_transport::RangeConfig::max_whole_object),
    /// or that rung is disabled.
    #[error("object of {len} bytes exceeds the whole-object limit for {reference}")]
    WholeObjectTooLarge {
        /// The reference that was read.
        reference: String,
        /// The object length.
        len: u64,
    },

    /// The binding cannot be checked over an asynchronous range transport.
    ///
    /// Box hashes and merkle-hashed non-fragmented BMFF need access patterns the async
    /// path cannot serve. Reported rather than passed unchecked.
    #[error("{binding} cannot be verified over an async range transport")]
    UnverifiableOverRanges {
        /// The binding kind that cannot be checked.
        binding: String,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Any other error.
    #[error(transparent)]
    #[non_exhaustive]
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

    /// A binding the async range path cannot check, named for the report.
    pub fn unverifiable(binding: &str) -> Self {
        AssetTransportError::UnverifiableOverRanges {
            binding: binding.to_owned(),
        }
    }

    /// Detailed errors parsed from I/O errors.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_errors_render_reference() {
        let range = AssetTransportError::RangeNotSatisfiable {
            reference: "https://x/y".to_string(),
            offset: 512,
            total: Some(256),
        };
        assert!(range.to_string().contains("not satisfiable"));
        assert!(range.to_string().contains("512"));
    }
}
