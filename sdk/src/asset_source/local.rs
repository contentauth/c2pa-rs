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

//! Built-in asset sources:
//! the local filesystem default and the unconfigured placeholder.

use super::{AssetRequest, AssetSourceError, ResolvedAsset, SyncAssetSource};
#[cfg(feature = "file_io")]
use super::AssetRef;

/// The SDK's default asset source: opens a reference as a local filesystem path.
///
/// Accepts an [`AssetRef::Path`], an [`AssetRef::Opaque`] (treated as a path), or a
/// `file:` [`AssetRef::Uri`].
/// Any other URI scheme is rejected with [`AssetSourceError::UnsupportedReference`]
/// rather than being opened as a relative path.
#[cfg(feature = "file_io")]
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalAssetSource;

#[cfg(feature = "file_io")]
impl SyncAssetSource for LocalAssetSource {
    fn open(&self, request: &AssetRequest<'_>) -> Result<ResolvedAsset, AssetSourceError> {
        use std::path::Path;

        let path: &Path = match request.reference {
            AssetRef::Path(p) => p,
            AssetRef::Opaque(s) => Path::new(s),
            AssetRef::Uri(u) => match u.strip_prefix("file://").or_else(|| u.strip_prefix("file:"))
            {
                Some(rest) => Path::new(rest),
                None => return Err(AssetSourceError::UnsupportedReference),
            },
        };

        let file = std::fs::File::open(path)
            .map_err(|e| AssetSourceError::from_io(e, &path.to_string_lossy()))?;
        Ok(ResolvedAsset::from_stream(Box::new(file)))
    }
}

/// Placeholder source used when no source is registered and no filesystem default
/// is available (the `file_io` feature is off).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoAssetSource;

impl SyncAssetSource for NoAssetSource {
    fn open(&self, _request: &AssetRequest<'_>) -> Result<ResolvedAsset, AssetSourceError> {
        Err(AssetSourceError::NotConfigured)
    }
}
