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

//! Default asset transport: the local filesystem (needs the `file_io` feature).

#[cfg(feature = "file_io")]
use std::{
    borrow::Cow,
    path::{Component, Path},
};

#[cfg(feature = "file_io")]
use super::AssetRef;
use super::{AssetRequest, AssetTransportError, ResolvedAsset, SyncAssetTransport};
#[cfg(feature = "file_io")]
use crate::utils::path_utils::{ensure_within_root, reject_unsafe_identifier};

/// Default asset transport: the local filesystem.
/// Accepts:
/// - [`AssetRef::Path`] (filesystem path).
/// - [`AssetRef::Custom`] (treated as a path).
/// - [`AssetRef::Uri`] (file URI).
///
/// Anything else is rejected with [`AssetTransportError::UnsupportedReference`].
///
/// If a root is set, references are sandboxed to it (see [`Self::rooted_at`]).
#[cfg(feature = "file_io")]
#[derive(Debug, Default, Clone)]
pub struct LocalAssetTransport {
    root: Option<std::path::PathBuf>,
}

#[cfg(feature = "file_io")]
impl LocalAssetTransport {
    /// Confines references to `root`. Anything outside it is rejected with
    /// [`AssetTransportError::OutsideRoot`].
    pub fn rooted_at(root: impl Into<std::path::PathBuf>) -> Self {
        let root = root.into();
        let root = root
            .canonicalize()
            .or_else(|_| std::path::absolute(&root))
            .unwrap_or(root);
        Self { root: Some(root) }
    }
}

#[cfg(feature = "file_io")]
impl SyncAssetTransport for LocalAssetTransport {
    /// Request to open an asset (and read its bytes).
    fn open(&self, request: AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError> {
        // Built only on error paths.
        let outside = || AssetTransportError::OutsideRoot {
            reference: request.reference.to_string(),
        };

        // Candidate path resolution.
        let candidate: Cow<'_, Path> = match request.reference {
            AssetRef::Path(p) => match &self.root {
                Some(root) if p.is_relative() => Cow::Owned(root.join(p)),
                _ => Cow::Borrowed(p),
            },
            AssetRef::Custom(s) => match &self.root {
                Some(root) => {
                    reject_unsafe_identifier(s).map_err(|_| outside())?;
                    Cow::Owned(root.join(s))
                }
                None => {
                    let candidate = Path::new(s);
                    if candidate
                        .components()
                        .any(|c| matches!(c, Component::ParentDir))
                    {
                        return Err(outside());
                    }
                    Cow::Borrowed(candidate)
                }
            },
            AssetRef::Uri(u) => {
                let url =
                    url::Url::parse(u).map_err(|_| AssetTransportError::UnsupportedReference)?;
                if url.scheme() != "file" {
                    return Err(AssetTransportError::UnsupportedReference);
                }
                Cow::Owned(
                    url.to_file_path()
                        .map_err(|()| AssetTransportError::UnsupportedReference)?,
                )
            }
        };

        // When a root is configured, open the canonicalized path.
        let to_open: Cow<'_, Path> = match &self.root {
            Some(root) => Cow::Owned(ensure_within_root(&candidate, root).map_err(|_| outside())?),
            None => candidate,
        };

        let file = std::fs::File::open(&to_open)
            .map_err(|e| AssetTransportError::from_io(e, &request.reference.to_string()))?;
        Ok(ResolvedAsset::new(file))
    }
}

/// Every read returns [`AssetTransportError::NotConfigured`]. Used when `file_io` is off,
/// or registered on a `Context` to disable sync filesystem reads on purpose.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnconfiguredAssetTransport;

impl SyncAssetTransport for UnconfiguredAssetTransport {
    fn open(&self, _request: AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError> {
        Err(AssetTransportError::NotConfigured)
    }
}

