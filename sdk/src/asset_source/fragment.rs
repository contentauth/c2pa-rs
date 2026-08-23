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

//! (Lazy) access to the fragments of a fragmented (DASH/CMAF) asset.
//!
//! Fragment verification opens one fragment at a time and drops it before the next.

use super::{AssetRequest, AssetSourceError, AssetSourceSlot};
use crate::{
    asset_io::CAIRead,
    maybe_send_sync::{MaybeSend, MaybeSync},
};

/// A lazily-opened sequence of asset fragments.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait FragmentSource: MaybeSend + MaybeSync {
    /// Number of fragments.
    fn count(&self) -> usize;

    /// Opens fragment `index`, returning a stream positioned at its start.
    fn open(&self, index: usize) -> Result<Box<dyn CAIRead>, AssetSourceError>;

    /// Async twin of [`open`](Self::open); defaults to `open`.
    async fn open_async(&self, index: usize) -> Result<Box<dyn CAIRead>, AssetSourceError> {
        self.open(index)
    }
}

/// Opens fragment paths directly from the filesystem.
#[cfg(feature = "file_io")]
impl FragmentSource for Vec<std::path::PathBuf> {
    fn count(&self) -> usize {
        self.len()
    }

    fn open(&self, index: usize) -> Result<Box<dyn CAIRead>, AssetSourceError> {
        let path = &self[index];
        let file = std::fs::File::open(path)
            .map_err(|e| AssetSourceError::from_io(e, &path.to_string_lossy()))?;
        Ok(Box::new(file))
    }
}

/// Opens fragment paths through an [`AssetSourceSlot`], so a custom source serves
/// the fragments the same way it serves the initialization segment.
#[cfg(feature = "file_io")]
pub(crate) struct SourcePathFragments<'a> {
    pub source: &'a AssetSourceSlot,
    pub paths: &'a [std::path::PathBuf],
    pub format: String,
}

#[cfg(feature = "file_io")]
impl FragmentSource for SourcePathFragments<'_> {
    fn count(&self) -> usize {
        self.paths.len()
    }

    fn open(&self, index: usize) -> Result<Box<dyn CAIRead>, AssetSourceError> {
        use super::AssetRef;
        let request = AssetRequest::new(AssetRef::Path(&self.paths[index]), Some(&self.format));
        self.source.open(&request)?.into_cai_read()
    }
}

/// Opens fragment references through an [`AssetSourceSlot`].
pub(crate) struct SourceRefFragments<'a> {
    pub source: &'a AssetSourceSlot,
    pub references: &'a [String],
    pub format: String,
}

impl FragmentSource for SourceRefFragments<'_> {
    fn count(&self) -> usize {
        self.references.len()
    }

    fn open(&self, index: usize) -> Result<Box<dyn CAIRead>, AssetSourceError> {
        let request = AssetRequest::from_reference(&self.references[index], Some(&self.format));
        self.source.open(&request)?.into_cai_read()
    }
}
