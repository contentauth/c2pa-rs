// Copyright 2024 Adobe. All rights reserved.
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

use crate::{
    error::Result, manifest_store::ManifestStore, validation_status::ValidationStatus,
    CAIReadWrite, Manifest,
};

/// A reader for the manifest store
pub struct Reader {
    pub(crate) manifest_store: ManifestStore,
}

impl Reader {
    /// Get the manifest store as a JSON string
    pub fn json(&self) -> String {
        self.manifest_store.to_string()
    }

    /// Get the validation status of the manifest store
    pub fn status(&self) -> Option<&[ValidationStatus]> {
        self.manifest_store.validation_status()
    }

    /// Get the active manifest if there is one
    pub fn active_manifest(&self) -> Option<&Manifest> {
        self.manifest_store.get_active()
    }

    /// Write a resource identified by uri to the given stream
    /// # Arguments
    /// * `uri` - The URI of the resource to write
    /// * `stream` - The stream to write to
    /// # Returns
    /// The number of bytes written
    /// # Errors
    /// If the resource does not exist
    pub fn resource(&self, uri: &str, stream: &mut dyn CAIReadWrite) -> Result<usize> {
        self.manifest_store
            .get_resource(uri, stream)
            .map(|size| size as usize)
    }
}
