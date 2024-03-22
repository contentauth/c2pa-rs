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

use crate::Result;

// Callback to allow user to change assertion data before the manifest is
// signed and embedded into an assert.  The input manifest_store is the
// JUMBF of C2PA manifest store. The size of the Vec returned from patch_manifest
// must be the same size as the source manifest_store.
pub trait ManifestPatchCallback {
    fn patch_manifest(&self, manifest_store: &[u8]) -> Result<Vec<u8>>;
}
