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

use c2pa::{CAIRead, CAIReadWrite, Manifest, ManifestPatchCallback, Signer};

use crate::{builder::IdentityAssertionBuilder, internal, IdentityAssertion};

/// TO DO: Docs
#[derive(Default)]
pub struct ManifestBuilder {
    identity_assertions: Vec<IdentityAssertion>,
    patched_manifest_store: Option<Vec<u8>>,
}

impl ManifestBuilder {
    /// Adds an identity assertion to the builder.
    pub fn add_assertion(&mut self, identity_assertion: IdentityAssertionBuilder) {
        self.identity_assertions
            .push(IdentityAssertion::from_builder(identity_assertion));
    }

    /// This function wraps all the C2PA SDK calls in the (currently)
    /// correct sequence. This is likely to change as the C2PA SDK
    /// evolves.
    pub async fn build(
        mut self,
        mut manifest: Manifest,
        _format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        signer: &dyn Signer,
    ) -> c2pa::Result<()> {
        for ia in self.identity_assertions.iter() {
            manifest.add_cbor_assertion("cawg.identity", ia)?;
        }

        let (placed_manifest, _active_manifest_label) =
            manifest.get_placed_manifest(signer.reserve_size(), "jpg", input_stream)?;

        let updated_manifest = self
            .rewrite_placed_manifest(&placed_manifest)
            .await
            .ok_or(c2pa::Error::ClaimEncoding)?;

        self.patched_manifest_store = Some(updated_manifest);

        input_stream.rewind()?;

        Manifest::embed_placed_manifest(
            &placed_manifest,
            "jpg",
            input_stream,
            output_stream,
            signer,
            &[Box::new(self)],
        )
        .map(|_| ())
    }

    async fn rewrite_placed_manifest(&mut self, manifest_store: &[u8]) -> Option<Vec<u8>> {
        let mut updated_ms = manifest_store.to_vec();

        let ms = internal::c2pa_parser::ManifestStore::from_slice(manifest_store)?;
        let m = ms.active_manifest()?;

        let claim = m.claim()?;
        let ast = m.assertion_store()?;

        for ia in self.identity_assertions.iter_mut() {
            // TO DO: Support for multiple identity assertions.

            let assertion = ast.find_by_label("cawg.identity")?;
            let assertion_dbox = assertion.data_box()?;

            let assertion_offset = assertion_dbox.offset_within_superbox(&ms.sbox)?;
            let assertion_size = assertion_dbox.data.len();

            updated_ms = ia
                .update_with_signature(updated_ms, assertion_offset, assertion_size, &claim)
                .await?;
        }

        Some(updated_ms)
    }
}

impl ManifestPatchCallback for ManifestBuilder {
    fn patch_manifest(&self, _manifest_store: &[u8]) -> c2pa::Result<Vec<u8>> {
        match self.patched_manifest_store.as_ref() {
            Some(ms) => Ok(ms.clone()),
            None => Err(c2pa::Error::ClaimEncoding),
        }
    }
}
