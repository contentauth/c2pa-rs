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

use std::io::Cursor;

use c2pa::Reader;

use crate::{claim_aggregation::IcaSignatureVerifier, IdentityAssertion};

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
async fn adobe_connected_identities() {
    let format = "image/jpeg";
    let test_image = include_bytes!("../fixtures/claim_aggregation/adobe_connected_identities.jpg");

    let mut test_image = Cursor::new(test_image);

    let manifest_store = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(manifest_store.validation_status(), None);

    let manifest = manifest_store.active_manifest().unwrap();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    dbg!(&ia);

    assert!(ia_iter.next().is_none());

    // And that identity assertion should be valid for this manifest.
    let nsv = IcaSignatureVerifier {};
    let ica = ia.validate(manifest, &nsv).await.unwrap();

    dbg!(&ica);
    unimplemented!("Check for expected ICA results");
}
