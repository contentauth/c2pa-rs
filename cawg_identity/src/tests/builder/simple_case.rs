// Copyright 2025 Adobe. All rights reserved.
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

use std::io::{Cursor, Seek};

use c2pa::{Builder, Reader, SigningAlg};
use serde_json::json;

use crate::{
    builder::{IdentityAssertionBuilder, IdentityAssertionSigner},
    tests::fixtures::{NaiveCredentialHolder, NaiveSignatureVerifier},
    IdentityAssertion,
};

const TEST_IMAGE: &[u8] = include_bytes!("../../../../sdk/tests/fixtures/CA.jpg");
const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../../sdk/tests/fixtures/thumbnail.jpg");

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
async fn simple_case() {
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_json(&manifest_json()).unwrap();
    builder
        .add_ingredient_from_stream(parent_json(), format, &mut source)
        .unwrap();

    builder
        .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
        .unwrap();

    let mut signer = IdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

    let nch = NaiveCredentialHolder {};
    let iab = IdentityAssertionBuilder::for_credential_holder(nch);
    signer.add_identity_assertion(iab);

    builder
        .sign_async(&signer, format, &mut source, &mut dest)
        .await
        .unwrap();

    // Read back the Manifest that was generated.
    dest.rewind().unwrap();

    let manifest_store = Reader::from_stream(format, &mut dest).unwrap();
    assert_eq!(manifest_store.validation_status(), None);

    let manifest = manifest_store.active_manifest().unwrap();
    let mut ia_iter = IdentityAssertion::from_manifest(&manifest);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    dbg!(&ia);

    assert!(ia_iter.next().is_none());

    // And that identity assertion should be valid for this manifest.
    let nsv = NaiveSignatureVerifier {};
    ia.validate(&manifest, &nsv).await.unwrap();
}

fn manifest_json() -> String {
    json!({
        "vendor": "test",
        "claim_generator_info": [
            {
                "name": "c2pa_test",
                "version": "1.0.0"
            }
        ],
        "metadata": [
            {
                "dateTime": "1985-04-12T23:20:50.52Z",
                "my_custom_metadata": "my custom metatdata value"
            }
        ],
        "title": "Test_Manifest",
        "format": "image/tiff",
        "instance_id": "1234",
        "thumbnail": {
            "format": "image/jpeg",
            "identifier": "thumbnail.jpg"
        },
        "ingredients": [
            {
                "title": "Test",
                "format": "image/jpeg",
                "instance_id": "12345",
                "relationship": "componentOf"
            }
        ],
        "assertions": [
            {
                "label": "org.test.assertion",
                "data": "assertion"
            }
        ]
    })
    .to_string()
}

fn parent_json() -> String {
    json!({
        "title": "Parent Test",
        "format": "image/jpeg",
        "instance_id": "12345",
        "relationship": "parentOf"
    })
    .to_string()
}
