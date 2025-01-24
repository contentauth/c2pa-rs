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
use c2pa_crypto::raw_signature;
use serde_json::json;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::{
    builder::{IdentityAssertionBuilder, IdentityAssertionSigner},
    tests::fixtures::cert_chain_and_private_key_for_alg,
    x509::{X509CredentialHolder, X509SignatureVerifier},
    IdentityAssertion,
};

const TEST_IMAGE: &[u8] = include_bytes!("../../../sdk/tests/fixtures/CA.jpg");
const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../sdk/tests/fixtures/thumbnail.jpg");

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

    let mut c2pa_signer = IdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

    let (cawg_cert_chain, cawg_private_key) =
        cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);

    let cawg_raw_signer = raw_signature::async_signer_from_cert_chain_and_private_key(
        &cawg_cert_chain,
        &cawg_private_key,
        SigningAlg::Ed25519,
        None,
    )
    .unwrap();

    let x509_holder = X509CredentialHolder::from_async_raw_signer(cawg_raw_signer);
    let iab = IdentityAssertionBuilder::for_credential_holder(x509_holder);
    c2pa_signer.add_identity_assertion(iab);

    builder
        .sign_async(&c2pa_signer, format, &mut source, &mut dest)
        .await
        .unwrap();

    // Read back the Manifest that was generated.
    dest.rewind().unwrap();

    let manifest_store = Reader::from_stream(format, &mut dest).unwrap();
    assert_eq!(manifest_store.validation_status(), None);

    let manifest = manifest_store.active_manifest().unwrap();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());

    // And that identity assertion should be valid for this manifest.
    let x509_verifier = X509SignatureVerifier {};
    let cert_info = ia.validate(manifest, &x509_verifier).await.unwrap();

    assert_eq!(cert_info.alg.unwrap(), SigningAlg::Ed25519);
    assert_eq!(
        cert_info.issuer_org.as_ref().unwrap(),
        "C2PA Test Signing Cert"
    );
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
