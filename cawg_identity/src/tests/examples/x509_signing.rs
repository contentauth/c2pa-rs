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

//! Test case that demonstrates generating a new C2PA asset (JPEG in this case)
//! with a C2PA claim signer signature and a CAWG identity assertion with its
//! own X.509 signature from a different credential holder.

use std::io::{Cursor, Seek};

use c2pa::{Builder, Reader, SigningAlg};
use c2pa_crypto::raw_signature;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::{
    builder::{AsyncIdentityAssertionBuilder, AsyncIdentityAssertionSigner},
    tests::fixtures::{cert_chain_and_private_key_for_alg, manifest_json, parent_json},
    x509::{X509CredentialHolder, X509SignatureVerifier},
    IdentityAssertion,
};

const TEST_IMAGE: &[u8] = include_bytes!("../../../../sdk/tests/fixtures/CA.jpg");
const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../../sdk/tests/fixtures/thumbnail.jpg");

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[ignore] // We'll only run this occasionally if we need to update this test.
async fn x509_signing() {
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

    let mut c2pa_signer = AsyncIdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

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
    let iab = AsyncIdentityAssertionBuilder::for_credential_holder(x509_holder);
    c2pa_signer.add_identity_assertion(iab);

    builder
        .sign_async(&c2pa_signer, format, &mut source, &mut dest)
        .await
        .unwrap();

    // Write the file for
    std::fs::write("src/tests/examples/x509_signing.jpg", dest.get_ref()).unwrap();

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
    let sig_info = ia.validate(manifest, &x509_verifier).await.unwrap();

    let cert_info = &sig_info.cert_info;
    assert_eq!(cert_info.alg.unwrap(), SigningAlg::Ed25519);
    assert_eq!(
        cert_info.issuer_org.as_ref().unwrap(),
        "C2PA Test Signing Cert"
    );

    // TO DO: Not sure what to check from COSE_Sign1.
}
