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
use c2pa_status_tracker::StatusTracker;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::{
    builder::{
        AsyncIdentityAssertionBuilder, AsyncIdentityAssertionSigner, IdentityAssertionBuilder,
        IdentityAssertionSigner,
    },
    tests::fixtures::{
        manifest_json, parent_json, NaiveAsyncCredentialHolder, NaiveCredentialHolder,
        NaiveSignatureVerifier,
    },
    IdentityAssertion, ToCredentialSummary,
};

const TEST_IMAGE: &[u8] = include_bytes!("../../../../sdk/tests/fixtures/CA.jpg");
const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../../sdk/tests/fixtures/thumbnail.jpg");

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn simple_case() {
    // NOTE: This needs to be async for now because the verification side is
    // async-only.

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
        .sign(&signer, format, &mut source, &mut dest)
        .unwrap();

    // Read back the Manifest that was generated.
    dest.rewind().unwrap();

    let manifest_store = Reader::from_stream(format, &mut dest).unwrap();
    assert_eq!(manifest_store.validation_status(), None);

    let manifest = manifest_store.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let nsv = NaiveSignatureVerifier {};
    let naive_credential = ia.validate(manifest, &mut st, &nsv).await.unwrap();

    let nc_summary = naive_credential.to_summary();
    let nc_json = serde_json::to_string(&nc_summary).unwrap();
    assert_eq!(nc_json, "{}");
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn simple_case_async() {
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

    let mut signer = AsyncIdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

    let nch = NaiveAsyncCredentialHolder {};
    let iab = AsyncIdentityAssertionBuilder::for_credential_holder(nch);
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
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let nsv = NaiveSignatureVerifier {};
    let naive_credential = ia.validate(manifest, &mut st, &nsv).await.unwrap();

    let nc_summary = naive_credential.to_summary();
    let nc_json = serde_json::to_string(&nc_summary).unwrap();
    assert_eq!(nc_json, "{}");
}
