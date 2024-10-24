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

use std::fs::OpenOptions;

use c2pa::{Manifest, ManifestStore};

use crate::{
    builder::{IdentityAssertionBuilder, ManifestBuilder},
    tests::fixtures::{fixture_path, temp_c2pa_signer, temp_dir_path, NaiveCredentialHolder},
    IdentityAssertion,
};

#[tokio::test]
async fn simple_case() {
    // TO DO: Clean up code and extract into builder interface.
    // For now, just looking for a simple proof-of-concept.

    let source = fixture_path("cloud.jpg");

    let mut input_stream = OpenOptions::new().read(true).open(&source).unwrap();

    let temp_dir = tempfile::tempdir().unwrap();
    let dest = temp_dir_path(&temp_dir, "cloud_output.jpg");

    let mut output_stream = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&dest)
        .unwrap();

    // TO DO: Add a metadata assertion as an example.

    let naive_credential = NaiveCredentialHolder {};
    let iab = IdentityAssertionBuilder::for_credential_holder(naive_credential);

    let signer = temp_c2pa_signer();
    let mut mb = ManifestBuilder::default();
    mb.add_assertion(iab);

    let manifest: Manifest = Manifest::new("identity_test/simple_case");
    mb.build(
        manifest,
        "jpg",
        &mut input_stream,
        &mut output_stream,
        signer.as_ref(),
    )
    .await
    .unwrap();

    let manifest_store = ManifestStore::from_file(&dest).unwrap();
    assert!(manifest_store.validation_status().is_none());

    // Coordinate with Gavin to make sure we can use the Reader.

    let manifest = manifest_store.get_active().unwrap();
    let identity: IdentityAssertion = manifest.find_assertion("cawg.identity").unwrap();

    let _sp = identity.check_signer_payload(manifest).unwrap();
    identity.check_padding().unwrap();

    let report = identity.validate(manifest).await.unwrap();

    let sp = report.signer_payload;
    let ra = &sp.referenced_assertions;
    assert_eq!(ra.len(), 1);

    let ra1 = ra.first().unwrap();
    assert_eq!(ra1.url, "self#jumbf=c2pa.assertions/c2pa.hash.data");
    assert_eq!(ra1.alg, Some("sha256".to_owned()));

    assert_eq!(
        report.signer_payload.sig_type,
        "INVALID.identity.naive_credential"
    );

    let na = report.named_actor;
    assert_eq!(
        na.display_name(),
        Some("Credential for internal testing purposes only".to_string())
    );

    assert!(!na.is_trusted());
}
