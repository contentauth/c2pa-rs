// Copyright 2022 Adobe. All rights reserved.
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

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use tempfile::TempDir;

use crate::{
    assertions::{labels, Action, Actions, Ingredient, ReviewRating, SchemaDotOrg, Thumbnail},
    claim::Claim,
    salt::DefaultSalt,
    store::Store,
    Result,
};
#[cfg(feature = "file_io")]
use crate::{create_signer, Signer};
#[cfg(feature = "sign")]
use crate::{openssl::RsaSigner, signer::ConfigurableSigner, SigningAlg};

pub const TEST_SMALL_JPEG: &str = "earth_apollo17.jpg";

pub const TEST_VC: &str = r#"{
    "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "http://schema.org"
    ],
    "type": [
    "VerifiableCredential",
    "NPPACredential"
    ],
    "issuer": "https://nppa.org/",
    "credentialSubject": {
        "id": "did:nppa:eb1bb9934d9896a374c384521410c7f14",
        "name": "Bob Ross",
        "memberOf": "https://nppa.org/"
    },
    "proof": {
        "type": "RsaSignature2018",
        "created": "2021-06-18T21:19:10Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod":
        "did:nppa:eb1bb9934d9896a374c384521410c7f14#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
        "jws": "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19DJBMvvFAIC00nSGB6Tn0XKbbF9XrsaJZREWvR2aONYTQQxnyXirtXnlewJMBBn2h9hfcGZrvnC1b6PgWmukzFJ1IiH1dWgnDIS81BH-IxXnPkbuYDeySorc4QU9MJxdVkY5EL4HYbcIfwKj6X4LBQ2_ZHZIu1jdqLcRZqHcsDF5KKylKc1THn5VRWy5WhYg_gBnyWny8E6Qkrze53MR7OuAmmNJ1m1nN8SxDrG6a08L78J0-Fbas5OjAQz3c17GY8mVuDPOBIOVjMEghBlgl3nOi1ysxbRGhHLEK4s0KKbeRogZdgt1DkQxDFxxn41QWDw_mmMCjs9qxg0zcZzqEJw"
    }
}"#;

/// creates a claim for testing
pub fn create_test_claim() -> Result<Claim> {
    let mut claim = Claim::new("adobe unit test", Some("adobe"));

    // add VC entry
    let _hu = claim.add_verifiable_credential(TEST_VC)?;

    // Add assertions.
    let actions = Actions::new()
        .add_action(
            Action::new("c2pa.cropped")
                .set_parameter(
                    "name".to_owned(),
                    r#"{
                    "left": 0,
                    "right": 2000,
                    "top": 1000,
                    "bottom": 4000
                }"#,
                )
                .unwrap(),
        )
        .add_action(
            Action::new("c2pa.filtered")
                .set_parameter("name".to_owned(), "gaussian blur")?
                .set_when("2015-06-26T16:43:23+0200"),
        );
    // add a binary thumbnail assertion  ('deadbeefadbeadbe')
    let some_binary_data: Vec<u8> = vec![
        0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d, 0x0b,
        0x0e,
    ];

    // create a schema.org claim
    let cr = r#"{
        "@context": "https://schema.org",
        "@type": "ClaimReview",
        "claimReviewed": "The world is flat",
        "reviewRating": {
            "@type": "Rating",
            "ratingValue": "1",
            "bestRating": "5",
            "worstRating": "1",
            "alternateName": "False"
        }
    }"#;
    let claim_review = SchemaDotOrg::from_json_str(cr)?;

    let thumbnail_claim = Thumbnail::new(labels::JPEG_CLAIM_THUMBNAIL, some_binary_data.clone());

    let thumbnail_ingred = Thumbnail::new(labels::JPEG_INGREDIENT_THUMBNAIL, some_binary_data);

    claim.add_assertion(&actions)?;
    claim.add_assertion(&claim_review)?;
    claim.add_assertion(&thumbnail_claim)?;

    let thumb_uri = claim.add_assertion_with_salt(&thumbnail_ingred, &DefaultSalt::default())?;

    let review = ReviewRating::new(
        "a 3rd party plugin was used",
        Some("actions.unknownActionsPerformed".to_string()),
        1,
    );

    //let data_path = claim.add_ingredient_data("some data".as_bytes());
    let ingredient = Ingredient::new(
        "image 1.jpg",
        "image/jpeg",
        "xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738d",
        Some("xmp.did:87d51599-286e-43b2-9478-88c79f49c347"),
    )
    .set_thumbnail(Some(&thumb_uri))
    //.set_manifest_data(&data_path)
    .add_review(review);

    let ingredient2 = Ingredient::new(
        "image 2.png",
        "image/png",
        "xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738c",
        Some("xmp.did:87d51599-286e-43b2-9478-88c79f49c346"),
    )
    .set_thumbnail(Some(&thumb_uri));

    claim.add_assertion_with_salt(&ingredient, &DefaultSalt::default())?;
    claim.add_assertion_with_salt(&ingredient2, &DefaultSalt::default())?;

    Ok(claim)
}

/// Creates a store with an unsigned claim for testing
pub fn create_test_store() -> Result<Store> {
    // Create claims store.
    let mut store = Store::new();

    let claim = create_test_claim()?;
    store.commit_claim(claim).unwrap();
    Ok(store)
}

/// returns a path to a file in the fixtures folder
pub fn fixture_path(file_name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures");
    path.push(file_name);
    path
}

/// returns a path to a file in the temp_dir folder
// note, you must pass TempDir from the caller's context
pub fn temp_dir_path(temp_dir: &TempDir, file_name: &str) -> PathBuf {
    let mut path = PathBuf::from(temp_dir.path());
    path.push(file_name);
    path
}

// copies a fixture to a temp file and returns path to copy
pub fn temp_fixture_path(temp_dir: &TempDir, file_name: &str) -> PathBuf {
    let fixture_src = fixture_path(file_name);
    let fixture_copy = temp_dir_path(temp_dir, file_name);
    std::fs::copy(&fixture_src, &fixture_copy).unwrap();
    fixture_copy
}

/// Create a [`Signer`] instance that can be used for testing purposes.
///
/// This is a suitable default for use when you need a [`Signer`], but
/// don't care what the format is.
///
/// # Returns
///
/// Returns a boxed [`Signer`] instance.
///
/// # Panics
///
/// Can panic if the certs cannot be read. (This function should only
/// be used as part of testing infrastructure.)
#[cfg(feature = "file_io")]
pub fn temp_signer_file() -> RsaSigner {
    #![allow(clippy::expect_used)]
    let mut sign_cert_path = fixture_path("certs");
    sign_cert_path.push("ps256");
    sign_cert_path.set_extension("pub");

    let mut pem_key_path = fixture_path("certs");
    pem_key_path.push("ps256");
    pem_key_path.set_extension("pem");

    RsaSigner::from_files(&sign_cert_path, &pem_key_path, SigningAlg::Ps256, None)
        .expect("get_temp_signer")
}

#[cfg(feature = "sign")]
pub fn temp_signer() -> RsaSigner {
    #![allow(clippy::expect_used)]
    let sign_cert = include_bytes!("../../tests/fixtures/certs/ps256.pub").to_vec();
    let pem_key = include_bytes!("../../tests/fixtures/certs/ps256.pem").to_vec();

    RsaSigner::from_signcert_and_pkey(&sign_cert, &pem_key, SigningAlg::Ps256, None)
        .expect("get_temp_signer")
}

/// Create a [`Signer`] instance for a specific algorithm that can be used for testing purposes.
///
/// # Returns
///
/// Returns a boxed [`Signer`] instance.
///
/// # Panics
///
/// Can panic if the certs cannot be read. (This function should only
/// be used as part of testing infrastructure.)
#[cfg(feature = "file_io")]
pub fn temp_signer_with_alg(alg: SigningAlg) -> Box<dyn Signer> {
    #![allow(clippy::expect_used)]
    // sign and embed into the target file
    let mut sign_cert_path = fixture_path("certs");
    sign_cert_path.push(alg.to_string());
    sign_cert_path.set_extension("pub");

    let mut pem_key_path = fixture_path("certs");
    pem_key_path.push(alg.to_string());
    pem_key_path.set_extension("pem");

    create_signer::from_files(sign_cert_path.clone(), pem_key_path, alg, None)
        .expect("get_temp_signer_with_alg")
}

#[test]
fn test_create_test_store() {
    #[allow(clippy::expect_used)]
    let store = create_test_store().expect("create test store");

    assert_eq!(store.claims().len(), 1);
}
