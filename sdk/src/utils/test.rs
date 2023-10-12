// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for thema
// specific language governing permissions and limitations under
// each license.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
#[cfg(feature = "file_io")]
use std::{
    io::{Cursor, Read, Write},
    path::Path,
};

use tempfile::TempDir;

use crate::{
    assertions::{labels, Action, Actions, Ingredient, ReviewRating, SchemaDotOrg, Thumbnail},
    claim::Claim,
    salt::DefaultSalt,
    store::Store,
    RemoteSigner, Result, Signer, SigningAlg,
};
#[cfg(feature = "file_io")]
use crate::{
    asset_io::CAIReadWrite, create_signer, hash_utils::Hasher,
    jumbf_io::get_assetio_handler_from_path,
};
#[cfg(feature = "openssl_sign")]
use crate::{openssl::RsaSigner, signer::ConfigurableSigner};

pub const TEST_SMALL_JPEG: &str = "earth_apollo17.jpg";

pub const TEST_WEBP: &str = "mars.webp";

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

    // add some data boxes
    let _db_uri = claim.add_databox("text/plain", "this is a test".as_bytes().to_vec(), None)?;
    let _db_uri_1 =
        claim.add_databox("text/plain", "this is more text".as_bytes().to_vec(), None)?;

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
    std::fs::copy(fixture_src, &fixture_copy).unwrap();
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

/// Utility to create a test file with a placeholder for a manifest
#[cfg(feature = "file_io")]
pub fn write_jpeg_placeholder_file(
    placeholder: &[u8],
    input: &Path,
    output_file: &mut dyn CAIReadWrite,
    mut hasher: Option<&mut Hasher>,
) -> Result<usize> {
    // get where we will put the data
    let mut f = std::fs::File::open(input).unwrap();
    let jpeg_io = get_assetio_handler_from_path(input).unwrap();
    let box_mapper = jpeg_io.asset_box_hash_ref().unwrap();
    let boxes = box_mapper.get_box_map(&mut f).unwrap();
    let sof = boxes.iter().find(|b| b.names[0] == "SOF0").unwrap();

    // build new asset with hole for new manifest
    let outbuf = Vec::new();
    let mut out_stream = Cursor::new(outbuf);
    let mut input_file = std::fs::File::open(input).unwrap();

    // write before
    let mut before = vec![0u8; sof.range_start];
    input_file.read_exact(before.as_mut_slice()).unwrap();
    if let Some(hasher) = hasher.as_deref_mut() {
        hasher.update(&before);
    }
    out_stream.write_all(&before).unwrap();

    // write placeholder
    out_stream.write_all(placeholder).unwrap();

    // write bytes after
    let mut after_buf = Vec::new();
    input_file.read_to_end(&mut after_buf).unwrap();
    if let Some(hasher) = hasher {
        hasher.update(&after_buf);
    }
    out_stream.write_all(&after_buf).unwrap();

    // save to output file
    output_file.write_all(&out_stream.into_inner()).unwrap();

    Ok(sof.range_start)
}

pub(crate) struct TestGoodSigner {}
impl crate::Signer for TestGoodSigner {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
        Ok(b"not a valid signature".to_vec())
    }

    fn alg(&self) -> SigningAlg {
        SigningAlg::Ps256
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }

    fn reserve_size(&self) -> usize {
        1024
    }
}

/// Create a [`Signer`] instance that can be used for testing purposes using ps256 alg.
///
/// # Returns
///
/// Returns a boxed [`Signer`] instance.
pub fn temp_signer() -> Box<dyn Signer> {
    #[cfg(feature = "openssl_sign")]
    {
        #![allow(clippy::expect_used)]
        let sign_cert = include_bytes!("../../tests/fixtures/certs/ps256.pub").to_vec();
        let pem_key = include_bytes!("../../tests/fixtures/certs/ps256.pem").to_vec();

        let signer =
            RsaSigner::from_signcert_and_pkey(&sign_cert, &pem_key, SigningAlg::Ps256, None)
                .expect("get_temp_signer");

        Box::new(signer)
    }

    // todo: the will be a RustTLS signer shortly
    #[cfg(not(feature = "openssl_sign"))]
    {
        Box::new(TestGoodSigner {})
    }
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

struct TempRemoteSigner {}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl crate::signer::RemoteSigner for TempRemoteSigner {
    async fn sign_remote(&self, claim_bytes: &[u8]) -> crate::error::Result<Vec<u8>> {
        #[cfg(feature = "openssl_sign")]
        {
            let signer =
                crate::openssl::temp_signer_async::AsyncSignerAdapter::new(SigningAlg::Ps256);

            // this would happen on some remote server
            crate::cose_sign::cose_sign_async(&signer, claim_bytes, self.reserve_size()).await
        }
        #[cfg(not(feature = "openssl_sign"))]
        {
            use std::io::{Seek, Write};

            let mut sign_bytes = std::io::Cursor::new(vec![0u8; self.reserve_size()]);

            sign_bytes.rewind()?;
            sign_bytes.write_all(claim_bytes)?;

            // fake sig
            Ok(sign_bytes.into_inner())
        }
    }

    fn reserve_size(&self) -> usize {
        10000
    }
}

/// Create a [`RemoteSigner`] instance that can be used for testing purposes.
///
/// # Returns
///
/// Returns a boxed [`RemoteSigner`] instance.
pub fn temp_remote_signer() -> Box<dyn RemoteSigner> {
    Box::new(TempRemoteSigner {})
}

#[test]
fn test_create_test_store() {
    #[allow(clippy::expect_used)]
    let store = create_test_store().expect("create test store");

    assert_eq!(store.claims().len(), 1);
}
