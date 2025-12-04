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

use c2pa::{
    identity::validator::CawgValidator, settings::Settings, validation_results, Builder, Error,
    Reader, Result, Signer,
};

#[test]
fn restricted_remote_manifest() {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml")).unwrap();
    Settings::from_toml(
        &toml::toml! {
            [core]
            allowed_network_hosts = []

            [verify]
            remote_manifest_fetch = true
        }
        .to_string(),
    )
    .unwrap();

    let mut builder = Builder::new();
    builder.no_embed = true;
    builder.remote_url = Some("https://www.example.com".to_owned());

    let mut source = Cursor::new(include_bytes!("fixtures/CA.jpg"));
    let format = "image/jpeg";

    let mut dest = Cursor::new(Vec::new());

    let signer = Settings::signer().unwrap();
    builder
        .sign(&signer, format, &mut source, &mut dest)
        .unwrap();

    dest.rewind().unwrap();

    let result = Reader::from_stream(format, dest);
    // REVIEW-NOTE: should we preserve the UriDisallowed error here?
    assert!(matches!(result, Err(Error::RemoteManifestFetch(..))));
}

#[test]
fn restricted_timestamp() {
    // Basic wrapper around a Signer to include a time authority URL.
    struct WrappedTsaSigner(Box<dyn Signer>);

    impl Signer for WrappedTsaSigner {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
            self.0.sign(data)
        }

        fn alg(&self) -> c2pa::SigningAlg {
            self.0.alg()
        }

        fn certs(&self) -> Result<Vec<Vec<u8>>> {
            self.0.certs()
        }

        fn reserve_size(&self) -> usize {
            self.0.reserve_size()
        }

        fn time_authority_url(&self) -> Option<String> {
            Some("https://www.example.com".to_owned())
        }
    }

    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml")).unwrap();
    Settings::from_toml(
        &toml::toml! {
            [core]
            allowed_network_hosts = []
        }
        .to_string(),
    )
    .unwrap();

    let mut source = Cursor::new(include_bytes!("fixtures/CA.jpg"));
    let format = "image/jpeg";

    let mut dest = Cursor::new(Vec::new());

    let signer = WrappedTsaSigner(Settings::signer().unwrap());

    let result = Builder::new().sign(&signer, format, &mut source, &mut dest);
    // REVIEW-NOTE: TimeStampError isn't exposed in the API so we can't match on it
    assert!(matches!(result, Err(Error::TimeStampError(..))));
}

#[test]
fn restricted_ocsp() {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml")).unwrap();
    Settings::from_toml(
        &toml::toml! {
            [core]
            allowed_network_hosts = []

            [verify]
            ocsp_fetch = true
        }
        .to_string(),
    )
    .unwrap();

    // TODO: need an asset that contains an OCSP URL
    let mut source = Cursor::new(include_bytes!("fixtures/firefly.png"));
    let format = "image/png";

    // let mut dest = Cursor::new(Vec::new());

    let signer = Settings::signer().unwrap();

    // Builder::new()
    //     .sign(&signer, format, &mut source, &mut dest)
    //     .unwrap();

    // dest.rewind().unwrap();

    let reader = Reader::from_stream(format, source).unwrap();
    let status_codes = reader
        .validation_results()
        .unwrap()
        .active_manifest()
        .unwrap();
    // assert!(status_codes
    //     .success
    //     .iter()
    //     .any(|status| status.code() == validation_results::SIGNING_CREDENTIAL_NOT_REVOKED));
    // println!("{:?}", reader);
    println!("{:?}", status_codes);

    // REVIEW-NOTE: use granular HttpError::UriDisallowed when public
    // assert!(matches!(result, Err(Error::HttpError(..))));
}

// TODO: CAWG doesn't read from settings yet so it can't do restriction
#[ignore]
#[cfg(not(target_arch = "wasm32"))] // TODO: tokio not supported on wasm
#[test]
fn restricted_cawg() {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml")).unwrap();
    Settings::from_toml(
        &toml::toml! {
            [core]
            allowed_network_hosts = []

            // TODO: need to enable anything here?
        }
        .to_string(),
    )
    .unwrap();

    let source = Cursor::new(include_bytes!(
        "../src/identity/tests/fixtures/claim_aggregation/adobe_connected_identities.jpg"
    ));
    let format = "image/jpeg";

    let mut reader = Reader::from_stream(format, source).unwrap();

    let result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(reader.post_validate_async(&CawgValidator {}));
    // REVIEW-NOTE: use granular HttpError::UriDisallowed when public
    assert!(matches!(result, Err(Error::HttpError(..))));
}

// #[c2pa_test_async]
// async fn restricted_cawg() {
//     Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml")).unwrap();
//     Settings::from_toml(
//         &toml::toml! {
//             [core]
//             allowed_network_hosts = []

//             // TODO: need to enable anything here?
//         }
//         .to_string(),
//     )
//     .unwrap();

//     let mut source = Cursor::new(include_bytes!("fixtures/CA.jpg"));
//     let format = "image/jpeg";

//     let reader = Reader::from_stream_async(format, source).await.unwrap();

//     let result = reader.post_validate_async(&CawgValidator {}).await;
//     REVIEW-NOTE: use granular HttpError::UriDisallowed when public
//     assert!(matches!(result, Err(Error::HttpError(..))));
// }
