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

//! This module contains the APIs you will use to validate a
//! C2PA Manifest that contains one or more CAWG identity assertions.

use async_trait::async_trait;
use serde_json::Value;

use crate::{
    dynamic_assertion::{AsyncPostValidator, PartialClaim},
    identity::IdentityAssertion,
    status_tracker::StatusTracker,
    ManifestAssertion,
};

/// Validates a CAWG identity assertion.
pub struct CawgValidator;
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AsyncPostValidator for CawgValidator {
    async fn validate(
        &self,
        label: &str,
        assertion: &ManifestAssertion,
        uri: &str,
        partial_claim: &PartialClaim,
        tracker: &mut StatusTracker,
    ) -> crate::Result<Option<Value>> {
        if label == "cawg.identity" || label.starts_with("cawg.identity__") {
            let identity_assertion: IdentityAssertion = assertion.to_assertion()?;
            tracker.push_current_uri(uri.to_string());
            let result = identity_assertion
                .validate_partial_claim_async(partial_claim, tracker)
                .await
                .ok();
            tracker.pop_current_uri();
            return Ok(result);
        };
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]
    use std::io::Cursor;

    use c2pa_macros::c2pa_test_async;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::{Reader, ValidationState};

    const CONNECTED_IDENTITIES_VALID: &[u8] =
        include_bytes!("tests/fixtures/claim_aggregation/adobe_connected_identities.jpg");

    const NO_HARD_BINDING: &[u8] =
        include_bytes!("tests/fixtures/validation_method/no_hard_binding.jpg");

    const MULTIPLE_IDENTITIES_VALID: &[u8] =
        include_bytes!("tests/fixtures/claim_aggregation/ims_multiple_manifests.jpg");

    // DID document for the `did:web` issuer that both Adobe-signed fixtures above
    // were signed against. Served by a local mock so validation does not depend on
    // reaching the Adobe stage server over the network.
    #[cfg(not(target_arch = "wasm32"))]
    const CONNECTED_IDENTITIES_DID: &str =
        include_str!("tests/fixtures/claim_aggregation/connected_identities_did.json");

    /// Start a local mock server that serves the issuer DID document and redirect
    /// `did:web` resolution for the Adobe stage domain to it. The returned
    /// `MockServer` must be kept alive for the duration of the test.
    #[cfg(not(target_arch = "wasm32"))]
    fn mock_connected_identities_did() -> httpmock::MockServer {
        use httpmock::prelude::*;

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/.well-known/did.json");
            then.status(200)
                .header("content-type", "application/did+json")
                .body(CONNECTED_IDENTITIES_DID);
        });

        crate::identity::claim_aggregation::w3c_vc::did_web::set_proxy(
            "connected-identities.identity-stage.adobe.com",
            &server.url("/"),
        );

        server
    }

    #[c2pa_test_async]
    async fn test_connected_identities_valid() {
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        #[cfg(not(target_arch = "wasm32"))]
        let _did_server = mock_connected_identities_did();

        let mut stream = Cursor::new(CONNECTED_IDENTITIES_VALID);

        let reader = Reader::default()
            .with_stream_async("image/jpeg", &mut stream)
            .await
            .unwrap();

        //println!("validation results: {}", reader);

        assert_eq!(
            reader
                .validation_results()
                .unwrap()
                .active_manifest()
                .unwrap()
                .success()
                .last()
                .unwrap()
                .code(),
            "cawg.ica.credential_valid"
        );
    }

    #[c2pa_test_async]
    async fn test_multiple_identities_valid() {
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        #[cfg(not(target_arch = "wasm32"))]
        let _did_server = mock_connected_identities_did();

        let mut stream = Cursor::new(MULTIPLE_IDENTITIES_VALID);

        let reader = Reader::default()
            .with_stream_async("image/jpeg", &mut stream)
            .await
            .unwrap();

        println!("validation results: {reader}");

        assert_eq!(
            reader
                .validation_results()
                .unwrap()
                .ingredient_deltas()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(reader.validation_state(), ValidationState::Valid);
    }

    #[c2pa_test_async]
    async fn test_cawg_validate_with_hard_binding_missing() {
        let mut stream = Cursor::new(NO_HARD_BINDING);

        let reader = Reader::default()
            .with_stream_async("image/jpeg", &mut stream)
            .await
            .unwrap();

        assert_eq!(
            reader
                .validation_results()
                .unwrap()
                .active_manifest()
                .unwrap()
                .failure()[0]
                .code(),
            "cawg.identity.hard_binding_missing"
        );
    }
}
