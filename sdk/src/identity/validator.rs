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
    settings::Settings,
    status_tracker::StatusTracker,
    Context, ManifestAssertion,
};

/// Validates a CAWG identity assertion.
///
/// A `CawgValidator` carries the [`Settings`] (taken from a [`Context`]) that
/// govern CAWG validation, such as the `cawg_trust.trusted_ica_issuers`
/// allow-list. Construct one with [`CawgValidator::new`] to validate under a
/// specific [`Context`], or use [`CawgValidator::default`] to validate under
/// default settings.
#[derive(Default)]
pub struct CawgValidator {
    settings: Settings,
}

impl CawgValidator {
    /// Create a `CawgValidator` whose trust configuration is drawn from the
    /// provided [`Context`].
    pub fn new(context: &Context) -> Self {
        Self {
            settings: context.settings().clone(),
        }
    }
}

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
                .validate_partial_claim_async(partial_claim, tracker, &self.settings)
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

        assert!(reader
            .validation_results()
            .unwrap()
            .active_manifest()
            .unwrap()
            .success()
            .iter()
            .any(|s| s.code() == "cawg.ica.credential_valid"));
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

    #[cfg(not(target_arch = "wasm32"))]
    #[c2pa_test_async]
    async fn ica_issuer_untrusted_does_not_affect_manifest_state() {
        use crate::{Context, Settings};

        let _did_server = mock_connected_identities_did();

        // Build a Context that trusts NO ICA issuers (empty allow-list) and skips
        // C2PA certificate trust checking. The empty list must reach the verifier
        // through the Context carried by the CawgValidator.
        let settings = Settings::new()
            .with_value("verify.verify_trust", false)
            .unwrap()
            .with_value("core.decode_identity_assertions", false)
            .unwrap()
            .with_value("cawg_trust.trusted_ica_issuers", Vec::<String>::new())
            .unwrap();
        let context = Context::new().with_settings(settings).unwrap();

        // Construct the validator from the context *before* moving the context
        // into the reader.
        let validator = super::CawgValidator::new(&context);

        let mut stream = Cursor::new(CONNECTED_IDENTITIES_VALID);
        let mut reader = Reader::from_context(context)
            .with_stream_async("image/jpeg", &mut stream)
            .await
            .unwrap();

        reader.post_validate_async(&validator).await.unwrap();

        let results = reader.validation_results().unwrap();
        let active = results.active_manifest().unwrap();

        // The credential's issuer is not on the (empty) allow-list, so an
        // untrusted-issuer failure is recorded for this identity assertion...
        assert!(active
            .failure()
            .iter()
            .any(|s| s.code() == "cawg.ica.untrusted_issuer"));

        // ...and, because a failure was generated, the credential is not reported
        // as valid.
        assert!(!active
            .success()
            .iter()
            .any(|s| s.code() == "cawg.ica.credential_valid"));

        // But the untrusted ICA issuer is scoped to the identity assertion: it
        // does NOT invalidate the enclosing C2PA manifest.
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
