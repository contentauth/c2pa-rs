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
    context::Context,
    dynamic_assertion::{AsyncPostValidator, PartialClaim},
    identity::IdentityAssertion,
    status_tracker::StatusTracker,
    ManifestAssertion,
};

/// Validates a CAWG identity assertion.
///
/// A `CawgValidator` carries the [`Context`] that governs CAWG validation,
/// including the `cawg_trust.trusted_ica_issuers` allow-list. Construct one with
/// [`CawgValidator::new`] to validate under a specific [`Context`].
pub struct CawgValidator<'a> {
    context: &'a Context,
}

impl<'a> CawgValidator<'a> {
    /// Create a [`CawgValidator`] from the provided context.
    pub fn new(context: &'a Context) -> Self {
        Self { context }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AsyncPostValidator for CawgValidator<'_> {
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
                .validate_partial_claim_async(partial_claim, tracker, self.context)
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

        // The default resolver now blocks non-globally-routable hosts (SSRF hardening,
        // CAI-12574). The proxy above points did:web resolution at this loopback mock server, so
        // the host must be allow-listed for resolution to reach it. Callers that build their
        // `Settings` from thread-local state pick this up; those that build a fresh `Settings`
        // must add the host themselves via [`allowed_host_pattern`].
        crate::settings::set_settings_value(
            "core.allowed_network_hosts",
            [allowed_host_pattern(&server)],
        )
        .unwrap();

        server
    }

    /// The `allowed_network_hosts` entry that permits requests to `server` (a loopback mock).
    #[cfg(not(target_arch = "wasm32"))]
    fn allowed_host_pattern(server: &httpmock::MockServer) -> String {
        format!("127.0.0.1:{}", server.port())
    }

    #[c2pa_test_async]
    async fn test_connected_identities_valid() {
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        // Start the mock server (registering its host in thread-local settings) before snapshotting
        // settings into the context, so the allow-list entry reaches the CAWG validator.
        #[cfg(not(target_arch = "wasm32"))]
        let _did_server = mock_connected_identities_did();

        let settings = crate::settings::get_thread_local_settings();
        let context = crate::Context::new().with_settings(settings).unwrap();

        let mut stream = Cursor::new(CONNECTED_IDENTITIES_VALID);

        let reader = Reader::from_context(context)
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
        crate::settings::set_settings_value(
            "soft_binding.soft_binding_algorithms",
            [
                "com.adobe.trustmark.P".to_string(),
                "com.adobe.icn.dense".to_string(),
            ],
        )
        .unwrap();
        // Start the mock server (and register its host in thread-local settings) before snapshotting
        // settings, so the allow-list entry is carried into the context below.
        #[cfg(not(target_arch = "wasm32"))]
        let _did_server = mock_connected_identities_did();

        let settings = crate::settings::get_thread_local_settings();
        let context = crate::Context::new().with_settings(settings).unwrap();

        let mut stream = Cursor::new(MULTIPLE_IDENTITIES_VALID);

        let reader = Reader::from_context(context)
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
            // This fresh `Settings` doesn't inherit thread-local state, so allow the loopback
            // mock host explicitly (see `mock_connected_identities_did`).
            .with_value(
                "core.allowed_network_hosts",
                [allowed_host_pattern(&_did_server)],
            )
            .unwrap()
            .with_value("cawg_trust.trusted_ica_issuers", Vec::<String>::new())
            .unwrap()
            .with_value(
                "soft_binding.soft_binding_algorithms",
                [
                    "com.adobe.trustmark.P".to_string(),
                    "com.adobe.icn.dense".to_string(),
                ],
            )
            .unwrap();
        let context = Context::new()
            .with_settings(settings)
            .unwrap()
            .into_shared();

        // Both the reader and the validator share this context, so the empty
        // allow-list reaches the verifier through the CawgValidator.
        let validator = super::CawgValidator::new(&context);

        let mut stream = Cursor::new(CONNECTED_IDENTITIES_VALID);
        let mut reader = Reader::from_shared_context(&context)
            .with_stream_async("image/jpeg", &mut stream)
            .await
            .unwrap();

        reader.post_validate_async(&validator).await.unwrap();

        let results = reader.validation_results().unwrap();
        let active = results.active_manifest().unwrap();

        // The credential's issuer is not on the (empty) allow-list, so an
        // untrusted-issuer notice is recorded informationally for this identity
        // assertion (not as a failure, so it does not affect manifest state)...
        assert!(active
            .informational()
            .iter()
            .any(|s| s.code() == "cawg.ica.untrusted_issuer"));
        assert!(!active
            .failure()
            .iter()
            .any(|s| s.code() == "cawg.ica.untrusted_issuer"));

        // ...and, because the issuer is untrusted, the credential is not reported
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
