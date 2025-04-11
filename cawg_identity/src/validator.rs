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
use c2pa::{
    dynamic_assertion::{AsyncPostValidator, PartialClaim},
    ManifestAssertion,
};
use c2pa_status_tracker::StatusTracker;
use serde_json::Value;

use crate::IdentityAssertion;

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
    ) -> c2pa::Result<Option<Value>> {
        if label.starts_with("cawg.identity") {
            let identity_assertion: IdentityAssertion = assertion.to_assertion()?;
            tracker.push_current_uri(uri);
            let result = identity_assertion
                .validate_partial_claim(partial_claim, tracker)
                .await
                .map(Some)
                .map_err(|e| c2pa::Error::ClaimVerification(e.to_string()));
            tracker.pop_current_uri();
            return result;
        };
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::io::Cursor;

    use c2pa::{Reader, ValidationState};

    use super::*;

    const CONNECTED_IDENTITIES_VALID: &[u8] =
        include_bytes!("tests/fixtures/claim_aggregation/adobe_connected_identities.jpg");

    const NO_HARD_BINDING: &[u8] =
        include_bytes!("tests/fixtures/validation_method/no_hard_binding.jpg");

    const MULTIPLE_IDENTITIES_VALID: &[u8] =
        include_bytes!("tests/fixtures/claim_aggregation/ims_multiple_manifests.jpg");

    #[tokio::test]
    async fn test_connected_identities_valid() {
        let mut stream = Cursor::new(CONNECTED_IDENTITIES_VALID);
        let mut reader = Reader::from_stream("image/jpeg", &mut stream).unwrap();
        reader.post_validate_async(&CawgValidator {}).await.unwrap();
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

    #[tokio::test]
    async fn test_multiple_identities_valid() {
        let mut stream = Cursor::new(MULTIPLE_IDENTITIES_VALID);
        let mut reader = Reader::from_stream("image/jpeg", &mut stream).unwrap();
        reader.post_validate_async(&CawgValidator {}).await.unwrap();
        println!("validation results: {}", reader);
        assert_eq!(
            reader
                .validation_results()
                .unwrap()
                .ingredient_deltas()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(reader.validation_state(), ValidationState::Valid);
    }

    #[tokio::test]
    async fn test_post_validate_with_hard_binding_missing() {
        let mut stream = Cursor::new(NO_HARD_BINDING);
        let mut reader = Reader::from_stream("image/jpeg", &mut stream).unwrap();
        reader.post_validate_async(&CawgValidator {}).await.unwrap();
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
