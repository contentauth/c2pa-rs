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

/// Validates a CAWG identity assertion.
#[deprecated(
    since = "0.14.0",
    note = "Use c2pa::identity::validator::CawgValidator instead"
)]
pub use c2pa::identity::validator::CawgValidator;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::io::Cursor;

    use c2pa::{Reader, ValidationState};
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    const CONNECTED_IDENTITIES_VALID: &[u8] =
        include_bytes!("tests/fixtures/claim_aggregation/adobe_connected_identities.jpg");

    const NO_HARD_BINDING: &[u8] =
        include_bytes!("tests/fixtures/validation_method/no_hard_binding.jpg");

    const MULTIPLE_IDENTITIES_VALID: &[u8] =
        include_bytes!("tests/fixtures/claim_aggregation/ims_multiple_manifests.jpg");

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    #[cfg_attr(target_os = "wasi", wstd::test)]
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

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    #[cfg_attr(target_os = "wasi", wstd::test)]
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

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    #[cfg_attr(target_os = "wasi", wstd::test)]
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
