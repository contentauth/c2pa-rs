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

use std::{collections::HashSet, fmt::Debug, sync::LazyLock};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    dynamic_assertion::PartialClaim, hash_utils::hash_by_alg, identity::ValidationError,
    log_current_item, status_tracker::StatusTracker, HashedUri, Manifest,
};

/// A set of _referenced assertions_ and other related data, known overall as
/// the **signer payload.** This binding **SHOULD** generally be construed as
/// authorization of or participation in the creation of the statements
/// described by those assertions and corresponding portions of the C2PA asset
/// in which they appear.
///
/// This is described in [§5.1, Overview], of the CAWG Identity Assertion
/// specification.
///
/// [§5.1, Overview]: https://cawg.io/identity/1.1-draft/#_overview
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct SignerPayload {
    /// List of assertions referenced by this credential signature
    pub referenced_assertions: Vec<HashedUri>,

    /// A string identifying the data type of the `signature` field
    pub sig_type: String,

    /// Roles associated with the named actor
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "role")]
    pub roles: Vec<String>,

    /// Hash of an expected partial claim
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_partial_claim: Option<HashedUri>,

    /// Hash of the expected claim signer credential
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_claim_generator: Option<HashedUri>,

    /// Descriptions of other expected identity assertions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_countersigners: Vec<HashedUri>,
}

impl Default for SignerPayload {
    fn default() -> Self {
        Self {
            referenced_assertions: vec![],
            sig_type: String::new(),
            roles: vec![],
            expected_partial_claim: None,
            expected_claim_generator: None,
            expected_countersigners: vec![],
        }
    }
}

impl SignerPayload {
    pub(super) fn check_against_partial_claim<E: Debug>(
        &self,
        partial_claim: &PartialClaim,
        status_tracker: &mut StatusTracker,
    ) -> Result<(), ValidationError<E>> {
        // All assertions mentioned in referenced_assertions also need to be referenced
        // in the claim.
        for ref_assertion in self.referenced_assertions.iter() {
            if let Some(claim_assertion) = partial_claim.assertions().find(|a| {
                // HACKY workaround for absolute assertion URLs as of c2pa-rs 0.36.0.
                // See https://github.com/contentauth/c2pa-rs/pull/603.
                let url = a.url();
                if url == ref_assertion.url() {
                    return true;
                }
                let url = ABSOLUTE_URL_PREFIX.replace(&url, "");
                url == ref_assertion.url()
            }) {
                if claim_assertion.hash() != ref_assertion.hash() {
                    return Err(ValidationError::AssertionMismatch(
                        ref_assertion.url().to_owned(),
                    ));
                }
            } else {
                log_current_item!(
                    "referenced assertion not in claim",
                    "SignerPayload::check_against_manifest"
                )
                .validation_status("cawg.identity.assertion.mismatch")
                .failure(
                    status_tracker,
                    ValidationError::<E>::AssertionNotInClaim(ref_assertion.url().to_owned()),
                )?;
            }
        }

        // Ensure that a hard binding assertion is present.
        let ref_assertion_labels: Vec<String> = self
            .referenced_assertions
            .iter()
            .map(|ra| ra.url().to_owned())
            .collect();

        if !ref_assertion_labels.iter().any(|ra| {
            if let Some((_jumbf_prefix, label)) = ra.rsplit_once('/') {
                label.starts_with("c2pa.hash.")
            } else {
                false
            }
        }) {
            log_current_item!(
                "no hard binding assertion",
                "SignerPayload::check_against_manifest"
            )
            .validation_status("cawg.identity.hard_binding_missing")
            .failure(status_tracker, ValidationError::<E>::NoHardBindingAssertion)?;
        }

        // Make sure no assertion references are duplicated.
        let mut labels = HashSet::<String>::new();

        for label in &ref_assertion_labels {
            let label = label.clone();
            if labels.contains(&label) {
                log_current_item!(
                    "multiple references to same assertion",
                    "SignerPayload::check_against_manifest"
                )
                .validation_status("cawg.identity.assertion.duplicate")
                .failure(
                    status_tracker,
                    ValidationError::<E>::DuplicateAssertionReference(label.clone()),
                )?;
            }
            labels.insert(label);
        }

        // Check expected_partial_claim
        if let Some(expected) = &self.expected_partial_claim {
            // Serialize the partial claim to CBOR for hashing.
            let pc_bytes = c2pa_cbor::to_vec(partial_claim).map_err(|e| {
                ValidationError::InternalError(format!("Failed to serialize PartialClaim: {}", e))
            })?;

            // Hash it
            let alg = expected.alg().unwrap_or_else(|| "sha256".to_string());
            let pc_hash = hash_by_alg(&alg, &pc_bytes, None);

            if pc_hash != expected.hash() {
                log_current_item!(
                    "expected partial claim mismatch",
                    "SignerPayload::check_against_partial_claim"
                )
                .validation_status("cawg.identity.expected_partial_claim.mismatch")
                .failure(status_tracker, ValidationError::<E>::ExpectedPartialClaimMismatch)?;
            }
        }

        // Check expected_countersigners
        for expected in &self.expected_countersigners {
            let found = partial_claim.assertions().any(|a| {
                // Simplified check: URIs and hashes match
                // We might need looser matching if URIs are relative/absolute
                let url_match = a.url() == expected.url()
                    || ABSOLUTE_URL_PREFIX.replace(&a.url(), "") == expected.url();
                
                url_match && a.hash() == expected.hash()
            });

            if !found {
                log_current_item!(
                    "expected countersigner mismatch",
                    "SignerPayload::check_against_partial_claim"
                )
                .validation_status("cawg.identity.expected_countersigner.mismatch")
                .failure(
                    status_tracker,
                    ValidationError::<E>::ExpectedCountersignerMismatch(expected.url().clone()),
                )?;
            }
        }

        Ok(())
    }

    pub(super) fn check_against_manifest<E: Debug>(
        &self,
        manifest: &Manifest,
        status_tracker: &mut StatusTracker,
    ) -> Result<(), ValidationError<E>> {
        // All assertions mentioned in referenced_assertions also need to be referenced
        // in the claim.
        for ref_assertion in self.referenced_assertions.iter() {
            if let Some(claim_assertion) = manifest.assertion_references().find(|a| {
                // HACKY workaround for absolute assertion URLs as of c2pa-rs 0.36.0.
                // See https://github.com/contentauth/c2pa-rs/pull/603.
                let url = a.url();
                if url == ref_assertion.url() {
                    return true;
                }
                let url = ABSOLUTE_URL_PREFIX.replace(&url, "");
                url == ref_assertion.url()
            }) {
                if claim_assertion.hash() != ref_assertion.hash() {
                    return Err(ValidationError::AssertionMismatch(
                        ref_assertion.url().to_owned(),
                    ));
                }

                // TO REVIEW WITH GAVIN: I'm getting different value for
                // assertion.alg (None) via the AsyncDynamicAssertion API than
                // what I'm getting when I read the claim back
                // on validation (Some("ps256")).

                // if let Some(alg) = claim_assertion.alg().as_ref() {
                //     if Some(alg) != ref_assertion.alg().as_ref() {
                //         return Err(ValidationError::AssertionMismatch(
                //             ref_assertion.url().to_owned(),
                //         ));
                //     }
                // } else {
                //     return Err(ValidationError::AssertionMismatch(
                //         ref_assertion.url().to_owned(),
                //     ));
                // }
            } else {
                log_current_item!(
                    "referenced assertion not in claim",
                    "SignerPayload::check_against_manifest"
                )
                .validation_status("cawg.identity.assertion.mismatch")
                .failure(
                    status_tracker,
                    ValidationError::<E>::AssertionNotInClaim(ref_assertion.url().to_owned()),
                )?;
            }
        }

        // Ensure that a hard binding assertion is present.
        let ref_assertion_labels: Vec<String> = self
            .referenced_assertions
            .iter()
            .map(|ra| ra.url().to_owned())
            .collect();

        if !ref_assertion_labels.iter().any(|ra| {
            if let Some((_jumbf_prefix, label)) = ra.rsplit_once('/') {
                label.starts_with("c2pa.hash.")
            } else {
                false
            }
        }) {
            log_current_item!(
                "no hard binding assertion",
                "SignerPayload::check_against_manifest"
            )
            .validation_status("cawg.identity.hard_binding_missing")
            .failure(status_tracker, ValidationError::<E>::NoHardBindingAssertion)?;
        }

        // Make sure no assertion references are duplicated.
        let mut labels = HashSet::<String>::new();

        for label in &ref_assertion_labels {
            let label = label.clone();
            if labels.contains(&label) {
                log_current_item!(
                    "multiple references to same assertion",
                    "SignerPayload::check_against_manifest"
                )
                .validation_status("cawg.identity.assertion.duplicate")
                .failure(
                    status_tracker,
                    ValidationError::<E>::DuplicateAssertionReference(label.clone()),
                )?;
            }

            labels.insert(label);
        }

        // Check expected_partial_claim
        if let Some(expected) = &self.expected_partial_claim {
            // Reconstruct PartialClaim from Manifest
            let mut partial_claim = PartialClaim::default();
            for assertion in manifest.assertion_references() {
                partial_claim.add_assertion(assertion);
            }
            partial_claim.set_claim_generator(
                manifest.claim_generator.clone(),
                manifest.claim_generator_info.clone(),
            );

            // Serialize and hash
            let pc_bytes = c2pa_cbor::to_vec(&partial_claim).map_err(|e| {
                ValidationError::InternalError(format!("Failed to serialize PartialClaim: {}", e))
            })?;

            let alg = expected.alg().unwrap_or_else(|| "sha256".to_string());
            let pc_hash = hash_by_alg(&alg, &pc_bytes, None);

            if pc_hash != expected.hash() {
                log_current_item!(
                    "expected partial claim mismatch",
                    "SignerPayload::check_against_manifest"
                )
                .validation_status("cawg.identity.expected_partial_claim.mismatch")
                .failure(status_tracker, ValidationError::<E>::ExpectedPartialClaimMismatch)?;
            }
        }

        // Check expected_claim_generator
        if self.expected_claim_generator.is_some() {
            // TO DO: Implement expected_claim_generator check.
            // Requires access to the signing certificate (leaf) in DER format to hash it.
            // Manifest::signature_info only provides the cert chain as a PEM string.
            // This might need to be moved to SignatureVerifier or SignatureInfo extended.
        }

        // Check expected_countersigners
        for expected in &self.expected_countersigners {
            let found = manifest.assertion_references().any(|a| {
                let url_match = a.url() == expected.url()
                    || ABSOLUTE_URL_PREFIX.replace(&a.url(), "") == expected.url();
                
                url_match && a.hash() == expected.hash()
            });

            if !found {
                log_current_item!(
                    "expected countersigner mismatch",
                    "SignerPayload::check_against_manifest"
                )
                .validation_status("cawg.identity.expected_countersigner.mismatch")
                .failure(
                    status_tracker,
                    ValidationError::<E>::ExpectedCountersignerMismatch(expected.url().clone()),
                )?;
            }
        }

        Ok(())
    }
}

#[allow(clippy::unwrap_used)]
static ABSOLUTE_URL_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new("/c2pa/[^/]+/").unwrap());

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use hex_literal::hex;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::{identity::SignerPayload, HashedUri};

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn impl_clone() {
        // Silly test to ensure code coverage on #[derive] line.

        let data_hash_ref = HashedUri::new(
        "self#jumbf=c2pa/urn:uuid:F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4/c2pa.assertions/c2pa.hash.data".to_owned(),
        Some("sha256".to_owned()),
        &hex!("53d1b2cf4e6d9a97ed9281183fa5d836c32751b9d2fca724b40836befee7d67f"));

        let signer_payload = SignerPayload {
            referenced_assertions: vec![data_hash_ref],
            roles: vec!["author".to_owned()],
            sig_type: "NONSENSE".to_owned(),
            expected_partial_claim: None,
            expected_claim_generator: None,
            expected_countersigners: vec![],
        };

        assert_eq!(signer_payload, signer_payload.clone());
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn test_serialization() {
        let data_hash_ref = HashedUri::new(
            "self#jumbf=c2pa/assertions/c2pa.hash.data".to_owned(),
            Some("sha256".to_owned()),
            &hex!("53d1b2cf4e6d9a97ed9281183fa5d836c32751b9d2fca724b40836befee7d67f"),
        );

        let signer_payload = SignerPayload {
            referenced_assertions: vec![data_hash_ref.clone()],
            roles: vec!["author".to_owned()],
            sig_type: "test_sig".to_owned(),
            expected_partial_claim: Some(data_hash_ref.clone()),
            expected_claim_generator: Some(data_hash_ref.clone()),
            expected_countersigners: vec![data_hash_ref],
        };

        let json = serde_json::to_string(&signer_payload).unwrap();
        let decoded: SignerPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(signer_payload, decoded);
        assert!(json.contains("\"expected_partial_claim\""));
        assert!(json.contains("\"expected_claim_generator\""));
        assert!(json.contains("\"expected_countersigners\""));
        assert!(json.contains("\"role\""));
    }
}
