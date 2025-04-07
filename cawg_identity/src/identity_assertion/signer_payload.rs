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

use c2pa::{dynamic_assertion::PartialClaim, HashedUri, Manifest};
use c2pa_status_tracker::{log_current_item, StatusTracker};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::ValidationError;

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
    // TO DO: Add expected_* fields.
    // (https://github.com/contentauth/c2pa-rs/issues/816)
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

        Ok(())
    }
}

#[allow(clippy::unwrap_used)]
static ABSOLUTE_URL_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new("/c2pa/[^/]+/").unwrap());
