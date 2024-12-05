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

use std::{
    collections::HashSet,
    fmt::{Debug, Formatter},
    sync::LazyLock,
};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    identity_assertion::{ValidationError, ValidationResult},
    internal::debug_byte_slice::DebugByteSlice,
};

#[allow(clippy::unwrap_used)]
static ABSOLUTE_URL_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new("/c2pa/[^/]+/").unwrap());

/// The set of data to be signed by the credential holder.
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct SignerPayload {
    /// List of assertions referenced by this credential signature
    pub referenced_assertions: Vec<HashedUri>,

    /// A string identifying the data type of the `signature` field
    pub sig_type: String,
}

impl SignerPayload {
    pub(super) fn check_against_manifest(&self, manifest: &c2pa::Manifest) -> ValidationResult<()> {
        // All assertions mentioned in referenced_assertions
        // also need to be referenced in the claim.

        for ref_assertion in self.referenced_assertions.iter() {
            if let Some(claim_assertion) = manifest.assertion_references().find(|a| {
                // HACKY workaround for absolute assertion URLs as of c2pa-rs 0.36.0.
                // See https://github.com/contentauth/c2pa-rs/pull/603.
                let url = a.url();
                if url == ref_assertion.url {
                    return true;
                }
                let url = ABSOLUTE_URL_PREFIX.replace(&url, "");
                url == ref_assertion.url
            }) {
                if claim_assertion.hash() != ref_assertion.hash {
                    return Err(ValidationError::AssertionMismatch(
                        ref_assertion.url.to_owned(),
                    ));
                }
                if let Some(alg) = claim_assertion.alg().as_ref() {
                    if Some(alg) != ref_assertion.alg.as_ref() {
                        return Err(ValidationError::AssertionMismatch(
                            ref_assertion.url.to_owned(),
                        ));
                    }
                } else {
                    return Err(ValidationError::AssertionMismatch(
                        ref_assertion.url.to_owned(),
                    ));
                }
            } else {
                return Err(ValidationError::AssertionNotInClaim(
                    ref_assertion.url.to_owned(),
                ));
            }
        }

        // Ensure that a hard binding assertion is present.

        let ref_assertion_labels: Vec<String> = self
            .referenced_assertions
            .iter()
            .map(|ra| ra.url.to_owned())
            .collect();

        if !ref_assertion_labels.iter().any(|ra| {
            if let Some((_jumbf_prefix, label)) = ra.rsplit_once('/') {
                label.starts_with("c2pa.hash.")
            } else {
                false
            }
        }) {
            return Err(ValidationError::NoHardBindingAssertion);
        }

        // Make sure no assertion references are duplicated.

        let mut labels = HashSet::<String>::new();

        for label in &ref_assertion_labels {
            let label = label.clone();
            if labels.contains(&label) {
                return Err(ValidationError::MultipleAssertionReferenced(label));
            }
            labels.insert(label);
        }

        Ok(())
    }
}

/// A `HashedUri` provides a reference to content available within the same
/// manifest store.
///
/// This is described in §8.3, “[URI References],” of the C2PA Technical
/// Specification.
///
/// [URI References]: https://c2pa.org/specifications/specifications/2.0/specs/C2PA_Specification.html#_uri_references
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct HashedUri {
    /// JUMBF URI reference
    pub url: String,

    /// A string identifying the cryptographic hash algorithm used to compute
    /// the hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// Byte string containing the hash value
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
}

impl Debug for HashedUri {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("HashedUri")
            .field("url", &self.url)
            .field("alg", &self.alg)
            .field("hash", &DebugByteSlice(&self.hash))
            .finish()
    }
}
