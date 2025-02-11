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

use serde::{ser::SerializeSeq, Serialize};

use crate::{
    identity_assertion::signer_payload::SignerPayload, SignatureVerifier, ToCredentialSummary,
    ValidationError,
};

/// Describes the content and validation results for all
/// [`IdentityAssertion`]s contained within a single [`Manifest`].
///
/// Primarily intended for use with [`Serialize`] to generate JSON
/// (or potentially similar) structured reports on any identity
/// information available for a [`Manifest`].
pub struct IdentityAssertionsForManifest<SV: SignatureVerifier>(
    pub(crate) Vec<Result<SV::Output, ValidationError<SV::Error>>>,
);

impl<SV: SignatureVerifier> Serialize for IdentityAssertionsForManifest<SV> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for result in self.0.iter() {
            match result {
                Ok(output) => {
                    let summary = output.to_summary();
                    seq.serialize_element(&summary)?;
                }
                Err(_) => {
                    todo!("Handle error case");
                }
            }
        }
        seq.end()
    }
}

#[derive(Serialize)]
pub(crate) struct IdentityAssertionReport<T: Serialize> {
    #[serde(flatten)]
    pub(crate) signer_payload: SignerPayloadReport,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) named_actor: Option<T>,
}

#[derive(Serialize)]
pub(crate) struct SignerPayloadReport {
    sig_type: String,
    referenced_assertions: Vec<String>,
    // TO DO: Add role and expected_* fields.
    // (https://github.com/contentauth/c2pa-rs/issues/816)
}

impl SignerPayloadReport {
    pub(crate) fn from_signer_payload(sp: &SignerPayload) -> Self {
        Self {
            referenced_assertions: sp
                .referenced_assertions
                .iter()
                .map(|a| a.url().replace("self#jumbf=c2pa.assertions/", ""))
                .collect(),
            sig_type: sp.sig_type.clone(),
        }
    }
}
