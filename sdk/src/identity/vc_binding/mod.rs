// Copyright 2026 Adobe. All rights reserved.
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

//! Validation of the CAWG identity assertion **verifiable credential binding**
//! (`sig_type` `cawg.verifiable_credential_binding`), described in §8.3 of the
//! [CAWG identity assertion 1.3 draft].
//!
//! **Experimental:** available with the `unstable_cawg_vcb` feature. It tracks
//! a draft specification and may change or be removed in any release; see
//! `docs/experimental-features.md`.
//!
//! Where the draft is inconsistent, this follows its normative text rather
//! than its examples: `termsOfUse` property names are lowerCamelCase, and the
//! outermost credential's `@context` must include
//! `https://cawg.io/identity/1.2/vcb/context/`.
//!
//! [CAWG identity assertion 1.3 draft]: https://cawg.io/identity/1.3-draft+vc-vp/

mod binding;

pub(crate) mod codes;

mod vcb_credential;
pub use vcb_credential::{
    VcbCredential, VcbCredentialSubject, VcbCredentialSummary, VcbIdentityProvider,
    VcbVerifiableCredential, VcbVerifiedIdentity, C2PA_BINDING_CREDENTIAL_TYPE,
    CAWG_VERIFIED_IDENTITIES_TYPE, VC_BINDING_CONTEXT_IRI,
};

mod vcb_signature_verifier;
pub use vcb_signature_verifier::VcbSignatureVerifier;

mod vcb_validation_error;
pub use vcb_validation_error::VcbValidationError;

/// The `sig_type` of a verifiable credential binding.
pub const CAWG_VCB_SIG_TYPE: &str = "cawg.verifiable_credential_binding";

/// Builds the `termsOfUse` entry that binds a verifiable credential to
/// `signer_payload`, for an issuer creating a verifiable credential binding.
///
/// It is the payload's JSON serialization without `sig_type`, with byte
/// strings as standard base 64 and property names in lowerCamelCase, plus
/// `"type": "C2PAAssetBinding"`.
pub fn terms_of_use_for(
    signer_payload: &crate::identity::SignerPayload,
) -> Result<serde_json::Value, crate::identity::ValidationError<VcbValidationError>> {
    let mut terms_of_use = binding::expected_binding(signer_payload)
        .map_err(crate::identity::ValidationError::InternalError)?;
    if let serde_json::Value::Object(ref mut map) = terms_of_use {
        map.insert(
            "type".to_owned(),
            serde_json::Value::String(binding::C2PA_ASSET_BINDING.to_owned()),
        );
    }
    Ok(terms_of_use)
}
