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

//! Contains implementations of [`AsyncCredentialHolder`] and
//! [`SignatureVerifier`] for the identity claim aggregation credential type
//! described as specified in [§8.1, Identity claims aggregation].
//!
//! [`AsyncCredentialHolder`]: crate::builder::AsyncCredentialHolder
//! [`SignatureVerifier`]: crate::SignatureVerifier
//! [§8.1, Identity claims aggregation]: https://creator-assertions.github.io/identity/1.1-draft/#_identity_claims_aggregation

mod ica_credential;
pub use ica_credential::{
    IcaCredential, IcaCredentialSummary, IdentityClaimsAggregationVc, IdentityProvider,
    VerifiedIdentity,
};

mod ica_signature_verifier;
pub use ica_signature_verifier::IcaSignatureVerifier;

mod ica_validation_error;
pub use ica_validation_error::IcaValidationError;

pub(crate) mod w3c_vc;

pub(crate) const CAWG_ICA_SIG_TYPE: &str = "cawg.identity_claims_aggregation";
