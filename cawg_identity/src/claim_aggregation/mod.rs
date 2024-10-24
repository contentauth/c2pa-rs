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

//! Contains implementations of [`CredentialHolder`] and [`SignatureHandler`]
//! for the identity claim aggregation credential type described as specified in
//! [§8.1, Identity claims aggregation].
//!
//! [`CredentialHolder`]: crate::builder::CredentialHolder
//! [`SignatureHandler`]: crate::SignatureHandler
//! [§8.1, Identity claims aggregation]: https://creator-assertions.github.io/identity/1.1-draft/#_identity_claims_aggregation

mod cose_vc_signature_handler;
pub use cose_vc_signature_handler::{CoseVcSignatureHandler, VcNamedActor};

mod identity_claims_aggregation_vc;
pub use identity_claims_aggregation_vc::{
    IdentityAssertionVc, IdentityClaimsAggregationVc, IdentityProvider, VcVerifiedIdentity,
};

pub(crate) mod w3c_vc;
