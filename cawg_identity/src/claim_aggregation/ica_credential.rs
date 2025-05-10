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

/// TO DO: Doc -- looks like CredentialV2 for our specific use
/// case.
#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::claim_aggregation::IcaCredential"
)]
pub use c2pa::identity::claim_aggregation::IcaCredential;
#[doc(hidden)]
#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::claim_aggregation::IcaCredentialSummary"
)]
pub use c2pa::identity::claim_aggregation::IcaCredentialSummary;
// /// Identity claims aggregation context IRI.
// pub const IDENTITY_CLAIMS_AGGREGATION_CONTEXT_IRI: &Iri =
//     static_iref::iri!("https://cawg.io/identity/1.1/ica/context/");

// /// Identity claims aggregation credential type name.
// pub const IDENTITY_CLAIMS_AGGREGATION_CREDENTIAL_TYPE: &str =
// "IdentityClaimsAggregationCredential";
/// An **identity claims aggregation** is a [W3C verifiable credential] that
/// binds one or more identity claim attestations regarding the _named actor_ to
/// the _C2PA asset_ in which the **identity assertion** appears.
///
/// [W3C verifiable credential]: https://www.w3.org/TR/vc-data-model-2.0/
#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::claim_aggregation::IdentityClaimsAggregationVc"
)]
pub use c2pa::identity::claim_aggregation::IdentityClaimsAggregationVc;
/// ## Identity provider details
///
/// The `verifiedIdentities[?].provider` property MUST be an object and MUST be
/// present. It contains details about the _identity provider_ and the identity
/// verification process. This specification mentions at least three properties
/// that MAY be used to represent the _named actor’s_ verification details:
/// `id`, `name`, and `proof`.
#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::claim_aggregation::IdentityProvider"
)]
pub use c2pa::identity::claim_aggregation::IdentityProvider;
/// Every item in the `verifiedIdentities` array MUST contain information about
/// the _named actor_ as verified by the _identity assertion generator_ or a
/// service contacted by the _identity assertion generator._
#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::claim_aggregation::VerifiedIdentities"
)]
pub use c2pa::identity::claim_aggregation::VerifiedIdentity;
