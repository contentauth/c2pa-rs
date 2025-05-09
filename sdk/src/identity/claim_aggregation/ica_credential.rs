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

use std::collections::BTreeMap;

use c2pa_crypto::asn1::rfc3161::TstInfo;
use chrono::{DateTime, FixedOffset};
use iref::{Iri, IriBuf, UriBuf};
use non_empty_string::NonEmptyString;
use nonempty_collections::NEVec;
use serde::{Deserialize, Serialize};

use crate::identity::{
    claim_aggregation::w3c_vc::credential::{CredentialV2, VerifiableCredentialSubtype},
    identity_assertion::signature_verifier::ToCredentialSummary,
    SignerPayload,
};

/// TO DO: Doc -- looks like CredentialV2 for our specific use
/// case.
pub type IcaCredential = CredentialV2<IdentityClaimsAggregationVc>;

impl ToCredentialSummary for IcaCredential {
    type CredentialSummary = IcaCredentialSummary;

    fn to_summary(&self) -> Self::CredentialSummary {
        IcaCredentialSummary::from_credential(self)
    }
}

/// Identity claims aggregation context IRI.
pub const IDENTITY_CLAIMS_AGGREGATION_CONTEXT_IRI: &Iri =
    static_iref::iri!("https://cawg.io/identity/1.1/ica/context/");

/// Identity claims aggregation credential type name.
pub const IDENTITY_CLAIMS_AGGREGATION_CREDENTIAL_TYPE: &str = "IdentityClaimsAggregationCredential";

/// An **identity claims aggregation** is a [W3C verifiable credential] that
/// binds one or more identity claim attestations regarding the _named actor_ to
/// the _C2PA asset_ in which the **identity assertion** appears.
///
/// [W3C verifiable credential]: https://www.w3.org/TR/vc-data-model-2.0/
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IdentityClaimsAggregationVc {
    /// ## Verified identities
    ///
    /// The `verifiedIdentities` property MUST be present and MUST be an array.
    /// Every item in the array MUST contain information about the _named actor_
    /// as verified by the _identity assertion generator_ or a service contacted
    /// by the _identity assertion generator._
    #[serde(rename = "verifiedIdentities")]
    pub verified_identities: NEVec<VerifiedIdentity>,

    /// ## Binding to C2PA asset
    ///
    /// The `credentialSubject` field MUST contain a `c2paAsset` entry, which
    /// MUST be the JSON serialization of the `signer_payload` data structure
    /// presented for signature with the following adaptations:
    /// * All CBOR bytestring values in `signer_payload` data structure (for example, `hash` entries in the `hashlink` data structure) MUST be converted to the corresponding base 64 encoding as specified in [Section 4, “Base 64 Encoding,”](https://datatracker.ietf.org/doc/html/rfc4648#section-4) of RFC 4648. The base 64 encoding MUST NOT use the URL-safe variation of base 64. The encoding MUST NOT include line feeds or additional annotations not directly required by the core base 64 specification.
    /// * The JSON encoding MUST use the field names exactly as specified in [Section 5.1, “Overview”](https://creator-assertions.github.io/identity/1.1-draft/#_overview).
    #[serde(rename = "c2paAsset")]
    pub c2pa_asset: SignerPayload,

    /// Time stamp info, if an RFC 3161 time stamp was used with this
    /// credential. This is technically not part of the credential. If found
    /// when reading a credential, this is added in a post-processing step.
    #[serde(skip)]
    pub time_stamp: Option<TstInfo>,
}

impl VerifiableCredentialSubtype for IdentityClaimsAggregationVc {
    fn required_contexts(&self) -> &[&'static Iri] {
        &[IDENTITY_CLAIMS_AGGREGATION_CONTEXT_IRI]
    }

    fn required_types(&self) -> &[&'static str] {
        &[IDENTITY_CLAIMS_AGGREGATION_CREDENTIAL_TYPE]
    }
}

/// Every item in the `verifiedIdentities` array MUST contain information about
/// the _named actor_ as verified by the _identity assertion generator_ or a
/// service contacted by the _identity assertion generator._
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedIdentity {
    /// ## Verified identity type
    ///
    /// The `verifiedIdentities[?].type` property MUST be present and MUST be a
    /// non-empty string that defines the type of verification that was
    /// performed by the identity provider.
    #[serde(rename = "type")]
    pub type_: NonEmptyString,

    /// ## Display name
    ///
    /// The `verifiedIdentities[?].name` property MAY be present. If present, it
    /// MUST NOT be empty and must be a string defining the _named actor’s_ name
    /// as understood by the identity provider.
    ///
    /// If the `type` of this verified identity is `cawg.document_verification`,
    /// the `verifiedIdentities[?].name` property MUST be present and MUST
    /// exactly match the name found on the identity documents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<NonEmptyString>,

    /// ## User name
    ///
    /// The `verifiedIdentities[?].username` property MAY be present. If
    /// present, it MUST be a non-empty text string representing the _named
    /// actor’s_ user name as assigned by the identity provider.
    ///
    /// If the type of this verified identity is `cawg.social_media`, the
    /// `verifiedIdentities[?].username` property MUST be present and MUST be
    /// the unique alphanumeric string that can be used to identity the _named
    /// actor_ within this service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<NonEmptyString>,

    /// ## Address
    ///
    /// The `verifiedIdentities[?].address` property MAY be present. If present,
    /// it MUST be a non-empty text string representing the _named actor’s_
    /// cryptographic address as assigned by the identity provider.
    ///
    /// If the type of this verified identity is `cawg.crypto_wallet`, the
    /// `verifiedIdentities[?].address` property MUST be present and MUST be the
    /// unique alphanumeric string that can be used to identity the _named
    /// actor_ within this service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<NonEmptyString>,

    /// ## URI
    ///
    /// The `verifiedIdentities[?].uri` property MAY be present. If present, it
    /// must be a valid URI which is the primary point of contact for the _named
    /// actor_ as assigned by the _identity provider._
    ///
    /// If the type of this verified identity is `cawg.social_media`, it is
    /// RECOMMENDED that the `verifiedIdentities[?].uri` be the primary web URI
    /// for the _named actor’s_ social media account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<UriBuf>,

    /// ## Identity verification date
    ///
    /// The `verifiedIdentities[?].verifiedAt` MUST be present and MUST be a
    /// valid date-time as specified by RFC 3339. It represents the date and
    /// time when the relationship between the _named actor_ and the _identity
    /// provider_ was verified by the _identity assertion generator._
    #[serde(rename = "verifiedAt")]
    pub verified_at: DateTime<FixedOffset>,

    /// ## Identity provider details
    ///
    /// The `verifiedIdentities[?].provider` property MUST be an object and MUST
    /// be present. It contains details about the _identity provider_ and the
    /// identity verification process.
    pub provider: IdentityProvider,
}

/// ## Identity provider details
///
/// The `verifiedIdentities[?].provider` property MUST be an object and MUST be
/// present. It contains details about the _identity provider_ and the identity
/// verification process. This specification mentions at least three properties
/// that MAY be used to represent the _named actor’s_ verification details:
/// `id`, `name`, and `proof`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityProvider {
    /// ## Identity provider ID
    ///
    /// The `verifiedIdentities[?].provider.id` MUST be present and MUST be a
    /// valid URI that, when dereferenced, MUST result in a proof of
    /// authenticity of the _identity provider._ This proof of authenticity of
    /// the identity provider MUST NOT be confused with the proof of
    /// verification of the _named actor._
    pub id: UriBuf,

    /// ## Identity provider name
    ///
    /// The `verifiedIdentities[?].provider.name` MUST be present and MUST be a
    /// non-empty string. ///The `verifiedIdentities[?].provider.name` property
    /// is the user-visible name of the _identity provider._
    pub name: NonEmptyString,
}

#[doc(hidden)]
#[derive(Serialize)]
pub struct IcaCredentialSummary {
    #[serde(rename = "@context")]
    contexts: NEVec<IriBuf>,

    #[serde(
        default,
        deserialize_with = "not_null",
        skip_serializing_if = "Option::is_none"
    )]
    id: Option<UriBuf>,

    #[serde(rename = "type")]
    types: NEVec<String>,

    issuer: UriBuf,

    #[serde(rename = "validFrom")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    valid_from: Option<DateTime<FixedOffset>>,

    #[serde(rename = "validUntil")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    valid_until: Option<DateTime<FixedOffset>>,

    #[serde(rename = "verifiedIdentities")]
    verified_identities: NEVec<VerifiedIdentity>,

    #[serde(flatten)]
    extra_properties: BTreeMap<String, serde_json::Value>,
}

impl IcaCredentialSummary {
    fn from_credential(ica: &IcaCredential) -> Self {
        let subject = ica.credential_subjects.first();

        Self {
            contexts: ica.contexts.clone(),
            id: ica.id.clone(),
            issuer: ica.issuer.clone(),
            types: ica.types.clone(),
            valid_from: ica.valid_from,
            valid_until: ica.valid_until,
            verified_identities: subject.verified_identities.clone(),
            extra_properties: ica.extra_properties.clone(),
        }
    }
}
