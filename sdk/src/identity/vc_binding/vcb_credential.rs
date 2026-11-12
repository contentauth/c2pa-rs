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

use std::collections::BTreeMap;

use chrono::{DateTime, FixedOffset};
use iref::{Iri, IriBuf, UriBuf};
use non_empty_string::NonEmptyString;
use nonempty_collections::NEVec;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::asn1::rfc3161::TstInfo,
    identity::{
        claim_aggregation::w3c_vc::credential::{CredentialV2, VerifiableCredentialSubtype},
        identity_assertion::signature_verifier::ToCredentialSummary,
        SignerPayload,
    },
};

/// The `@context` entry that the outermost credential of a verifiable
/// credential binding must contain.
pub const VC_BINDING_CONTEXT_IRI: &Iri =
    static_iref::iri!("https://cawg.io/identity/1.2/vcb/context/");

/// The `type` entry of a verifiable credential that carries a
/// `C2PAAssetBinding` `termsOfUse`.
pub const C2PA_BINDING_CREDENTIAL_TYPE: &str = "C2PABindingCredential";

/// The `type` entry of a verifiable credential whose credential subjects are
/// CAWG verified identities.
pub const CAWG_VERIFIED_IDENTITIES_TYPE: &str = "CAWGVerifiedIdentities";

/// A verifiable credential used as the outermost credential of a verifiable
/// credential binding (W3C VC data model 2.0).
pub type VcbVerifiableCredential = CredentialV2<VcbCredentialSubject>;

/// One `credentialSubject` entry of a verifiable credential binding.
///
/// Any properties are allowed. When the credential has type
/// `CAWGVerifiedIdentities`, each subject must also be a valid
/// [`VcbVerifiedIdentity`].
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct VcbCredentialSubject {
    /// The subject's identifier, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// All other properties of the subject.
    #[serde(flatten)]
    pub properties: BTreeMap<String, serde_json::Value>,
}

impl VerifiableCredentialSubtype for VcbCredentialSubject {
    fn required_contexts(&self) -> &[&'static Iri] {
        &[VC_BINDING_CONTEXT_IRI]
    }

    fn required_types(&self) -> &[&'static str] {
        &[C2PA_BINDING_CREDENTIAL_TYPE]
    }
}

/// A verified identity carried as a `credentialSubject` entry of a
/// `CAWGVerifiedIdentities` credential.
///
/// It serializes the same way as the identity claims aggregation
/// [`VerifiedIdentity`](crate::identity::claim_aggregation::VerifiedIdentity),
/// but follows the verifiable credential binding rules: `provider.id` is
/// optional and `method` may be present.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VcbVerifiedIdentity {
    /// The type of verification the identity provider performed, e.g.
    /// `cawg.social_media`.
    #[serde(rename = "type")]
    pub type_: NonEmptyString,

    /// The named actor's name as understood by the identity provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<NonEmptyString>,

    /// The named actor's user name as assigned by the identity provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<NonEmptyString>,

    /// The named actor's cryptographic address as assigned by the identity
    /// provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<NonEmptyString>,

    /// The named actor's primary point of contact at the identity provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<UriBuf>,

    /// How the identity assertion generator contacted the identity provider,
    /// e.g. `cawg.federated_login`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<NonEmptyString>,

    /// When the relationship with the identity provider was verified.
    #[serde(rename = "verifiedAt")]
    pub verified_at: DateTime<FixedOffset>,

    /// The identity provider.
    pub provider: VcbIdentityProvider,
}

/// The identity provider of a [`VcbVerifiedIdentity`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VcbIdentityProvider {
    /// A URI with information about the identity provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    /// The identity provider's user-visible name.
    pub name: NonEmptyString,
}

impl VcbVerifiedIdentity {
    /// Checks the type-specific requirements of “Verified identity type”: a
    /// `cawg.document_verification` identity needs `name`, `cawg.social_media`
    /// needs `username`, `cawg.crypto_wallet` needs `address` and
    /// `cawg.web_site` needs `uri`.
    pub(crate) fn check_type_requirements(&self) -> Result<(), String> {
        let (field, present) = match self.type_.as_str() {
            "cawg.document_verification" => ("name", self.name.is_some()),
            "cawg.social_media" => ("username", self.username.is_some()),
            "cawg.crypto_wallet" => ("address", self.address.is_some()),
            "cawg.web_site" => ("uri", self.uri.is_some()),
            _ => return Ok(()),
        };

        if present {
            Ok(())
        } else {
            Err(format!("{} identity has no {field}", self.type_))
        }
    }
}

/// The result of validating a verifiable credential binding.
#[derive(Clone, Debug)]
pub struct VcbCredential {
    /// The outermost verifiable credential.
    pub credential: VcbVerifiableCredential,

    /// The verified identities, when the credential has type
    /// `CAWGVerifiedIdentities` and its subjects are valid.
    pub verified_identities: Vec<VcbVerifiedIdentity>,

    /// The `signer_payload` that the credential is bound to.
    pub signer_payload: SignerPayload,

    /// The RFC 3161 time stamp on the `COSE_Sign1`, if it was valid.
    pub time_stamp: Option<TstInfo>,
}

impl ToCredentialSummary for VcbCredential {
    type CredentialSummary = VcbCredentialSummary;

    fn to_summary(&self) -> Self::CredentialSummary {
        let c = &self.credential;
        VcbCredentialSummary {
            contexts: c.contexts.clone(),
            id: c.id.clone(),
            types: c.types.clone(),
            issuer: c.issuer.clone(),
            valid_from: c.valid_from,
            valid_until: c.valid_until,
            credential_subjects: c.credential_subjects.clone(),
            verified_identities: self.verified_identities.clone(),
            signer_payload: self.signer_payload.clone(),
            extra_properties: c.extra_properties.clone(),
        }
    }
}

/// The JSON summary of a [`VcbCredential`]: the credential itself, plus the
/// verified identities and `signer_payload` it was checked against.
#[derive(Serialize)]
pub struct VcbCredentialSummary {
    #[serde(rename = "@context")]
    contexts: NEVec<IriBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<UriBuf>,

    #[serde(rename = "type")]
    types: NEVec<String>,

    issuer: UriBuf,

    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    valid_from: Option<DateTime<FixedOffset>>,

    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    valid_until: Option<DateTime<FixedOffset>>,

    #[serde(rename = "credentialSubject")]
    credential_subjects: NEVec<VcbCredentialSubject>,

    #[serde(rename = "verifiedIdentities", skip_serializing_if = "Vec::is_empty")]
    verified_identities: Vec<VcbVerifiedIdentity>,

    signer_payload: SignerPayload,

    #[serde(flatten)]
    extra_properties: BTreeMap<String, serde_json::Value>,
}
