// Loosely derived from
// https://github.com/spruceid/ssi/blob/ssi/v0.9.0/crates/dids/core/src/document.rs
// and
// https://github.com/spruceid/ssi/blob/ssi/v0.9.0/crates/dids/core/src/document/verification_method.rs
// which were published under an Apache 2.0 license.

// Subsequent modifications are subject to license from Adobe
// as follows:

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

use serde::{Deserialize, Serialize};

use super::did::DidBuf;

/// A [DID document]
///
/// [DID document]: https://www.w3.org/TR/did-core/#dfn-did-documents
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    /// DID subject identifier.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-subject>
    pub id: DidBuf,

    /// Verification relationships.
    ///
    /// Properties that express the relationship between the DID subject and a
    /// verification method using a verification relationship.
    ///
    /// See: <https://www.w3.org/TR/did-core/#verification-relationships>
    #[serde(flatten)]
    pub verification_relationships: VerificationRelationships,

    /// [`verificationMethod`](https://www.w3.org/TR/did-core/#dfn-verificationmethod) property of a
    /// DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_method: Vec<DidVerificationMethod>,

    /// Additional properties of a DID document. Some may be registered in [DID
    /// Specification Registries](https://www.w3.org/TR/did-spec-registries/#did-document-properties).
    #[serde(flatten)]
    pub property_set: BTreeMap<String, serde_json::Value>,
}

impl DidDocument {
    /// Construct a DID document from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerificationRelationships {
    /// [`authentication`](https://www.w3.org/TR/did-core/#dfn-authentication) property of a DID
    /// document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [authentication](https://www.w3.org/TR/did-core/#authentication) purposes (e.g. generating verifiable presentations).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<ValueOrReference>,

    /// [`assertionMethod`](https://www.w3.org/TR/did-core/#dfn-assertionmethod) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [assertion](https://www.w3.org/TR/did-core/#assertion) purposes (e.g. issuing verifiable credentials).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<ValueOrReference>,

    /// [`keyAgreement`](https://www.w3.org/TR/did-core/#dfn-keyagreement) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [key agreement](https://www.w3.org/TR/did-core/#key-agreement) purposes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_agreement: Vec<ValueOrReference>,

    /// [`capabilityInvocation`](https://www.w3.org/TR/did-core/#dfn-capabilityinvocation) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [invoking cryptographic capabilities](https://www.w3.org/TR/did-core/#capability-invocation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_invocation: Vec<ValueOrReference>,

    /// [`capabilityDelegation`](https://www.w3.org/TR/did-core/#dfn-capabilitydelegation) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [delegating cryptographic capabilities](https://www.w3.org/TR/did-core/#capability-delegation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_delegation: Vec<ValueOrReference>,
}

/// Reference to, or value of, a verification method.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum ValueOrReference {
    Reference(DidBuf),
    Value(DidVerificationMethod),
}

impl From<DidVerificationMethod> for ValueOrReference {
    fn from(value: DidVerificationMethod) -> Self {
        Self::Value(value)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DidVerificationMethod {
    /// Verification method identifier.
    pub id: DidBuf,

    /// type [property](https://www.w3.org/TR/did-core/#dfn-did-urls) of a verification method map.
    /// Should be registered in [DID Specification
    /// registries - Verification method types](https://www.w3.org/TR/did-spec-registries/#verification-method-types).
    #[serde(rename = "type")]
    pub type_: String,

    // Note: different than when the DID Document is the subject:
    //    The value of the controller property, which identifies the
    //    controller of the corresponding private key, MUST be a valid DID.
    /// [controller](https://w3c-ccg.github.io/ld-proofs/#controller) property of a verification
    /// method map.
    ///
    /// Not to be confused with the [controller](https://www.w3.org/TR/did-core/#dfn-controller) property of a DID document.
    pub controller: DidBuf,

    /// Verification methods properties.
    #[serde(flatten)]
    pub properties: BTreeMap<String, serde_json::Value>,
}
