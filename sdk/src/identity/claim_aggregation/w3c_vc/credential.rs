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

use chrono::{DateTime, FixedOffset};
use iref::{Iri, IriBuf, UriBuf};
use nonempty_collections::NEVec;
use serde::{Deserialize, Serialize};

use super::serialization::{not_null, one_or_many};

pub const VERIFIABLE_CREDENTIAL_CONTEXT: &Iri =
    static_iref::iri!("https://www.w3.org/ns/credentials/v2");

pub const VERIFIABLE_CREDENTIAL_TYPE: &str = "VerifiableCredential";

/// A lightweight implementation of the W3C Verifiable Credential data model,
/// version 2.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize", deserialize = "T: Deserialize<'de>"))]
pub struct CredentialV2<T>
where
    T: VerifiableCredentialSubtype,
{
    #[serde(rename = "@context")]
    pub contexts: NEVec<IriBuf>,

    #[serde(
        default,
        deserialize_with = "not_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<UriBuf>,

    #[serde(rename = "type")]
    pub types: NEVec<String>,

    #[serde(rename = "credentialSubject")]
    #[serde(with = "one_or_many")]
    pub credential_subjects: NEVec<T>,

    pub issuer: UriBuf,

    #[serde(rename = "validFrom")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<FixedOffset>>,

    #[serde(rename = "validUntil")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<FixedOffset>>,

    #[serde(flatten)]
    pub extra_properties: BTreeMap<String, serde_json::Value>,
}

impl<T> CredentialV2<T>
where
    T: VerifiableCredentialSubtype,
{
    /// Creates a new credential.
    pub fn new(id: Option<UriBuf>, issuer: UriBuf, credential_subjects: NEVec<T>) -> Self {
        let mut extra_contexts: Vec<IriBuf> = credential_subjects
            .first()
            .required_contexts()
            .iter()
            .map(|context_| context_.to_owned().to_owned())
            .collect();

        let mut contexts: NEVec<IriBuf> = NEVec::new(VERIFIABLE_CREDENTIAL_CONTEXT.to_owned());
        contexts.append(&mut extra_contexts);

        let mut extra_types = credential_subjects
            .first()
            .required_types()
            .iter()
            .map(|type_| type_.to_string())
            .collect();

        let mut types: NEVec<String> = NEVec::new(VERIFIABLE_CREDENTIAL_TYPE.to_owned());
        types.append(&mut extra_types);

        Self {
            contexts,
            id,
            types,
            issuer,
            credential_subjects,
            valid_from: None,
            valid_until: None,
            extra_properties: BTreeMap::<String, serde_json::Value>::default(),
        }
    }
}

/// Specifies required context(s) and type(s) for specific VC subtypes.
pub trait VerifiableCredentialSubtype {
    /// Return any number of required "@context" entries for this credential
    /// type.
    fn required_contexts(&self) -> &[&'static Iri];

    /// Return any number of required "type" entries for this credential type.
    fn required_types(&self) -> &[&'static str];
}
