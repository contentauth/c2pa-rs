// Copyright 2022 Adobe. All rights reserved.
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

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};

use super::AssetType;
use crate::{
    assertion::{Assertion, AssertionBase, AssertionDecodeError, AssertionDecodeErrorCause},
    assertions::{labels, Metadata, ReviewRating},
    cbor_types::map_cbor_to_type,
    error::Result,
    hashed_uri::HashedUri,
    validation_results::ValidationResults,
    validation_status::ValidationStatus,
    Error,
};

const ASSERTION_CREATION_VERSION: usize = 3;

/// The relationship of the ingredient to the current asset.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub enum Relationship {
    /// The current asset is derived from this ingredient.
    #[serde(rename = "parentOf")]
    ParentOf,
    /// The current asset is a part of this ingredient.
    #[serde(rename = "componentOf")]
    #[default]
    ComponentOf,
    /// The ingredient was used as an input to a computational process to create or modify the asset.
    #[serde(rename = "inputTo")]
    InputTo,
}

/// An ingredient assertion
#[derive(Debug, Default, PartialEq)]
pub struct Ingredient {
    pub title: Option<String>,
    pub format: Option<String>,
    pub document_id: Option<String>,
    pub instance_id: Option<String>,
    pub c2pa_manifest: Option<HashedUri>,
    pub validation_status: Option<Vec<ValidationStatus>>,
    pub relationship: Relationship,
    pub thumbnail: Option<HashedUri>,
    pub metadata: Option<Metadata>,
    pub data: Option<HashedUri>,
    pub description: Option<String>,
    pub informational_uri: Option<String>,
    pub data_types: Option<Vec<AssetType>>,

    pub validation_results: Option<ValidationResults>,
    pub active_manifest: Option<HashedUri>,
    pub claim_signature: Option<HashedUri>,

    pub version: usize,
}

impl Serialize for Ingredient {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.version {
            1 => self.serialize_v1(serializer),
            2 => self.serialize_v2(serializer),
            3 => self.serialize_v3(serializer),
            v => Err(serde::ser::Error::custom(format!(
                "Unsupported ingredient version: {v}"
            ))),
        }
    }
}

impl Ingredient {
    /// Label prefix for an ingredient assertion.
    ///
    /// See <https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#ingredient_assertion>.
    pub const LABEL: &'static str = labels::INGREDIENT;

    pub fn new(title: &str, format: &str, instance_id: &str, document_id: Option<&str>) -> Self {
        Self {
            title: Some(title.to_owned()),
            format: Some(format.to_owned()),
            document_id: document_id.map(|id| id.to_owned()),
            instance_id: Some(instance_id.to_owned()),
            version: 1,
            ..Default::default()
        }
    }

    pub fn new_v2<S1, S2>(title: S1, format: S2) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Self {
            title: Some(title.into()),
            format: Some(format.into()),
            version: 2,
            ..Default::default()
        }
    }

    pub fn new_v3(relationship: Relationship) -> Self {
        Self {
            relationship,
            version: 3,
            ..Default::default()
        }
    }

    pub fn c2pa_manifest(&self) -> Option<HashedUri> {
        // get correct hashed URI
        match &self.active_manifest {
            Some(m) => Some(m.clone()), // > v2 ingredient assertion
            None => self.c2pa_manifest.clone(),
        }
    }

    pub fn signature(&self) -> Option<HashedUri> {
        self.claim_signature.clone()
    }

    fn is_v1_compatible(&self) -> bool {
        self.title.is_some()
            && self.format.is_some()
            && self.instance_id.is_some()
            && self.data.is_none()   // V2 exclusive params
            && self.data_types.is_none()
            && self.description.is_none()
            && self.informational_uri.is_none()
            && self.validation_results.is_none() // V3 exclusive params
            && self.active_manifest.is_none()
            && self.claim_signature.is_none()
    }

    /// determines if an ingredient is a v2 ingredient
    fn is_v2_compatible(&self) -> bool {
        self.title.is_some()
        && self.format.is_some()
        && self.validation_results.is_none() // V3 exclusive params
        && self.active_manifest.is_none()
        && self.claim_signature.is_none()
    }

    fn is_v3_compatible(&self) -> bool {
        self.document_id.is_none()    // V3 restricted fields
            && self.validation_status.is_none()
            && self.c2pa_manifest.is_none()
            && self.validation_results.is_some()
            && self.active_manifest.is_some()
            && self.claim_signature.is_some()
    }

    pub fn set_title<S: Into<String>>(mut self, title: S) -> Self {
        self.title = Some(title.into());
        self
    }

    pub fn set_format<S: Into<String>>(mut self, format: S) -> Self {
        self.format = Some(format.into());
        self
    }

    pub fn set_parent(mut self) -> Self {
        self.relationship = Relationship::ParentOf;
        self
    }

    pub fn set_c2pa_manifest_from_hashed_uri(mut self, provenance: Option<HashedUri>) -> Self {
        self.c2pa_manifest = provenance;
        self
    }

    pub fn set_active_manifests_and_signature_from_hashed_uri(
        mut self,
        provenance: Option<HashedUri>,
        signature: Option<HashedUri>,
    ) -> Self {
        self.active_manifest = provenance;
        self.claim_signature = signature;
        self
    }

    pub fn set_validation_results(mut self, validation_results: Option<ValidationResults>) -> Self {
        self.validation_results = validation_results;
        self
    }

    pub fn set_thumbnail_hash_link(mut self, thumbnail: Option<&str>) -> Self {
        self.thumbnail =
            thumbnail.map(|thumb| HashedUri::new(thumb.to_owned(), None, "Hash".as_bytes()));
        self
    }

    pub fn set_thumbnail(mut self, hashed_uri: Option<&HashedUri>) -> Self {
        self.thumbnail = hashed_uri.map(|h| h.to_owned());
        self
    }

    pub fn add_review(mut self, review: ReviewRating) -> Self {
        let metadata = self.metadata.unwrap_or_default();
        self.metadata = Some(metadata.add_review(review));
        self
    }

    pub fn add_reviews(mut self, reviews: Option<Vec<ReviewRating>>) -> Self {
        if let Some(reviews) = reviews {
            let metadata = Metadata::new().set_reviews(reviews);
            self.metadata = Some(metadata);
        };
        self
    }

    pub fn add_validation_status(mut self, status: ValidationStatus) {
        match &mut self.validation_status {
            None => self.validation_status = Some(vec![status]),
            Some(validation_status) => validation_status.push(status),
        }
    }

    fn serialize_v1<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        /* Ingredient V1 fields
            "dc:title": tstr, ; name of the ingredient
            "dc:format": format-string, ; Media Type of the ingredient
            ? "documentID": tstr, ; value of the ingredient's `xmpMM:DocumentID`
            "instanceID": tstr, ; unique identifier, such as the value of the ingredient's `xmpMM:InstanceID`
            "relationship": $relation-choice, ; The relationship of this ingredient to the asset it is an ingredient of.
            ? "c2pa_manifest": $hashed-uri-map, ; hashed_uri reference to the C2PA Manifest of the ingredient
            ? "thumbnail": $hashed-uri-map, ; hashed_uri reference to an ingredient thumbnail
            ? "validationStatus": [1* $status-map] ; validation status of the ingredient
            ? "metadata": $assertion-metadata-map ; additional information about the assertion
        */

        let mut ingredient_map_len = 4;
        if self.document_id.is_some() {
            ingredient_map_len += 1
        }
        if self.c2pa_manifest.is_some() {
            ingredient_map_len += 1
        }
        if self.thumbnail.is_some() {
            ingredient_map_len += 1
        }
        if self.validation_status.is_some() {
            ingredient_map_len += 1
        }
        if self.metadata.is_some() {
            ingredient_map_len += 1
        }

        let mut ingredient_map = serializer.serialize_struct("Ingredient", ingredient_map_len)?;

        // serialize mandatory fields
        ingredient_map.serialize_field("dc:title", &self.title)?;
        ingredient_map.serialize_field("dc:format", &self.format)?;
        if let Some(instance_id) = &self.instance_id {
            ingredient_map.serialize_field("instanceID", instance_id)?;
        } else {
            return Err(serde::ser::Error::custom("Ingredient_v1 miss instanceId"));
        }
        ingredient_map.serialize_field("relationship", &self.relationship)?;

        // serialize optional fields
        if let Some(doc_id) = &self.document_id {
            ingredient_map.serialize_field("documentID", doc_id)?;
        }
        if let Some(cm) = &self.c2pa_manifest {
            ingredient_map.serialize_field("c2pa_manifest", cm)?;
        }
        if let Some(thumbnail) = &self.thumbnail {
            ingredient_map.serialize_field("thumbnail", thumbnail)?;
        }
        if let Some(vs) = &self.validation_status {
            ingredient_map.serialize_field("validationStatus", vs)?;
        }
        if let Some(md) = &self.metadata {
            ingredient_map.serialize_field("metadata", md)?;
        }

        ingredient_map.end()
    }

    fn serialize_v2<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        /* Ingredient V2 fields
            "dc:title": tstr, ; name of the ingredient
            "dc:format": format-string, ; Media Type of the ingredient
            "relationship": $relation-choice, ; The relationship of this ingredient to the asset it is an ingredient of.
            ? "documentID": tstr, ; value of the ingredient's `xmpMM:DocumentID`
            ? "instanceID": tstr, ; unique identifier, such as the value of the ingredient's `xmpMM:InstanceID`
            ? "data" : $hashed-uri-map / $hashed-ext-uri-map, ; hashed_uri reference to a data box or a hashed_ext_uri to external data
            ? "data_types": [1* $asset-type-map],  ; additional information about the data's type to the ingredient V2 structure.
            ? "c2pa_manifest": $hashed-uri-map, ; hashed_uri reference to the C2PA Manifest of the ingredient
            ? "thumbnail": $hashed-uri-map, ; hashed_uri reference to a thumbnail in a data box
            ? "validationStatus": [1* $status-map] ; validation status of the ingredient
            ? "description": tstr .size (1..max-tstr-length) ; Additional description of the ingredient
            ? "informational_URI": tstr .size (1..max-tstr-length) ; URI to an informational page about the ingredient or its data
            ? "metadata": $assertion-metadata-map ; additional information about the assertion
        */

        let mut ingredient_map_len = 3;
        if self.document_id.is_some() {
            ingredient_map_len += 1
        }
        if self.instance_id.is_some() {
            ingredient_map_len += 1
        }
        if self.data.is_some() {
            ingredient_map_len += 1
        }
        if self.data_types.is_some() {
            ingredient_map_len += 1
        }
        if self.c2pa_manifest.is_some() {
            ingredient_map_len += 1
        }
        if self.thumbnail.is_some() {
            ingredient_map_len += 1
        }
        if self.validation_status.is_some() {
            ingredient_map_len += 1
        }
        if self.description.is_some() {
            ingredient_map_len += 1
        }
        if self.informational_uri.is_some() {
            ingredient_map_len += 1
        }
        if self.metadata.is_some() {
            ingredient_map_len += 1
        }

        let mut ingredient_map = serializer.serialize_struct("Ingredient", ingredient_map_len)?;

        // serialize mandatory fields
        ingredient_map.serialize_field("dc:title", &self.title)?;
        ingredient_map.serialize_field("dc:format", &self.format)?;
        ingredient_map.serialize_field("relationship", &self.relationship)?;

        // serialize optional fields
        if let Some(doc_id) = &self.document_id {
            ingredient_map.serialize_field("documentID", doc_id)?;
        }
        if let Some(instance_id) = &self.instance_id {
            ingredient_map.serialize_field("instanceID", instance_id)?;
        }
        if let Some(data) = &self.data {
            ingredient_map.serialize_field("data", data)?;
        }
        if let Some(data_types) = &self.data_types {
            ingredient_map.serialize_field("data_types", data_types)?;
        }
        if let Some(cm) = &self.c2pa_manifest {
            ingredient_map.serialize_field("c2pa_manifest", cm)?;
        }
        if let Some(thumbnail) = &self.thumbnail {
            ingredient_map.serialize_field("thumbnail", thumbnail)?;
        }
        if let Some(vs) = &self.validation_status {
            ingredient_map.serialize_field("validationStatus", vs)?;
        }
        if let Some(desc) = &self.description {
            ingredient_map.serialize_field("description", desc)?;
        }
        if let Some(info) = &self.informational_uri {
            ingredient_map.serialize_field("informational_URI", info)?;
        }
        if let Some(md) = &self.metadata {
            ingredient_map.serialize_field("metadata", md)?;
        }

        ingredient_map.end()
    }

    fn serialize_v3<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        /* Ingredient V3 fields
            ? "dc:title": tstr, ; name of the ingredient
            ? "dc:format": format-string, ; Media Type of the ingredient
            "relationship": $relation-choice, ; The relationship of this ingredient to the asset it is an ingredient of.
            ? "validationResults": $validation-results-map, ; Results from the claim generator performing full validation on the ingredient asset
            ? "instanceID": tstr, ; unique identifier such as the value of the ingredient's `xmpMM:InstanceID`
            ? "data" : $hashed-uri-map / $hashed-ext-uri-map, ; hashed_uri reference to a data box or a hashed_ext_uri to external data
            ? "dataTypes": [1* $asset-type-map],  ; additional information about the data's type to the ingredient V3 structure
            ? "activeManifest": $hashed-uri-map, ; hashed_uri to the box corresponding to the active manifest of the ingredient
            ? "claimSignature": $hashed-uri-map, ; hashed_uri to the Claim Signature box in the C2PA Manifest of the ingredient
            ? "thumbnail": $hashed-uri-map, ; hashed_uri reference to a thumbnail in a data box
            ? "description": tstr .size (1..max-tstr-length), ; Additional description of the ingredient
            ? "informationalURI": tstr .size (1..max-tstr-length), ; URI to an informational page about the ingredient or its data
            ? "metadata": $assertion-metadata-map ; additional information about the assertion
        */

        // check rules
        if self.active_manifest.is_none() && self.validation_results.is_some()
            || self.active_manifest.is_some() && self.validation_results.is_none()
        {
            return Err(serde::ser::Error::custom(
                "Ingredient has incompatible fields",
            ));
        }

        let mut ingredient_map_len = 1;
        if self.title.is_some() {
            ingredient_map_len += 1
        }
        if self.format.is_some() {
            ingredient_map_len += 1
        }
        if self.validation_results.is_some() {
            ingredient_map_len += 1
        }
        if self.instance_id.is_some() {
            ingredient_map_len += 1
        }
        if self.data.is_some() {
            ingredient_map_len += 1
        }
        if self.data_types.is_some() {
            ingredient_map_len += 1
        }
        if self.active_manifest.is_some() {
            ingredient_map_len += 1
        }
        if self.claim_signature.is_some() {
            ingredient_map_len += 1
        }
        if self.thumbnail.is_some() {
            ingredient_map_len += 1
        }
        if self.description.is_some() {
            ingredient_map_len += 1
        }
        if self.informational_uri.is_some() {
            ingredient_map_len += 1
        }
        if self.metadata.is_some() {
            ingredient_map_len += 1
        }

        let mut ingredient_map = serializer.serialize_struct("Ingredient", ingredient_map_len)?;

        // serialize mandatory fields
        ingredient_map.serialize_field("relationship", &self.relationship)?;

        // serialize optional fields
        if let Some(title) = &self.title {
            ingredient_map.serialize_field("dc:title", title)?;
        }
        if let Some(format) = &self.format {
            ingredient_map.serialize_field("dc:format", format)?;
        }
        if let Some(vr) = &self.validation_results {
            ingredient_map.serialize_field("validationResults", vr)?;
        }
        if let Some(instance_id) = &self.instance_id {
            ingredient_map.serialize_field("instanceID", instance_id)?;
        }
        if let Some(data) = &self.data {
            ingredient_map.serialize_field("data", data)?;
        }
        if let Some(data_types) = &self.data_types {
            ingredient_map.serialize_field("dataTypes", data_types)?;
        }
        if let Some(am) = &self.active_manifest {
            ingredient_map.serialize_field("activeManifest", am)?;
        }
        if let Some(cs) = &self.claim_signature {
            ingredient_map.serialize_field("claimSignature", cs)?;
        }
        if let Some(thumbnail) = &self.thumbnail {
            ingredient_map.serialize_field("thumbnail", thumbnail)?;
        }
        if let Some(desc) = &self.description {
            ingredient_map.serialize_field("description", desc)?;
        }
        if let Some(info) = &self.informational_uri {
            ingredient_map.serialize_field("informationalURI", info)?;
        }
        if let Some(md) = &self.metadata {
            ingredient_map.serialize_field("metadata", md)?;
        }

        ingredient_map.end()
    }
}

fn to_decoding_err(label: &str, version: usize, field: &str) -> Error {
    Error::AssertionDecoding(AssertionDecodeError::from_err(
        label.to_owned(),
        Some(version),
        "application/cbor".to_owned(),
        AssertionDecodeErrorCause::FieldDecoding {
            expected: field.to_owned(),
        },
    ))
}

impl AssertionBase for Ingredient {
    const LABEL: &'static str = Self::LABEL;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    /// if we require v2 fields then use V2
    fn version(&self) -> Option<usize> {
        if self.version > 1 {
            Some(self.version)
        } else {
            None
        }
    }

    fn to_assertion(&self) -> Result<Assertion> {
        let data = crate::assertion::AssertionData::Cbor(
            serde_cbor::to_vec(self).map_err(|err| Error::AssertionEncoding(err.to_string()))?,
        );
        Ok(Assertion::new(self.label(), self.version(), data))
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        let ingredient_value: serde_cbor::Value = serde_cbor::from_slice(assertion.data())
            .map_err(|e| {
                Error::AssertionDecoding(AssertionDecodeError::from_err(
                    assertion.label(),
                    Some(assertion.get_ver()),
                    "application/cbor".to_owned(),
                    e,
                ))
            })?;

        let version = assertion.get_ver();

        static V1_FIELDS: [&str; 9] = [
            "dc:title",
            "dc:format",
            "documentID",
            "instanceID",
            "relationship",
            "c2pa_manifest",
            "thumbnail",
            "validationStatus",
            "metadata",
        ];

        static V2_FIELDS: [&str; 13] = [
            "dc:title",
            "dc:format",
            "relationship",
            "documentID",
            "instanceID",
            "data",
            "data_types",
            "c2pa_manifest",
            "thumbnail",
            "validationStatus",
            "description",
            "informational_URI",
            "metadata",
        ];

        static V3_FIELDS: [&str; 13] = [
            "dc:title",
            "dc:format",
            "relationship",
            "validationResults",
            "instanceID",
            "data",
            "dataTypes",
            "activeManifest",
            "claimSignature",
            "thumbnail",
            "description",
            "informationalURI",
            "metadata",
        ];

        // make sure decoded matches expected fields
        let decoded = match version {
            1 => {
                // make sure only V1 fields are present
                if let serde_cbor::Value::Map(m) = &ingredient_value {
                    if !m.keys().all(|v| match v {
                        serde_cbor::Value::Text(t) => V1_FIELDS.contains(&t.as_str()),
                        _ => false,
                    }) {
                        return Err(to_decoding_err(
                            &assertion.label(),
                            assertion.get_ver(),
                            "invalid field found in Ingredient assertion",
                        ));
                    }
                } else {
                    return Err(to_decoding_err(
                        &assertion.label(),
                        assertion.get_ver(),
                        "invalid field found in Ingredient assertion",
                    ));
                }

                // add mandatory field
                let title: String = map_cbor_to_type("dc:title", &ingredient_value).ok_or(
                    to_decoding_err(&assertion.label(), assertion.get_ver(), "dc:title"),
                )?;
                let format: String = map_cbor_to_type("dc:format", &ingredient_value).ok_or(
                    to_decoding_err(&assertion.label(), assertion.get_ver(), "dc:format"),
                )?;
                let instance_id: String = map_cbor_to_type("instanceID", &ingredient_value).ok_or(
                    to_decoding_err(&assertion.label(), assertion.get_ver(), "instanceID"),
                )?;
                let relationship: Relationship =
                    map_cbor_to_type("relationship", &ingredient_value).ok_or(to_decoding_err(
                        &assertion.label(),
                        assertion.get_ver(),
                        "relationship",
                    ))?;

                // add optional fields
                let document_id: Option<String> = map_cbor_to_type("documentID", &ingredient_value);
                let c2pa_manifest: Option<HashedUri> =
                    map_cbor_to_type("c2pa_manifest", &ingredient_value);
                let thumbnail: Option<HashedUri> = map_cbor_to_type("thumbnail", &ingredient_value);
                let validation_status: Option<Vec<ValidationStatus>> =
                    map_cbor_to_type("validationStatus", &ingredient_value);
                let metadata: Option<Metadata> = map_cbor_to_type("metadata", &ingredient_value);

                Ingredient {
                    title: Some(title),
                    format: Some(format),
                    document_id,
                    instance_id: Some(instance_id),
                    c2pa_manifest,
                    validation_status,
                    relationship,
                    thumbnail,
                    metadata,
                    version,
                    ..Default::default()
                }
            }
            2 => {
                // make sure only V2 fields are present
                if let serde_cbor::Value::Map(m) = &ingredient_value {
                    if !m.keys().all(|v| match v {
                        serde_cbor::Value::Text(t) => V2_FIELDS.contains(&t.as_str()),
                        _ => false,
                    }) {
                        return Err(to_decoding_err(
                            &assertion.label(),
                            assertion.get_ver(),
                            "invalid field found in Ingredient assertion",
                        ));
                    }
                } else {
                    return Err(to_decoding_err(
                        &assertion.label(),
                        assertion.get_ver(),
                        "invalid field found in Ingredient assertion",
                    ));
                }

                // add mandatory field
                let title: String = map_cbor_to_type("dc:title", &ingredient_value).ok_or(
                    to_decoding_err(&assertion.label(), assertion.get_ver(), "dc:title"),
                )?;
                let format: String = map_cbor_to_type("dc:format", &ingredient_value).ok_or(
                    to_decoding_err(&assertion.label(), assertion.get_ver(), "dc:format"),
                )?;
                let relationship: Relationship =
                    map_cbor_to_type("relationship", &ingredient_value).ok_or(to_decoding_err(
                        &assertion.label(),
                        assertion.get_ver(),
                        "relationship",
                    ))?;

                // add optional fields
                let document_id: Option<String> = map_cbor_to_type("documentID", &ingredient_value);
                let instance_id: Option<String> = map_cbor_to_type("instanceID", &ingredient_value);
                let data: Option<HashedUri> = map_cbor_to_type("data", &ingredient_value);
                let data_types: Option<Vec<AssetType>> =
                    map_cbor_to_type("data_types", &ingredient_value);
                let c2pa_manifest: Option<HashedUri> =
                    map_cbor_to_type("c2pa_manifest", &ingredient_value);
                let thumbnail: Option<HashedUri> = map_cbor_to_type("thumbnail", &ingredient_value);
                let validation_status: Option<Vec<ValidationStatus>> =
                    map_cbor_to_type("validationStatus", &ingredient_value);
                let description: Option<String> =
                    map_cbor_to_type("description", &ingredient_value);
                let informational_uri: Option<String> =
                    map_cbor_to_type("informational_URI", &ingredient_value);
                let metadata: Option<Metadata> = map_cbor_to_type("metadata", &ingredient_value);

                Ingredient {
                    title: Some(title),
                    format: Some(format),
                    document_id,
                    instance_id,
                    c2pa_manifest,
                    validation_status,
                    relationship,
                    thumbnail,
                    metadata,
                    data,
                    description,
                    informational_uri,
                    data_types,
                    version,
                    ..Default::default()
                }
            }
            3 => {
                // make sure only V3 fields are present
                if let serde_cbor::Value::Map(m) = &ingredient_value {
                    if !m.keys().all(|v| match v {
                        serde_cbor::Value::Text(t) => V3_FIELDS.contains(&t.as_str()),
                        _ => false,
                    }) {
                        return Err(to_decoding_err(
                            &assertion.label(),
                            assertion.get_ver(),
                            "invalid field found in Ingredient assertion",
                        ));
                    }
                } else {
                    return Err(to_decoding_err(
                        &assertion.label(),
                        assertion.get_ver(),
                        "invalid field found in Ingredient assertion",
                    ));
                }

                // add mandatory field
                let relationship: Relationship =
                    map_cbor_to_type("relationship", &ingredient_value).ok_or(to_decoding_err(
                        &assertion.label(),
                        assertion.get_ver(),
                        "relationship",
                    ))?;

                // add optional fields
                let title: Option<String> = map_cbor_to_type("dc:title", &ingredient_value);
                let format: Option<String> = map_cbor_to_type("dc:format", &ingredient_value);
                let validation_results: Option<ValidationResults> =
                    map_cbor_to_type("validationResults", &ingredient_value);
                let instance_id: Option<String> = map_cbor_to_type("instanceID", &ingredient_value);
                let data: Option<HashedUri> = map_cbor_to_type("data", &ingredient_value);
                let data_types: Option<Vec<AssetType>> =
                    map_cbor_to_type("dataTypes", &ingredient_value);
                let active_manifest: Option<HashedUri> =
                    map_cbor_to_type("activeManifest", &ingredient_value);
                let claim_signature: Option<HashedUri> =
                    map_cbor_to_type("claimSignature", &ingredient_value);
                let thumbnail: Option<HashedUri> = map_cbor_to_type("thumbnail", &ingredient_value);
                let description: Option<String> =
                    map_cbor_to_type("description", &ingredient_value);
                let informational_uri: Option<String> =
                    map_cbor_to_type("informationalURI", &ingredient_value);
                let metadata: Option<Metadata> = map_cbor_to_type("metadata", &ingredient_value);

                Ingredient {
                    title,
                    format,
                    instance_id,
                    validation_results,
                    relationship,
                    thumbnail,
                    metadata,
                    data,
                    description,
                    informational_uri,
                    data_types,
                    active_manifest,
                    claim_signature,
                    version,
                    ..Default::default()
                }
            }
            _ => {
                return Err(Error::VersionCompatibility(
                    "Ingredient version to new".into(),
                ))
            }
        };

        Ok(decoded)
    }
}
#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{
        assertion::AssertionData,
        assertions::AssetTypeEnum,
        validation_results::{IngredientDeltaValidationResult, StatusCodes},
    };

    #[test]
    fn assertion_ingredient() {
        let original = Ingredient::new(
            "image 1.jpg",
            "image/jpeg",
            "xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738d",
            Some("xmp.did:87d51599-286e-43b2-9478-88c79f49c347"),
        )
        .set_thumbnail_hash_link(Some("#c2pa.ingredient.thumbnail.jpeg"));
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/cbor");
        assert_eq!(assertion.label(), Ingredient::LABEL);
        let result = Ingredient::from_assertion(&assertion).expect("from_assertion");
        assert_eq!(original.title, result.title);
        assert_eq!(original.format, result.format);
        assert_eq!(original.document_id, result.document_id);
        assert_eq!(original.instance_id, result.instance_id);
        assert_eq!(original.thumbnail, result.thumbnail);
    }

    #[test]
    fn test_build_assertion() {
        let assertion = Ingredient::new(
            "image 1.jpg",
            "image/jpeg",
            "xmp.did:87d51599-286e-43b2-9478-88c79f49c347",
            Some("xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738d"),
        )
        .set_thumbnail_hash_link(Some("#c2pa.ingredient.thumbnail.jpeg"))
        .to_assertion()
        .unwrap();

        println!("assertion label: {}", assertion.label());

        let j = assertion.data();

        let from_j = Assertion::from_data_cbor(&assertion.label(), j);
        let ad_ref = from_j.decode_data();

        if let AssertionData::Cbor(ref ad_cbor) = ad_ref {
            // compare results
            let orig_d = assertion.decode_data();
            if let AssertionData::Cbor(ref orig_cbor) = orig_d {
                assert_eq!(orig_cbor, ad_cbor);
            } else {
                panic!("Couldn't decode orig_d");
            }
        } else {
            panic!("Couldn't decode ad_ref");
        }
    }

    #[test]
    fn test_binary_round_trip() {
        let assertion = Ingredient::new(
            "image 1.jpg",
            "image/jpeg",
            "xmp.did:87d51599-286e-43b2-9478-88c79f49c347",
            Some("xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738d"),
        )
        //.set_provenance("")
        .set_thumbnail_hash_link(Some("#c2pa.ingredient.thumbnail.jpeg"))
        .to_assertion()
        .unwrap();

        let orig_bytes = assertion.data();

        let assertion_from_binary = Assertion::from_data_cbor(&assertion.label(), orig_bytes);

        println!(
            "Label Match Test {} = {}",
            assertion.label(),
            assertion_from_binary.label()
        );
        assert_eq!(assertion.label(), assertion_from_binary.label());

        // compare the data as bytes
        assert_eq!(orig_bytes, assertion_from_binary.data());
        println!("Decoded binary matches")
    }

    #[test]
    fn test_assertion_with_reviews() {
        let review = ReviewRating::new(
            "a 3rd party plugin was used",
            Some("actions.unknownActionsPerformed".to_string()),
            1,
        );
        let original = Ingredient::new(
            "image 1.jpg",
            "image/jpeg",
            "xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738d",
            Some("xmp.did:87d51599-286e-43b2-9478-88c79f49c347"),
        )
        .add_review(review);

        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/cbor");
        assert_eq!(assertion.label(), Ingredient::LABEL);
        let restored = Ingredient::from_assertion(&assertion).expect("from_assertion");
        assert_eq!(original.title, restored.title);
        assert_eq!(original.format, restored.format);
        assert_eq!(original.document_id, restored.document_id);
        assert_eq!(original.instance_id, restored.instance_id);
        assert_eq!(original.thumbnail, restored.thumbnail);

        assert!(restored.metadata.is_some());
        let metadata = restored.metadata.unwrap();
        let date_time = metadata.date_time().unwrap();
        let date_time_parsed = chrono::DateTime::parse_from_rfc3339(date_time);

        assert!(metadata.reviews().is_some());
        assert!(date_time_parsed.is_ok());

        let reviews = metadata.reviews().unwrap();

        assert_eq!(reviews.len(), 1);
        assert_eq!(
            reviews[0].code.as_ref().unwrap(),
            "actions.unknownActionsPerformed"
        );
        assert_eq!(reviews[0].explanation, "a 3rd party plugin was used");
        assert_eq!(reviews[0].value, 1);
    }

    #[test]
    fn test_serialization() {
        let validation_status = vec![ValidationStatus::new("claimSignature.validated")];

        let active_manifest_codes = StatusCodes::default()
            .add_success_val(ValidationStatus::new("claimSignature.validated").set_url(
                "self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322/c2pa.signature",
            ))
            .add_success_val(ValidationStatus::new("claimSignature.trusted").set_url(
                "self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322/c2pa.signature",
            ))
            .add_informational_val(
                ValidationStatus::new("signingCredential.ocsp.skipped").set_url(
                    "self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322/c2pa.signature",
                ),
            );

        let ingredient_deltas = IngredientDeltaValidationResult::new(
            "self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322/c2pa.assertions/c2pa.ingredient.v3", 
            StatusCodes::default()
                .add_failure_val(ValidationStatus::new("assertion.hashedURI.mismatch")
                    .set_url("self#jumbf=c2pa/urn:c2pa:F095F30E-6CD5-4BF7-8C44-CE8420CA9FB7/c2pa.assertions/c2pa.metadata"))
        );

        let validation_results = ValidationResults::default()
            .add_active_manifest(active_manifest_codes)
            .add_ingredient_delta(ingredient_deltas);

        let review_rating = ReviewRating::new("Content bindings validated", None, 5);

        let metadata = Metadata::new()
            .set_date_time("2021-06-28T16:49:32.874Z".to_owned())
            .add_review(review_rating);

        let data_types = vec![AssetType::new(
            AssetTypeEnum::GeneratorPrompt,
            Some("1.0.0".into()),
        )];

        let mut all_vals = Ingredient {
            title: Some("test_title".to_owned()),
            format: Some("image/jpg".to_owned()),
            document_id: Some("12345".to_owned()),
            instance_id: Some("67890".to_owned()),
            c2pa_manifest: Some(HashedUri::new("self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322".to_owned(), Some("sha256".to_owned()), &[1,2,3,4,5,6,7,8,9,0])),
            validation_status: Some(validation_status.clone()),
            relationship: Relationship::ParentOf,
            thumbnail: Some(HashedUri::new("self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322/c2pa.thumbnail.ingredient_1.jpg".to_owned(), Some("sha256".to_owned()), &[1,2,3,4,5,6,7,8,9,0])),
            metadata: Some(metadata.clone()),
            data: Some(HashedUri::new("self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322/c2pa.databoxes/c2pa.data".to_owned(), Some("sha256".to_owned()), &[1,2,3,4,5,6,7,8,9,0])),
            description: Some("Some ingredient description".to_owned()),
            informational_uri: Some("https://tfhub.dev/deepmind/bigbigan-resnet50/1".to_owned()),
            data_types: Some(data_types.clone()),
            validation_results: Some(validation_results.clone()),
            active_manifest: Some(HashedUri::new("self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322".to_owned(), Some("sha256".to_owned()), &[1,2,3,4,5,6,7,8,9,0])),
            claim_signature: Some(HashedUri::new("self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322/c2pa.signature".to_owned(), Some("sha256".to_owned()), &[1,2,3,4,5,6,7,8,9,0])),
            version: 1,
        };

        // Save as V1
        let v1 = all_vals.to_assertion().unwrap();

        // Save as V2
        all_vals.version = 2;
        let v2 = all_vals.to_assertion().unwrap();

        // Save as V3
        all_vals.version = 3;
        let v3 = all_vals.to_assertion().unwrap();

        // test v1
        let v1_decoded = Ingredient::from_assertion(&v1).unwrap();
        let v1_expected = Ingredient {
            title: Some("test_title".to_owned()),
            format: Some("image/jpg".to_owned()),
            document_id: Some("12345".to_owned()),
            instance_id: Some("67890".to_owned()),
            c2pa_manifest: Some(HashedUri::new("self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322".to_owned(), Some("sha256".to_owned()), &[1,2,3,4,5,6,7,8,9,0])),
            validation_status: Some(validation_status.clone()),
            relationship: Relationship::ParentOf,
            thumbnail: Some(HashedUri::new("self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322/c2pa.thumbnail.ingredient_1.jpg".to_owned(), Some("sha256".to_owned()), &[1,2,3,4,5,6,7,8,9,0])),
            metadata: Some(metadata.clone()),
            version: 1,
            ..Default::default()
        };
        assert_eq!(v1_decoded, v1_expected);
        assert!(v1_decoded.is_v1_compatible());
        assert!(v1_decoded.is_v2_compatible());
        assert!(!v1_decoded.is_v3_compatible());

        // test v2
        let v2_decoded = Ingredient::from_assertion(&v2).unwrap();
        let v2_expected = Ingredient {
            title: Some("test_title".to_owned()),
            format: Some("image/jpg".to_owned()),
            document_id: Some("12345".to_owned()),
            instance_id: Some("67890".to_owned()),
            c2pa_manifest: Some(HashedUri::new("self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322".to_owned(), Some("sha256".to_owned()), &[1,2,3,4,5,6,7,8,9,0])),
            validation_status: Some(validation_status.clone()),
            relationship: Relationship::ParentOf,
            thumbnail: Some(HashedUri::new("self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322/c2pa.thumbnail.ingredient_1.jpg".to_owned(), Some("sha256".to_owned()), &[1,2,3,4,5,6,7,8,9,0])),
            metadata: Some(metadata.clone()),
            data: Some(HashedUri::new("self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322/c2pa.databoxes/c2pa.data".to_owned(), Some("sha256".to_owned()), &[1,2,3,4,5,6,7,8,9,0])),
            description: Some("Some ingredient description".to_owned()),
            informational_uri: Some("https://tfhub.dev/deepmind/bigbigan-resnet50/1".to_owned()),
            data_types: Some(data_types.clone()),
            version: 2,
            ..Default::default()
        };
        assert_eq!(v2_decoded, v2_expected);
        assert!(!v2_decoded.is_v1_compatible());
        assert!(v2_decoded.is_v2_compatible());
        assert!(!v2_decoded.is_v3_compatible());

        // test v3
        let v3_decoded = Ingredient::from_assertion(&v3).unwrap();
        let v3_expected = Ingredient {
            title: Some("test_title".to_owned()),
            format: Some("image/jpg".to_owned()),
            instance_id: Some("67890".to_owned()),
            relationship: Relationship::ParentOf,
            thumbnail: Some(HashedUri::new("self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322/c2pa.thumbnail.ingredient_1.jpg".to_owned(), Some("sha256".to_owned()), &[1,2,3,4,5,6,7,8,9,0])),
            metadata: Some(metadata),
            data: Some(HashedUri::new("self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322/c2pa.databoxes/c2pa.data".to_owned(), Some("sha256".to_owned()), &[1,2,3,4,5,6,7,8,9,0])),
            description: Some("Some ingredient description".to_owned()),
            informational_uri: Some("https://tfhub.dev/deepmind/bigbigan-resnet50/1".to_owned()),
            data_types: Some(data_types),
            validation_results: Some(validation_results),
            active_manifest: Some(HashedUri::new("self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322".to_owned(), Some("sha256".to_owned()), &[1,2,3,4,5,6,7,8,9,0])),
            claim_signature: Some(HashedUri::new("self#jumbf=c2pa/urn:c2pa:5E7B01FC-4932-4BAB-AB32-D4F12A8AA322/c2pa.signature".to_owned(), Some("sha256".to_owned()), &[1,2,3,4,5,6,7,8,9,0])),
            version: 3,
            ..Default::default()
        };
        assert_eq!(v3_decoded, v3_expected);
        assert!(!v3_decoded.is_v1_compatible());
        assert!(!v3_decoded.is_v2_compatible());
        assert!(v3_decoded.is_v3_compatible());
    }
}
