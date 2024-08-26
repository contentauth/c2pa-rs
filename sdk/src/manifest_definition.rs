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

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use uuid::Uuid;

use crate::{
    assertions::Metadata, resource_store::ResourceRef, ClaimGeneratorInfo, Error, Ingredient,
    Result,
};

/// A Manifest Definition
/// This is used to define a manifest and is used to build a ManifestStore
/// A Manifest is a collection of ingredients and assertions
/// It is used to define a claim that can be signed and embedded into a file
#[skip_serializing_none]
#[derive(Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[non_exhaustive]
pub struct ManifestDefinition {
    /// Optional prefix added to the generated Manifest Label
    /// This is typically Internet domain name for the vendor (i.e. `adobe`)
    pub vendor: Option<String>,

    /// Clam Generator Info is always required with at least one entry
    #[serde(default = "default_claim_generator_info")]
    pub claim_generator_info: Vec<ClaimGeneratorInfo>,

    /// A human-readable title, generally source filename.
    pub title: Option<String>,

    /// The format of the source file as a MIME type.
    #[serde(default = "default_format")]
    pub format: String,

    /// Instance ID from `xmpMM:InstanceID` in XMP metadata.
    #[serde(default = "default_instance_id")]
    pub instance_id: String,

    pub thumbnail: Option<ResourceRef>,

    /// A List of ingredients
    #[serde(default = "default_vec::<Ingredient>")]
    pub ingredients: Vec<Ingredient>,

    /// A list of assertions
    #[serde(default = "default_vec::<AssertionDefinition>")]
    pub assertions: Vec<AssertionDefinition>,

    /// A list of redactions - URIs to a redacted assertions
    pub redactions: Option<Vec<String>>,

    pub label: Option<String>,

    /// Optional manifest metadata
    pub metadata: Option<Vec<Metadata>>,
}

fn default_instance_id() -> String {
    format!("xmp:iid:{}", Uuid::new_v4())
}

fn default_claim_generator_info() -> Vec<ClaimGeneratorInfo> {
    [ClaimGeneratorInfo::default()].to_vec()
}

fn default_format() -> String {
    "application/octet-stream".to_owned()
}

fn default_vec<T>() -> Vec<T> {
    Vec::new()
}

impl ManifestDefinition {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_claim_generator_info<I>(&mut self, claim_generator_info: I) -> &mut Self
    where
        I: Into<ClaimGeneratorInfo>,
    {
        self.claim_generator_info = [claim_generator_info.into()].to_vec();
        self
    }

    pub fn set_title<S>(&mut self, title: S) -> &mut Self
    where
        S: Into<String>,
    {
        self.title = Some(title.into());
        self
    }

    pub fn set_instance_id<S>(&mut self, instance_id: S) -> &mut Self
    where
        S: Into<String>,
    {
        self.instance_id = instance_id.into();
        self
    }

    // pub fn set_thumbnail<S, R>(&mut self, format: S, stream: &mut R) -> Result<&mut Self>
    // where
    //     S: Into<String>,
    //     R: Read + Seek + ?Sized,
    // {
    //     // just read into a buffer until resource store handles reading streams
    //     let mut resource = Vec::new();
    //     stream.read_to_end(&mut resource)?;
    //     // add the resource and set the resource reference
    //     self.resources.add(&self.definition.instance_id, resource)?;
    //     self.definition.thumbnail = Some(ResourceRef::new(
    //         format,
    //         self.definition.instance_id.clone(),
    //     ));
    //     Ok(self)
    // }

    /// Adds a CBOR assertion to the manifest.
    /// # Arguments
    /// * `label` - A label for the assertion.
    /// * `data` - The data for the assertion. The data is any Serde Serializable type.
    /// # Returns
    /// * A mutable reference to the [`ManifestDefinition`].
    /// # Errors
    /// * If the assertion is not valid.
    pub fn add_assertion<S, T>(&mut self, label: S, data: &T) -> Result<&mut Self>
    where
        S: Into<String>,
        T: Serialize,
    {
        self.assertions.push(AssertionDefinition {
            label: label.into(),
            data: AssertionData::Cbor(serde_cbor::value::to_value(data)?),
        });
        Ok(self)
    }

    /// Adds a Json assertion to the manifest.
    /// # Arguments
    /// * `label` - A label for the assertion.
    /// * `data` - The data for the assertion. The data is any Serde Serializable type.
    /// # Returns
    /// * A mutable reference to the [`ManifestDefinition`].
    /// # Errors
    /// * If the assertion is not valid.
    pub fn add_assertion_json<S, T>(&mut self, label: S, data: &T) -> Result<&mut Self>
    where
        S: Into<String>,
        T: Serialize,
    {
        self.assertions.push(AssertionDefinition {
            label: label.into(),
            data: AssertionData::Json(serde_json::to_value(data)?),
        });
        Ok(self)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[serde(untagged)]
pub enum AssertionData {
    #[cfg_attr(feature = "json_schema", schemars(skip))]
    Cbor(serde_cbor::Value),
    Json(serde_json::Value),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[non_exhaustive]
pub struct AssertionDefinition {
    pub label: String,
    pub data: AssertionData,
}

use serde::de::DeserializeOwned;

use crate::assertion::AssertionDecodeError;
impl AssertionDefinition {
    pub(crate) fn to_assertion<T: DeserializeOwned>(&self) -> Result<T> {
        match &self.data {
            AssertionData::Json(value) => serde_json::from_value(value.clone()).map_err(|e| {
                Error::AssertionDecoding(AssertionDecodeError::from_err(
                    self.label.to_owned(),
                    None,
                    "application/json".to_owned(),
                    e,
                ))
            }),
            AssertionData::Cbor(value) => {
                serde_cbor::value::from_value(value.clone()).map_err(|e| {
                    Error::AssertionDecoding(AssertionDecodeError::from_err(
                        self.label.to_owned(),
                        None,
                        "application/cbor".to_owned(),
                        e,
                    ))
                })
            }
        }
    }
}
