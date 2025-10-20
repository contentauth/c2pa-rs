// Copyright 2025 Adobe. All rights reserved.
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

use std::{
    collections::HashMap,
    io::{Read, Seek, Write},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    assertion::AssertionBase,
    assertions::{c2pa_action, Action, Actions, Ingredient, Relationship},
    claim::Claim,
    crypto::base64,
    manifest::{Manifest, StoreOptions},
    manifest_store_report::ManifestStoreReport,
    settings::Settings,
    status_tracker::StatusTracker,
    store::Store,
    validation_status::ValidationStatus,
    ClaimGeneratorInfo, DigitalSourceType, Error, HashedUri, Result, ValidationResults,
};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct StandardStoreReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// A label for the active (most recent) manifest in the store
    active_manifest: Option<String>,

    /// A HashMap of Manifests
    manifests: HashMap<String, Manifest>,

    validation_results: ValidationResults,
}

impl StandardStoreReport {
    fn from_store(store: &Store, validation_results: &ValidationResults) -> Result<Self> {
        let settings = Settings::default();
        let mut validation_results = validation_results.clone();
        let active_manifest = store.provenance_label();
        let mut manifests = HashMap::new();
        let mut validation_log = StatusTracker::default();
        let mut options = StoreOptions::default();

        for claim in store.claims() {
            let manifest_label = claim.label();
            let result = Manifest::from_store(
                store,
                manifest_label,
                &mut options,
                &mut validation_log,
                &settings,
            );

            match result {
                Ok(manifest) => {
                    manifests.insert(manifest_label.to_owned(), manifest);
                }
                Err(e) => {
                    validation_results.add_status(ValidationStatus::from_error(&e));
                    return Err(e);
                }
            };
        }
        Ok(Self {
            active_manifest,
            manifests,
            validation_results,
        })
    }
}

/// Experimental optimized Content Credential Structure
pub struct ContentCredential {
    claim: Claim,
    store: Store,
    settings: Settings,
}

impl ContentCredential {
    pub fn new(settings: &Settings) -> Self {
        let mut claim = Claim::new("", settings.builder.vendor.as_deref(), 2);
        claim.instance_id = uuid::Uuid::new_v4().to_string();
        ContentCredential {
            claim,
            store: Store::new(),
            settings: settings.clone(),
        }
    }

    /// Use this for a content credential that is being created from scratch
    pub fn create(source_type: DigitalSourceType, settings: &Settings) -> Result<Self> {
        let mut cc = Self::new(settings);

        let actions = Actions::new()
            .add_action(Action::new(c2pa_action::CREATED).set_source_type(source_type));

        cc.add_assertion(&actions)?;

        Ok(cc)
    }

    /// creates a content credential from an existing stream
    pub fn from_stream(
        settings: &Settings,
        format: &str,
        mut stream: impl Read + Seek + Send,
    ) -> Result<Self> {
        let mut cc = Self::new(settings);
        stream.rewind()?;
        let (_, store) = cc.with_stream_impl(Relationship::ParentOf, format, &mut stream)?;
        cc.store = store; // replaces the empty store
        Ok(cc)
    }

    fn parent_ingredient(&self) -> Option<Ingredient> {
        for i in self.claim.ingredient_assertions() {
            if let Ok(ingredient) = Ingredient::from_assertion(i.assertion()) {
                if ingredient.relationship == Relationship::ParentOf {
                    return Some(ingredient);
                }
            }
        }
        None
    }

    pub fn add_assertion(&mut self, assertion: &impl AssertionBase) -> Result<HashedUri> {
        self.claim.add_assertion(assertion)
    }

    pub fn add_action(&mut self, action: Action) -> Result<()> {
        self.claim.add_action(action)?;
        Ok(())
    }

    /// This is used to add component ingredients from a stream
    ///
    /// Parent ingredients are created using from_stream.
    pub fn add_ingredient_from_stream(
        &mut self,
        format: &str,
        mut stream: impl Read + Seek + Send,
    ) -> Result<&Self> {
        Ok(self
            .with_stream_impl(Relationship::ComponentOf, format, &mut stream)?
            .0)
    }

    /// internal implementation to add ingredient from stream
    fn with_stream_impl(
        &mut self,
        relationship: Relationship,
        format: &str,
        mut stream: impl Read + Seek + Send,
    ) -> Result<(&Self, Store)> {
        // create an action associated with the ingredient
        let action_label = if relationship == Relationship::ParentOf {
            c2pa_action::OPENED
        } else {
            c2pa_action::PLACED
        };

        let (ingredient_assertion, store) =
            Ingredient::from_stream(relationship, format, &mut stream, &self.settings)?;

        let manifest_bytes = store.to_jumbf_internal(0)?;
        Store::load_ingredient_to_claim(&mut self.claim, &manifest_bytes, None, &self.settings)?;

        // add the ingredient assertion and get it's uri
        let ingredient_hashed_uri = self.add_assertion(&ingredient_assertion)?;

        // todo add to exiting actions and check fo
        let action = Action::new(action_label).add_ingredient(ingredient_hashed_uri)?;

        //let actions = Actions::new().add_action_checked(action)?;
        self.claim.add_action(action)?;

        //self.add_assertion(&action)?;

        // capture the store and validation results from the assertion
        Ok((self, store))
    }

    /// sets the default claim generator info if not already set
    fn set_default_claim_generator_info(&mut self) -> Result<&Self> {
        if self.claim.claim_generator_info().is_none() {
            // only set if not already set
            self.claim
                .add_claim_generator_info(ClaimGeneratorInfo::default());
        }
        Ok(self)
    }

    /// signs and saves the content credential to the destination stream
    pub fn save_to_stream<R, W>(
        &mut self,
        format: &str,
        source: &mut R,
        dest: &mut W,
    ) -> Result<Vec<u8>>
    where
        R: Read + Seek + Send,
        W: Write + Read + Seek + Send,
    {
        let signer = Settings::signer()?;
        self.set_default_claim_generator_info()?;
        self.store.commit_claim(self.claim.clone())?;
        source.rewind()?; // always reset source to start
        self.store
            .save_to_stream(format, source, dest, &signer, &self.settings)
    }

    /// replace byte arrays with base64 encoded strings for more readable output
    fn hash_to_b64(mut value: Value) -> Value {
        use std::collections::VecDeque;

        let mut queue = VecDeque::new();
        queue.push_back(&mut value);

        while let Some(current) = queue.pop_front() {
            match current {
                Value::Object(obj) => {
                    for (_, v) in obj.iter_mut() {
                        if let Value::Array(hash_arr) = v {
                            if !hash_arr.is_empty() && hash_arr.iter().all(|x| x.is_number()) {
                                // Pre-allocate with capacity to avoid reallocations
                                let mut hash_bytes = Vec::with_capacity(hash_arr.len());
                                // Convert numbers to bytes safely
                                for n in hash_arr.iter() {
                                    if let Some(num) = n.as_u64() {
                                        hash_bytes.push(num as u8);
                                    }
                                }
                                *v = Value::String(base64::encode(&hash_bytes));
                            }
                        }
                        queue.push_back(v);
                    }
                }
                Value::Array(arr) => {
                    for v in arr.iter_mut() {
                        queue.push_back(v);
                    }
                }
                _ => {}
            }
        }
        value
    }

    /// Generates a value similar to the C2PA Reader output
    pub fn reader_value(&self) -> Result<Value> {
        // get the validation results from the parent ingredient
        let results = self
            .parent_ingredient()
            .and_then(|i| i.validation_results)
            .ok_or(Error::ClaimMissing {
                label: "Parent Ingredient missing".to_string(),
            })?;
        let report = StandardStoreReport::from_store(&self.store, &results)?;
        let json = serde_json::to_value(report).map_err(Error::JsonError)?;
        Ok(Self::hash_to_b64(json))
    }

    /// generates a value similar to the C2PA Reader detailed output
    pub fn detailed_value(&self) -> Result<Value> {
        let results = self
            .parent_ingredient()
            .and_then(|i| i.validation_results)
            .ok_or(Error::ClaimMissing {
                label: "Parent Ingredient missing".to_string(),
            })?;
        let report = ManifestStoreReport::from_store_with_results(&self.store, &results)?;
        let json = serde_json::to_value(report).map_err(Error::JsonError)?;
        Ok(Self::hash_to_b64(json))
    }
}

impl std::fmt::Display for ContentCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = self.reader_value().map_err(|_| std::fmt::Error)?;
        f.write_str(
            serde_json::to_string_pretty(&value)
                .map_err(|_| std::fmt::Error)?
                .as_str(),
        )
    }
}

impl std::fmt::Debug for ContentCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = self.detailed_value().map_err(|_| std::fmt::Error)?;
        f.write_str(
            serde_json::to_string_pretty(&value)
                .map_err(|_| std::fmt::Error)?
                .as_str(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test::*;

    #[test]
    fn test_content_credential_created() -> Result<()> {
        let (format, mut source, mut dest) = create_test_streams(CA_JPEG);
        let settings = Settings::default();

        let mut cr = ContentCredential::create(DigitalSourceType::Empty, &settings)?;

        cr.save_to_stream(format, &mut source, &mut dest)?;

        let cr = ContentCredential::from_stream(&settings, format, &mut dest)?;
        println!("{cr}");
        Ok(())
    }

    #[test]
    fn test_content_credential_from_stream() -> Result<()> {
        let (format, mut source, mut dest) = create_test_streams(CA_JPEG);
        let settings = Settings::default();

        let mut cr = ContentCredential::from_stream(&settings, format, &mut source)?;
        println!("{cr}");

        cr.save_to_stream(format, &mut source, &mut dest)?;

        let cr2 = ContentCredential::from_stream(&settings, format, &mut dest)?;
        println!("{cr2}");
        Ok(())
    }

    #[test]
    fn test_add_ingredient_from_stream() -> Result<()> {
        let (format, mut source, mut dest) = create_test_streams(CA_JPEG);
        let settings = Settings::default();

        let mut cr = ContentCredential::create(DigitalSourceType::Empty, &settings)?;
        cr.add_ingredient_from_stream(format, &mut source)?;

        cr.save_to_stream(format, &mut source, &mut dest)?;

        let cr = ContentCredential::from_stream(&settings, format, &mut dest)?;
        println!("{cr:?}");
        Ok(())
    }
}
