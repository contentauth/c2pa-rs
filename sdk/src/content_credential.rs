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
    context::Context,
    manifest::{Manifest, StoreOptions},
    manifest_store_report::ManifestStoreReport,
    settings::Settings,
    status_tracker::StatusTracker,
    store::Store,
    utils::hash_utils::hash_to_b64,
    validation_status::ValidationStatus,
    DigitalSourceType, Error, HashedUri, Result, ValidationResults,
};

/// This Generates the standard Reader output format for a Store
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
pub struct ContentCredential<'a> {
    claim: Claim,
    store: Store,
    context: &'a Context,
}

impl<'a> ContentCredential<'a> {
    pub fn new(context: &'a Context) -> Self {
        let mut claim = Claim::new("", context.settings().builder.vendor.as_deref(), 2);
        claim.instance_id = uuid::Uuid::new_v4().to_string();
        ContentCredential {
            claim,
            store: Store::new(),
            context,
        }
    }

    /// Use this for a content credential that is being created from scratch
    pub fn create(mut self, source_type: DigitalSourceType) -> Result<Self> {
        let actions = Actions::new()
            .add_action(Action::new(c2pa_action::CREATED).set_source_type(source_type));

        self.add_assertion(&actions)?;

        Ok(self)
    }

    // edits the content credential by setting the parent ingredient from the provided stream
    pub fn open_stream(
        mut self,
        format: &str,
        mut stream: impl Read + Seek + Send,
    ) -> Result<Self> {
        stream.rewind()?;
        self.add_ingredient_from_stream(Relationship::ParentOf, format, &mut stream)?;
        Ok(self)
    }

    /// creates a content credential from an existing stream
    pub fn from_stream(
        context: &'a Context,
        format: &str,
        mut stream: impl Read + Seek + Send,
    ) -> Result<Self> {
        let mut cr = Self::new(context);
        stream.rewind()?;
        cr.add_ingredient_from_stream(Relationship::ParentOf, format, &mut stream)?;
        Ok(cr)
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

    /// adds an assertion to the content credential's claim
    pub fn add_assertion(&mut self, assertion: &impl AssertionBase) -> Result<HashedUri> {
        self.claim.add_assertion(assertion)
    }

    /// create a manifest store report from the store and validation results
    pub fn add_action(&mut self, action: Action) -> Result<()> {
        self.claim.add_action(action)?;
        Ok(())
    }

    /// internal implementation to add ingredient from stream
    fn add_ingredient_from_stream(
        &mut self,
        relationship: Relationship,
        format: &str,
        mut stream: impl Read + Seek + Send,
    ) -> Result<HashedUri> {
        let (ingredient_assertion, store) =
            Ingredient::from_stream(relationship.clone(), format, &mut stream, self.context)?;

        // todo: allow passing store to load_ingredient_to_claim to avoid this conversion
        let manifest_bytes = store.to_jumbf_internal(0)?;
        Store::load_ingredient_to_claim(&mut self.claim, &manifest_bytes, None, self.context)?;

        if relationship == Relationship::ParentOf {
            // we must replace the store for parent ingredients
            self.store = store;
        }

        // add the ingredient assertion and get it's uri
        let ingredient_uri = self.add_assertion(&ingredient_assertion)?;

        // This part automatically adds the correct associated action for the ingredient
        // I'm not sure if we want to have this behavior here or leave it to the user
        let action_label = if relationship == Relationship::ParentOf {
            c2pa_action::OPENED
        } else {
            c2pa_action::PLACED
        };

        let action = Action::new(action_label).add_ingredient(ingredient_uri.clone())?;

        self.add_action(action)?;

        Ok(ingredient_uri)
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
        let signer = self.context.signer()?;
        if self.claim.claim_generator_info().is_none() {
            if let Some(cgi) = &self.context.settings().builder.claim_generator_info {
                self.claim.add_claim_generator_info(cgi.try_into()?);
            }
        }
        self.store.commit_claim(self.claim.clone())?;
        source.rewind()?; // always reset source to start
        self.store
            .save_to_stream(format, source, dest, signer, self.context)
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
        Ok(hash_to_b64(json))
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
        Ok(hash_to_b64(json))
    }
}

impl std::fmt::Display for ContentCredential<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = self.reader_value().map_err(|_| std::fmt::Error)?;
        f.write_str(
            serde_json::to_string_pretty(&value)
                .map_err(|_| std::fmt::Error)?
                .as_str(),
        )
    }
}

impl std::fmt::Debug for ContentCredential<'_> {
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

    fn test_settings_json() -> serde_json::Value {
        serde_json::json!({
            "builder": {
                "claim_generator_info": {
                    "name": "Content Credential Tests",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        })
    }

    #[test]
    fn test_content_credential_create() -> Result<()> {
        let (format, mut source, mut dest) = create_test_streams(CA_JPEG);

        let context = Context::new().with_settings(test_settings_json())?;

        let mut cr = ContentCredential::new(&context).create(DigitalSourceType::Empty)?;

        cr.save_to_stream(format, &mut source, &mut dest)?;

        let cr = ContentCredential::new(&context).open_stream(format, &mut dest)?;
        println!("{cr}");
        Ok(())
    }

    #[test]
    fn test_content_credential_open_stream() -> Result<()> {
        let (format, mut source, mut dest) = create_test_streams(CA_JPEG);
        let context = Context::new().with_settings(test_settings_json())?;

        let mut cr = ContentCredential::new(&context).open_stream(format, &mut source)?;
        cr.add_action(Action::new(c2pa_action::PUBLISHED))?;

        cr.save_to_stream(format, &mut source, &mut dest)?;

        let cr2 = ContentCredential::new(&context).open_stream(format, &mut dest)?;
        println!("{cr2}");
        Ok(())
    }

    #[test]
    fn test_add_ingredient_from_stream() -> Result<()> {
        let (format, mut source, mut dest) = create_test_streams(CA_JPEG);
        let context = Context::new().with_settings(test_settings_json())?;

        let mut cr = ContentCredential::new(&context).create(DigitalSourceType::Empty)?;
        cr.add_ingredient_from_stream(Relationship::ComponentOf, format, &mut source)?;

        cr.save_to_stream(format, &mut source, &mut dest)?;

        let cr2 = ContentCredential::new(&context).open_stream(format, &mut dest)?;
        println!("{cr2}");
        Ok(())
    }
}
