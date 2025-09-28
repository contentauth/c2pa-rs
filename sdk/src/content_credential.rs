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
    settings::{self, Settings},
    store::Store,
    validation_status::ValidationStatus,
    Error, Result, ValidationResults,
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
        let mut validation_results = validation_results.clone();
        let active_manifest = store.provenance_label();
        let mut manifests = HashMap::new();
        let mut options = StoreOptions::default();

        for claim in store.claims() {
            let manifest_label = claim.label();
            let result = Manifest::from_store(store, manifest_label, &mut options);

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

/// Experimental optimized Content Credential StructureSett
pub struct ContentCredential {
    claim: Claim,
    store: Store,
}

impl ContentCredential {
    pub fn new(_settings: &Settings) -> Self {
        let vendor =
            settings::get_settings_value::<Option<String>>("builder.vendor").unwrap_or(None);
        let claim = Claim::new("", vendor.as_deref(), 2);
        ContentCredential {
            claim,
            store: Store::new(),
        }
    }

    pub fn from_stream(
        settings: &Settings,
        format: &str,
        mut stream: impl Read + Seek + Send,
    ) -> Result<Self> {
        let mut cc = Self::new(settings);
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

    pub fn add_assertion(&mut self, assertion: &impl AssertionBase) -> Result<&Self> {
        self.claim.add_assertion(assertion)?;
        Ok(self)
    }

    pub fn add_ingredient_from_stream(
        &mut self,
        format: &str,
        mut stream: impl Read + Seek + Send,
    ) -> Result<&Self> {
        Ok(self
            .with_stream_impl(Relationship::ComponentOf, format, &mut stream)?
            .0)
    }

    fn with_stream_impl(
        &mut self,
        relationship: Relationship,
        format: &str,
        mut stream: impl Read + Seek + Send,
    ) -> Result<(&Self, Store)> {
        //let verify = get_settings_value::<bool>("verify.verify_after_reading")?; // defaults to true

        let (ingredient_assertion, store) =
            Ingredient::from_stream(relationship, format, &mut stream)?;

        // add the ingredient assertion and get it's uri
        let ingredient_hashed_uri = self.claim.add_assertion(&ingredient_assertion)?;

        // create an action associated with the ingredient
        let opened = Action::new(c2pa_action::OPENED)
            .set_parameter("ingredients", vec![ingredient_hashed_uri])?;
        let actions = Actions::new().add_action(opened);

        self.claim.add_assertion(&actions)?;

        // capture the store and validation results from the assertion
        Ok((self, store))
    }

    fn set_claim_generator_info(&mut self) -> Result<&Self> {
        self.claim
            .add_claim_generator_info(crate::ClaimGeneratorInfo::default());
        Ok(self)
    }

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
        self.set_claim_generator_info()?;
        self.store.commit_claim(self.claim.clone())?;
        self.store.save_to_stream(format, source, dest, &signer)
    }

    /// replace byte arrays with base64 encoded strings
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

    pub fn value(&self) -> Result<Value> {
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
        let value = self.value().map_err(|_| std::fmt::Error)?;
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

#[test]
fn test_content_credential_from_stream() -> Result<()> {
    const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
    //let settings = Settings::default();
    let mut source = std::io::Cursor::new(IMAGE_WITH_MANIFEST);
    let settings = Settings::default();
    let mut cr = ContentCredential::from_stream(&settings, "image/jpeg", &mut source)?;
    println!("{cr}");

    source.set_position(0);
    let mut dest = std::io::Cursor::new(Vec::new());
    cr.save_to_stream("image/jpeg", &mut source, &mut dest)?;

    dest.set_position(0);
    let cr2 = ContentCredential::from_stream(&settings, "image/jpeg", &mut dest)?;
    println!("{cr2}");
    Ok(())
}

#[test]
fn test_content_credential_created() -> Result<()> {
    const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
    //let settings = Settings::default();
    let mut source = std::io::Cursor::new(IMAGE_WITH_MANIFEST);
    let settings = Settings::default();
    let mut cr = ContentCredential::new(&settings);
    let action = crate::assertions::Actions::new().add_action(
        crate::assertions::Action::new(crate::assertions::c2pa_action::CREATED)
            .set_source_type(crate::DigitalSourceType::Empty)
            .set_parameter("note", "Created by test_content_credential_created")?,
    );
    cr.add_assertion(&action)?;

    source.set_position(0);
    let mut dest = std::io::Cursor::new(Vec::new());
    cr.save_to_stream("image/jpeg", &mut source, &mut dest)?;

    dest.set_position(0);
    let cr = ContentCredential::from_stream(&settings, "image/jpeg", &mut dest)?;
    println!("{cr}");
    Ok(())
}
