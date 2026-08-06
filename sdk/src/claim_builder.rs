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

//! Builds a [`crate::claim::Claim`] directly and eagerly, instead of staging everything into a
//! JSON-serializable [`crate::ManifestDefinition`] for translation at signing time the way
//! [`crate::Builder`] does.
//!
//! `ClaimBuilder` has no `ManifestDefinition`/`ResourceStore` — every writer call places its
//! assertion at a stable claim position immediately and returns the assertion's real
//! [`HashedUri`], so it can be referenced from another assertion (e.g. an action referencing
//! the ingredient it operated on) before signing. Every assertion is described by a
//! [`ClaimAssertion`], which does its own generation ([`ClaimAssertion::generate`]) using this
//! `ClaimBuilder`'s [`Context`] — `ClaimBuilder` itself just adds the concrete result to the
//! claim (merging in an ingredient's provenance, which needs the claim directly, and checking a
//! hard binding against whatever one is already there, are the two exceptions).
//!
//! `ClaimBuilder` never manages placeholder/reserve-space embedding itself — the caller is
//! expected to have already reserved space for, and embedded, the manifest placeholder in the
//! asset before adding a hard-binding assertion or calling [`ClaimBuilder::sign`].

use std::sync::Arc;

use crate::{
    assertion::AssertionBase,
    assertions::{BmffHash, BoxHash, DataHash, IngredientAssertion},
    claim::Claim,
    claim_assertion::{ClaimAssertion, GeneratedAssertion, IngredientMerge},
    context::Context,
    error::{Error, Result},
    jumbf::labels::{to_assertion_uri, to_manifest_uri, to_signature_uri},
    store::Store,
    HashType, HashedUri,
};

/// Builds a `Claim` directly and eagerly. See the module documentation for the model this
/// implements and how it differs from [`crate::Builder`].
pub struct ClaimBuilder {
    claim: Claim,
    context: Arc<Context>,
    is_update: bool,
    redactions: Vec<String>,
}

impl ClaimBuilder {
    /// `ClaimBuilder` only supports Claims v2+ — a v1 claim's `claim_generator` string can only
    /// be computed once every `ClaimGeneratorInfo` is known, which has no equivalent here, so
    /// there's no v1 code path to opt into in the first place.
    const CLAIM_VERSION: usize = 2;

    /// Creates a new claim with an auto-generated label.
    pub fn new(context: Arc<Context>) -> Self {
        let claim = Claim::new("", None, Self::CLAIM_VERSION).with_context(context.clone());
        Self::from_claim(claim, context)
    }

    /// Like [`ClaimBuilder::new`], but with a caller-supplied claim label instead of an
    /// auto-generated UUID. `label` must already be a valid C2PA v2 manifest label (see
    /// `Claim::new_with_user_guid`).
    pub fn with_label(context: Arc<Context>, label: impl Into<String>) -> Result<Self> {
        let claim = Claim::new_with_user_guid(String::new(), label.into(), Self::CLAIM_VERSION)?
            .with_context(context.clone());
        Ok(Self::from_claim(claim, context))
    }

    /// Creates a new `ClaimBuilder` from an existing `Claim`
    fn from_claim(mut claim: Claim, context: Arc<Context>) -> Self {
        let info: crate::ClaimGeneratorInfo =
            match context.settings().builder.claim_generator_info.as_ref() {
                Some(settings) => settings
                    .clone()
                    .try_into()
                    .unwrap_or_else(|_| crate::ClaimGeneratorInfo::default()),
                None => crate::ClaimGeneratorInfo::default(),
            };
        claim.add_claim_generator_info(info);

        // The claim's default hash algorithm is set from the `builder.hash_alg`, if configured.
        // Claim::new already defaults `alg` to `Some(BUILD_HASH_ALG)`; only override it here when
        // there's an explicit setting to apply — assigning `None` would trip a pre-existing bug
        // in Claim::serialize_v2 where the CBOR field count assumes `alg` is always present
        // (tracked separately).
        if let Some(hash_alg) = context.settings().builder.hash_alg.clone() {
            claim.alg = Some(hash_alg);
        }

        // Honor the compressed_manifest setting from the context core settings
        claim.set_compressed_manifest(context.settings().core.prefer_compress_manifests);

        Self {
            claim,
            context,
            is_update: false,
            redactions: Vec::new(),
        }
    }

    /// Marks this as an update manifest — [`ClaimBuilder::sign`] then calls
    /// `Store::commit_update_manifest` instead of `Store::commit_claim`. `ClaimBuilder` has
    /// no equivalent of [`crate::BuilderIntent::Create`]/`Edit` — those only govern `Builder`'s
    /// auto-thumbnail/auto-parent/auto-action automation, none of which `ClaimBuilder` does,
    /// since everything here is added explicitly by the caller.
    pub fn update(mut self) -> Self {
        self.is_update = true;
        self
    }

    /// Sets the claim title.
    pub fn set_title(&mut self, title: impl Into<String>) -> &mut Self {
        self.claim.set_title(Some(title.into()));
        self
    }

    /// Sets the instance ID (e.g. an `xmp:iid:...` URN) of the asset this claim describes.
    pub fn set_instance_id(&mut self, instance_id: impl Into<String>) -> &mut Self {
        self.claim.instance_id = instance_id.into();
        self
    }

    /// Sets the claim's default hash algorithm (e.g. `"sha384"`). Defaults to `"sha256"`.
    pub fn set_hash_alg(&mut self, alg: impl Into<String>) -> &mut Self {
        self.claim.alg = Some(alg.into());
        self
    }

    /// Records a JUMBF URI to redact from an ingredient's manifest chain the next time one is
    /// merged in via a [`ClaimAssertion`] under [`IngredientAssertion::LABEL`] (with a stream
    /// attached). Applies to every ingredient added afterward — URIs that aren't present in a
    /// given ingredient's chain are simply not found there and have no effect. This only
    /// performs the mechanical redaction; the caller is responsible for separately recording a
    /// `c2pa.redacted` action with a reason for each one, since the reason is caller-specific
    /// domain knowledge this method has no way to infer.
    pub fn add_redaction(&mut self, uri: impl Into<String>) -> &mut Self {
        self.redactions.push(uri.into());
        self
    }

    /// Adds `assertion` to the claim as *gathered* (mirroring `Claim::add_assertion`'s default)
    /// and returns its [`HashedUri`]. See [`ClaimAssertion`] for what each label expects.
    /// Hash assertions (`BoxHash`/`DataHash`/`BmffHash`) must always be stored as *created* by
    /// `Claim` — errors if `assertion` is one of these; use
    /// [`ClaimBuilder::add_created_assertion`] for those instead.
    pub fn add_gathered_assertion(&mut self, assertion: ClaimAssertion) -> Result<HashedUri> {
        self.insert_claim_assertion(assertion, false)
    }

    /// Same as [`ClaimBuilder::add_gathered_assertion`], but adds the assertion as *created*
    /// rather than *gathered* (mirroring `Claim::add_created_assertion`). Required for hash
    /// assertions ([`BoxHash`]/[`DataHash`]/[`BmffHash`]), which `Claim` only ever stores as
    /// created.
    pub fn add_created_assertion(&mut self, assertion: ClaimAssertion) -> Result<HashedUri> {
        self.insert_claim_assertion(assertion, true)
    }

    /// Generates the concrete assertion `assertion` describes (see [`ClaimAssertion::generate`])
    /// and adds it to the claim. Everything but ingredient merging and hard-binding conflict
    /// checking is a direct add from here — see [`ClaimBuilder::insert_ingredient`]/
    /// [`ClaimBuilder::insert_data_hash`]/[`ClaimBuilder::insert_bmff_hash`]/
    /// [`ClaimBuilder::insert_box_hash`].
    fn insert_claim_assertion(
        &mut self,
        assertion: ClaimAssertion,
        created: bool,
    ) -> Result<HashedUri> {
        match assertion.generate(&self.context)? {
            GeneratedAssertion::Actions(a) => self.insert_assertion(a.as_ref(), created),
            GeneratedAssertion::Metadata(a) => self.insert_assertion(&a, created),
            GeneratedAssertion::UserCbor(a) => self.insert_assertion(&a, created),
            GeneratedAssertion::User(a) => self.insert_assertion(&a, created),
            GeneratedAssertion::EmbeddedData(a) => self.insert_assertion(&a, created),
            GeneratedAssertion::Ingredient { assertion, merge } => {
                self.insert_ingredient(*assertion, merge, created)
            }
            GeneratedAssertion::DataHash(dh) => {
                Self::require_created(created, DataHash::LABEL)?;
                self.insert_data_hash(dh)
            }
            GeneratedAssertion::BmffHash(bh) => {
                Self::require_created(created, BmffHash::LABEL)?;
                self.insert_bmff_hash(bh)
            }
            GeneratedAssertion::BoxHash(bh) => {
                Self::require_created(created, BoxHash::LABEL)?;
                self.insert_box_hash(bh)
            }
        }
    }

    /// Hash assertions are always stored as *created* by `Claim` (see
    /// [`ClaimBuilder::add_gathered_assertion`]'s docs) — reject the mismatch explicitly rather
    /// than silently treating a gathered hard binding as created.
    fn require_created(created: bool, label: &str) -> Result<()> {
        if !created {
            return Err(Error::BadParam(format!(
                "'{label}' is a hard binding and must be added via add_created_assertion, not \
                 add_gathered_assertion."
            )));
        }
        Ok(())
    }

    fn insert_assertion(
        &mut self,
        assertion: &impl AssertionBase,
        created: bool,
    ) -> Result<HashedUri> {
        if created {
            self.claim.add_created_assertion(assertion)
        } else {
            self.claim.add_assertion(assertion)
        }
    }

    /// Adds `assertion` as-is if it has no provenance of its own to merge (`merge` is `None`).
    /// Otherwise merges `merge.manifest_bytes` into this claim's ingredient store (the one step
    /// that needs `ClaimBuilder`'s own claim and accumulated redactions, rather than something
    /// [`ClaimAssertion::generate`] could do on its own) and fills in `assertion`'s
    /// `active_manifest`/`claim_signature`/`validation_results` from the result before adding it.
    fn insert_ingredient(
        &mut self,
        mut assertion: IngredientAssertion,
        merge: Option<IngredientMerge>,
        created: bool,
    ) -> Result<HashedUri> {
        let Some(IngredientMerge {
            manifest_bytes,
            validation_results,
        }) = merge
        else {
            return self.insert_assertion(&assertion, created);
        };

        let redactions = (!self.redactions.is_empty()).then(|| self.redactions.clone());
        let ingredient_store = Store::load_ingredient_to_claim(
            &mut self.claim,
            &manifest_bytes,
            redactions,
            &self.context,
        )?;

        let ingredient_active_claim = ingredient_store
            .provenance_claim()
            .ok_or(Error::JumbfNotFound)?;
        let manifest_label = ingredient_active_claim.label();
        let hashes = ingredient_store.get_manifest_box_hashes(ingredient_active_claim);
        let alg = Some(ingredient_active_claim.alg().to_owned());

        assertion.active_manifest = Some(HashedUri::new(
            to_manifest_uri(manifest_label),
            alg.clone(),
            hashes.manifest_box_hash.as_ref(),
        ));
        assertion.claim_signature = Some(HashedUri::new(
            to_signature_uri(manifest_label),
            alg,
            hashes.signature_box_hash.as_ref(),
        ));
        assertion.validation_results = Some(validation_results);

        self.insert_assertion(&assertion, created)
    }

    /// Returns the kind and encoded byte length of the claim's current hard binding assertion,
    /// if one has been added.
    fn existing_hard_binding(&self) -> Option<(HashType, usize)> {
        for ca in self.claim.claim_assertion_store() {
            let label = ca.label_raw();
            let hash_type = if label.starts_with(DataHash::LABEL) {
                HashType::Data
            } else if label.starts_with(BmffHash::LABEL) {
                HashType::Bmff
            } else if label.starts_with(BoxHash::LABEL) {
                HashType::Box
            } else {
                continue;
            };
            return Some((hash_type, ca.assertion().data().len()));
        }
        None
    }

    fn find_hard_binding_uri(&self, label_prefix: &str) -> Option<HashedUri> {
        self.claim
            .claim_assertion_store()
            .iter()
            .find(|ca| ca.label_raw().starts_with(label_prefix))
            .map(|ca| {
                let label = ca.label();
                let url = to_assertion_uri(self.claim.label(), &label);
                HashedUri::new(url, Some(ca.hash_alg().to_owned()), ca.hash())
            })
    }

    /// First-time add or replace of a `DataHash` hard binding. A replacement is padded back up to
    /// match the existing one's encoded byte length exactly (`update_data_hash` handles this),
    /// erroring only if the new value is already larger than that.
    fn insert_data_hash(&mut self, dh: DataHash) -> Result<HashedUri> {
        match self.existing_hard_binding() {
            None => self.insert_assertion(&dh, true),
            Some((HashType::Data, _)) => {
                self.claim.update_data_hash(dh)?;
                self.find_hard_binding_uri(DataHash::LABEL)
                    .ok_or(Error::NotFound)
            }
            Some((existing_type, _)) => {
                Err(Self::hard_binding_mismatch(existing_type, HashType::Data))
            }
        }
    }

    /// First-time add or replace of a `BmffHash` hard binding. A replacement must not be larger
    /// than the existing one's encoded byte length — the claim's byte layout must not grow, and
    /// `BmffHash` has no padding field to absorb a smaller replacement's slack.
    fn insert_bmff_hash(&mut self, bh: BmffHash) -> Result<HashedUri> {
        match self.existing_hard_binding() {
            None => self.insert_assertion(&bh, true),
            Some((HashType::Bmff, existing_len)) => {
                let assertion = bh.to_assertion()?;
                if assertion.data().len() > existing_len {
                    return Err(Self::hard_binding_too_large("BmffHash"));
                }
                self.claim.update_bmff_hash(bh)?;
                self.find_hard_binding_uri(BmffHash::LABEL)
                    .ok_or(Error::NotFound)
            }
            Some((existing_type, _)) => {
                Err(Self::hard_binding_mismatch(existing_type, HashType::Bmff))
            }
        }
    }

    /// First-time add or replace of a `BoxHash` hard binding. A replacement must not be larger
    /// than the existing one's encoded byte length — the claim's byte layout must not grow (the
    /// container tolerates a smaller replacement's resulting slack).
    fn insert_box_hash(&mut self, bh: BoxHash) -> Result<HashedUri> {
        match self.existing_hard_binding() {
            None => self.insert_assertion(&bh, true),
            Some((HashType::Box, existing_len)) => {
                let assertion = bh.to_assertion()?;
                if assertion.data().len() > existing_len {
                    return Err(Self::hard_binding_too_large("BoxHash"));
                }
                self.claim.replace_assertion(assertion)?;
                self.find_hard_binding_uri(BoxHash::LABEL)
                    .ok_or(Error::NotFound)
            }
            Some((existing_type, _)) => {
                Err(Self::hard_binding_mismatch(existing_type, HashType::Box))
            }
        }
    }

    fn hard_binding_mismatch(existing: HashType, replacement: HashType) -> Error {
        Error::BadParam(format!(
            "Hard binding kind mismatch: existing is {existing:?}, replacement is \
             {replacement:?}. There can only be one hard binding per claim."
        ))
    }

    fn hard_binding_too_large(kind: &str) -> Error {
        Error::BadParam(format!(
            "Replacement {kind} is larger than the existing one — the claim's byte layout must \
             not grow."
        ))
    }

    /// Signs the manifest and returns the raw signed JUMBF bytes, using the signer configured on
    /// this `ClaimBuilder`'s `Context` (see `Context::with_signer`/the `signer` settings key).
    ///
    /// Unlike [`crate::Builder::sign_embeddable`], this does not compose the result into a
    /// format-specific container (a JPEG APP11 segment, a BMFF UUID box, etc.) — there's no
    /// `format` parameter for the same reason. The caller does that themselves, the same way
    /// they own placeholder embedding: builds a `Store` directly from this claim (no
    /// `ManifestDefinition` translation), verifies a hard binding assertion is present, and
    /// signs. There is no Mode 1/placeholder concept on `ClaimBuilder` at all — the caller must
    /// have already added a real hard binding via a `ClaimAssertion` under a hard-binding label.
    pub fn sign(&self) -> Result<Vec<u8>> {
        if self.existing_hard_binding().is_none() {
            return Err(Error::BadParam(
                "No hard binding assertion found. Add one via add_gathered_assertion/\
                 add_created_assertion before sign()."
                    .to_string(),
            ));
        }

        let mut store = Store::from_context(&self.context);
        if self.is_update {
            store.commit_update_manifest(self.claim.clone())?;
        } else {
            store.commit_claim(self.claim.clone())?;
        }

        let signer = self.context.signer()?;
        let dynamic_assertions = signer.dynamic_assertions();
        if !dynamic_assertions.is_empty() {
            store.add_dynamic_assertion_placeholders(&dynamic_assertions)?;
        }

        store.sign_manifest(signer, &self.context)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use std::io::Cursor;

    use super::*;
    use crate::{
        assertions::{c2pa_action, Action, Actions, DigitalSourceType, Relationship},
        error::Error,
        jumbf_io,
        utils::{
            test::{create_test_streams, test_context},
            test_signer::test_signer,
        },
        HashRange, Reader, SigningAlg, ValidationState,
    };

    const TEST_IMAGE_CLEAN: &[u8] = include_bytes!("../tests/fixtures/IMG_0003.jpg");

    /// A `Context` with `prefer_box_hash` enabled (so JPEG signing needs no placeholder) and a
    /// signer configured, for `ClaimBuilder::sign()` to use.
    fn pbh_context() -> Arc<Context> {
        Arc::new(
            Context::new()
                .with_settings(
                    serde_json::json!({"builder": {"prefer_box_hash": true}}).to_string(),
                )
                .expect("valid settings")
                .with_signer(test_signer(SigningAlg::Ps256)),
        )
    }

    #[test]
    fn test_claim_builder_end_to_end_ingredient_and_actions() {
        let mut stream = Cursor::new(TEST_IMAGE_CLEAN);
        let context = pbh_context();

        let mut claim_builder = ClaimBuilder::new(context.clone());
        claim_builder.set_title("Test ClaimBuilder end to end");

        // Ingredient thumbnail as a binary EmbeddedData assertion — returns a HashedUri.
        let thumb_uri = claim_builder
            .add_gathered_assertion(
                ClaimAssertion::new(crate::assertions::labels::INGREDIENT_THUMBNAIL).with_stream(
                    "image/jpeg",
                    &mut Cursor::new(b"thumbnail bytes".as_slice()),
                ),
            )
            .expect("add ingredient thumbnail");

        // Ingredient assertion referencing the thumbnail directly by HashedUri.
        let ing_assertion = IngredientAssertion::new_v3(Relationship::ParentOf)
            .set_title("Test Ingredient")
            .set_format("image/jpeg")
            .set_thumbnail(Some(&thumb_uri));
        let ing_uri = claim_builder
            .add_gathered_assertion(
                ClaimAssertion::new(IngredientAssertion::LABEL)
                    .with_json(&ing_assertion)
                    .expect("with_json"),
            )
            .expect("add ingredient assertion");

        // Actions referencing the ingredient directly by HashedUri.
        let action = Action::new(c2pa_action::OPENED).add_ingredient_ref(ing_uri);
        let actions = Actions::new().add_action(action);
        claim_builder
            .add_gathered_assertion(
                ClaimAssertion::new(Actions::LABEL)
                    .with_json(&actions)
                    .expect("with_json"),
            )
            .expect("add actions assertion");

        // Hard binding — no placeholder step, generated directly from the (unmodified) asset.
        claim_builder
            .add_created_assertion(
                ClaimAssertion::new(BoxHash::LABEL).with_stream("image/jpeg", &mut stream),
            )
            .expect("set hard binding");

        let jumbf = claim_builder.sign().expect("sign");

        let mut embedded_stream = Cursor::new(Vec::new());
        jumbf_io::save_jumbf_to_stream("image/jpeg", &mut stream, &mut embedded_stream, &jumbf)
            .expect("save jumbf to stream");
        embedded_stream.set_position(0);

        let reader = Reader::default()
            .with_stream("image/jpeg", &mut embedded_stream)
            .expect("read signed asset");
        assert_eq!(
            reader.validation_state(),
            ValidationState::Trusted,
            "manifest should validate as trusted"
        );

        let manifest = reader.active_manifest().expect("active manifest");
        assert_eq!(manifest.ingredients().len(), 1, "expected one ingredient");
        assert_eq!(manifest.ingredients()[0].title(), Some("Test Ingredient"));

        let found_actions: Actions = manifest
            .find_assertion(Actions::LABEL)
            .expect("actions assertion in manifest");
        assert_eq!(found_actions.actions()[0].action(), c2pa_action::OPENED);
        assert!(
            found_actions.actions()[0]
                .parameters()
                .and_then(|p| p.ingredients.as_ref())
                .is_some(),
            "opened action should reference the ingredient"
        );
    }

    #[test]
    fn test_claim_builder_gathered_vs_created_assertion() {
        let mut stream = Cursor::new(TEST_IMAGE_CLEAN);
        let context = pbh_context();

        let mut claim_builder = ClaimBuilder::new(context.clone());
        claim_builder.set_title("Test gathered vs created");

        claim_builder
            .add_gathered_assertion(
                ClaimAssertion::new("org.test.gathered")
                    .with_json(&serde_json::json!({"value": 1}))
                    .expect("with_json"),
            )
            .expect("gathered assertion");
        claim_builder
            .add_created_assertion(
                ClaimAssertion::new("org.test.created")
                    .with_json(&serde_json::json!({"value": 2}))
                    .expect("with_json"),
            )
            .expect("created assertion");

        // At least one c2pa.created/c2pa.opened action is required by spec.
        let action = Action::new(c2pa_action::CREATED).set_source_type(DigitalSourceType::Empty);
        claim_builder
            .add_gathered_assertion(
                ClaimAssertion::new(Actions::LABEL)
                    .with_json(&Actions::new().add_action(action))
                    .expect("with_json"),
            )
            .expect("add actions assertion");

        claim_builder
            .add_created_assertion(
                ClaimAssertion::new(BoxHash::LABEL).with_stream("image/jpeg", &mut stream),
            )
            .expect("set hard binding");

        let jumbf = claim_builder.sign().expect("sign");

        let mut embedded_stream = Cursor::new(Vec::new());
        jumbf_io::save_jumbf_to_stream("image/jpeg", &mut stream, &mut embedded_stream, &jumbf)
            .expect("save jumbf to stream");
        embedded_stream.set_position(0);

        let reader = Reader::default()
            .with_stream("image/jpeg", &mut embedded_stream)
            .expect("read signed asset");
        assert_eq!(reader.validation_state(), ValidationState::Trusted);

        let manifest = reader.active_manifest().expect("active manifest");
        let gathered = manifest
            .assertions()
            .iter()
            .find(|a| a.label() == "org.test.gathered")
            .expect("gathered assertion in manifest");
        assert!(!gathered.created(), "should be gathered");

        let created = manifest
            .assertions()
            .iter()
            .find(|a| a.label() == "org.test.created")
            .expect("created assertion in manifest");
        assert!(created.created(), "should be created");
    }

    #[test]
    fn test_claim_builder_add_gathered_ingredient_with_reader() {
        let (format, mut ingredient_stream, _) = create_test_streams("C.jpg");

        let mut claim_builder = ClaimBuilder::new(Arc::new(test_context()));
        claim_builder.set_title("Test add_gathered_ingredient with reader");

        let ing_uri = claim_builder
            .add_gathered_assertion(
                ClaimAssertion::new(IngredientAssertion::LABEL)
                    .with_json(&serde_json::json!({
                        "relationship": "parentOf", "dc:title": "C.jpg", "dc:format": "image/jpeg"
                    }))
                    .expect("with_json")
                    .with_stream(format, &mut ingredient_stream),
            )
            .expect("add gathered ingredient with stream");

        let action = Action::new(c2pa_action::OPENED).add_ingredient_ref(ing_uri.clone());
        claim_builder
            .add_gathered_assertion(
                ClaimAssertion::new(Actions::LABEL)
                    .with_json(&Actions::new().add_action(action))
                    .expect("with_json"),
            )
            .expect("add actions assertion");

        // Not signing here (DataHash over an arbitrary stream would need a placeholder we don't
        // have) — this test only exercises the ingredient merge, so verify the assertion landed
        // with a resolved manifest link by inspecting the claim's assertion store directly.
        let decoded: IngredientAssertion = claim_builder
            .claim
            .claim_assertion_store()
            .iter()
            .find(|ca| ca.label_raw().starts_with(IngredientAssertion::LABEL))
            .map(|ca| IngredientAssertion::from_assertion(ca.assertion()).expect("decode"))
            .expect("ingredient assertion present");
        assert!(
            decoded.active_manifest.is_some(),
            "ingredient should resolve to its own embedded manifest"
        );
    }

    #[test]
    fn test_claim_builder_add_gathered_ingredient_without_stream() {
        let mut claim_builder = ClaimBuilder::new(Arc::new(test_context()));

        let ing_assertion = IngredientAssertion::new_v3(Relationship::ComponentOf)
            .set_title("no provenance")
            .set_format("image/jpeg");
        claim_builder
            .add_gathered_assertion(
                ClaimAssertion::new(IngredientAssertion::LABEL)
                    .with_json(&ing_assertion)
                    .expect("with_json"),
            )
            .expect("add ingredient without stream");

        let decoded: IngredientAssertion = claim_builder
            .claim
            .claim_assertion_store()
            .iter()
            .find(|ca| ca.label_raw().starts_with(IngredientAssertion::LABEL))
            .map(|ca| IngredientAssertion::from_assertion(ca.assertion()).expect("decode"))
            .expect("ingredient assertion present");
        assert_eq!(decoded.title, Some("no provenance".to_string()));
        assert!(
            decoded.active_manifest.is_none(),
            "no stream means no manifest link to resolve"
        );
    }

    #[test]
    fn test_claim_builder_hard_binding_set_and_update() {
        let context = Arc::new(test_context());
        let mut claim_builder = ClaimBuilder::new(context.clone());

        let mut stream1 = Cursor::new(vec![1u8; 100]);
        claim_builder
            .add_created_assertion(
                ClaimAssertion::new(DataHash::LABEL).with_stream("image/jpeg", &mut stream1),
            )
            .expect("set hard binding");

        // A same-type replacement should succeed automatically (existing_hard_binding() found).
        let mut stream3 = Cursor::new(vec![3u8; 100]);
        claim_builder
            .add_created_assertion(
                ClaimAssertion::new(DataHash::LABEL).with_stream("image/jpeg", &mut stream3),
            )
            .expect("update hard binding");

        // A different-type replacement should fail.
        let mut stream4 = Cursor::new(vec![0u8; 64]);
        assert!(
            claim_builder
                .add_created_assertion(
                    ClaimAssertion::new(BmffHash::LABEL).with_stream("video/mp4", &mut stream4),
                )
                .is_err(),
            "replacing with a different hard-binding kind should fail"
        );
    }

    #[test]
    fn test_claim_builder_update_hard_binding_rejects_larger_replacement() {
        let context = Arc::new(test_context());
        let mut claim_builder = ClaimBuilder::new(context.clone());

        // No exclusions — the smallest possible DataHash encoding.
        let mut stream1 = Cursor::new(vec![1u8; 100]);
        claim_builder
            .add_created_assertion(
                ClaimAssertion::new(DataHash::LABEL).with_stream("image/jpeg", &mut stream1),
            )
            .expect("set hard binding");

        // Extra exclusions make this replacement's encoded size strictly larger.
        let mut stream2 = Cursor::new(vec![2u8; 100]);
        assert!(
            claim_builder
                .add_created_assertion(
                    ClaimAssertion::new(DataHash::LABEL)
                        .with_stream("image/jpeg", &mut stream2)
                        .with_exclusions(vec![HashRange::new(0, 10), HashRange::new(20, 10)]),
                )
                .is_err(),
            "a strictly larger replacement should be rejected"
        );
    }

    #[test]
    fn test_claim_builder_sign_without_hard_binding_errors() {
        let claim_builder = ClaimBuilder::new(pbh_context());
        let result = claim_builder.sign();
        assert!(
            matches!(result, Err(Error::BadParam(_))),
            "sign() without a hard binding should error, got {result:?}"
        );
    }

    #[test]
    fn test_claim_builder_hard_binding_as_gathered_errors() {
        let context = Arc::new(test_context());
        let mut claim_builder = ClaimBuilder::new(context.clone());

        let mut stream = Cursor::new(vec![1u8; 100]);
        let result = claim_builder.add_gathered_assertion(
            ClaimAssertion::new(DataHash::LABEL).with_stream("image/jpeg", &mut stream),
        );
        assert!(
            matches!(result, Err(Error::BadParam(_))),
            "a hard binding added via add_gathered_assertion should error, got {result:?}"
        );
    }
}
