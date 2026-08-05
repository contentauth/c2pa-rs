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
//! the ingredient it operated on) before signing. Asset input is limited to two places: reading
//! an already-validated ingredient [`Reader`], and generating hard-binding assertions from an
//! asset stream via [`crate::HardBinding`]. Everything else is caller-supplied in-memory data.
//!
//! `ClaimBuilder` never manages placeholder/reserve-space embedding itself — the caller is
//! expected to have already reserved space for, and embedded, the manifest placeholder in the
//! asset before calling [`ClaimBuilder::set_hard_binding`]/[`ClaimBuilder::update_hard_binding`]
//! or [`ClaimBuilder::sign`].

use std::{io::Read, sync::Arc};

use serde::Serialize;

use crate::{
    assertion::AssertionBase,
    assertions::{
        labels::parse_label, Actions, BmffHash, BoxHash, DataHash, EmbeddedData,
        IngredientAssertion, Metadata, UserCbor,
    },
    claim::Claim,
    context::Context,
    error::{Error, Result},
    hard_binding::HardBindingAssertion,
    jumbf::labels::{to_assertion_uri, to_manifest_uri, to_signature_uri},
    store::Store,
    utils::mime::format_to_mime,
    HashType, HashedUri, Reader,
};

/// Builds a `Claim` directly and eagerly. See the module documentation for the model this
/// implements and how it differs from [`crate::Builder`].
pub struct ClaimBuilder {
    claim: Claim,
    context: Arc<Context>,
    is_update: bool,
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

    /// Adds the single default `ClaimGeneratorInfo` entry every v2+ claim must carry (required
    /// by `Claim::verify_claim_generator_info`) — pulled from `Context` settings
    /// (`builder.claim_generator_info`) if configured, else [`ClaimGeneratorInfo::default`].
    /// Mirrors the fallback half of `Builder::to_claim()`'s own claim_generator_info handling;
    /// unlike `Builder::set_claim_generator_info`, there is no way to add more than this one
    /// entry on `ClaimBuilder` yet.
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

        Self {
            claim,
            context,
            is_update: false,
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

    /// Adds an assertion from a label and any serializable data, and returns its [`HashedUri`].
    ///
    /// If `label` matches a known assertion type (e.g. [`crate::assertions::labels::ACTIONS`],
    /// [`IngredientAssertion::LABEL`], [`BoxHash::LABEL`], [`DataHash::LABEL`],
    /// [`BmffHash::LABEL`], `Metadata::LABEL`), `data` is decoded into that concrete type so
    /// it's stored with its native schema. Otherwise `data` is wrapped generically in a
    /// `UserCbor` assertion under `label`.
    ///
    /// Added as *gathered* (mirroring `Claim::add_assertion`'s default), except hash
    /// assertions ([`BoxHash`]/[`DataHash`]/[`BmffHash`]), which `Claim` always adds as
    /// *created* regardless. Use [`ClaimBuilder::add_created_assertion`] to add any other
    /// assertion as *created* instead.
    pub fn add_gathered_assertion<S, T>(&mut self, label: S, data: &T) -> Result<HashedUri>
    where
        S: Into<String>,
        T: Serialize,
    {
        self.add_assertion_impl(label.into(), data, false)
    }

    /// Same as [`ClaimBuilder::add_gathered_assertion`], but adds the assertion as *created*
    /// rather than *gathered* (mirroring `Claim::add_created_assertion`). Has no effect on
    /// hash assertions ([`BoxHash`]/[`DataHash`]/[`BmffHash`]), which are always created
    /// regardless — see [`ClaimBuilder::add_gathered_assertion`].
    pub fn add_created_assertion<S, T>(&mut self, label: S, data: &T) -> Result<HashedUri>
    where
        S: Into<String>,
        T: Serialize,
    {
        self.add_assertion_impl(label.into(), data, true)
    }

    fn add_assertion_impl<T>(&mut self, label: String, data: &T, created: bool) -> Result<HashedUri>
    where
        T: Serialize,
    {
        let (match_label, version, _instance) = parse_label(&label);
        let cbor_value = c2pa_cbor::value::to_value(data)?;

        match match_label {
            Actions::LABEL => {
                let a: Actions = c2pa_cbor::value::from_value(cbor_value)?;
                self.insert_assertion(&a, created)
            }
            IngredientAssertion::LABEL => {
                let a: IngredientAssertion = c2pa_cbor::value::from_value(cbor_value)?;
                self.insert_assertion(&a, created)
            }
            BoxHash::LABEL => {
                let a: BoxHash = c2pa_cbor::value::from_value(cbor_value)?;
                self.insert_assertion(&a, created)
            }
            DataHash::LABEL => {
                let a: DataHash = c2pa_cbor::value::from_value(cbor_value)?;
                self.insert_assertion(&a, created)
            }
            BmffHash::LABEL => {
                let mut a: BmffHash = c2pa_cbor::value::from_value(cbor_value)?;
                a.set_bmff_version(version);
                self.insert_assertion(&a, created)
            }
            Metadata::LABEL => {
                // Metadata::to_assertion() always writes JSON
                let a: Metadata = serde_json::from_value(serde_json::to_value(data)?)?;
                self.insert_assertion(&a, created)
            }
            _ => {
                let cbor_bytes = c2pa_cbor::to_vec(data)?;
                self.insert_assertion(&UserCbor::new(&label, cbor_bytes), created)
            }
        }
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

    /// Adds an [`EmbeddedData`] assertion from a stream and returns its [`HashedUri`].
    ///
    /// Convenience wrapper for binary resources (thumbnails, icons, arbitrary resources).
    /// `label` determines the assertion type (e.g. [`crate::assertions::labels::EMBEDDED_DATA`]
    /// or [`crate::assertions::labels::CLAIM_THUMBNAIL`]). Added as *gathered* — see
    /// [`ClaimBuilder::add_created_data`] for the *created* variant.
    pub fn add_gathered_data(
        &mut self,
        label: &str,
        format: &str,
        stream: &mut impl Read,
    ) -> Result<HashedUri> {
        self.add_data_impl(label, format, stream, false)
    }

    /// Same as [`ClaimBuilder::add_gathered_data`], but adds the assertion as *created* rather
    /// than *gathered*.
    pub fn add_created_data(
        &mut self,
        label: &str,
        format: &str,
        stream: &mut impl Read,
    ) -> Result<HashedUri> {
        self.add_data_impl(label, format, stream, true)
    }

    fn add_data_impl(
        &mut self,
        label: &str,
        format: &str,
        stream: &mut impl Read,
        created: bool,
    ) -> Result<HashedUri> {
        let mut data = Vec::new();
        stream.read_to_end(&mut data)?;
        let embedded_data = EmbeddedData::new(label, format_to_mime(format), data);
        self.insert_assertion(&embedded_data, created)
    }

    /// Adds an ingredient assertion built from an [`IngredientAssertion`] and, optionally, an
    /// already-read [`Reader`], returning the assertion's [`HashedUri`]. Added as *gathered* —
    /// see [`ClaimBuilder::add_created_ingredient`] for the *created* variant.
    ///
    /// * `reader = Some(r)` — `r` has already read and validated the ingredient's own asset.
    ///   Its manifest data is merged into this claim's ingredient store, and
    ///   `active_manifest`/`claim_signature`/`validation_results` on the assertion are filled in
    ///   from it (overwriting whatever was already set on `ingredient_assertion`).
    /// * `reader = None` — the ingredient has no provenance of its own to merge in (no manifest
    ///   chain, no redactions): the assertion is added as-is, exactly like
    ///   [`ClaimBuilder::add_gathered_assertion`]/[`ClaimBuilder::add_created_assertion`] would.
    ///
    /// `redactions` is a list of JUMBF URIs of assertions to strip from the ingredient's
    /// manifest chain as it's merged in (only meaningful when `reader` is `Some`; empty if
    /// none). This only performs the mechanical redaction; it deliberately does *not* auto-add
    /// the corresponding `c2pa.redacted` action — the caller is responsible for separately
    /// recording one action per redacted URI, since the required `reason` is caller-specific
    /// domain knowledge this method has no way to infer.
    pub fn add_gathered_ingredient<T>(
        &mut self,
        ingredient_assertion: T,
        reader: Option<&Reader>,
        redactions: Vec<String>,
    ) -> Result<HashedUri>
    where
        T: TryInto<IngredientAssertion>,
        Error: From<T::Error>,
    {
        self.add_ingredient_impl(ingredient_assertion, reader, redactions, false)
    }

    /// Same as [`ClaimBuilder::add_gathered_ingredient`], but adds the assertion as *created*
    /// rather than *gathered*.
    pub fn add_created_ingredient<T>(
        &mut self,
        ingredient_assertion: T,
        reader: Option<&Reader>,
        redactions: Vec<String>,
    ) -> Result<HashedUri>
    where
        T: TryInto<IngredientAssertion>,
        Error: From<T::Error>,
    {
        self.add_ingredient_impl(ingredient_assertion, reader, redactions, true)
    }

    fn add_ingredient_impl<T>(
        &mut self,
        ingredient_assertion: T,
        reader: Option<&Reader>,
        redactions: Vec<String>,
        created: bool,
    ) -> Result<HashedUri>
    where
        T: TryInto<IngredientAssertion>,
        Error: From<T::Error>,
    {
        let mut ing_assertion: IngredientAssertion = ingredient_assertion.try_into()?;

        let Some(reader) = reader else {
            return self.insert_assertion(&ing_assertion, created);
        };

        // If the ingredient assertion already carries a manifest link (e.g. it was decoded via
        // `Reader::read_assertion` out of a larger store), scope to that specific claim rather
        // than assuming `reader` is a single-ingredient reader.
        let target_claim = match ing_assertion
            .active_manifest
            .as_ref()
            .or(ing_assertion.c2pa_manifest.as_ref())
        {
            Some(uri) => {
                let label = Store::manifest_label_from_path(&uri.url());
                reader
                    .store
                    .get_claim(&label)
                    .ok_or(Error::ClaimMissing { label })?
            }
            None => reader
                .store
                .provenance_claim()
                .ok_or(Error::JumbfNotFound)?,
        };

        let validation_results = reader.validation_results().cloned().unwrap_or_default();
        let ingredient_scope = Store::build_flat_ingredient_store(&reader.store, target_claim)?;
        let manifest_bytes = ingredient_scope.to_jumbf_internal(0)?;

        let redactions = (!redactions.is_empty()).then_some(redactions);
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

        ing_assertion.active_manifest = Some(HashedUri::new(
            to_manifest_uri(manifest_label),
            alg.clone(),
            hashes.manifest_box_hash.as_ref(),
        ));
        ing_assertion.claim_signature = Some(HashedUri::new(
            to_signature_uri(manifest_label),
            alg,
            hashes.signature_box_hash.as_ref(),
        ));
        ing_assertion.validation_results = Some(validation_results);

        self.insert_assertion(&ing_assertion, created)
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

    /// First-time add of the claim's hard binding. Typically a placeholder-shaped value the
    /// caller constructs directly (correct type/size, dummy hash) before they've embedded
    /// anything into the real asset — `ClaimBuilder` never manages placeholder embedding
    /// itself, that's entirely the caller's job. Errors if a hard binding already exists — use
    /// [`ClaimBuilder::update_hard_binding`] to replace it.
    pub fn set_hard_binding(&mut self, binding: HardBindingAssertion) -> Result<HashedUri> {
        if self.existing_hard_binding().is_some() {
            return Err(Error::BadParam(
                "A hard binding assertion already exists — use update_hard_binding() to replace \
                 it."
                .to_string(),
            ));
        }
        match binding {
            HardBindingAssertion::Data(dh) => self.insert_assertion(&dh, true),
            HardBindingAssertion::Bmff(bh) => self.insert_assertion(&bh, true),
            HardBindingAssertion::Box(bh) => self.insert_assertion(&bh, true),
        }
    }

    /// Replaces the existing hard binding — the normal second half of the
    /// [`ClaimBuilder::set_hard_binding`]/`update_hard_binding` pair, called once the caller has
    /// embedded the placeholder into the real asset and computed the real value (typically via
    /// [`crate::HardBinding::generate`] reading that finished asset).
    ///
    /// There can only be one hard binding per claim, so this both verifies `binding` is the
    /// *same kind* (Data/Bmff/Box) as the one it's replacing, and that it's no larger — the
    /// claim's byte layout must not grow. A [`DataHash`] replacement that's smaller is padded
    /// back up to match exactly; `BmffHash`/`BoxHash` have no padding field, so a smaller
    /// replacement is accepted as-is (the container tolerates the resulting slack; see
    /// [`crate::Builder::placeholder`]'s note on converting extra reserved space to a "free" box).
    ///
    /// Errors if there is no existing hard binding, if `binding`'s kind differs from the
    /// existing one, or if `binding` is larger than the existing one.
    pub fn update_hard_binding(&mut self, binding: HardBindingAssertion) -> Result<HashedUri> {
        let Some((existing_type, existing_len)) = self.existing_hard_binding() else {
            return Err(Error::BadParam(
                "No existing hard binding assertion to update. Call set_hard_binding() first."
                    .to_string(),
            ));
        };

        if binding.hash_type() != existing_type {
            return Err(Error::BadParam(format!(
                "Hard binding kind mismatch: existing is {existing_type:?}, replacement is \
                 {:?}. There can only be one hard binding per claim.",
                binding.hash_type()
            )));
        }

        let label_prefix = match &binding {
            HardBindingAssertion::Data(_) => DataHash::LABEL,
            HardBindingAssertion::Bmff(_) => BmffHash::LABEL,
            HardBindingAssertion::Box(_) => BoxHash::LABEL,
        };

        match binding {
            // update_data_hash() already pads to match existing_len exactly, erroring if larger.
            HardBindingAssertion::Data(dh) => self.claim.update_data_hash(dh)?,
            HardBindingAssertion::Bmff(bh) => {
                let assertion = bh.to_assertion()?;
                if assertion.data().len() > existing_len {
                    return Err(Error::BadParam(
                        "Replacement BmffHash is larger than the existing one — the claim's \
                         byte layout must not grow."
                            .to_string(),
                    ));
                }
                self.claim.update_bmff_hash(bh)?
            }
            HardBindingAssertion::Box(bh) => {
                let assertion = bh.to_assertion()?;
                if assertion.data().len() > existing_len {
                    return Err(Error::BadParam(
                        "Replacement BoxHash is larger than the existing one — the claim's byte \
                         layout must not grow."
                            .to_string(),
                    ));
                }
                self.claim.replace_assertion(assertion)?
            }
        };

        self.find_hard_binding_uri(label_prefix)
            .ok_or(Error::NotFound)
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
    /// have already added a real hard binding via
    /// [`ClaimBuilder::set_hard_binding`]/[`ClaimBuilder::update_hard_binding`].
    pub fn sign(&self) -> Result<Vec<u8>> {
        if self.existing_hard_binding().is_none() {
            return Err(Error::BadParam(
                "No hard binding assertion found. Call set_hard_binding() before sign()."
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
        hard_binding::HardBinding,
        jumbf_io,
        utils::{
            test::{create_test_streams, test_context},
            test_signer::test_signer,
        },
        HashRange, SigningAlg, ValidationState,
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

    /// Signs `claim_builder` (which must already have a `BoxHash` hard binding matching
    /// `stream`'s current content) and embeds the raw JUMBF into `stream` via
    /// `jumbf_io::save_jumbf_to_stream` (which handles the format-specific box/segment
    /// insertion itself), returning the embedded bytes.
    fn sign_and_embed(claim_builder: &ClaimBuilder, stream: &mut Cursor<&[u8]>) -> Vec<u8> {
        let jumbf = claim_builder.sign().expect("sign");

        stream.set_position(0);
        let mut output = Cursor::new(Vec::new());
        jumbf_io::save_jumbf_to_stream("image/jpeg", stream, &mut output, &jumbf)
            .expect("save jumbf to stream");
        output.into_inner()
    }

    #[test]
    fn test_claim_builder_end_to_end_ingredient_and_actions() {
        let mut stream = Cursor::new(TEST_IMAGE_CLEAN);
        let context = pbh_context();

        let mut claim_builder = ClaimBuilder::new(context.clone());
        claim_builder.set_title("Test ClaimBuilder end to end");

        // Ingredient thumbnail as a binary EmbeddedData assertion — returns a HashedUri.
        let thumb_uri = claim_builder
            .add_gathered_data(
                crate::assertions::labels::INGREDIENT_THUMBNAIL,
                "image/jpeg",
                &mut Cursor::new(b"thumbnail bytes".as_slice()),
            )
            .expect("add ingredient thumbnail");

        // Ingredient assertion referencing the thumbnail directly by HashedUri.
        let ing_assertion = IngredientAssertion::new_v3(Relationship::ParentOf)
            .set_title("Test Ingredient")
            .set_format("image/jpeg")
            .set_thumbnail(Some(&thumb_uri));
        let ing_uri = claim_builder
            .add_gathered_assertion(IngredientAssertion::LABEL, &ing_assertion)
            .expect("add ingredient assertion");

        // Actions referencing the ingredient directly by HashedUri.
        let action = Action::new(c2pa_action::OPENED).add_ingredient_ref(ing_uri);
        let actions = Actions::new().add_action(action);
        claim_builder
            .add_gathered_assertion(Actions::LABEL, &actions)
            .expect("add actions assertion");

        // Hard binding — no placeholder step, generated directly from the (unmodified) asset.
        let binding = HardBinding::new("image/jpeg", &context)
            .generate(&context, &mut stream)
            .expect("generate hard binding");
        claim_builder
            .set_hard_binding(binding)
            .expect("set hard binding");

        let embedded = sign_and_embed(&claim_builder, &mut stream);

        let mut embedded_stream = Cursor::new(embedded);
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
            .add_gathered_assertion("org.test.gathered", &serde_json::json!({"value": 1}))
            .expect("gathered assertion");
        claim_builder
            .add_created_assertion("org.test.created", &serde_json::json!({"value": 2}))
            .expect("created assertion");

        // At least one c2pa.created/c2pa.opened action is required by spec.
        let action = Action::new(c2pa_action::CREATED).set_source_type(DigitalSourceType::Empty);
        claim_builder
            .add_gathered_assertion(Actions::LABEL, &Actions::new().add_action(action))
            .expect("add actions assertion");

        let binding = HardBinding::new("image/jpeg", &context)
            .generate(&context, &mut stream)
            .expect("generate hard binding");
        claim_builder
            .set_hard_binding(binding)
            .expect("set hard binding");

        let embedded = sign_and_embed(&claim_builder, &mut stream);
        let mut embedded_stream = Cursor::new(embedded);
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
        let ingredient_reader = Reader::default()
            .with_stream(format, &mut ingredient_stream)
            .expect("read ingredient asset");

        let mut claim_builder = ClaimBuilder::new(Arc::new(test_context()));
        claim_builder.set_title("Test add_gathered_ingredient with reader");

        let ing_uri = claim_builder
            .add_gathered_ingredient(
                r#"{"relationship": "parentOf", "dc:title": "C.jpg", "dc:format": "image/jpeg"}"#,
                Some(&ingredient_reader),
                vec![],
            )
            .expect("add gathered ingredient with reader");

        let action = Action::new(c2pa_action::OPENED).add_ingredient_ref(ing_uri.clone());
        claim_builder
            .add_gathered_assertion(Actions::LABEL, &Actions::new().add_action(action))
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
    fn test_claim_builder_add_gathered_ingredient_without_reader() {
        let mut claim_builder = ClaimBuilder::new(Arc::new(test_context()));

        let ing_assertion = IngredientAssertion::new_v3(Relationship::ComponentOf)
            .set_title("no provenance")
            .set_format("image/jpeg");
        claim_builder
            .add_gathered_ingredient(ing_assertion, None, vec![])
            .expect("add ingredient without reader");

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
            "no reader means no manifest link to resolve"
        );
    }

    #[test]
    fn test_claim_builder_hard_binding_set_and_update() {
        let context = Arc::new(test_context());
        let mut claim_builder = ClaimBuilder::new(context.clone());

        let mut stream1 = Cursor::new(vec![1u8; 100]);
        let binding1 = HardBinding::new("image/jpeg", &context)
            .generate(&context, &mut stream1)
            .expect("generate first binding");
        claim_builder
            .set_hard_binding(binding1)
            .expect("set hard binding");

        // Setting again should fail — must use update_hard_binding.
        let mut stream2 = Cursor::new(vec![2u8; 100]);
        let binding2 = HardBinding::new("image/jpeg", &context)
            .generate(&context, &mut stream2)
            .expect("generate second binding");
        assert!(
            claim_builder.set_hard_binding(binding2).is_err(),
            "set_hard_binding should refuse to overwrite an existing binding"
        );

        // A same-type replacement should succeed via update_hard_binding.
        let mut stream3 = Cursor::new(vec![3u8; 100]);
        let binding3 = HardBinding::new("image/jpeg", &context)
            .generate(&context, &mut stream3)
            .expect("generate third binding");
        claim_builder
            .update_hard_binding(binding3)
            .expect("update hard binding");

        // A different-type replacement should fail.
        let mut stream4 = Cursor::new(vec![0u8; 64]);
        let bmff_binding = HardBinding::new("video/mp4", &context)
            .generate(&context, &mut stream4)
            .expect("generate bmff binding");
        assert!(
            claim_builder.update_hard_binding(bmff_binding).is_err(),
            "update_hard_binding should refuse a type mismatch"
        );
    }

    #[test]
    fn test_claim_builder_update_hard_binding_rejects_larger_replacement() {
        let context = Arc::new(test_context());
        let mut claim_builder = ClaimBuilder::new(context.clone());

        // No exclusions — the smallest possible DataHash encoding.
        let mut stream1 = Cursor::new(vec![1u8; 100]);
        let binding1 = HardBinding::new("image/jpeg", &context)
            .generate(&context, &mut stream1)
            .expect("generate first binding");
        claim_builder
            .set_hard_binding(binding1)
            .expect("set hard binding");

        // Extra exclusions make this replacement's encoded size strictly larger.
        let mut stream2 = Cursor::new(vec![2u8; 100]);
        let mut larger = HardBinding::new("image/jpeg", &context);
        larger.set_exclusions(vec![HashRange::new(0, 10), HashRange::new(20, 10)]);
        let larger_binding = larger
            .generate(&context, &mut stream2)
            .expect("generate larger binding");

        assert!(
            claim_builder.update_hard_binding(larger_binding).is_err(),
            "update_hard_binding should refuse a strictly larger replacement"
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
}
