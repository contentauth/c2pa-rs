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
//! [`ClaimAssertion`] — a small builder that carries whatever a label needs (structured data, a
//! stream, hard-binding exclusions, an ingredient's sidecar manifest data) — and is interpreted
//! using this `ClaimBuilder`'s own [`Context`] only once it's added via
//! [`ClaimBuilder::add_gathered_assertion`]/[`ClaimBuilder::add_created_assertion`].
//!
//! `ClaimBuilder` never manages placeholder/reserve-space embedding itself — the caller is
//! expected to have already reserved space for, and embedded, the manifest placeholder in the
//! asset before adding a hard-binding assertion or calling [`ClaimBuilder::sign`].

use std::sync::Arc;

use crate::{
    assertion::AssertionBase,
    assertions::{
        labels::parse_label, Actions, BmffHash, BoxHash, DataHash, EmbeddedData,
        IngredientAssertion, Metadata, UserCbor,
    },
    claim::Claim,
    claim_assertion::ClaimAssertion,
    context::Context,
    error::{Error, Result},
    hard_binding::{generate_hard_binding, HardBindingAssertion},
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
    /// Hash assertions (`BoxHash`/`DataHash`/`BmffHash`) are always stored as *created* by
    /// `Claim` regardless of which method adds them. Use [`ClaimBuilder::add_created_assertion`]
    /// to add any other assertion as *created* instead.
    pub fn add_gathered_assertion(&mut self, assertion: ClaimAssertion) -> Result<HashedUri> {
        self.insert_claim_assertion(assertion, false)
    }

    /// Same as [`ClaimBuilder::add_gathered_assertion`], but adds the assertion as *created*
    /// rather than *gathered* (mirroring `Claim::add_created_assertion`). Has no effect on hash
    /// assertions ([`BoxHash`]/[`DataHash`]/[`BmffHash`]), which are always created regardless.
    pub fn add_created_assertion(&mut self, assertion: ClaimAssertion) -> Result<HashedUri> {
        self.insert_claim_assertion(assertion, true)
    }

    fn insert_claim_assertion(
        &mut self,
        assertion: ClaimAssertion,
        created: bool,
    ) -> Result<HashedUri> {
        let ClaimAssertion {
            label,
            value,
            stream,
            c2pa_data,
            exclusions,
        } = assertion;
        let (match_label, version, _instance) = parse_label(&label);

        match match_label {
            DataHash::LABEL | BmffHash::LABEL | BoxHash::LABEL => {
                self.insert_hard_binding(match_label, version, stream, exclusions)
            }
            IngredientAssertion::LABEL => self.insert_ingredient(value, stream, c2pa_data, created),
            _ => self.insert_generic(&label, match_label, value, stream, created),
        }
    }

    fn insert_generic(
        &mut self,
        label: &str,
        match_label: &str,
        value: Option<c2pa_cbor::Value>,
        stream: Option<(String, &mut dyn crate::asset_io::CAIRead)>,
        created: bool,
    ) -> Result<HashedUri> {
        if let Some((format, stream)) = stream {
            let mut data = Vec::new();
            stream.read_to_end(&mut data)?;
            let embedded_data = EmbeddedData::new(label, format_to_mime(&format), data);
            return self.insert_assertion(&embedded_data, created);
        }

        let Some(value) = value else {
            return Err(Error::BadParam(format!(
                "assertion '{label}' requires with_json or with_stream"
            )));
        };

        match match_label {
            Actions::LABEL => {
                let a: Actions = c2pa_cbor::value::from_value(value)?;
                self.insert_assertion(&a, created)
            }
            Metadata::LABEL => {
                let a: Metadata = c2pa_cbor::value::from_value(value)?;
                self.insert_assertion(&a, created)
            }
            _ => {
                let cbor_bytes = c2pa_cbor::to_vec(&value)?;
                self.insert_assertion(&UserCbor::new(label, cbor_bytes), created)
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

    fn insert_ingredient(
        &mut self,
        value: Option<c2pa_cbor::Value>,
        stream: Option<(String, &mut dyn crate::asset_io::CAIRead)>,
        c2pa_data: Option<Vec<u8>>,
        created: bool,
    ) -> Result<HashedUri> {
        let Some(value) = value else {
            return Err(Error::BadParam(format!(
                "'{}' requires with_json (the ingredient's own metadata)",
                IngredientAssertion::LABEL
            )));
        };
        let mut ing_assertion: IngredientAssertion = c2pa_cbor::value::from_value(value)?;

        let Some((format, stream)) = stream else {
            if c2pa_data.is_some() {
                return Err(Error::BadParam(format!(
                    "with_c2pa_data requires with_stream on '{}'",
                    IngredientAssertion::LABEL
                )));
            }
            return self.insert_assertion(&ing_assertion, created);
        };

        let reader = match c2pa_data {
            Some(data) => Reader::from_shared_context(&self.context)
                .with_manifest_data_and_stream(&data, &format, stream)?,
            None => Reader::from_shared_context(&self.context).with_stream(&format, stream)?,
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

    /// Generates a hard-binding assertion of the kind named by `label` (`DataHash`/`BmffHash`/
    /// `BoxHash`) from `stream`, then adds it as the claim's hard binding (first add) or
    /// replaces the existing one (every add after the first) — there can only be one per claim.
    ///
    /// A replacement must be the same kind as the existing one and no larger — the claim's byte
    /// layout must not grow. A `DataHash` replacement that's smaller is padded back up to match
    /// exactly; `BmffHash`/`BoxHash` have no padding field, so a smaller replacement is accepted
    /// as-is (the container tolerates the resulting slack).
    fn insert_hard_binding(
        &mut self,
        label: &str,
        version: usize,
        stream: Option<(String, &mut dyn crate::asset_io::CAIRead)>,
        exclusions: Option<Vec<crate::HashRange>>,
    ) -> Result<HashedUri> {
        let hash_type = match label {
            DataHash::LABEL => HashType::Data,
            BmffHash::LABEL => HashType::Bmff,
            BoxHash::LABEL => HashType::Box,
            _ => unreachable!("insert_hard_binding only called for hard-binding labels"),
        };

        if hash_type != HashType::Data && exclusions.is_some() {
            return Err(Error::BadParam(format!(
                "with_exclusions is only valid for '{}'",
                DataHash::LABEL
            )));
        }

        let Some((format, stream)) = stream else {
            return Err(Error::BadParam(format!(
                "'{label}' requires with_stream (the asset to hash)"
            )));
        };

        let binding = generate_hard_binding(
            hash_type,
            &format,
            exclusions.unwrap_or_default(),
            &self.context,
            stream,
        )?;

        match self.existing_hard_binding() {
            None => match binding {
                HardBindingAssertion::Data(dh) => self.insert_assertion(&dh, true),
                HardBindingAssertion::Bmff(mut bh) => {
                    bh.set_bmff_version(version);
                    self.insert_assertion(&bh, true)
                }
                HardBindingAssertion::Box(bh) => self.insert_assertion(&bh, true),
            },
            Some((existing_type, existing_len)) => {
                if binding.hash_type() != existing_type {
                    return Err(Error::BadParam(format!(
                        "Hard binding kind mismatch: existing is {existing_type:?}, replacement \
                         is {:?}. There can only be one hard binding per claim.",
                        binding.hash_type()
                    )));
                }

                match binding {
                    // update_data_hash() already pads to match existing_len exactly, erroring
                    // if larger.
                    HardBindingAssertion::Data(dh) => self.claim.update_data_hash(dh)?,
                    HardBindingAssertion::Bmff(mut bh) => {
                        bh.set_bmff_version(version);
                        let assertion = bh.to_assertion()?;
                        if assertion.data().len() > existing_len {
                            return Err(Error::BadParam(
                                "Replacement BmffHash is larger than the existing one — the \
                                 claim's byte layout must not grow."
                                    .to_string(),
                            ));
                        }
                        self.claim.update_bmff_hash(bh)?
                    }
                    HardBindingAssertion::Box(bh) => {
                        let assertion = bh.to_assertion()?;
                        if assertion.data().len() > existing_len {
                            return Err(Error::BadParam(
                                "Replacement BoxHash is larger than the existing one — the \
                                 claim's byte layout must not grow."
                                    .to_string(),
                            ));
                        }
                        self.claim.replace_assertion(assertion)?
                    }
                };

                self.find_hard_binding_uri(label).ok_or(Error::NotFound)
            }
        }
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
            .add_gathered_assertion(
                ClaimAssertion::new(BoxHash::LABEL).with_stream("image/jpeg", &mut stream),
            )
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
            .add_gathered_assertion(
                ClaimAssertion::new(BoxHash::LABEL).with_stream("image/jpeg", &mut stream),
            )
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
            .add_gathered_assertion(
                ClaimAssertion::new(DataHash::LABEL).with_stream("image/jpeg", &mut stream1),
            )
            .expect("set hard binding");

        // A same-type replacement should succeed automatically (existing_hard_binding() found).
        let mut stream3 = Cursor::new(vec![3u8; 100]);
        claim_builder
            .add_gathered_assertion(
                ClaimAssertion::new(DataHash::LABEL).with_stream("image/jpeg", &mut stream3),
            )
            .expect("update hard binding");

        // A different-type replacement should fail.
        let mut stream4 = Cursor::new(vec![0u8; 64]);
        assert!(
            claim_builder
                .add_gathered_assertion(
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
            .add_gathered_assertion(
                ClaimAssertion::new(DataHash::LABEL).with_stream("image/jpeg", &mut stream1),
            )
            .expect("set hard binding");

        // Extra exclusions make this replacement's encoded size strictly larger.
        let mut stream2 = Cursor::new(vec![2u8; 100]);
        assert!(
            claim_builder
                .add_gathered_assertion(
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
}
