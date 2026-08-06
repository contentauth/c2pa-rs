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

//! Describes one assertion to add to a [`crate::ClaimBuilder`].
//!
//! [`ClaimAssertion`] is a builder: start with [`ClaimAssertion::new`] and a label, then attach
//! whichever of `with_json`/`with_stream`/`with_c2pa_data`/`with_exclusions` that label needs.
//! Nothing is validated or converted until [`ClaimAssertion::generate`] runs — called by
//! [`crate::ClaimBuilder::add_gathered_assertion`]/[`crate::ClaimBuilder::add_created_assertion`]
//! — which is also where the `ClaimBuilder`'s own [`Context`] gets used (for hard-binding hash
//! generation and ingredient provenance reading). `ClaimBuilder` itself only adds the resulting
//! concrete assertion to the claim, and — for hard-binding labels — checks it against whatever
//! hard binding is already there.

use std::{io::Read, sync::Arc};

use serde::Serialize;

use crate::{
    assertion::AssertionBase,
    assertions::{
        labels::parse_label, Actions, BmffHash, BoxHash, DataHash, EmbeddedData,
        IngredientAssertion, Metadata, UserCbor,
    },
    asset_io::{CAIRead, CAIReadWrapper},
    context::{Context, ProgressPhase},
    error::{Error, Result},
    jumbf_io,
    maybe_send_sync::MaybeSend,
    store::Store,
    utils::mime::format_to_mime,
    HashRange, Reader, ValidationResults,
};

/// One assertion to add via [`crate::ClaimBuilder::add_gathered_assertion`]/
/// [`crate::ClaimBuilder::add_created_assertion`].
///
/// Which `with_*` calls are valid depends on `label`:
/// * `DataHash`/`BmffHash`/`BoxHash` labels require [`ClaimAssertion::with_stream`] (the asset to
///   hash) and accept [`ClaimAssertion::with_exclusions`] (`DataHash` only — the placeholder
///   region to exclude from hashing).
/// * [`crate::assertions::IngredientAssertion::LABEL`] requires [`ClaimAssertion::with_json`]
///   (the ingredient's own metadata) and accepts [`ClaimAssertion::with_stream`] (the
///   ingredient's own asset, to extract its provenance) plus [`ClaimAssertion::with_c2pa_data`]
///   (a sidecar/remote manifest for that asset, when its provenance isn't embedded in-band).
/// * Everything else takes [`ClaimAssertion::with_json`] (structured data — decoded into the
///   label's native schema if it's a known one, else wrapped generically) or
///   [`ClaimAssertion::with_stream`] (binary data, e.g. a thumbnail — wrapped in `EmbeddedData`).
pub struct ClaimAssertion<'a> {
    label: String,
    value: Option<c2pa_cbor::Value>,
    stream: Option<(String, &'a mut dyn CAIRead)>,
    c2pa_data: Option<Vec<u8>>,
    exclusions: Option<Vec<HashRange>>,
}

impl ClaimAssertion<'static> {
    /// Starts building an assertion under `label` (e.g.
    /// [`crate::assertions::Actions::LABEL`], [`crate::assertions::IngredientAssertion::LABEL`],
    /// `DataHash::LABEL`, or any custom reverse-domain label).
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: None,
            stream: None,
            c2pa_data: None,
            exclusions: None,
        }
    }
}

impl<'a> ClaimAssertion<'a> {
    /// Sets structured data for this assertion. If `label` matches a known assertion type, `data`
    /// is decoded into that concrete type so it's stored with its native schema; otherwise it's
    /// wrapped generically under `label`.
    pub fn with_json<T: Serialize>(mut self, data: &T) -> Result<Self> {
        self.value = Some(c2pa_cbor::value::to_value(data)?);
        Ok(self)
    }

    /// Attaches a stream to this assertion — the asset to hash (hard-binding labels), the asset
    /// to extract provenance from ([`crate::assertions::IngredientAssertion::LABEL`]), or raw
    /// binary content to store as-is (everything else). `format` is the stream's MIME type or
    /// file extension.
    pub fn with_stream<'b>(
        self,
        format: impl Into<String>,
        stream: &'b mut (impl Read + std::io::Seek + MaybeSend),
    ) -> ClaimAssertion<'b> {
        let stream: &'b mut dyn CAIRead = stream;
        ClaimAssertion {
            label: self.label,
            value: self.value,
            stream: Some((format.into(), stream)),
            c2pa_data: self.c2pa_data,
            exclusions: self.exclusions,
        }
    }

    /// Supplies the ingredient's manifest store directly (JUMBF bytes) instead of extracting it
    /// from the stream in-band — for a sidecar or remote manifest.
    /// [`crate::assertions::IngredientAssertion::LABEL`] only.
    pub fn with_c2pa_data(mut self, c2pa_data: Vec<u8>) -> Self {
        self.c2pa_data = Some(c2pa_data);
        self
    }

    /// Sets the byte ranges to exclude when hashing — the region where the caller embedded the
    /// manifest placeholder. `DataHash::LABEL` only.
    pub fn with_exclusions(mut self, exclusions: Vec<HashRange>) -> Self {
        self.exclusions = Some(exclusions);
        self
    }

    /// Interprets this assertion according to its label, producing a concrete, ready-to-insert
    /// [`GeneratedAssertion`]. This is where every `with_*` field actually gets used: streams are
    /// read/hashed, `with_json` values are decoded into their native schema, and an ingredient's
    /// own provenance is resolved into a merge-ready form — all using `context`.
    pub(crate) fn generate(self, context: &Arc<Context>) -> Result<GeneratedAssertion> {
        let ClaimAssertion {
            label,
            value,
            stream,
            c2pa_data,
            exclusions,
        } = self;
        let (match_label, version, _instance) = parse_label(&label);

        match match_label {
            DataHash::LABEL => {
                let (_, stream) = require_stream(stream, match_label)?;
                let dh = generate_data_hash(exclusions.unwrap_or_default(), context, stream)?;
                Ok(GeneratedAssertion::DataHash(dh))
            }
            BmffHash::LABEL => {
                reject_exclusions(exclusions, BmffHash::LABEL)?;
                let (_, stream) = require_stream(stream, match_label)?;
                let mut bh = generate_bmff_hash(context, stream)?;
                bh.set_bmff_version(version);
                Ok(GeneratedAssertion::BmffHash(bh))
            }
            BoxHash::LABEL => {
                reject_exclusions(exclusions, BoxHash::LABEL)?;
                let (format, stream) = require_stream(stream, match_label)?;
                let bh = generate_box_hash(&format, context, stream)?;
                Ok(GeneratedAssertion::BoxHash(bh))
            }
            IngredientAssertion::LABEL => generate_ingredient(value, stream, c2pa_data, context),
            _ => generate_generic(&label, match_label, value, stream),
        }
    }
}

/// What a [`ClaimAssertion`] turned into, once [`ClaimAssertion::generate`] has interpreted it.
/// `ClaimBuilder` just adds these — the hard-binding variants are the only ones it also checks
/// against whatever hard binding is already on the claim.
pub(crate) enum GeneratedAssertion {
    Actions(Box<Actions>),
    Metadata(Metadata),
    UserCbor(UserCbor),
    EmbeddedData(EmbeddedData),
    Ingredient {
        assertion: Box<IngredientAssertion>,
        merge: Option<IngredientMerge>,
    },
    DataHash(DataHash),
    BmffHash(BmffHash),
    BoxHash(BoxHash),
}

/// The ingredient's own provenance, resolved from its stream — everything `ClaimBuilder` needs to
/// merge it into the claim (via `Store::load_ingredient_to_claim`) and fill in the resulting
/// `IngredientAssertion`'s `active_manifest`/`claim_signature`/`validation_results`.
pub(crate) struct IngredientMerge {
    pub manifest_bytes: Vec<u8>,
    pub validation_results: ValidationResults,
}

fn require_stream<'a>(
    stream: Option<(String, &'a mut dyn CAIRead)>,
    label: &str,
) -> Result<(String, &'a mut dyn CAIRead)> {
    stream.ok_or_else(|| {
        Error::BadParam(format!(
            "'{label}' requires with_stream (the asset to hash)"
        ))
    })
}

/// `with_exclusions` is only meaningful for `DataHash` — reject it for any other hard-binding
/// label instead of silently ignoring it.
fn reject_exclusions(exclusions: Option<Vec<HashRange>>, label: &str) -> Result<()> {
    if exclusions.is_some() {
        return Err(Error::BadParam(format!(
            "with_exclusions is only valid for '{}', not '{label}'",
            DataHash::LABEL
        )));
    }
    Ok(())
}

/// Fixed hash algorithm used for hard-binding generation (independent of
/// `ClaimBuilder::set_hash_alg`, which only affects the claim's own default).
const HARD_BINDING_ALG: &str = "sha256";

/// Reads `stream` (the finished asset, with the manifest placeholder already embedded) and
/// computes a `DataHash` over it, excluding `exclusions` (the placeholder region).
fn generate_data_hash(
    exclusions: Vec<HashRange>,
    context: &Context,
    stream: &mut dyn CAIRead,
) -> Result<DataHash> {
    let exclusion_arg = if exclusions.is_empty() {
        None
    } else {
        Some(exclusions.clone())
    };
    let mut cb = |step, total| context.check_progress(ProgressPhase::Hashing, step, total);
    let hash = crate::utils::hash_utils::hash_stream_by_alg_with_progress(
        HARD_BINDING_ALG,
        stream,
        exclusion_arg,
        true,
        &mut cb,
    )?;

    let mut dh = DataHash::new("jumbf manifest", HARD_BINDING_ALG);
    for exclusion in exclusions {
        dh.add_exclusion(exclusion);
    }
    dh.set_hash(hash);

    Ok(dh)
}

/// Reads `stream` (the finished asset, with the manifest placeholder already embedded) and
/// computes a `BmffHash` over it. Exclusions are derived automatically from the BMFF structure.
fn generate_bmff_hash(context: &Context, stream: &mut dyn CAIRead) -> Result<BmffHash> {
    let mut bmff_hash = BmffHash::new("jumbf manifest", HARD_BINDING_ALG, None);
    bmff_hash.set_default_exclusions();

    let mut cb = |step, total| context.check_progress(ProgressPhase::Hashing, step, total);
    bmff_hash.gen_hash_from_stream_with_progress(stream, &mut cb)?;

    Ok(bmff_hash)
}

/// Reads `stream` (the finished asset, with the manifest placeholder already embedded) and
/// computes a `BoxHash` over it. `format` must support box hashing (see
/// `AssetIOHandler::asset_box_hash_ref`).
fn generate_box_hash(format: &str, context: &Context, stream: &mut dyn CAIRead) -> Result<BoxHash> {
    let handler = jumbf_io::get_assetio_handler(format).ok_or(Error::UnsupportedType)?;
    let bhp = handler
        .asset_box_hash_ref()
        .ok_or_else(|| Error::BadParam(format!("Format '{format}' does not support BoxHash")))?;

    let mut bh = BoxHash { boxes: Vec::new() };
    // minimal_form=false: hash each structural box independently rather than summing ranges
    // (see Builder::update_hash_from_stream for why).
    let cb: Box<dyn FnMut(u32, u32) -> Result<()>> =
        Box::new(|step, total| context.check_progress(ProgressPhase::Hashing, step, total));
    // generate_box_hash_from_stream_with_progress requires a Sized stream type; CAIReadWrapper
    // gives `dyn CAIRead` a concrete Sized wrapper to satisfy that.
    let mut wrapper = CAIReadWrapper { reader: stream };
    bh.generate_box_hash_from_stream_with_progress(&mut wrapper, HARD_BINDING_ALG, bhp, false, cb)?;

    Ok(bh)
}

/// Decodes the ingredient's own metadata from `value`, and — if `stream` is attached — resolves
/// its own provenance (reading/validating the asset, then flattening its manifest chain into
/// mergeable bytes) into an [`IngredientMerge`]. The actual claim-mutating merge
/// (`Store::load_ingredient_to_claim`, which needs `ClaimBuilder`'s claim and accumulated
/// redactions) stays on the `ClaimBuilder` side.
fn generate_ingredient(
    value: Option<c2pa_cbor::Value>,
    stream: Option<(String, &mut dyn CAIRead)>,
    c2pa_data: Option<Vec<u8>>,
    context: &Arc<Context>,
) -> Result<GeneratedAssertion> {
    let Some(value) = value else {
        return Err(Error::BadParam(format!(
            "'{}' requires with_json (the ingredient's own metadata)",
            IngredientAssertion::LABEL
        )));
    };
    let ing_assertion: IngredientAssertion = c2pa_cbor::value::from_value(value)?;

    let Some((format, stream)) = stream else {
        if c2pa_data.is_some() {
            return Err(Error::BadParam(format!(
                "with_c2pa_data requires with_stream on '{}'",
                IngredientAssertion::LABEL
            )));
        }
        return Ok(GeneratedAssertion::Ingredient {
            assertion: Box::new(ing_assertion),
            merge: None,
        });
    };

    let reader = match c2pa_data {
        Some(data) => Reader::from_shared_context(context)
            .with_manifest_data_and_stream(&data, &format, stream)?,
        None => Reader::from_shared_context(context).with_stream(&format, stream)?,
    };

    // If the ingredient assertion already carries a manifest link (e.g. it was decoded via
    // `Reader::read_assertion` out of a larger store), scope to that specific claim rather than
    // assuming `reader` is a single-ingredient reader.
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

    Ok(GeneratedAssertion::Ingredient {
        assertion: Box::new(ing_assertion),
        merge: Some(IngredientMerge {
            manifest_bytes,
            validation_results,
        }),
    })
}

/// Everything that isn't a hard binding or an ingredient: binary data (wrapped in
/// `EmbeddedData`) if `stream` is attached, otherwise structured data from `value` — decoded into
/// `label`'s native schema if it's a known one (`c2pa.actions`/`Metadata`), else wrapped
/// generically in a `UserCbor` assertion.
fn generate_generic(
    label: &str,
    match_label: &str,
    value: Option<c2pa_cbor::Value>,
    stream: Option<(String, &mut dyn CAIRead)>,
) -> Result<GeneratedAssertion> {
    if let Some((format, stream)) = stream {
        let mut data = Vec::new();
        stream.read_to_end(&mut data)?;
        return Ok(GeneratedAssertion::EmbeddedData(EmbeddedData::new(
            label,
            format_to_mime(&format),
            data,
        )));
    }

    let Some(value) = value else {
        return Err(Error::BadParam(format!(
            "assertion '{label}' requires with_json or with_stream"
        )));
    };

    match match_label {
        Actions::LABEL => Ok(GeneratedAssertion::Actions(Box::new(
            c2pa_cbor::value::from_value(value)?,
        ))),
        Metadata::LABEL => Ok(GeneratedAssertion::Metadata(c2pa_cbor::value::from_value(
            value,
        )?)),
        _ => {
            let cbor_bytes = c2pa_cbor::to_vec(&value)?;
            Ok(GeneratedAssertion::UserCbor(UserCbor::new(
                label, cbor_bytes,
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use std::io::Cursor;

    use super::*;
    use crate::utils::test::test_context;

    const TEST_IMAGE_CLEAN: &[u8] = include_bytes!("../tests/fixtures/IMG_0003.jpg");

    #[test]
    fn test_generate_data_hash() {
        let context = test_context();
        let mut stream = Cursor::new(b"arbitrary asset bytes, not a real jpeg".to_vec());

        let dh = generate_data_hash(vec![], &context, &mut stream).expect("generate DataHash");
        assert!(!dh.hash.is_empty(), "hash should be computed");
    }

    #[test]
    fn test_generate_data_hash_with_exclusions() {
        let context = test_context();
        let mut stream = Cursor::new(vec![0u8; 100]);

        let dh = generate_data_hash(vec![HashRange::new(0, 10)], &context, &mut stream)
            .expect("generate DataHash with exclusions");
        assert_eq!(dh.exclusions.as_ref().map(|e| e.len()), Some(1));
    }

    #[test]
    fn test_generate_box_hash() {
        let context = test_context();
        let mut stream = Cursor::new(TEST_IMAGE_CLEAN);

        let bh = generate_box_hash("image/jpeg", &context, &mut stream).expect("generate BoxHash");
        assert!(!bh.boxes.is_empty(), "BoxHash must have at least one box");
        assert!(
            bh.boxes.iter().any(|bm| !bm.hash.is_empty()),
            "at least one box should have a computed hash"
        );
    }

    #[test]
    fn test_generate_bmff_hash() {
        let context = test_context();
        // A minimal-enough stream: BmffHash's own default exclusions/hashing don't require a
        // structurally valid BMFF file for this codepath (no mdat exclusions were registered).
        let mut stream = Cursor::new(vec![0u8; 64]);

        let bh = generate_bmff_hash(&context, &mut stream).expect("generate BmffHash");
        assert!(
            !bh.exclusions().is_empty(),
            "default exclusions should be set"
        );
    }
}
