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

//! Everything about a single assertion, on both the write and read side.
//!
//! [`ClaimAssertionBuilder`] is the write side, used to add an assertion to a
//! [`crate::ClaimBuilder`]: start with [`ClaimAssertionBuilder::new`] and a label, then attach
//! whichever of `with_json`/`from_assertion`/`with_stream`/`with_c2pa_data`/`with_exclusions`
//! that label needs. `from_assertion` takes a concrete type that already knows how to encode
//! itself (e.g. [`crate::assertions::Actions`]) — this module never needs to know about it by
//! name, which keeps assertion types free to live anywhere, including outside this crate.
//! Nothing is validated or converted until [`ClaimAssertionBuilder::generate`] runs — called by
//! [`crate::ClaimBuilder::add_gathered_assertion`]/[`crate::ClaimBuilder::add_created_assertion`]
//! — which is also where the `ClaimBuilder`'s own [`Context`] gets used (for hard-binding hash
//! generation and ingredient provenance reading). `ClaimBuilder` itself only adds the resulting
//! concrete assertion to the claim, and — for hard-binding labels — checks it against whatever
//! hard binding is already there.
//!
//! [`ClaimAssertion`] is the read side, handed back by [`crate::StoreReader`] — a small, owned,
//! purpose-built public type (mirroring [`crate::ManifestAssertion`] at the `Manifest` layer) that
//! never wraps or exposes the crate's internal `Claim`/`Assertion` representation.

use std::{
    io::{Read, Write},
    sync::Arc,
};

use serde::{de::DeserializeOwned, Serialize};

use crate::{
    assertion::{Assertion, AssertionBase},
    assertions::{
        labels::parse_label, BmffHash, BoxHash, DataHash, EmbeddedData, IngredientAssertion, User,
        UserCbor,
    },
    asset_io::{CAIRead, CAIReadWrapper},
    context::{Context, ProgressPhase},
    error::{Error, Result},
    jumbf_io,
    maybe_send_sync::MaybeSend,
    store::Store,
    store_reader::StoreReader,
    utils::mime::format_to_mime,
    ValidationResults,
};

/// One assertion to add via [`crate::ClaimBuilder::add_gathered_assertion`]/
/// [`crate::ClaimBuilder::add_created_assertion`].
///
/// Which `with_*` calls are valid depends on `label`:
/// * `DataHash`/`BmffHash`/`BoxHash` labels require [`ClaimAssertionBuilder::with_stream`] (the asset to
///   hash).
/// * [`crate::assertions::IngredientAssertion::LABEL`] requires [`ClaimAssertionBuilder::with_json`]
///   (the ingredient's own metadata) and accepts [`ClaimAssertionBuilder::with_stream`] (the
///   ingredient's own asset, to extract its provenance) plus [`ClaimAssertionBuilder::with_c2pa_data`]
///   (a sidecar/remote manifest for that asset, when its provenance isn't embedded in-band).
/// * Everything else takes [`ClaimAssertionBuilder::from_assertion`] (a concrete type that
///   encodes itself, e.g. [`crate::assertions::Actions`]), [`ClaimAssertionBuilder::with_json`]
///   (structured data with no Rust type, wrapped generically), or
///   [`ClaimAssertionBuilder::with_stream`] (binary data, e.g. a thumbnail — wrapped in `EmbeddedData`).
pub struct ClaimAssertionBuilder<'a> {
    label: String,
    value: Option<c2pa_cbor::Value>,
    assertion: Option<Assertion>,
    json: bool,
    content_type: Option<String>,
    stream: Option<(String, &'a mut dyn CAIRead)>,
    c2pa_data: Option<Vec<u8>>,
}

impl ClaimAssertionBuilder<'static> {
    /// Starts building an assertion under `label` (e.g.
    /// [`crate::assertions::Actions::LABEL`], [`crate::assertions::IngredientAssertion::LABEL`],
    /// `DataHash::LABEL`, or any custom reverse-domain label).
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: None,
            assertion: None,
            json: false,
            content_type: None,
            stream: None,
            c2pa_data: None,
        }
    }
}

impl<'a> ClaimAssertionBuilder<'a> {
    /// Sets this assertion's data from a concrete type that already knows how to encode itself
    /// (label, version, and content type included) — e.g. [`crate::assertions::Actions`] or
    /// [`crate::assertions::Metadata`]. This is what lets any assertion type — including ones this crate has never heard of
    /// — define its own serialization instead of being packed into a generic `User`/`UserCbor`
    /// wrapper.
    pub fn from_assertion<T: AssertionBase>(data: &T) -> Result<Self> {
        let assertion = data.to_assertion()?;
        Ok(Self {
            label: assertion.label().to_string(),
            value: None,
            assertion: Some(assertion),
            json: false,
            content_type: None,
            stream: None,
            c2pa_data: None,
        })
    }

    /// Sets structured data for this assertion, wrapped generically under `label` — CBOR by
    /// default, or JSON if [`ClaimAssertionBuilder::as_json`] is set. Use
    /// [`ClaimAssertionBuilder::from_assertion`] instead for a label with a known Rust type
    /// (e.g. [`crate::assertions::Actions`]), so it's stored with its own native schema/encoding
    /// rather than generically.
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
    ) -> ClaimAssertionBuilder<'b> {
        let stream: &'b mut dyn CAIRead = stream;
        ClaimAssertionBuilder {
            label: self.label,
            value: self.value,
            assertion: self.assertion,
            json: self.json,
            content_type: self.content_type,
            stream: Some((format.into(), stream)),
            c2pa_data: self.c2pa_data,
        }
    }

    /// Sets an explicit content type (MIME type) for a binary/embedded-data assertion, overriding
    /// the default derived from the source stream's `format` argument. Has no effect on
    /// `DataHash`/`BmffHash`/`BoxHash` or [`crate::assertions::IngredientAssertion::LABEL`]
    /// (fixed content types), or on [`ClaimAssertionBuilder::with_json`]-based assertions
    /// (`Actions`/`Metadata`/CBOR/JSON all have their own fixed content type too).
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Supplies the ingredient's manifest store directly (JUMBF bytes) instead of extracting it
    /// from the stream in-band — for a sidecar or remote manifest.
    /// [`crate::assertions::IngredientAssertion::LABEL`] only.
    pub fn with_c2pa_data(mut self, c2pa_data: Vec<u8>) -> Self {
        self.c2pa_data = Some(c2pa_data);
        self
    }

    /// Requests JSON encoding (instead of the default CBOR) for a [`ClaimAssertionBuilder::with_json`]
    /// assertion. Has no effect on [`ClaimAssertionBuilder::from_assertion`] (which has its own
    /// fixed encoding) or [`ClaimAssertionBuilder::with_stream`] (binary content has its own MIME
    /// type).
    pub fn as_json(mut self) -> Self {
        self.json = true;
        self
    }

    /// Interprets this assertion according to its label, producing a concrete, ready-to-insert
    /// [`GeneratedAssertion`]. This is where every `with_*` field actually gets used: streams are
    /// read/hashed, `with_json` values are wrapped generically, and an ingredient's own
    /// provenance is resolved into a merge-ready form — all using `context`.
    pub(crate) fn generate(self, context: &Arc<Context>) -> Result<GeneratedAssertion> {
        let ClaimAssertionBuilder {
            label,
            value,
            assertion,
            json,
            content_type,
            stream,
            c2pa_data,
        } = self;
        if let Some(assertion) = assertion {
            return Ok(GeneratedAssertion::Assertion(assertion));
        }
        let (match_label, version, _instance) = parse_label(&label);

        match match_label {
            DataHash::LABEL => {
                let (_, stream) = require_stream(stream, match_label)?;
                let dh = generate_data_hash(context, value, stream)?;
                Ok(GeneratedAssertion::DataHash(dh))
            }
            BmffHash::LABEL => {
                let (_, stream) = require_stream(stream, match_label)?;
                let mut bh = generate_bmff_hash(context, stream)?;
                bh.set_bmff_version(version);
                Ok(GeneratedAssertion::BmffHash(bh))
            }
            BoxHash::LABEL => {
                let (format, stream) = require_stream(stream, match_label)?;
                let bh = generate_box_hash(&format, context, stream)?;
                Ok(GeneratedAssertion::BoxHash(bh))
            }
            IngredientAssertion::LABEL => generate_ingredient(value, stream, c2pa_data, context),
            _ => generate_generic(&label, value, json, content_type, stream),
        }
    }
}

/// What a [`ClaimAssertionBuilder`] turned into, once [`ClaimAssertionBuilder::generate`] has interpreted it.
/// `ClaimBuilder` just adds these — the hard-binding variants are the only ones it also checks
/// against whatever hard binding is already on the claim.
pub(crate) enum GeneratedAssertion {
    /// Anything with no special insertion behavior — `Actions`, `Metadata`, `UserCbor`, `User`,
    /// `EmbeddedData`, and any future generically-inserted type — already encoded, since nothing
    /// downstream needs the concrete Rust type back.
    Assertion(Assertion),
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

/// Fixed hash algorithm used for hard-binding generation (independent of
/// `ClaimBuilder::set_hash_alg`, which only affects the claim's own default).
const HARD_BINDING_ALG: &str = "sha256";

/// Reads `stream` (the finished asset, with the manifest placeholder already embedded) and
/// computes a `DataHash` over it, excluding `exclusions` (the placeholder region).
fn generate_data_hash(
    context: &Context,
    value: Option<c2pa_cbor::Value>,
    stream: &mut dyn CAIRead,
) -> Result<DataHash> {
    let mut dh = match value {
        Some(value) => c2pa_cbor::from_value(value)?,
        None => DataHash::new("jumbf manifest", HARD_BINDING_ALG),
    };
    let mut cb = |step, total| context.check_progress(ProgressPhase::Hashing, step, total);
    dh.gen_hash_from_stream_with_progress(stream, &mut cb)?;
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

    let store_reader = match c2pa_data {
        Some(data) => StoreReader::new(context.clone())
            .with_manifest_data_and_stream(&data, &format, stream)?,
        None => StoreReader::new(context.clone()).with_stream(&format, stream)?,
    };

    // If the ingredient assertion already carries a manifest link (e.g. it was decoded via
    // `Reader::read_assertion` out of a larger store), scope to that specific claim rather than
    // assuming `store_reader` is a single-ingredient reader.
    let target_claim = match ing_assertion
        .active_manifest
        .as_ref()
        .or(ing_assertion.c2pa_manifest.as_ref())
    {
        Some(uri) => {
            let label = Store::manifest_label_from_path(&uri.url());
            store_reader
                .store
                .get_claim(&label)
                .ok_or(Error::ClaimMissing { label })?
        }
        None => store_reader
            .store
            .provenance_claim()
            .ok_or(Error::JumbfNotFound)?,
    };

    let validation_results = store_reader
        .validation_results()
        .cloned()
        .unwrap_or_default();
    let ingredient_scope = Store::build_flat_ingredient_store(&store_reader.store, target_claim)?;
    let manifest_bytes = ingredient_scope.to_jumbf_internal(0)?;

    Ok(GeneratedAssertion::Ingredient {
        assertion: Box::new(ing_assertion),
        merge: Some(IngredientMerge {
            manifest_bytes,
            validation_results,
        }),
    })
}

/// Everything that isn't a hard binding, an ingredient, or set via
/// [`ClaimAssertionBuilder::from_assertion`]: binary data (wrapped in `EmbeddedData`) if `stream`
/// is attached, otherwise structured data from `value`, wrapped generically under `label` (JSON
/// if [`ClaimAssertionBuilder::as_json`] was set, else CBOR). A label with a known Rust type
/// (e.g. `c2pa.actions`, or a custom `.metadata`-suffixed one) should go through
/// [`ClaimAssertionBuilder::from_assertion`] instead, so it keeps its own native schema/encoding
/// rather than this generic wrap.
fn generate_generic(
    label: &str,
    value: Option<c2pa_cbor::Value>,
    json: bool,
    content_type: Option<String>,
    stream: Option<(String, &mut dyn CAIRead)>,
) -> Result<GeneratedAssertion> {
    if let Some((format, stream)) = stream {
        let mut data = Vec::new();
        stream.read_to_end(&mut data)?;
        let embedded = EmbeddedData::new(
            label,
            content_type.unwrap_or_else(|| format_to_mime(&format)),
            data,
        );
        return Ok(GeneratedAssertion::Assertion(embedded.to_assertion()?));
    }

    let Some(value) = value else {
        return Err(Error::BadParam(format!(
            "assertion '{label}' requires with_json, from_assertion, or with_stream"
        )));
    };

    let assertion = if json {
        let json = serde_json::to_string(&value)?;
        User::new(label, &json).to_assertion()?
    } else {
        let cbor_bytes = c2pa_cbor::to_vec(&value)?;
        UserCbor::new(label, cbor_bytes).to_assertion()?
    };
    Ok(GeneratedAssertion::Assertion(assertion))
}

// ── Read side ────────────────────────────────────────────────────────────────

/// Whether a stored assertion is a v1 assertion, or (v2+) created vs. gathered. See
/// [`crate::ClaimBuilder::add_created_assertion`]/[`crate::ClaimBuilder::add_gathered_assertion`]
/// for what created/gathered means when writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimAssertionAttribution {
    V1,
    Created,
    Gathered,
}

/// One assertion as actually stored in a claim — the read-side counterpart to
/// [`ClaimAssertionBuilder`], handed back by [`crate::StoreReader`]. Owns its data outright; never
/// wraps or exposes the crate's internal `Claim`/`Assertion` representation.
#[derive(Debug, Clone)]
pub struct ClaimAssertion {
    label: String,
    attribution: ClaimAssertionAttribution,
    content_type: String,
    data: Vec<u8>,
}

impl ClaimAssertion {
    pub(crate) fn new(
        label: String,
        attribution: ClaimAssertionAttribution,
        content_type: String,
        data: Vec<u8>,
    ) -> Self {
        Self {
            label,
            attribution,
            content_type,
            data,
        }
    }

    /// This assertion's label, including its instance suffix (`__N`) and version suffix (`.vN`)
    /// when present — e.g. `c2pa.actions__2.v2`.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Whether this is a v1 assertion, or (v2+) created vs. gathered.
    pub fn kind(&self) -> ClaimAssertionAttribution {
        self.attribution
    }

    /// The content type (MIME type) of this assertion's stored data.
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// Decodes this assertion's stored data as `T` (e.g. a typed assertion like
    /// [`crate::assertions::Actions`], or a hard-binding type like
    /// [`crate::assertions::DataHash`] — which can then be verified against a stream via its own
    /// `verify_stream_hash`). Mirrors [`crate::ManifestAssertion::to_assertion`].
    ///
    /// Returns [`Error::UnsupportedType`] if the content type isn't `application/json` or
    /// `application/cbor` (e.g. a binary assertion like a thumbnail) — use
    /// [`ClaimAssertion::write_to_stream`] for those instead.
    pub fn to_assertion<T: DeserializeOwned>(&self) -> Result<T> {
        match self.content_type.as_str() {
            "application/json" => serde_json::from_slice(&self.data)
                .map_err(|e| Error::AssertionEncoding(e.to_string())),
            "application/cbor" => c2pa_cbor::from_slice(&self.data)
                .map_err(|e| Error::AssertionEncoding(e.to_string())),
            _ => Err(Error::UnsupportedType),
        }
    }

    /// Writes this assertion's raw stored bytes to `stream` — use this for binary assertions
    /// (e.g. a thumbnail) that [`ClaimAssertion::to_assertion`] can't decode. Returns the number
    /// of bytes written.
    pub fn write_to_stream(&self, stream: &mut impl Write) -> Result<usize> {
        stream.write_all(&self.data)?;
        Ok(self.data.len())
    }
}

/// One claim as actually stored in a manifest store — the read-side counterpart to
/// [`crate::ClaimBuilder`], handed back by [`crate::StoreReader`]. Owns its data outright; never
/// wraps or exposes the crate's internal `Claim` representation.
#[derive(Debug, Clone)]
pub struct Claim {
    label: String,
    title: Option<String>,
    instance_id: String,
    alg: String,
    version: usize,
    assertions: Vec<ClaimAssertion>,
}

impl Claim {
    pub(crate) fn new(
        label: String,
        title: Option<String>,
        instance_id: String,
        alg: String,
        version: usize,
        assertions: Vec<ClaimAssertion>,
    ) -> Self {
        Self {
            label,
            title,
            instance_id,
            alg,
            version,
            assertions,
        }
    }

    /// This claim's label (e.g. `urn:c2pa:...`).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// This claim's title, if set.
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// The instance ID (e.g. an `xmp:iid:...` URN) of the asset this claim describes.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// This claim's default hash algorithm (e.g. `"sha256"`).
    pub fn alg(&self) -> &str {
        &self.alg
    }

    /// The claim version (1 or 2+).
    pub fn version(&self) -> usize {
        self.version
    }

    /// Every assertion stored in this claim.
    pub fn assertions(&self) -> &[ClaimAssertion] {
        &self.assertions
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use std::io::Cursor;

    use super::*;
    use crate::{assertions::Actions, utils::test::test_context, HashRange};

    const TEST_IMAGE_CLEAN: &[u8] = include_bytes!("../tests/fixtures/IMG_0003.jpg");

    #[test]
    fn test_generate_generic_with_json_wraps_generically_regardless_of_label() {
        // with_json has no label-based special-casing (that's what from_assertion is for) — a
        // `.metadata`-suffixed label gets the same generic CBOR wrap as any other custom label.
        let context = Arc::new(test_context());
        let value = serde_json::json!({
            "@context": {"ex": "https://example.com/"},
            "ex:foo": "bar",
        });

        let generated = ClaimAssertionBuilder::new("org.contentauth.custom.metadata")
            .with_json(&value)
            .expect("with_json")
            .generate(&context)
            .expect("generate");

        let GeneratedAssertion::Assertion(a) = generated else {
            panic!("expected Assertion, got a different variant");
        };
        assert_eq!(a.label(), "org.contentauth.custom.metadata");
        assert_eq!(a.content_type(), "application/cbor");
    }

    #[test]
    fn test_from_assertion_uses_native_schema_and_version() {
        // Actions has its own fixed encoding/version (content type "application/cbor", label
        // suffixed ".v2") — from_assertion should preserve that instead of the generic wrap
        // with_json would produce.
        let context = Arc::new(test_context());
        let actions = Actions::new();

        let generated = ClaimAssertionBuilder::from_assertion(&actions)
            .expect("from_assertion")
            .generate(&context)
            .expect("generate");

        let GeneratedAssertion::Assertion(a) = generated else {
            panic!("expected Assertion, got a different variant");
        };
        assert_eq!(a.label(), Actions::LABEL_VERSIONED);
        assert_eq!(a.content_type(), "application/cbor");
    }

    #[test]
    fn test_generate_generic_as_json() {
        let context = Arc::new(test_context());

        let generated = ClaimAssertionBuilder::new("org.test.custom")
            .with_json(&serde_json::json!({"value": 1}))
            .expect("with_json")
            .as_json()
            .generate(&context)
            .expect("generate");

        let GeneratedAssertion::Assertion(a) = generated else {
            panic!("expected Assertion, got a different variant");
        };
        assert_eq!(a.content_type(), "application/json");
    }

    #[test]
    fn test_generate_generic_defaults_to_cbor() {
        let context = Arc::new(test_context());

        let generated = ClaimAssertionBuilder::new("org.test.custom")
            .with_json(&serde_json::json!({"value": 1}))
            .expect("with_json")
            .generate(&context)
            .expect("generate");

        let GeneratedAssertion::Assertion(a) = generated else {
            panic!("expected Assertion, got a different variant");
        };
        assert_eq!(a.content_type(), "application/cbor");
    }

    #[test]
    fn test_generate_data_hash() {
        let context = test_context();
        let mut stream = Cursor::new(b"arbitrary asset bytes, not a real jpeg".to_vec());

        let dh = generate_data_hash(&context, None, &mut stream).expect("generate DataHash");
        assert!(!dh.hash.is_empty(), "hash should be computed");
    }

    #[test]
    fn test_generate_data_hash_with_exclusions() {
        let context = test_context();
        let mut stream = Cursor::new(vec![0u8; 100]);

        let mut initial = DataHash::new("jumbf manifest", HARD_BINDING_ALG);
        initial.add_exclusion(HashRange::new(10, 10));
        let value = c2pa_cbor::value::to_value(initial).expect("to_value");

        let dh = generate_data_hash(&context, Some(value), &mut stream).expect("generate DataHash");
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
