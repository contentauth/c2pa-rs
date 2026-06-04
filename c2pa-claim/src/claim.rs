// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use serde::ser::SerializeStruct;

use crate::{
    assertion::Assertion,
    claim_generator_info::ClaimGeneratorInfo,
    error::{Error, Result},
    hashed_uri::HashedUri,
};

// V2 CBOR field names
const CLAIM_GENERATOR_F: &str = "claim_generator";
const CLAIM_GENERATOR_INFO_F: &str = "claim_generator_info";
const SIGNATURE_F: &str = "signature";
const ASSERTIONS_F: &str = "assertions";
const DC_FORMAT_F: &str = "dc:format";
const INSTANCE_ID_F: &str = "instanceID";
const DC_TITLE_F: &str = "dc:title";
const REDACTED_ASSERTIONS_F: &str = "redacted_assertions";
const ALG_F: &str = "alg";
const ALG_SOFT_F: &str = "alg_soft";
const CREATED_ASSERTIONS_F: &str = "created_assertions";
const GATHERED_ASSERTIONS_F: &str = "gathered_assertions";

/// A C2PA Claim — collects assertions about an asset from a single actor.
///
/// This is a minimal standalone implementation that supports V2 CBOR
/// construction and round-trip deserialization. JUMBF box construction
/// and cryptographic signing are deferred to Phase 2.
#[derive(Clone)]
pub struct Claim {
    /// JUMBF label for this claim (e.g. `urn:c2pa:…`)
    label: String,

    /// XMP instance ID of the asset this claim describes
    instance_id: String,

    /// Generator metadata
    claim_generator_info: ClaimGeneratorInfo,

    /// `dc:format` of the asset — present in V1, not serialized in V2
    format: Option<String>,

    /// JUMBF URI pointing to the signature box
    signature: String,

    /// Assertion payloads stored for later JUMBF construction
    assertion_store: Vec<Assertion>,

    /// Hashed URI references in the claim's `created_assertions` list
    created_assertions: Vec<HashedUri>,

    /// Hashed URI references in the claim's `gathered_assertions` list
    gathered_assertions: Option<Vec<HashedUri>>,

    title: Option<String>,
    redacted_assertions: Option<Vec<String>>,

    /// Hash algorithm for assertion hashes (default: sha256)
    pub alg: Option<String>,
    pub alg_soft: Option<String>,

    claim_version: usize,

    /// Raw COSE signature bytes — empty until populated by a signer or loaded from JUMBF.
    signature_val: Vec<u8>,

    /// Original CBOR bytes as read from JUMBF.
    ///
    /// When present, `data()` returns these bytes verbatim so that the COSE
    /// signature (which was computed over the original bytes) continues to
    /// verify after a JUMBF round-trip.  Cleared to `None` by `add_assertion`
    /// so mutated claims always re-encode fresh.
    original_bytes: Option<Vec<u8>>,
}

impl Claim {
    /// Create a new V2 claim.
    pub fn new(label: impl Into<String>, generator_info: ClaimGeneratorInfo) -> Self {
        use uuid::Uuid;
        let label = label.into();
        let instance_id = format!("xmp:iid:{}", Uuid::new_v4());
        let signature = format!("self#jumbf={}/c2pa.signature", label);
        Self {
            label,
            instance_id,
            claim_generator_info: generator_info,
            format: None,
            signature,
            assertion_store: Vec::new(),
            created_assertions: Vec::new(),
            gathered_assertions: None,
            title: None,
            redacted_assertions: None,
            alg: Some("sha256".to_string()),
            alg_soft: None,
            claim_version: 2,
            signature_val: Vec::new(),
            original_bytes: None,
        }
    }

    // ---- accessors ----

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn version(&self) -> usize {
        self.claim_version
    }

    pub fn claim_generator_info(&self) -> &ClaimGeneratorInfo {
        &self.claim_generator_info
    }

    pub fn format(&self) -> Option<&str> {
        self.format.as_deref()
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    pub fn set_title(&mut self, title: impl Into<String>) -> &mut Self {
        self.title = Some(title.into());
        self
    }

    /// Assertions stored in this claim (full payloads).
    pub fn assertions(&self) -> &[Assertion] {
        &self.assertion_store
    }

    /// Hashed URI references in `created_assertions`.
    pub fn created_assertions(&self) -> &[HashedUri] {
        &self.created_assertions
    }

    pub fn gathered_assertions(&self) -> Option<&[HashedUri]> {
        self.gathered_assertions.as_deref()
    }

    // ---- signature ----

    /// The raw COSE signature bytes for this claim.
    ///
    /// Empty until the claim is signed (via a store's sign method) or loaded
    /// from JUMBF by a store's `from_jumbf`.
    pub fn signature_val(&self) -> &[u8] {
        &self.signature_val
    }

    /// Set the raw COSE signature bytes. Called by the store after signing or
    /// after loading a signed manifest from JUMBF.
    pub fn set_signature_val(&mut self, val: Vec<u8>) {
        self.signature_val = val;
    }

    // ---- mutation ----

    /// Add an assertion to this claim.
    ///
    /// Appends the full payload to the internal assertion store and creates a
    /// placeholder `HashedUri` (empty hash) in `created_assertions`. Real
    /// hash values are filled in during JUMBF box construction (Phase 2).
    ///
    /// Returns the `HashedUri` created for this assertion so callers can
    /// reference it from other assertions (e.g. an `Action`'s
    /// `parameters.ingredients` array).
    pub fn add_assertion(&mut self, assertion: Assertion) -> HashedUri {
        let uri = format!(
            "self#jumbf={}/c2pa.assertions/{}",
            self.label,
            assertion.label()
        );
        let hashed_uri = HashedUri::new(uri, Some("sha256".to_string()), &[]);
        self.created_assertions.push(hashed_uri.clone());
        self.assertion_store.push(assertion);
        self.original_bytes = None; // mutation invalidates the cached original
        hashed_uri
    }

    /// Replace an existing assertion by label.
    ///
    /// Finds the first assertion in the store whose [`label()`] matches and
    /// replaces it in-place, preserving the position in the list.  No-op if
    /// no matching assertion is found.
    ///
    /// Clears `original_bytes` because the claim CBOR must be re-encoded after
    /// a mutation — the old bytes were signed over different content.
    pub fn replace_assertion(&mut self, label: &str, new_assertion: Assertion) {
        if let Some(pos) = self.assertion_store.iter().position(|a| a.label() == label) {
            self.assertion_store[pos] = new_assertion;
            self.original_bytes = None;
        }
    }

    /// Restore an assertion loaded from JUMBF.
    ///
    /// Unlike `add_assertion`, this only appends to the assertion payload store
    /// and does not create a new `HashedUri` entry — the `created_assertions`
    /// list is already populated from the claim CBOR when loading from JUMBF.
    pub fn restore_assertion(&mut self, assertion: Assertion) {
        self.assertion_store.push(assertion);
    }

    // ---- serialization ----

    /// Serialize this claim to CBOR bytes.
    ///
    /// Returns the original bytes as loaded from JUMBF when available, so that
    /// COSE signatures computed over those bytes survive a round-trip.  A claim
    /// built from scratch (or mutated via `add_assertion`) always re-encodes.
    pub fn data(&self) -> Result<Vec<u8>> {
        if let Some(ref raw) = self.original_bytes {
            return Ok(raw.clone());
        }
        c2pa_cbor::to_vec(self).map_err(Error::CborError)
    }

    /// Deserialize a claim from CBOR bytes.
    pub fn from_data(label: &str, data: &[u8]) -> Result<Self> {
        let value: c2pa_cbor::Value =
            c2pa_cbor::from_slice(data).map_err(|e| Error::ClaimDecoding(e.to_string()))?;
        let mut claim = Self::from_value(value, label)?;
        claim.original_bytes = Some(data.to_vec());
        Ok(claim)
    }

    fn from_value(v: c2pa_cbor::Value, label: &str) -> Result<Self> {
        // Detect version: V2 has `created_assertions`, V1 has `assertions`.
        let has_created = map_cbor_to_type::<Vec<HashedUri>>(CREATED_ASSERTIONS_F, &v).is_some();
        let has_v1_assertions = map_cbor_to_type::<Vec<HashedUri>>(ASSERTIONS_F, &v).is_some();

        if has_created && !has_v1_assertions {
            Self::from_value_v2(v, label)
        } else {
            Self::from_value_v1(v, label)
        }
    }

    fn from_value_v2(v: c2pa_cbor::Value, label: &str) -> Result<Self> {
        let instance_id = map_cbor_to_type::<String>(INSTANCE_ID_F, &v)
            .ok_or_else(|| Error::ClaimDecoding("missing instanceID".to_string()))?;
        let claim_generator_info =
            map_cbor_to_type::<ClaimGeneratorInfo>(CLAIM_GENERATOR_INFO_F, &v)
                .ok_or_else(|| Error::ClaimDecoding("missing claim_generator_info".to_string()))?;
        let signature = map_cbor_to_type::<String>(SIGNATURE_F, &v)
            .ok_or_else(|| Error::ClaimDecoding("missing signature".to_string()))?;
        let created_assertions = map_cbor_to_type::<Vec<HashedUri>>(CREATED_ASSERTIONS_F, &v)
            .ok_or_else(|| Error::ClaimDecoding("missing created_assertions".to_string()))?;

        Ok(Self {
            label: label.to_string(),
            instance_id,
            claim_generator_info,
            format: None,
            signature,
            assertion_store: Vec::new(),
            created_assertions,
            gathered_assertions: map_cbor_to_type(GATHERED_ASSERTIONS_F, &v),
            title: map_cbor_to_type(DC_TITLE_F, &v),
            redacted_assertions: map_cbor_to_type(REDACTED_ASSERTIONS_F, &v),
            alg: map_cbor_to_type(ALG_F, &v),
            alg_soft: map_cbor_to_type(ALG_SOFT_F, &v),
            claim_version: 2,
            signature_val: Vec::new(),
            original_bytes: None,
        })
    }

    fn from_value_v1(v: c2pa_cbor::Value, label: &str) -> Result<Self> {
        let claim_generator = map_cbor_to_type::<String>(CLAIM_GENERATOR_F, &v).unwrap_or_default();
        let signature = map_cbor_to_type::<String>(SIGNATURE_F, &v)
            .ok_or_else(|| Error::ClaimDecoding("missing signature".to_string()))?;
        let assertions = map_cbor_to_type::<Vec<HashedUri>>(ASSERTIONS_F, &v)
            .ok_or_else(|| Error::ClaimDecoding("missing assertions".to_string()))?;
        let format = map_cbor_to_type::<String>(DC_FORMAT_F, &v);
        let instance_id = map_cbor_to_type::<String>(INSTANCE_ID_F, &v).unwrap_or_default();
        let claim_generator_info =
            map_cbor_to_type::<ClaimGeneratorInfo>(CLAIM_GENERATOR_INFO_F, &v)
                .unwrap_or_else(|| ClaimGeneratorInfo::new(claim_generator));

        Ok(Self {
            label: label.to_string(),
            instance_id,
            claim_generator_info,
            format,
            signature,
            assertion_store: Vec::new(),
            created_assertions: assertions,
            gathered_assertions: None,
            title: map_cbor_to_type(DC_TITLE_F, &v),
            redacted_assertions: map_cbor_to_type(REDACTED_ASSERTIONS_F, &v),
            alg: map_cbor_to_type(ALG_F, &v),
            alg_soft: map_cbor_to_type(ALG_SOFT_F, &v),
            claim_version: 1,
            signature_val: Vec::new(),
            original_bytes: None,
        })
    }
}

// ---- Serialize ----

impl serde::Serialize for Claim {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if self.claim_version > 1 {
            self.serialize_v2(s)
        } else {
            self.serialize_v1(s)
        }
    }
}

impl Claim {
    fn serialize_v2<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut len = 4; // instanceID, claim_generator_info, signature, created_assertions
        if self.gathered_assertions.is_some() {
            len += 1;
        }
        if self.title.is_some() {
            len += 1;
        }
        if self.redacted_assertions.is_some() {
            len += 1;
        }
        if self.alg.is_some() {
            len += 1;
        }
        if self.alg_soft.is_some() {
            len += 1;
        }

        let mut m = s.serialize_struct("Claim", len)?;
        m.serialize_field(INSTANCE_ID_F, &self.instance_id)?;
        m.serialize_field(CLAIM_GENERATOR_INFO_F, &self.claim_generator_info)?;
        m.serialize_field(SIGNATURE_F, &self.signature)?;
        m.serialize_field(CREATED_ASSERTIONS_F, &self.created_assertions)?;
        if let Some(ga) = &self.gathered_assertions {
            m.serialize_field(GATHERED_ASSERTIONS_F, ga)?;
        }
        if let Some(t) = &self.title {
            m.serialize_field(DC_TITLE_F, t)?;
        }
        if let Some(ra) = &self.redacted_assertions {
            m.serialize_field(REDACTED_ASSERTIONS_F, ra)?;
        }
        if let Some(alg) = &self.alg {
            m.serialize_field(ALG_F, alg)?;
        }
        if let Some(soft) = &self.alg_soft {
            m.serialize_field(ALG_SOFT_F, soft)?;
        }
        m.end()
    }

    fn serialize_v1<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut len = 5; // claim_generator, instanceID, dc:format, signature, assertions
        if self.title.is_some() {
            len += 1;
        }
        if self.alg.is_some() {
            len += 1;
        }

        let mut m = s.serialize_struct("Claim", len)?;
        m.serialize_field(CLAIM_GENERATOR_F, &self.claim_generator_info.name)?;
        m.serialize_field(INSTANCE_ID_F, &self.instance_id)?;
        m.serialize_field(DC_FORMAT_F, &self.format.as_deref().unwrap_or_default())?;
        m.serialize_field(SIGNATURE_F, &self.signature)?;
        m.serialize_field(ASSERTIONS_F, &self.created_assertions)?;
        if let Some(t) = &self.title {
            m.serialize_field(DC_TITLE_F, t)?;
        }
        if let Some(alg) = &self.alg {
            m.serialize_field(ALG_F, alg)?;
        }
        m.end()
    }
}

// ---- helper ----

fn map_cbor_to_type<T: serde::de::DeserializeOwned>(key: &str, mp: &c2pa_cbor::Value) -> Option<T> {
    if let c2pa_cbor::Value::Map(m) = mp {
        let k = c2pa_cbor::Value::Text(key.to_string());
        let v = m.get(&k)?;
        let v_bytes = c2pa_cbor::ser::to_vec(v).ok()?;
        c2pa_cbor::from_slice(&v_bytes).ok()
    } else {
        None
    }
}
