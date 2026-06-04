// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use std::fmt;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::error::{Error, Result};

// ---- label helpers (inlined from sdk/src/assertions/labels.rs + sdk/src/claim.rs) ----

const SCHEMA_ORG: &str = "schema.org";
const CLAIM_THUMBNAIL: &str = "c2pa.thumbnail.claim";
const INGREDIENT_THUMBNAIL: &str = "c2pa.thumbnail.ingredient";

/// Parse a label into (base, version, instance).
///
/// `version` defaults to 1 when no `.vN` suffix is present.
/// `instance` defaults to 0 when no `__N` suffix is present.
fn parse_label(label: &str) -> (&str, usize, usize) {
    let (without_instance, instance) = if let Some(pos) = label.rfind("__") {
        let instance = label[pos + 2..].parse::<usize>().unwrap_or(0);
        (&label[..pos], instance)
    } else {
        (label, 0)
    };

    let components: Vec<&str> = without_instance.split('.').collect();
    if let Some(last) = components.last() {
        if last.starts_with('v') && last.len() > 1 && last[1..].chars().all(|c| c.is_ascii_digit())
        {
            if let Ok(version) = last[1..].parse::<usize>() {
                if without_instance.len() > last.len() {
                    let base_end = without_instance.len() - last.len() - 1;
                    return (&without_instance[..base_end], version, instance);
                }
            }
        }
    }

    (without_instance, 1, instance)
}

fn label_version(label: &str) -> usize {
    parse_label(label).1
}

fn get_thumbnail_type(label: &str) -> &'static str {
    if label.starts_with(CLAIM_THUMBNAIL) {
        return CLAIM_THUMBNAIL;
    }
    if label.starts_with(INGREDIENT_THUMBNAIL) {
        return INGREDIENT_THUMBNAIL;
    }
    "none"
}

fn get_thumbnail_image_type(label: &str) -> Option<String> {
    let components: Vec<&str> = label.split('.').collect();
    if label.contains("thumbnail") && components.len() >= 4 {
        let image_type: Vec<&str> = components[3].split('_').collect();
        Some(image_type[0].to_ascii_lowercase())
    } else {
        None
    }
}

fn get_thumbnail_instance(label: &str) -> Option<usize> {
    match get_thumbnail_type(label) {
        INGREDIENT_THUMBNAIL => {
            let components: Vec<&str> = label.split("__").collect();
            if components.len() == 2 {
                let subparts: Vec<&str> = components[1].split('.').collect();
                subparts[0].parse::<usize>().ok()
            } else {
                Some(0)
            }
        }
        _ => None,
    }
}

/// Parse a JUMBF assertion URI into (label, instance).
///
/// Handles both `self#jumbf=.../c2pa.assertions/label__instance` style URIs
/// and plain label strings.
fn assertion_label_from_link(uri: &str) -> (String, usize) {
    // Strip `self#jumbf=` prefix if present, then take segment after last `/`
    let normalized = uri.splitn(2, '=').last().unwrap_or(uri);
    let last = normalized.split('/').next_back().unwrap_or(normalized);

    if get_thumbnail_type(last) == INGREDIENT_THUMBNAIL {
        let instance = get_thumbnail_instance(last).unwrap_or(0);
        let label = match get_thumbnail_image_type(last) {
            None => get_thumbnail_type(last).to_string(),
            Some(image_type) => format!("{}.{}", get_thumbnail_type(last), image_type),
        };
        return (label, instance);
    }

    let parts: Vec<&str> = last.split("__").collect();
    let instance = if parts.len() == 2 {
        parts[1].parse::<usize>().unwrap_or(0)
    } else {
        0
    };
    (parts[0].to_owned(), instance)
}

fn label_with_instance(label: &str, instance: usize) -> String {
    if instance == 0 {
        label.to_string()
    } else if get_thumbnail_type(label) == INGREDIENT_THUMBNAIL {
        let base = format!("{}__{}", get_thumbnail_type(label), instance);
        match get_thumbnail_image_type(label) {
            Some(image_type) => format!("{base}.{image_type}"),
            None => base,
        }
    } else {
        format!("{label}__{instance}")
    }
}

fn get_mutable_label(var_label: &str) -> (String, Option<usize>) {
    if var_label.starts_with(SCHEMA_ORG) {
        (var_label.to_string(), None)
    } else {
        let tn = get_thumbnail_type(var_label);
        if tn == "none" {
            let components: Vec<&str> = var_label.split('.').collect();
            match components.last() {
                Some(last) if last.len() > 1 => {
                    let (ver, ver_inst_str) = last.split_at(1);
                    if ver == "v" {
                        if let Ok(ver_inst) = ver_inst_str.parse::<usize>() {
                            let ver_trim = format!(".{last}");
                            let root_label = var_label.trim_end_matches(&ver_trim);
                            return (root_label.to_string(), Some(ver_inst));
                        }
                    }
                    (var_label.to_string(), None)
                }
                _ => (var_label.to_string(), None),
            }
        } else {
            (tn.to_string(), None)
        }
    }
}

// ---- AssertionBase trait ----

/// Core required trait for all assertions.
pub trait AssertionBase
where
    Self: Sized,
{
    const LABEL: &'static str = "unknown";
    const VERSION: Option<usize> = None;

    fn label(&self) -> &str {
        Self::LABEL
    }

    fn version(&self) -> Option<usize> {
        Self::VERSION
    }

    fn to_assertion(&self) -> Result<Assertion>;
    fn from_assertion(assertion: &Assertion) -> Result<Self>;
}

/// Default CBOR encoding/decoding for assertions.
pub trait AssertionCbor: Serialize + DeserializeOwned + AssertionBase {
    fn to_cbor_assertion(&self) -> Result<Assertion> {
        let data = AssertionData::Cbor(
            c2pa_cbor::to_vec(self).map_err(|e| Error::AssertionEncoding(e.to_string()))?,
        );
        Ok(Assertion::new(self.label(), self.version(), data).set_content_type("application/cbor"))
    }

    fn from_cbor_assertion(assertion: &Assertion) -> Result<Self> {
        assertion.check_max_version(Self::VERSION)?;
        match assertion.decode_data() {
            AssertionData::Cbor(data) => {
                c2pa_cbor::from_slice(data).map_err(|e| Error::AssertionDecoding(e.to_string()))
            }
            data => Err(Error::AssertionDecoding(format!(
                "expected cbor, found {}",
                AssertionDecodeError::data_type_name(data)
            ))),
        }
    }
}

/// Default JSON encoding/decoding for assertions.
pub trait AssertionJson: Serialize + DeserializeOwned + AssertionBase {
    fn to_json_assertion(&self) -> Result<Assertion> {
        let data = AssertionData::Json(
            serde_json::to_string(self).map_err(|e| Error::AssertionEncoding(e.to_string()))?,
        );
        Ok(Assertion::new(self.label(), self.version(), data).set_content_type("application/json"))
    }

    fn from_json_assertion(assertion: &Assertion) -> Result<Self> {
        assertion.check_max_version(Self::VERSION)?;
        match assertion.decode_data() {
            AssertionData::Json(data) => {
                serde_json::from_str(data).map_err(|e| Error::AssertionDecoding(e.to_string()))
            }
            data => Err(Error::AssertionDecoding(format!(
                "expected json, found {}",
                AssertionDecodeError::data_type_name(data)
            ))),
        }
    }
}

// ---- AssertionData ----

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Hash)]
pub enum AssertionData {
    Json(String),
    Binary(Vec<u8>),
    Cbor(Vec<u8>),
    Uuid(String, Vec<u8>),
}

impl From<AssertionData> for Vec<u8> {
    fn from(ad: AssertionData) -> Self {
        match ad {
            AssertionData::Json(s) => s.into_bytes(),
            AssertionData::Binary(x) | AssertionData::Uuid(_, x) => x,
            AssertionData::Cbor(x) => x,
        }
    }
}

impl fmt::Debug for AssertionData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Json(s) => write!(f, "{s:?}"),
            Self::Binary(_) => write!(f, "<omitted>"),
            Self::Uuid(uuid, _) => write!(f, "uuid: {uuid}, <omitted>"),
            Self::Cbor(s) => {
                let buf: Vec<u8> = Vec::new();
                let mut from = c2pa_cbor::Deserializer::from_slice(s);
                let mut to = serde_json::Serializer::pretty(buf);
                serde_transcode::transcode(&mut from, &mut to).map_err(|_| fmt::Error)?;
                let decoded: Value =
                    serde_json::from_slice(&to.into_inner()).map_err(|_| fmt::Error)?;
                write!(f, "{:?}", decoded.to_string())
            }
        }
    }
}

// ---- Assertion ----

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Assertion {
    label: String,
    version: Option<usize>,
    data: AssertionData,
    content_type: String,
    /// JUMBF description-box salt, preserved when loading from JUMBF so that
    /// the re-serialized box bytes are identical to the originals.
    salt: Option<Vec<u8>>,
}

impl Assertion {
    pub fn new(label: &str, version: Option<usize>, data: AssertionData) -> Self {
        Self {
            label: label.to_owned(),
            version,
            content_type: "application/cbor".to_owned(),
            data,
            salt: None,
        }
    }

    pub fn set_content_type(mut self, content_type: &str) -> Self {
        content_type.clone_into(&mut self.content_type);
        self
    }

    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    pub fn salt(&self) -> Option<&Vec<u8>> {
        self.salt.as_ref()
    }

    pub fn set_salt(&mut self, salt: Vec<u8>) {
        self.salt = Some(salt);
    }

    pub fn version(&self) -> usize {
        self.version.unwrap_or(1)
    }

    fn get_ver(&self) -> usize {
        self.version.unwrap_or(1)
    }

    pub fn decode_data(&self) -> &AssertionData {
        &self.data
    }

    pub fn data(&self) -> &[u8] {
        match self.decode_data() {
            AssertionData::Json(x) => x.as_bytes(),
            AssertionData::Binary(x) | AssertionData::Uuid(_, x) => x,
            AssertionData::Cbor(x) => x,
        }
    }

    /// Returns the canonical label root (no version suffix) plus any thumbnail image type.
    pub fn label_root(&self) -> String {
        let label = get_mutable_label(&self.label).0;
        match get_thumbnail_image_type(&self.label) {
            None => label,
            Some(image_type) => format!("{label}.{image_type}"),
        }
    }

    /// Returns the label with version suffix when version > 1.
    pub fn label(&self) -> String {
        let base_label = self.label_root();
        let v = self.get_ver();
        if v > 1 {
            format!("{base_label}.v{v}")
        } else {
            base_label
        }
    }

    pub fn assertions_eq(a: &Assertion, b: &Assertion) -> bool {
        a.label_root() == b.label_root()
    }

    fn from_assertion_data(label: &str, content_type: &str, data: AssertionData) -> Assertion {
        let version = label_version(label);
        let (label, instance) = assertion_label_from_link(label);
        let label = label_with_instance(&label, instance);
        Self {
            label,
            version: if version == 1 { None } else { Some(version) },
            data,
            content_type: content_type.to_owned(),
            salt: None,
        }
    }

    pub fn from_data_binary(label: &str, mime_type: &str, binary_data: &[u8]) -> Assertion {
        Self::from_assertion_data(
            label,
            mime_type,
            AssertionData::Binary(binary_data.to_vec()),
        )
    }

    pub fn from_data_uuid(label: &str, uuid_str: &str, binary_data: &[u8]) -> Assertion {
        Self::from_assertion_data(
            label,
            "application/octet-stream",
            AssertionData::Uuid(uuid_str.to_owned(), binary_data.to_vec()),
        )
    }

    pub fn from_data_cbor(label: &str, binary_data: &[u8]) -> Assertion {
        Self::from_assertion_data(
            label,
            "application/cbor",
            AssertionData::Cbor(binary_data.to_vec()),
        )
    }

    pub fn from_data_json(label: &str, binary_data: &[u8]) -> AssertionDecodeResult<Assertion> {
        let json = String::from_utf8(binary_data.to_vec()).map_err(|_| AssertionDecodeError {
            label: label.to_string(),
            version: None,
            content_type: "application/json".to_string(),
            source: AssertionDecodeErrorCause::BinaryDataNotUtf8,
        })?;
        Ok(Self::from_assertion_data(
            label,
            "application/json",
            AssertionData::Json(json),
        ))
    }

    fn check_max_version(&self, max_version: Option<usize>) -> Result<()> {
        if let (Some(data_version), Some(max)) = (self.version, max_version) {
            if data_version > max {
                return Err(Error::AssertionDecoding(format!(
                    "assertion {} version {data_version} > max {max}",
                    self.label
                )));
            }
        }
        Ok(())
    }
}

// ---- AssertionDecodeError ----

#[non_exhaustive]
pub struct AssertionDecodeError {
    pub label: String,
    pub version: Option<usize>,
    pub content_type: String,
    pub source: AssertionDecodeErrorCause,
}

impl AssertionDecodeError {
    fn data_type_name(data: &AssertionData) -> &'static str {
        match data {
            AssertionData::Json(_) => "json",
            AssertionData::Binary(_) => "binary",
            AssertionData::Cbor(_) => "cbor",
            AssertionData::Uuid(_, _) => "uuid",
        }
    }

    fn fmt_internal(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "could not decode assertion {} (version {}, content type {}): {}",
            self.label,
            self.version
                .map_or("(no version)".to_string(), |v| v.to_string()),
            self.content_type,
            self.source
        )
    }
}

impl fmt::Debug for AssertionDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_internal(f)
    }
}

impl fmt::Display for AssertionDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_internal(f)
    }
}

impl std::error::Error for AssertionDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AssertionDecodeErrorCause {
    #[error("unexpected data type: expected {expected}, found {found}")]
    UnexpectedDataType { expected: String, found: String },

    #[error("assertion version too new: expected no later than {max}, found {found}")]
    AssertionTooNew { max: usize, found: usize },

    #[error("binary data could not be interpreted as UTF-8")]
    BinaryDataNotUtf8,

    #[error("assertion data did not match hash link")]
    AssertionDataIncorrect,

    #[error(transparent)]
    JsonError(#[from] serde_json::Error),

    #[error(transparent)]
    CborError(#[from] c2pa_cbor::Error),

    #[error("mandatory field could not be decoded: {expected}")]
    FieldDecoding { expected: String },
}

pub type AssertionDecodeResult<T> = std::result::Result<T, AssertionDecodeError>;

// ---- ClaimAssertion ----

#[derive(PartialEq, Debug, Eq, Clone, Hash)]
pub enum ClaimAssertionType {
    V1,
    Gathered,
    Created,
}

#[derive(PartialEq, Eq, Clone, Hash)]
pub struct ClaimAssertion {
    assertion: Assertion,
    instance: usize,
    hash_val: Vec<u8>,
    hash_alg: String,
    salt: Option<Vec<u8>>,
    typ: ClaimAssertionType,
}

impl ClaimAssertion {
    pub fn new(
        assertion: Assertion,
        instance: usize,
        hash_val: &[u8],
        alg: &str,
        salt: Option<Vec<u8>>,
        typ: ClaimAssertionType,
    ) -> Self {
        Self {
            assertion,
            instance,
            hash_val: hash_val.to_vec(),
            hash_alg: alg.to_string(),
            salt,
            typ,
        }
    }

    pub fn label(&self) -> String {
        let al_ref = self.assertion.label();
        if self.instance > 0 {
            if get_thumbnail_type(&al_ref) == INGREDIENT_THUMBNAIL {
                let label = format!("{}__{}", get_thumbnail_type(&al_ref), self.instance);
                match get_thumbnail_image_type(&al_ref) {
                    Some(image_type) => format!("{label}.{image_type}"),
                    None => label,
                }
            } else {
                format!("{}__{}", al_ref, self.instance)
            }
        } else {
            self.assertion.label()
        }
    }

    pub fn instance(&self) -> usize {
        self.instance
    }

    pub fn assertion(&self) -> &Assertion {
        &self.assertion
    }

    pub fn hash(&self) -> &[u8] {
        &self.hash_val
    }

    pub fn salt(&self) -> &Option<Vec<u8>> {
        &self.salt
    }

    pub fn hash_alg(&self) -> &str {
        &self.hash_alg
    }

    pub fn assertion_type(&self) -> &ClaimAssertionType {
        &self.typ
    }
}

impl fmt::Debug for ClaimAssertion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?}, instance: {}, type: {:?}",
            self.assertion, self.instance, self.typ
        )
    }
}
