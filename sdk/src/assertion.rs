// Copyright 2022 Adobe. All rights reserved.
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

use std::fmt;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::Value;
use thiserror::Error;

use crate::{
    assertions::labels,
    error::{Error, Result},
};

/// Check to see if this a label whose string can vary, if so return the root of the label and version if available
fn get_mutable_label(var_label: &str) -> (String, Option<usize>) {
    if var_label.starts_with(labels::SCHEMA_ORG) {
        (var_label.to_string(), None)
    } else {
        // is it a type of thumbnail
        let tn = get_thumbnail_type(var_label);

        if tn == "none" {
            let components: Vec<&str> = var_label.split('.').collect();
            match components.last() {
                Some(last) => {
                    // check for a valid version number
                    if last.len() > 1 {
                        let (ver, ver_inst_str) = last.split_at(1);
                        if ver == "v" {
                            if let Ok(ver_inst) = ver_inst_str.parse::<usize>() {
                                let ver_trim = format!(".{}", last);
                                let root_label = var_label.trim_end_matches(&ver_trim);
                                return (root_label.to_string(), Some(ver_inst));
                            }
                        }
                    }
                    (var_label.to_string(), None)
                }
                None => (var_label.to_string(), None),
            }
        } else {
            (tn, None)
        }
    }
}

pub fn get_thumbnail_type(thumbnail_label: &str) -> String {
    if thumbnail_label.starts_with(labels::CLAIM_THUMBNAIL) {
        return labels::CLAIM_THUMBNAIL.to_string();
    }
    if thumbnail_label.starts_with(labels::INGREDIENT_THUMBNAIL) {
        return labels::INGREDIENT_THUMBNAIL.to_string();
    }
    "none".to_string()
}

pub fn get_thumbnail_image_type(thumbnail_label: &str) -> String {
    let components: Vec<&str> = thumbnail_label.split('.').collect();

    if thumbnail_label.contains("thumbnail") && components.len() >= 4 {
        let image_type: Vec<&str> = components[3].split('_').collect(); // strip and other label adornments
        image_type[0].to_ascii_lowercase()
    } else {
        "none".to_string()
    }
}

pub fn get_thumbnail_instance(label: &str) -> Option<usize> {
    let label_type = get_thumbnail_type(label);
    // only ingredients thumbs store ids in the label, so use placeholder ids for the others
    match label_type.as_ref() {
        labels::INGREDIENT_THUMBNAIL => {
            // extract id from underscore separated part of the full label
            let components: Vec<&str> = label.split("__").collect();
            if components.len() == 2 {
                let subparts: Vec<&str> = components[1].split('.').collect();
                match subparts[0].parse::<usize>() {
                    Ok(i) => Some(i),
                    Err(_e) => None,
                }
            } else {
                Some(0)
            }
        }
        _ => None,
    }
}

/// The core required trait for all assertions.
///
/// This defines the label and version for the assertion
/// and supplies the to/from converters for C2PA assertion format.
pub trait AssertionBase
where
    Self: Sized,
{
    const LABEL: &'static str = "unknown";

    const VERSION: Option<usize> = None;

    /// Returns a label for this assertion.
    fn label(&self) -> &str {
        Self::LABEL
    }

    /// Returns an Assertion upon success or Error otherwise.
    fn to_assertion(&self) -> Result<Assertion>;

    /// Returns Self or AssertionDecode Result from an assertion
    fn from_assertion(assertion: &Assertion) -> Result<Self>;
}

/// Trait to handle default Cbor encoding/decoding of Assertions
pub trait AssertionCbor: Serialize + DeserializeOwned + AssertionBase {
    fn to_cbor_assertion(&self) -> Result<Assertion> {
        let data =
            AssertionData::Cbor(serde_cbor::to_vec(self).map_err(|_err| Error::AssertionEncoding)?);
        Ok(Assertion::new(self.label(), Self::VERSION, data))
    }

    fn from_cbor_assertion(assertion: &Assertion) -> Result<Self> {
        assertion.check_max_version(Self::VERSION)?;

        match assertion.decode_data() {
            AssertionData::Cbor(data) => Ok(serde_cbor::from_slice(data).map_err(|e| {
                Error::AssertionDecoding(AssertionDecodeError::from_assertion_and_cbor_err(
                    assertion, e,
                ))
            })?),

            data => Err(AssertionDecodeError::from_assertion_unexpected_data_type(
                assertion, data, "cbor",
            )
            .into()),
        }
    }
}

/// Trait to handle default Json encoding/decoding of Assertions
pub trait AssertionJson: Serialize + DeserializeOwned + AssertionBase {
    fn to_json_assertion(&self) -> Result<Assertion> {
        let data = AssertionData::Json(
            serde_json::to_string(self).map_err(|_err| Error::AssertionEncoding)?,
        );
        Ok(Assertion::new(self.label(), Self::VERSION, data).set_content_type("application/json"))
    }

    fn from_json_assertion(assertion: &Assertion) -> Result<Self> {
        assertion.check_max_version(Self::VERSION)?;

        match assertion.decode_data() {
            AssertionData::Json(data) => Ok(serde_json::from_str(data)
                .map_err(|e| AssertionDecodeError::from_assertion_and_json_err(assertion, e))?),
            data => Err(Error::AssertionDecoding(
                AssertionDecodeError::from_assertion_unexpected_data_type(assertion, data, "json"),
            )),
        }
    }
}

/// Assertion data as binary CBOR or JSON depending upon
/// the Assertion type (see spec).
/// For JSON assertions the data is a JSON string and a Vec of u8 values for
/// binary data and JSON data to be CBOR encoded.
#[derive(Deserialize, Serialize, PartialEq, Eq, Clone)]
pub enum AssertionData {
    Json(String),          // json encoded data
    Binary(Vec<u8>),       // binary data
    Cbor(Vec<u8>),         // binary cbor encoded data
    Uuid(String, Vec<u8>), // user defined content (uuid, data)
}

impl fmt::Debug for AssertionData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Json(s) => write!(f, "{:?}", s), // json encoded data
            Self::Binary(_) => write!(f, "<omitted>"),
            Self::Uuid(uuid, _) => {
                write!(f, "uuid: {}, <omitted>", uuid)
            }
            Self::Cbor(s) => {
                let buf: Vec<u8> = Vec::new();
                let mut from = serde_cbor::Deserializer::from_slice(s);
                let mut to = serde_json::Serializer::pretty(buf);

                serde_transcode::transcode(&mut from, &mut to).map_err(|_err| fmt::Error)?;
                let buf2 = to.into_inner();

                let decoded: Value = serde_json::from_slice(&buf2).map_err(|_err| fmt::Error)?;

                write!(f, "{:?}", decoded.to_string())
            }
        }
    }
}

/// Internal Assertion structure
///
// Each assertion type will
// contain its AssertionData.  For the User Assertion type we
// allow a String to set the label. The AssertionData contains
// the data payload for the assertion and the version number for its schema (if supported).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assertion {
    label: String,
    version: Option<usize>,
    data: AssertionData,
    content_type: String,
}

impl Assertion {
    pub(crate) fn new(label: &str, version: Option<usize>, data: AssertionData) -> Self {
        Self {
            label: label.to_owned(),
            version,
            content_type: "application/cbor".to_owned(),
            data,
        }
    }

    pub(crate) fn set_content_type(mut self, content_type: &str) -> Self {
        self.content_type = content_type.to_owned();
        self
    }

    /// return content_type for the the data enclosed in the Assertion
    pub(crate) fn content_type(&self) -> String {
        self.content_type.clone()
    }

    // pub(crate) fn set_data(mut self, data: &AssertionData) -> Self {
    //     self.data = data.to_owned();
    //     self
    // }

    // Return version string of known assertion if available
    pub(crate) fn get_ver(&self) -> Option<usize> {
        self.version
    }

    // pub fn check_version(&self, max_version: usize) -> AssertionDecodeResult<()> {
    //     match self.version {
    //         Some(version) if version > max_version => Err(AssertionDecodeError {
    //             label: self.label.clone(),
    //             version: self.version,
    //             content_type: self.content_type.clone(),
    //             source: AssertionDecodeErrorCause::AssertionTooNew {
    //                 max: max_version,
    //                 found: version,
    //             },
    //         }),
    //         _ => Ok(()),
    //     }
    // }

    /// Return a reference to the AssertionData bound to this Assertion
    pub(crate) fn decode_data(&self) -> &AssertionData {
        &self.data
    }

    /// return mimetype for the the data enclosed in the Assertion
    pub(crate) fn mime_type(&self) -> String {
        self.content_type.clone()
    }

    /// Test to see if the Assertions are of the same variant
    pub(crate) fn assertions_eq(a: &Assertion, b: &Assertion) -> bool {
        a.label_root() == b.label_root()
    }

    /// Return the CAI label for this Assertion (no version)
    pub(crate) fn label_root(&self) -> String {
        let label = get_mutable_label(&self.label).0;
        // thumbnails need the image_type added
        match get_thumbnail_image_type(&self.label).as_str() {
            "none" => label,
            image_type => format!("{}.{}", label, image_type),
        }
    }

    /// Return the CAI label for this Assertion with version string if available
    pub(crate) fn label(&self) -> String {
        let base_label = self.label_root();
        match self.get_ver() {
            Some(v) => {
                if v > 1 {
                    // c2pa does not include v1 labels
                    format!("{}.v{}", base_label, v)
                } else {
                    base_label
                }
            }
            None => base_label,
        }
    }

    /// Return a reference to the data as a byte array
    pub(crate) fn data(&self) -> &[u8] {
        // return bytes of the assertion data
        match self.decode_data() {
            AssertionData::Json(x) => x.as_bytes(), // json encoded data
            AssertionData::Binary(x) | AssertionData::Uuid(_, x) => x, // binary data
            AssertionData::Cbor(x) => x,
        }
    }

    /// Return assertion as serde_json Object
    /// this may have loss of cbor structure if unsupported in conversion to json
    pub(crate) fn as_json_object(&self) -> AssertionDecodeResult<Value> {
        match self.decode_data() {
            AssertionData::Json(x) => serde_json::from_str(x)
                .map_err(|e| AssertionDecodeError::from_assertion_and_json_err(self, e)),

            AssertionData::Cbor(x) => {
                let buf: Vec<u8> = Vec::new();
                let mut from = serde_cbor::Deserializer::from_slice(x);
                let mut to = serde_json::Serializer::new(buf);

                serde_transcode::transcode(&mut from, &mut to)
                    .map_err(|e| AssertionDecodeError::from_assertion_and_json_err(self, e))?;

                let buf2 = to.into_inner();
                serde_json::from_slice(&buf2)
                    .map_err(|e| AssertionDecodeError::from_assertion_and_json_err(self, e))
            }

            AssertionData::Binary(x) => {
                let binary_bytes = ByteBuf::from(x.clone());
                let binary_str = serde_json::to_string(&binary_bytes)
                    .map_err(|e| AssertionDecodeError::from_assertion_and_json_err(self, e))?;

                serde_json::from_str(&binary_str)
                    .map_err(|e| AssertionDecodeError::from_assertion_and_json_err(self, e))
            }
            AssertionData::Uuid(uuid, x) => {
                #[derive(Serialize)]
                struct TmpObj<'a> {
                    uuid: &'a str,
                    data: ByteBuf,
                }

                let v = TmpObj {
                    uuid,
                    data: ByteBuf::from(x.clone()),
                };

                let binary_str = serde_json::to_string(&v)
                    .map_err(|e| AssertionDecodeError::from_assertion_and_json_err(self, e))?;

                serde_json::from_str(&binary_str)
                    .map_err(|e| AssertionDecodeError::from_assertion_and_json_err(self, e))
            }
        }
    }

    fn from_assertion_data(label: &str, content_type: &str, data: AssertionData) -> Assertion {
        use crate::claim::Claim;
        let version = labels::version(label);
        let (label, instance) = Claim::assertion_label_from_link(label);
        let label = Claim::label_with_instance(&label, instance);

        Self {
            label,
            version,
            data,
            content_type: content_type.to_owned(),
        }
    }

    /// create an assertion from binary data
    pub(crate) fn from_data_binary(label: &str, mime_type: &str, binary_data: &[u8]) -> Assertion {
        Self::from_assertion_data(
            label,
            mime_type,
            AssertionData::Binary(binary_data.to_vec()),
        )
    }

    /// create an assertion from user binary data
    pub(crate) fn from_data_uuid(label: &str, uuid_str: &str, binary_data: &[u8]) -> Assertion {
        Self::from_assertion_data(
            label,
            "application/octet-stream",
            AssertionData::Uuid(uuid_str.to_owned(), binary_data.to_vec()),
        )
    }

    pub(crate) fn from_data_cbor(label: &str, binary_data: &[u8]) -> Assertion {
        Self::from_assertion_data(
            label,
            "application/cbor",
            AssertionData::Cbor(binary_data.to_vec()),
        )
    }

    pub(crate) fn from_data_json(
        label: &str,
        binary_data: &[u8],
    ) -> AssertionDecodeResult<Assertion> {
        let json = String::from_utf8(binary_data.to_vec()).map_err(|_| AssertionDecodeError {
            label: label.to_string(),
            version: None, // TODO: Can we get this info?
            content_type: "json".to_string(),
            source: AssertionDecodeErrorCause::BinaryDataNotUtf8,
        })?;

        Ok(Self::from_assertion_data(
            label,
            "application/json",
            AssertionData::Json(json),
        ))
    }

    // Check assertion label against a target label.
    pub(crate) fn check_version_from_label(
        &self,
        desired_version: usize,
    ) -> AssertionDecodeResult<()> {
        if let Some(base_version) = labels::version(&self.label) {
            if desired_version > base_version {
                return Err(AssertionDecodeError {
                    label: self.label.clone(),
                    version: self.version,
                    content_type: self.content_type.clone(),
                    source: AssertionDecodeErrorCause::AssertionTooNew {
                        max: desired_version,
                        found: base_version,
                    },
                });
            }
        }

        Ok(())
    }

    fn check_max_version(&self, max_version: Option<usize>) -> AssertionDecodeResult<()> {
        if let Some(data_version) = self.version {
            if let Some(max_version) = max_version {
                if data_version > max_version {
                    return Err(AssertionDecodeError {
                        label: self.label.clone(),
                        version: self.version,
                        content_type: self.content_type.clone(),
                        source: AssertionDecodeErrorCause::AssertionTooNew {
                            max: max_version,
                            found: data_version,
                        },
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct JsonAssertionData {
    label: String,
    data: Value,
    is_cbor: bool,
}

/// This error type is returned when an assertion can not be decoded.
#[non_exhaustive]
pub struct AssertionDecodeError {
    pub label: String,
    pub version: Option<usize>,
    pub content_type: String,
    pub source: AssertionDecodeErrorCause,
}

impl AssertionDecodeError {
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

    pub(crate) fn from_assertion_and_cbor_err(
        assertion: &Assertion,
        source: serde_cbor::error::Error,
    ) -> Self {
        Self {
            label: assertion.label.clone(),
            version: assertion.version,
            content_type: assertion.content_type.clone(),
            source: source.into(),
        }
    }

    pub(crate) fn from_assertion_and_json_err(
        assertion: &Assertion,
        source: serde_json::error::Error,
    ) -> Self {
        Self {
            label: assertion.label.clone(),
            version: assertion.version,
            content_type: assertion.content_type.clone(),
            source: source.into(),
        }
    }

    pub(crate) fn from_assertion_unexpected_data_type(
        assertion: &Assertion,
        assertion_data: &AssertionData,
        expected: &str,
    ) -> Self {
        Self {
            label: assertion.label.clone(),
            version: assertion.version,
            content_type: assertion.content_type.clone(),
            source: AssertionDecodeErrorCause::UnexpectedDataType {
                expected: expected.to_string(),
                found: Self::data_type_from_assertion_data(assertion_data),
            },
        }
    }

    fn data_type_from_assertion_data(assertion_data: &AssertionData) -> String {
        match assertion_data {
            AssertionData::Json(_) => "json".to_string(),
            AssertionData::Binary(_) => "binary".to_string(),
            AssertionData::Cbor(_) => "cbor".to_string(),
            AssertionData::Uuid(_, _) => "uuid".to_string(),
        }
    }

    pub(crate) fn from_json_err(
        label: String,
        version: Option<usize>,
        content_type: String,
        source: serde_json::error::Error,
    ) -> Self {
        Self {
            label,
            version,
            content_type,
            source: source.into(),
        }
    }
}

impl std::fmt::Debug for AssertionDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_internal(f)
    }
}

impl std::fmt::Display for AssertionDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_internal(f)
    }
}

impl std::error::Error for AssertionDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// This error type is used inside `AssertionDecodeError` to describe the
/// root cause for the decoding error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AssertionDecodeErrorCause {
    /// The assertion had an unexpected data type.
    #[error("the assertion had an unexpected data type: expected {expected}, found {found}")]
    UnexpectedDataType { expected: String, found: String },

    /// The assertion has a version that is newer that this toolkit can understand.
    #[error("the assertion version is too new: expected no later than {max}, found {found}")]
    AssertionTooNew { max: usize, found: usize },

    /// Binary data could not be interepreted as UTF-8.
    #[error("binary data could not be interpreted as UTF-8")]
    BinaryDataNotUtf8,

    /// Assertion data did not match hash link.
    #[error("the assertion data did not match the hash embedded in the link")]
    AssertionDataIncorrect,

    #[error(transparent)]
    JsonError(#[from] serde_json::Error),

    #[error(transparent)]
    CborError(#[from] serde_cbor::Error),
}

pub(crate) type AssertionDecodeResult<T> = std::result::Result<T, AssertionDecodeError>;

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::assertions::{Action, Actions};

    #[test]
    fn test_version_label() {
        let test_json = r#"{
            "left": 0,
            "right": 2000,
            "top": 1000,
            "botton": 4000
        }"#;
        let json = AssertionData::Json(test_json.to_string());
        let json2 = AssertionData::Json(test_json.to_string());

        let a = Assertion::new(Actions::LABEL, Some(2), json);
        let a_no_ver = Assertion::new(Actions::LABEL, None, json2);

        assert_eq!(a.get_ver().unwrap(), 2);
        assert_eq!(a_no_ver.get_ver(), None);
        assert_eq!(a.label(), format!("{}.{}", Actions::LABEL, "v2"));
        assert_eq!(a.label_root(), Actions::LABEL);
        assert_eq!(a_no_ver.label(), Actions::LABEL);
    }

    #[test]
    fn test_cbor_conversion() {
        let action = Actions::new()
            .add_action(
                Action::new("c2pa.cropped")
                    .set_parameter(
                        "coordinate".to_owned(),
                        r#"{"left": 0,"right": 2000,"top": 1000,"botton": 4000}"#,
                    )
                    .unwrap(),
            )
            .add_action(
                Action::new("c2pa.filtered")
                    .set_parameter("name".to_owned(), "gaussian blur")
                    .unwrap()
                    .set_software_agent("Photoshop")
                    .set_when("2015-06-26T16:43:23+0200"),
            )
            .to_assertion()
            .unwrap();

        let action_cbor = action.data();

        let action_restored = Assertion::from_data_cbor(&action.label(), action_cbor);

        assert!(Assertion::assertions_eq(&action, &action_restored));

        let action_obj = action.as_json_object().unwrap();
        let action_restored_obj = action_restored.as_json_object().unwrap();

        assert_eq!(action_obj, action_restored_obj);
    }
}
