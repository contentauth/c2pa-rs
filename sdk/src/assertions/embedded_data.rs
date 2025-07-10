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

use serde::Serialize;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionData},
    assertions::labels,
    error::Result,
};

/// A EmbeddedData assertion
/// From C2PA v2.0, this is used to embed binary data such as thumbnails or icons.
/// It replaces the old Thumbnail assertion type.
/// The label is used to identify the type of data, and the content type specifies the format.
/// The data is stored as a binary vector.
/// <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_embedded_data>
#[derive(Serialize)]
pub struct EmbeddedData {
    pub label: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

impl EmbeddedData {
    /// Label prefix for a embedded data assertion.
    /// Note that this is often overridden for thumbnails or icons
    pub const LABEL: &'static str = labels::EMBEDDED_DATA;

    /// Create a new EmbeddedData with a specific content type
    pub fn new<L, C, D>(label: L, content_type: C, data: D) -> Self
    where
        L: Into<String>,
        C: Into<String>,
        D: Into<Vec<u8>>,
    {
        Self {
            data: data.into(),
            label: label.into(),
            content_type: content_type.into(),
        }
    }
}

impl AssertionBase for EmbeddedData {
    fn label(&self) -> &str {
        self.label.as_str()
    }

    fn to_assertion(&self) -> Result<Assertion> {
        let data = AssertionData::Binary(self.data.to_owned());
        Ok(Assertion::new(&self.label, None, data).set_content_type(&self.content_type))
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        // Clone the assertion to use the TryFrom implementation
        // This avoids code duplication while maintaining the interface
        assertion.try_into()
    }
}

impl TryFrom<Assertion> for EmbeddedData {
    type Error = crate::Error;

    fn try_from(assertion: Assertion) -> Result<Self> {
        match crate::assertion::Assertion::binary_deconstruct(assertion) {
            Ok((label, _version, content_type, data)) => Ok(Self {
                data,
                label,
                content_type,
            }),
            Err(err) => Err(err),
        }
    }
}

impl TryFrom<&Assertion> for EmbeddedData {
    type Error = crate::Error;

    fn try_from(assertion: &Assertion) -> Result<Self> {
        assertion.clone().try_into()
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    // a binary assertion  ('deadbeefadbeadbe')
    fn some_binary_data() -> Vec<u8> {
        vec![
            0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d,
            0x0b, 0x0e,
        ]
    }

    fn embedded_data_test(label: &str, content_type: &str) {
        let original = EmbeddedData::new(label, content_type, some_binary_data());
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.content_type(), content_type);
        assert_eq!(assertion.label(), label);
        let result = EmbeddedData::from_assertion(&assertion).expect("from_assertion");
        assert_eq!(original.label, result.label);
        assert_eq!(original.content_type, result.content_type);
        assert_eq!(original.data, result.data);
    }

    #[test]
    fn assertion_embedded_data_valid() {
        embedded_data_test(labels::JPEG_CLAIM_THUMBNAIL, "image/jpeg");
        embedded_data_test(labels::PNG_CLAIM_THUMBNAIL, "image/png");
        embedded_data_test(labels::JPEG_INGREDIENT_THUMBNAIL, "image/jpeg");
        embedded_data_test(labels::PNG_INGREDIENT_THUMBNAIL, "image/png");
        // unrecognized labels will be formatted as octet_streams
        embedded_data_test("foo", "application/octet-stream");
    }

    #[test]
    fn assertion_embedded_data_invalid_from() {
        // only current error is if the assertion data is the wrong type, so use JSON
        let data = AssertionData::Json("foo".to_owned());
        let assertion = Assertion::new(labels::JPEG_CLAIM_THUMBNAIL, None, data);
        let result = EmbeddedData::from_assertion(&assertion);
        assert!(result.is_err())
    }

    #[test]
    fn assertion_embedded_data_with_format() {
        let original = EmbeddedData::new(EmbeddedData::LABEL, "image/png", some_binary_data());
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.content_type(), "image/png");
        assert_eq!(assertion.label(), EmbeddedData::LABEL);
        let result = EmbeddedData::from_assertion(&assertion).expect("from_assertion");
        assert_eq!(original.label, result.label);
        assert_eq!(original.content_type, result.content_type);
        assert_eq!(original.data, result.data);
    }
}
