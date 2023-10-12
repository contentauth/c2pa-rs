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
    assertion::{
        get_thumbnail_image_type, Assertion, AssertionBase, AssertionData, AssertionDecodeError,
    },
    assertions::labels,
    error::Result,
};

/// A Thumbnail assertion
#[derive(Serialize)]
pub struct Thumbnail {
    pub data: Vec<u8>,
    pub label: String,
    pub content_type: String,
}

impl Thumbnail {
    pub fn new(label: &str, data: Vec<u8>) -> Self {
        let image_type = get_thumbnail_image_type(label);
        let content_type = match image_type.as_str() {
            "jpeg" | "jpk2" => "image/jpeg",
            "png" => "image/png",
            "bmp" => "image/bmp",
            "gif" => "image/gif",
            "tiff" => "image/tiff",
            "ico" => "image/x-icon",
            "webp" => "image/webp",
            _ => "application/octet-stream",
        }
        .to_string();

        Thumbnail {
            data,
            label: label.to_owned(),
            content_type,
        }
    }
}

impl AssertionBase for Thumbnail {
    /// returns the base label type for this thumbnail
    fn label(&self) -> &str {
        if self.label.starts_with(labels::CLAIM_THUMBNAIL) {
            labels::CLAIM_THUMBNAIL
        } else {
            labels::INGREDIENT_THUMBNAIL
        }
    }

    fn to_assertion(&self) -> Result<Assertion> {
        let data = AssertionData::Binary(self.data.to_owned());
        Ok(Assertion::new(&self.label, None, data).set_content_type(&self.content_type))
    }

    fn from_assertion(assertion: &Assertion) -> Result<Thumbnail> {
        match assertion.decode_data() {
            AssertionData::Binary(data) => Ok(Self {
                data: data.to_owned(),
                label: assertion.label(),
                content_type: assertion.content_type(),
            }),
            ad => Err(AssertionDecodeError::from_assertion_unexpected_data_type(
                assertion, ad, "binary",
            )
            .into()),
        }
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::assertions::labels;

    // a binary assertion  ('deadbeefadbeadbe')
    fn some_binary_data() -> Vec<u8> {
        vec![
            0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d,
            0x0b, 0x0e,
        ]
    }

    fn thumbnail_test(label: &str, content_type: &str) {
        let original = Thumbnail::new(label, some_binary_data());
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.content_type(), content_type);
        assert_eq!(assertion.label(), label);
        let result = Thumbnail::from_assertion(&assertion).expect("from_assertion");
        assert_eq!(original.label, result.label);
        assert_eq!(original.content_type, result.content_type);
        assert_eq!(original.data, result.data);
    }

    #[test]
    fn assertion_thumbnail_valid() {
        thumbnail_test(labels::JPEG_CLAIM_THUMBNAIL, "image/jpeg");
        thumbnail_test(labels::PNG_CLAIM_THUMBNAIL, "image/png");
        thumbnail_test(labels::JPEG_INGREDIENT_THUMBNAIL, "image/jpeg");
        thumbnail_test(labels::PNG_INGREDIENT_THUMBNAIL, "image/png");
        // unrecognized labels will be formatted as octet_streams
        thumbnail_test("foo", "application/octet-stream");
    }

    #[test]
    fn assertion_thumbnail_invalid_from() {
        // only current error is if the assertion data is the wrong type, so use JSON
        let data = AssertionData::Json("foo".to_owned());
        let assertion = Assertion::new(labels::JPEG_CLAIM_THUMBNAIL, None, data);
        let result = Thumbnail::from_assertion(&assertion);
        assert!(result.is_err())
    }
}
