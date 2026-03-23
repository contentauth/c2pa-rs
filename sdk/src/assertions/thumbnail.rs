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

use std::ops::{Deref, DerefMut};

use serde::Serialize;

use crate::{
    assertion::{get_thumbnail_image_type, Assertion, AssertionBase, AssertionData},
    assertions::{labels, EmbeddedData},
    error::Result,
};

/// A Thumbnail assertion
#[derive(Serialize)]
/// We no longer need a specific Thumbnail Assertion type, so this is deprecated.
/// Please use EmbeddedData instead.
/// This exists to maintain compatibility with existing assertions that use the old v1 label format.
pub struct Thumbnail(EmbeddedData);

impl Thumbnail {
    /// This creates thumbnails with the old v1 label format and is deprecated.
    /// Use `EmbeddedData::new` instead to specify the content type.
    pub(crate) fn new(label: &str, data: Vec<u8>) -> Self {
        let image_type = get_thumbnail_image_type(label);
        let content_type = match &image_type {
            Some(it) => match it.as_str() {
                "jpeg" | "jpk2" => "image/jpeg",
                "png" => "image/png",
                "bmp" => "image/bmp",
                "gif" => "image/gif",
                "tiff" => "image/tiff",
                "ico" => "image/x-icon",
                "webp" => "image/webp",
                _ => "application/octet-stream",
            },
            None => "application/octet-stream",
        }
        .to_string();
        Self(EmbeddedData::new(label, content_type, data))
    }
}

impl Deref for Thumbnail {
    type Target = EmbeddedData;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Thumbnail {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
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
        let data = AssertionData::Binary(self.data.clone());
        Ok(Assertion::new(&self.label, None, data).set_content_type(&self.content_type))
    }

    fn from_assertion(assertion: &Assertion) -> Result<Thumbnail> {
        let embedded_data = EmbeddedData::from_assertion(assertion)?;
        Ok(Self(embedded_data))
    }
}

// make it easy to convert from EmbeddedData to Thumbnail and vice versa
impl From<EmbeddedData> for Thumbnail {
    fn from(embedded_data: EmbeddedData) -> Self {
        Self(embedded_data)
    }
}

impl From<Thumbnail> for EmbeddedData {
    fn from(val: Thumbnail) -> Self {
        val.0
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

    #[test]
    fn assertion_thumbnail_with_format() {
        let original = EmbeddedData::new("foo", "image/png", some_binary_data());
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.content_type(), "image/png");
        assert_eq!(assertion.label(), "foo");
        let result = Thumbnail::from_assertion(&assertion).expect("from_assertion");
        assert_eq!(original.label, result.label);
        assert_eq!(original.content_type, result.content_type);
        assert_eq!(original.data, result.data);
    }
}
