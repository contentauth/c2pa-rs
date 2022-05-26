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

use crate::{
    assertion::{Assertion, AssertionBase, AssertionData, AssertionDecodeError},
    error::{Error, Result},
};

/// Helper class to create User assertion
#[derive(Debug, Default)]
pub struct Uuid {
    label: String,
    uuid: String,
    data: Vec<u8>,
}

impl Uuid {
    /// Create new Identity instance
    pub fn new(label: &str, uuid: String, data: Vec<u8>) -> Uuid {
        Uuid {
            label: label.to_owned(),
            uuid,
            data,
        }
    }
}

impl AssertionBase for Uuid {
    /// returns the label for this instance
    fn label(&self) -> &str {
        &self.label
    }

    // Build UUID assertion containing user defined data
    // Uuid must be a hex string representing a uuid
    fn to_assertion(&self) -> Result<Assertion> {
        // validate that the string is 16 hex bytes
        match hex::decode(&self.uuid) {
            Ok(v) if v.len() == 16 => (),
            _ => return Err(Error::BadParam("uuid must be 32 hex digits".to_string())),
        }

        let data = AssertionData::Uuid(self.uuid.to_owned(), self.data.to_owned());
        Ok(Assertion::new(&self.label, None, data).set_content_type("application/octet-stream"))
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        match assertion.decode_data() {
            AssertionData::Uuid(s, data) => {
                Ok(Uuid::new(&assertion.label(), s.clone(), data.clone()))
            }
            ad => Err(AssertionDecodeError::from_assertion_unexpected_data_type(
                assertion, ad, "uuid",
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
    const LABEL: &str = "uuid_test_assertion";
    const UUID: &str = "ABCDABCDABCDABCDABCDABCDABCDABCD";
    const INVALID_UUID: &str = "I am bad";
    const DATA: [u8; 16] = [
        0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d, 0x0b,
        0x0e,
    ];

    #[test]
    fn assertion_uuid() {
        let original = Uuid::new(LABEL, UUID.to_string(), DATA.to_vec());
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/octet-stream");
        assert_eq!(assertion.label(), LABEL);
        let result = Uuid::from_assertion(&assertion).expect("from_assertion");
        assert_eq!(original.data, result.data);
    }

    #[test]
    fn assertion_bad_uuid() {
        let original = Uuid::new(LABEL, INVALID_UUID.to_string(), DATA.to_vec());
        original
            .to_assertion()
            .expect_err("Assertion encoding error expected");
    }
}
