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

use serde::{Deserialize, Serialize};

use crate::{
    assertion::{Assertion, AssertionBase, AssertionData, AssertionDecodeError},
    error::{Error, Result},
};

/// Helper class to create Cbor User assertion
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
pub struct UserCbor {
    label: String,
    cbor_data: Vec<u8>,
}

impl UserCbor {
    /// Create new UserCbor instance
    pub fn new(label: &str, data: Vec<u8>) -> UserCbor {
        UserCbor {
            label: label.to_owned(),
            cbor_data: data,
        }
    }
}

impl AssertionBase for UserCbor {
    /// returns the label for this instance
    fn label(&self) -> &str {
        &self.label
    }

    fn to_assertion(&self) -> Result<Assertion> {
        // validate cbor
        let _value: serde_cbor::Value =
            serde_cbor::from_slice(&self.cbor_data).map_err(|_err| Error::AssertionEncoding)?;
        let data = AssertionData::Cbor(self.cbor_data.clone());
        Ok(Assertion::new(&self.label, None, data))
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        match assertion.decode_data() {
            AssertionData::Cbor(data) => {
                // validate cbor
                let _value: serde_cbor::Value = serde_cbor::from_slice(data).map_err(|e| {
                    Error::AssertionDecoding(AssertionDecodeError::from_assertion_and_cbor_err(
                        assertion, e,
                    ))
                })?;

                Ok(Self::new(&assertion.label(), data.clone()))
            }
            ad => Err(AssertionDecodeError::from_assertion_unexpected_data_type(
                assertion, ad, "cbor",
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
    const LABEL: &str = "user_test_assertion";
    const DATA: &str = r#"{ "l1":"some data", "l2":"some other data" }"#;

    #[test]
    fn assertion_user_cbor() {
        let json: serde_json::Value = serde_json::from_str(DATA).unwrap();
        let data = serde_cbor::to_vec(&json).unwrap();
        let original = UserCbor::new(LABEL, data);
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/cbor");
        assert_eq!(assertion.label(), LABEL);
        let result = UserCbor::from_assertion(&assertion).expect("from_assertion");
        assert_eq!(original.cbor_data, result.cbor_data);
    }

    #[test]
    fn assertion_user_cbor_invalid_to() {
        let invalid_cbor = vec![0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f];
        let original = UserCbor::new(LABEL, invalid_cbor);
        original
            .to_assertion()
            .expect_err("Assertion encoding error expected");
    }

    #[test]
    fn assertion_user_cbor_invalid_from() {
        let invalid_cbor = vec![0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f];
        let data = AssertionData::Cbor(invalid_cbor);
        let assertion = Assertion::new(LABEL, None, data);
        let _result =
            UserCbor::from_assertion(&assertion).expect_err("Assertion decoding error expected");
    }
}
