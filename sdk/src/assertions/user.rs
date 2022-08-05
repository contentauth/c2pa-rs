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
    assertion::{Assertion, AssertionBase, AssertionData, AssertionDecodeError},
    error::{Error, Result},
};

/// Helper class to create User assertion
#[derive(Debug, Default, Serialize)]
pub struct User {
    label: String,
    data: String,
}

impl User {
    /// Create new Identity instance
    pub fn new(label: &str, data: &str) -> User {
        User {
            label: label.to_owned(),
            data: data.to_owned(),
        }
    }
}

impl AssertionBase for User {
    /// returns the label for this instance
    fn label(&self) -> &str {
        &self.label
    }

    fn to_assertion(&self) -> Result<Assertion> {
        // validate that the string is valid json, but don't modify it
        let _json_value: serde_json::Value =
            serde_json::from_str(&self.data).map_err(|_err| Error::AssertionEncoding)?;
        //let data = AssertionData::AssertionJson(json_value.to_string());
        let data = AssertionData::Json(self.data.to_owned());
        Ok(Assertion::new(&self.label, None, data).set_content_type("application/json"))
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        match assertion.decode_data() {
            AssertionData::Json(data) => {
                // validate that the data is valid json, but do not modify it if valid
                let _value: serde_json::Value = serde_json::from_str(data).map_err(|e| {
                    Error::AssertionDecoding(AssertionDecodeError::from_assertion_and_json_err(
                        assertion, e,
                    ))
                })?;

                Ok(User::new(&assertion.label(), data))
            }
            ad => Err(AssertionDecodeError::from_assertion_unexpected_data_type(
                assertion, ad, "json",
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
    const INVALID_JSON: &str = "={this isn't valid{";

    #[test]
    fn assertion_user() {
        let original = User::new(LABEL, DATA);
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/json");
        assert_eq!(assertion.label(), LABEL);
        let result = User::from_assertion(&assertion).expect("from_assertion");
        assert_eq!(original.data, result.data);
    }

    #[test]
    fn assertion_user_invalid_json_to() {
        let original = User::new(LABEL, INVALID_JSON);
        original
            .to_assertion()
            .expect_err("Assertion encoding error expected");
    }

    #[test]
    fn assertion_user_invalid_json_from() {
        let data = AssertionData::Json(INVALID_JSON.to_owned());
        let assertion = Assertion::new(LABEL, None, data);
        let _result =
            User::from_assertion(&assertion).expect_err("Assertion decoding error expected");
    }
}
