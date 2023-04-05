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

//! Example: Creating a custom assertion
use c2pa::{Assertion, AssertionBase, AssertionCbor, Manifest, Result};
use serde::{Deserialize, Serialize};

/// Defines a Custom assertion
/// This can be any Rust structure
/// It must support serde Serialize and Deserialize
/// In this example the assertion contains a version of this sdk
#[derive(Serialize, Deserialize)]
pub struct Custom {
    /// Records the version of this c2pa library
    pub version: String,
}

impl Custom {
    pub fn new() -> Self {
        Self {
            version: c2pa::VERSION.to_owned(),
        }
    }
}

// Implementing default is a good idea
impl Default for Custom {
    fn default() -> Self {
        Self::new()
    }
}

// Implement either AssertionCbor or AssertionJson
impl AssertionCbor for Custom {}

// Always implement AssertionBase by copying this template
// If you chose AssertionJson, use to_json_assertion and from_json_assertion instead
impl AssertionBase for Custom {
    // A label for our assertion, use reverse domain name syntax
    const LABEL: &'static str = "org.contentauth.custom";

    fn to_assertion(&self) -> c2pa::Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

fn main() -> Result<()> {
    let mut manifest = Manifest::new("c2pa-rs".to_owned());
    let original = Custom::new();
    manifest.add_assertion(&original)?;
    let result: Custom = manifest.find_assertion(Custom::LABEL)?;
    println!("{manifest}\n");
    println!("c2pa sdk version = {}", result.version);

    Ok(())
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn assertion_custom() {
        let mut manifest = Manifest::new("my_app".to_owned());
        let original = Custom::new();
        manifest.add_assertion(&original).expect("adding assertion");
        println!("{}", manifest);
        let result: Custom = manifest
            .find_assertion(Custom::LABEL)
            .expect("find_assertion");
        assert_eq!(original.version, result.version);
    }
}
