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

use crate::{
    assertion::{get_thumbnail_image_type, get_thumbnail_type, Assertion},
    assertions,
    error::Result,
};

#[derive(PartialEq, Debug, Eq, Clone, Hash)]
pub enum ClaimAssertionType {
    V1,       // V1 assertion
    Gathered, // Machine generated assertion
    Created,  // User generated assertion
}

// helper struct to allow arbitrary order for assertions stored in jumbf.  The instance is
// stored separate from the Assertion to allow for late binding to the label.  Also,
// we can load assertions in any order and know the position without re-parsing label. We also
// save on parsing the cbor assertion each time we need its contents
#[derive(PartialEq, Eq, Clone, Hash)]
pub struct ClaimAssertion {
    pub(super) assertion: Assertion,
    pub(super) instance: usize,
    hash_val: Vec<u8>,
    hash_alg: String,
    salt: Option<Vec<u8>>,
    typ: ClaimAssertionType,
}

impl ClaimAssertion {
    pub fn new(
        assertion: Assertion,
        instance: usize,
        hashval: &[u8],
        alg: &str,
        salt: Option<Vec<u8>>,
        typ: ClaimAssertionType,
    ) -> ClaimAssertion {
        ClaimAssertion {
            assertion,
            instance,
            hash_val: hashval.to_vec(),
            hash_alg: alg.to_string(),
            salt,
            typ,
        }
    }

    pub fn update_assertion(&mut self, assertion: Assertion, hash: Vec<u8>) -> Result<()> {
        self.hash_val = hash;
        self.assertion = assertion;
        Ok(())
    }

    pub fn label(&self) -> String {
        let al_ref = self.assertion.label();
        if self.instance > 0 {
            if get_thumbnail_type(&al_ref) == assertions::labels::INGREDIENT_THUMBNAIL {
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

    pub fn instance_string(&self) -> String {
        format!("{}", self.instance)
    }

    pub fn label_raw(&self) -> String {
        self.assertion.label()
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

    /// returns true if assertions are of the same enum variant
    pub fn is_same_type(&self, input_assertion: &Assertion) -> bool {
        Assertion::assertions_eq(&self.assertion, input_assertion)
    }

    pub fn assertion_type(&self) -> ClaimAssertionType {
        self.typ.clone()
    }

    pub fn set_assertion_type(&mut self, typ: ClaimAssertionType) {
        self.typ = typ;
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
