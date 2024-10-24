// Copyright 2024 Adobe. All rights reserved.
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

use hex_literal::hex;
use jumbf::parser::SuperBox;

pub(crate) const LABEL: &str = "c2pa.assertions";
const UUID: &[u8; 16] = &hex!("63326173 0011 0010 8000 00aa00389b71");

/// On-demand parser for the assertion store within a C2PA Manifest.
pub(crate) struct AssertionStore<'a> {
    // Superbox containing parsed assertion boxes.
    sbox: &'a SuperBox<'a>,
}

impl<'a> AssertionStore<'a> {
    /// Parse the assertion store box of a C2PA Manifest.
    ///
    /// Returns `None` if unable to parse as an assertion store.
    pub(crate) fn from_super_box(sbox: &'a SuperBox<'a>) -> Option<Self> {
        // Enforced by Manifest find code.
        // if sbox.desc.label != Some(LABEL) {
        //     return None;
        // }

        if sbox.desc.uuid != UUID {
            return None;
        }

        Some(Self { sbox })
    }

    /// Find an assertion by label and verify that exactly one such child
    /// exists.
    ///
    /// Will return `None` if no matching child superbox is found _or_ if
    /// more than one matching child superbox is found.
    pub(crate) fn find_by_label(&self, label: &str) -> Option<&'a SuperBox<'a>> {
        self.sbox.find_by_label(label)
    }
}
