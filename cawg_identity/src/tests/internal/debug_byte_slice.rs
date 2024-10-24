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

use crate::internal::debug_byte_slice::*;

#[test]
fn debug_byte_slice() {
    let h = hex!("01020354595f");
    let s = DebugByteSlice(&h);
    assert_eq!(format!("{s:#?}"), "[01, 02, 03, 54, 59, 5f]");

    let h = hex!("000102030405060708090a0b0c0d0e0f10111213");
    let s = DebugByteSlice(&h);
    assert_eq!(
        format!("{s:#?}"),
        "[00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f, 10, 11, 12, 13]"
    );

    let h = hex!("000102030405060708090a0b0c0d0e0f1011121314");
    let s = DebugByteSlice(&h);
    assert_eq!(
        format!("{s:#?}"),
        "21 bytes starting with [00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f, 10, 11, 12, 13]"
    );
}
