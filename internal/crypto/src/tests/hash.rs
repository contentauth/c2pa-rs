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

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::hash::sha1;

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_sha1() {
    let hash = sha1(b"test message");
    assert_eq!(
        hash,
        [
            53, 238, 131, 134, 65, 13, 65, 209, 75, 63, 119, 159, 201, 95, 70, 149, 244, 133, 22,
            130
        ]
    );
}
