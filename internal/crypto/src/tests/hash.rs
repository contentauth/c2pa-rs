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

#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::hash::{sha1, sha256};

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
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

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn test_sha256() {
    let hash = sha256(b"test message");
    assert_eq!(
        hash,
        [
            63, 10, 55, 123, 160, 164, 164, 96, 236, 182, 22, 246, 80, 124, 224, 216, 207, 163,
            231, 4, 2, 93, 79, 218, 62, 208, 197, 202, 5, 70, 135, 40
        ]
    );
}
