// Copyright 2025 Adobe. All rights reserved.
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

use crate::builder::IdentityBuilderError;

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn impl_from_ciborium_err() {
    let ciborium_err: ciborium::ser::Error<String> = ciborium::ser::Error::Value("foo".to_string());
    let builder_err: IdentityBuilderError = ciborium_err.into();

    assert_eq!(
        builder_err.to_string(),
        "error while generating CBOR (Value(\"foo\"))"
    );
}
