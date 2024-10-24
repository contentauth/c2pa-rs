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

use wasm_bindgen_test::*;

use crate::{wasm::validate_async, SigningAlg};

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_async_verify_rsa_pss() {
    // PS signatures
    let sig_bytes = include_bytes!("../fixtures/test_certs/sig_ps256.data");
    let data_bytes = include_bytes!("../fixtures/test_certs/data_ps256.data");
    let key_bytes = include_bytes!("../fixtures/test_certs/key_ps256.data");

    let validated = validate_async(SigningAlg::Ps256, sig_bytes, data_bytes, key_bytes)
        .await
        .unwrap();

    assert_eq!(validated, true);
}

#[wasm_bindgen_test]
async fn test_async_verify_ecdsa() {
    // EC signatures
    let sig_es384_bytes = include_bytes!("../fixtures/test_certs/sig_es384.data");
    let data_es384_bytes = include_bytes!("../fixtures/test_certs/data_es384.data");
    let key_es384_bytes = include_bytes!("../fixtures/test_certs/key_es384.data");

    let mut validated = validate_async(
        SigningAlg::Es384,
        sig_es384_bytes,
        data_es384_bytes,
        key_es384_bytes,
    )
    .await
    .unwrap();

    assert_eq!(validated, true);

    let sig_es512_bytes = include_bytes!("../fixtures/test_certs/sig_es512.data");
    let data_es512_bytes = include_bytes!("../fixtures/test_certs/data_es512.data");
    let key_es512_bytes = include_bytes!("../fixtures/test_certs/key_es512.data");

    validated = validate_async(
        SigningAlg::Es512,
        sig_es512_bytes,
        data_es512_bytes,
        key_es512_bytes,
    )
    .await
    .unwrap();

    assert_eq!(validated, true);

    let sig_es256_bytes = include_bytes!("../fixtures/test_certs/sig_es256.data");
    let data_es256_bytes = include_bytes!("../fixtures/test_certs/data_es256.data");
    let key_es256_bytes = include_bytes!("../fixtures/test_certs/key_es256.data");

    let validated = validate_async(
        SigningAlg::Es256,
        sig_es256_bytes,
        data_es256_bytes,
        key_es256_bytes,
    )
    .await
    .unwrap();

    assert_eq!(validated, true);
}

#[wasm_bindgen_test]
#[ignore]
async fn test_async_verify_bad() {
    let sig_bytes = include_bytes!("../fixtures/test_certs/sig_ps256.data");
    let data_bytes = include_bytes!("../fixtures/test_certs/data_ps256.data");
    let key_bytes = include_bytes!("../fixtures/test_certs/key_ps256.data");

    let mut bad_bytes = data_bytes.to_vec();
    bad_bytes[0] = b'c';
    bad_bytes[1] = b'2';
    bad_bytes[2] = b'p';
    bad_bytes[3] = b'a';

    let validated = validate_async(SigningAlg::Ps256, sig_bytes, &bad_bytes, key_bytes)
        .await
        .unwrap();

    assert_eq!(validated, false);
}
