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

use wasm_bindgen_test::wasm_bindgen_test;

use crate::raw_signature::{
    async_validator_for_signing_alg, RawSignatureValidationError, SigningAlg,
};

const SAMPLE_DATA: &[u8] = b"some sample content to sign";

#[wasm_bindgen_test]
async fn es256() {
    let signature = include_bytes!("../fixtures/raw_signature/es256.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/es256.pub_key");

    let validator = async_validator_for_signing_alg(SigningAlg::Es256).unwrap();

    validator
        .validate_async(signature, SAMPLE_DATA, pub_key)
        .await
        .unwrap();
}

#[wasm_bindgen_test]
async fn es256_bad_signature() {
    let mut signature = include_bytes!("../fixtures/raw_signature/es256.raw_sig").to_vec();
    assert_ne!(signature[10], 10);
    signature[10] = 10;

    let pub_key = include_bytes!("../fixtures/raw_signature/es256.pub_key");

    let validator = async_validator_for_signing_alg(SigningAlg::Es256).unwrap();

    assert_eq!(
        validator
            .validate_async(&signature, SAMPLE_DATA, pub_key)
            .await
            .unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[wasm_bindgen_test]
async fn es256_bad_data() {
    let signature = include_bytes!("../fixtures/raw_signature/es256.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/es256.pub_key");

    let mut data = SAMPLE_DATA.to_vec();
    data[10] = 0;

    let validator = async_validator_for_signing_alg(SigningAlg::Es256).unwrap();

    assert_eq!(
        validator
            .validate_async(signature, &data, pub_key)
            .await
            .unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[wasm_bindgen_test]
async fn es384() {
    let signature = include_bytes!("../fixtures/raw_signature/es384.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/es384.pub_key");

    let validator = async_validator_for_signing_alg(SigningAlg::Es384).unwrap();

    validator
        .validate_async(signature, SAMPLE_DATA, pub_key)
        .await
        .unwrap();
}

#[wasm_bindgen_test]
async fn es512() {
    let signature = include_bytes!("../fixtures/raw_signature/es512.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/es512.pub_key");

    let validator = async_validator_for_signing_alg(SigningAlg::Es512).unwrap();

    validator
        .validate_async(signature, SAMPLE_DATA, pub_key)
        .await
        .unwrap();
}
