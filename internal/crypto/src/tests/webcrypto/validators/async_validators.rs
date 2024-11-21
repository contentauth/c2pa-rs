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

use bcder::Oid;
use rasn::types::OctetString;
use wasm_bindgen_test::wasm_bindgen_test;

use crate::{
    raw_signature::RawSignatureValidationError,
    webcrypto::{
        async_validator_for_sig_and_hash_algs, async_validators::async_validator_for_signing_alg,
    },
    SigningAlg,
};

const SAMPLE_DATA: &[u8] = b"some sample content to sign";

// #[wasm_bindgen_test]
// async fn es256() {
//     let signature =
// include_bytes!("../../fixtures/raw_signature/es256.raw_sig");     let cert =
// include_bytes!("../../fixtures/raw_signature/es256.pub");

//     assert!(verify_data_async(
//         cert.to_vec(),
//         Some("es256".to_string()),
//         signature.to_vec(),
//         SAMPLE_DATA.to_vec()
//     )
//     .await
//     .unwrap());

//     // let validator = validator_for_signing_alg(SigningAlg::Es256).unwrap();

//     // validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
// }

// #[wasm_bindgen_test]
// async fn es256_bad_signature() {
//     let mut signature =
// include_bytes!("../../fixtures/raw_signature/es256.raw_sig").to_vec();
//     assert_ne!(signature[10], 10);
//     signature[10] = 10;

//     let pub_key =
// include_bytes!("../../fixtures/raw_signature/es256.pub_key");

//     let validator = validator_for_signing_alg(SigningAlg::Es256).unwrap();

//     assert_eq!(
//         validator
//             .validate(&signature, SAMPLE_DATA, pub_key)
//             .unwrap_err(),
//         RawSignatureValidationError::SignatureMismatch
//     );
// }

// #[wasm_bindgen_test]
// async fn es256_bad_data() {
//     let signature =
// include_bytes!("../../fixtures/raw_signature/es256.raw_sig");     let pub_key
// = include_bytes!("../../fixtures/raw_signature/es256.pub_key");

//     let mut data = SAMPLE_DATA.to_vec();
//     data[10] = 0;

//     let validator = validator_for_signing_alg(SigningAlg::Es256).unwrap();

//     assert_eq!(
//         validator.validate(signature, &data, pub_key).unwrap_err(),
//         RawSignatureValidationError::SignatureMismatch
//     );
// }

// #[wasm_bindgen_test]
// async fn es384() {
//     let signature =
// include_bytes!("../../fixtures/raw_signature/es384.raw_sig");     let pub_key
// = include_bytes!("../../fixtures/raw_signature/es384.pub_key");

//     let validator = validator_for_signing_alg(SigningAlg::Es384).unwrap();

//     validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
// }

// // #[wasm_bindgen_test] // ES512 not
// // implemented
// async fn es512() {
//     let signature =
// include_bytes!("../../fixtures/raw_signature/es512.raw_sig");     let pub_key
// = include_bytes!("../../fixtures/raw_signature/es512.pub_key");

//     let validator = validator_for_signing_alg(SigningAlg::Es512).unwrap();

//     validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
// }

#[wasm_bindgen_test]
async fn ed25519() {
    let signature = include_bytes!("../../fixtures/raw_signature/ed25519.raw_sig");
    let pub_key = include_bytes!("../../fixtures/raw_signature/ed25519.pub_key");

    let validator = async_validator_for_signing_alg(SigningAlg::Ed25519).unwrap();

    validator
        .validate_async(signature, SAMPLE_DATA, pub_key)
        .await
        .unwrap();
}

#[wasm_bindgen_test]
async fn ed25519_bad_data() {
    let signature = include_bytes!("../../fixtures/raw_signature/ed25519.raw_sig");
    let pub_key = include_bytes!("../../fixtures/raw_signature/ed25519.pub_key");

    let mut data = SAMPLE_DATA.to_vec();
    data[5] = 10;
    data[6] = 11;

    let validator = async_validator_for_signing_alg(SigningAlg::Ed25519).unwrap();

    assert_eq!(
        validator
            .validate_async(signature, &data, pub_key)
            .await
            .unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[wasm_bindgen_test]
async fn ps256() {
    let signature = include_bytes!("../../fixtures/raw_signature/ps256.raw_sig");
    let pub_key = include_bytes!("../../fixtures/raw_signature/ps256.pub_key");

    let validator = async_validator_for_signing_alg(SigningAlg::Ps256).unwrap();

    validator
        .validate_async(signature, SAMPLE_DATA, pub_key)
        .await
        .unwrap();
}

#[wasm_bindgen_test]
async fn ps256_bad_signature() {
    let mut signature = include_bytes!("../../fixtures/raw_signature/ps256.raw_sig").to_vec();
    assert_ne!(signature[10], 10);
    signature[10] = 10;

    let pub_key = include_bytes!("../../fixtures/raw_signature/ps256.pub_key");

    let validator = async_validator_for_signing_alg(SigningAlg::Ps256).unwrap();

    assert_eq!(
        validator
            .validate_async(&signature, SAMPLE_DATA, pub_key)
            .await
            .unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[wasm_bindgen_test]
async fn ps256_bad_data() {
    let signature = include_bytes!("../../fixtures/raw_signature/ps256.raw_sig");
    let pub_key = include_bytes!("../../fixtures/raw_signature/ps256.pub_key");

    let mut data = SAMPLE_DATA.to_vec();
    data[10] = 0;

    let validator = async_validator_for_signing_alg(SigningAlg::Ps256).unwrap();

    assert_eq!(
        validator
            .validate_async(signature, &data, pub_key)
            .await
            .unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[wasm_bindgen_test]
async fn ps384() {
    let signature = include_bytes!("../../fixtures/raw_signature/ps384.raw_sig");
    let pub_key = include_bytes!("../../fixtures/raw_signature/ps384.pub_key");

    let validator = async_validator_for_signing_alg(SigningAlg::Ps384).unwrap();

    validator
        .validate_async(signature, SAMPLE_DATA, pub_key)
        .await
        .unwrap();
}

#[wasm_bindgen_test]
async fn ps512() {
    let signature = include_bytes!("../../fixtures/raw_signature/ps512.raw_sig");
    let pub_key = include_bytes!("../../fixtures/raw_signature/ps512.pub_key");

    let validator = async_validator_for_signing_alg(SigningAlg::Ps512).unwrap();

    validator
        .validate_async(signature, SAMPLE_DATA, pub_key)
        .await
        .unwrap();
}

// Argh. Different Oid types across different crates, so we have to construct
// our own constants here.
const RSA_OID: Oid = bcder::Oid(OctetString::from_static(&[
    42, 134, 72, 134, 247, 13, 1, 1, 1,
]));

const SHA256_OID: Oid = bcder::Oid(OctetString::from_static(&[96, 134, 72, 1, 101, 3, 4, 2, 1]));

const SHA384_OID: Oid = bcder::Oid(OctetString::from_static(&[96, 134, 72, 1, 101, 3, 4, 2, 2]));

const SHA512_OID: Oid = bcder::Oid(OctetString::from_static(&[96, 134, 72, 1, 101, 3, 4, 2, 3]));

#[wasm_bindgen_test]
async fn legacy_rs256() {
    let signature = include_bytes!("../../fixtures/raw_signature/legacy/rs256.raw_sig");
    let pub_key = include_bytes!("../../fixtures/raw_signature/legacy/rs256.pub_key");

    let validator = async_validator_for_sig_and_hash_algs(&RSA_OID, &SHA256_OID).unwrap();

    validator
        .validate_async(signature, SAMPLE_DATA, pub_key)
        .await
        .unwrap();
}

#[wasm_bindgen_test]
async fn legacy_rs256_bad_signature() {
    let mut signature =
        include_bytes!("../../fixtures/raw_signature/legacy/rs256.raw_sig").to_vec();
    assert_ne!(signature[10], 10);
    signature[10] = 10;

    let pub_key = include_bytes!("../../fixtures/raw_signature/legacy/rs256.pub_key");

    let validator = async_validator_for_sig_and_hash_algs(&RSA_OID, &SHA256_OID).unwrap();

    assert_eq!(
        validator
            .validate_async(&signature, SAMPLE_DATA, pub_key)
            .await
            .unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[wasm_bindgen_test]
async fn legacy_rs256_bad_data() {
    let signature = include_bytes!("../../fixtures/raw_signature/legacy/rs256.raw_sig");
    let pub_key = include_bytes!("../../fixtures/raw_signature/legacy/rs256.pub_key");

    let mut data = SAMPLE_DATA.to_vec();
    data[10] = 0;

    let validator = async_validator_for_sig_and_hash_algs(&RSA_OID, &SHA256_OID).unwrap();

    assert_eq!(
        validator
            .validate_async(signature, &data, pub_key)
            .await
            .unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[wasm_bindgen_test]
async fn legacy_rs384() {
    let signature = include_bytes!("../../fixtures/raw_signature/legacy/rs384.raw_sig");
    let pub_key = include_bytes!("../../fixtures/raw_signature/legacy/rs384.pub_key");

    let validator = async_validator_for_sig_and_hash_algs(&RSA_OID, &SHA384_OID).unwrap();

    validator
        .validate_async(signature, SAMPLE_DATA, pub_key)
        .await
        .unwrap();
}

#[wasm_bindgen_test]
async fn legacy_rs512() {
    let signature = include_bytes!("../../fixtures/raw_signature/legacy/rs512.raw_sig");
    let pub_key = include_bytes!("../../fixtures/raw_signature/legacy/rs512.pub_key");

    let validator = async_validator_for_sig_and_hash_algs(&RSA_OID, &SHA512_OID).unwrap();

    validator
        .validate_async(signature, SAMPLE_DATA, pub_key)
        .await
        .unwrap();
}
