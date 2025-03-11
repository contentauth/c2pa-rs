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

use std::str::FromStr;

use bcder::Oid;
use rasn::types::OctetString;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::raw_signature::{
    validator_for_sig_and_hash_algs, validator_for_signing_alg, RawSignatureValidationError,
    SigningAlg,
};

const SAMPLE_DATA: &[u8] = b"some sample content to sign";

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn es256() {
    let signature = include_bytes!("../fixtures/raw_signature/es256.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/es256.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Es256).unwrap();

    validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn es256_bad_signature() {
    let mut signature = include_bytes!("../fixtures/raw_signature/es256.raw_sig").to_vec();
    assert_ne!(signature[10], 10);
    signature[10] = 10;

    let pub_key = include_bytes!("../fixtures/raw_signature/es256.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Es256).unwrap();

    assert_eq!(
        validator
            .validate(&signature, SAMPLE_DATA, pub_key)
            .unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn es256_bad_data() {
    let signature = include_bytes!("../fixtures/raw_signature/es256.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/es256.pub_key");

    let mut data = SAMPLE_DATA.to_vec();
    data[10] = 0;

    let validator = validator_for_signing_alg(SigningAlg::Es256).unwrap();

    assert_eq!(
        validator.validate(signature, &data, pub_key).unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn es384() {
    let signature = include_bytes!("../fixtures/raw_signature/es384.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/es384.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Es384).unwrap();

    validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
}

#[test]
// #[cfg_attr(all(target_arch = "wasm32", not(target_os = "wasi")),
// wasm_bindgen_test)] // ES512 not implemented
fn es512() {
    let signature = include_bytes!("../fixtures/raw_signature/es512.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/es512.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Es512).unwrap();

    validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ed25519() {
    let signature = include_bytes!("../fixtures/raw_signature/ed25519.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/ed25519.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ed25519).unwrap();

    validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ed25519_bad_data() {
    let signature = include_bytes!("../fixtures/raw_signature/ed25519.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/ed25519.pub_key");

    let mut data = SAMPLE_DATA.to_vec();
    data[5] = 10;
    data[6] = 11;

    let validator = validator_for_signing_alg(SigningAlg::Ed25519).unwrap();

    assert_eq!(
        validator.validate(signature, &data, pub_key).unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ps256() {
    let signature = include_bytes!("../fixtures/raw_signature/ps256.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/ps256.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ps256).unwrap();

    validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ps256_bad_signature() {
    let mut signature = include_bytes!("../fixtures/raw_signature/ps256.raw_sig").to_vec();
    assert_ne!(signature[10], 10);
    signature[10] = 10;

    let pub_key = include_bytes!("../fixtures/raw_signature/ps256.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ps256).unwrap();

    assert_eq!(
        validator
            .validate(&signature, SAMPLE_DATA, pub_key)
            .unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ps256_bad_data() {
    let signature = include_bytes!("../fixtures/raw_signature/ps256.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/ps256.pub_key");

    let mut data = SAMPLE_DATA.to_vec();
    data[10] = 0;

    let validator = validator_for_signing_alg(SigningAlg::Ps256).unwrap();

    assert_eq!(
        validator.validate(signature, &data, pub_key).unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ps384() {
    let signature = include_bytes!("../fixtures/raw_signature/ps384.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/ps384.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ps384).unwrap();

    validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn ps512() {
    let signature = include_bytes!("../fixtures/raw_signature/ps512.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/ps512.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ps512).unwrap();

    validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
}

// Argh. Different Oid types across different crates, so we have to construct
// our own constants here.
const RSA_OID: Oid = bcder::Oid(OctetString::from_static(&[
    42, 134, 72, 134, 247, 13, 1, 1, 1,
]));

const SHA256_OID: Oid = bcder::Oid(OctetString::from_static(&[96, 134, 72, 1, 101, 3, 4, 2, 1]));

const SHA384_OID: Oid = bcder::Oid(OctetString::from_static(&[96, 134, 72, 1, 101, 3, 4, 2, 2]));

const SHA512_OID: Oid = bcder::Oid(OctetString::from_static(&[96, 134, 72, 1, 101, 3, 4, 2, 3]));

#[cfg_attr(target_arch = "wasm32", allow(unused))]
const SHA1_OID: Oid = bcder::Oid(OctetString::from_static(&[43, 14, 3, 2, 26]));

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn legacy_rs256() {
    let signature = include_bytes!("../fixtures/raw_signature/legacy/rs256.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/legacy/rs256.pub_key");

    let validator = validator_for_sig_and_hash_algs(&RSA_OID, &SHA256_OID).unwrap();

    validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn legacy_rs256_bad_signature() {
    let mut signature = include_bytes!("../fixtures/raw_signature/legacy/rs256.raw_sig").to_vec();
    assert_ne!(signature[10], 10);
    signature[10] = 10;

    let pub_key = include_bytes!("../fixtures/raw_signature/legacy/rs256.pub_key");

    let validator = validator_for_sig_and_hash_algs(&RSA_OID, &SHA256_OID).unwrap();

    assert_eq!(
        validator
            .validate(&signature, SAMPLE_DATA, pub_key)
            .unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn legacy_rs256_bad_data() {
    let signature = include_bytes!("../fixtures/raw_signature/legacy/rs256.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/legacy/rs256.pub_key");

    let mut data = SAMPLE_DATA.to_vec();
    data[10] = 0;

    let validator = validator_for_sig_and_hash_algs(&RSA_OID, &SHA256_OID).unwrap();

    assert_eq!(
        validator.validate(signature, &data, pub_key).unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn rs384() {
    let signature = include_bytes!("../fixtures/raw_signature/legacy/rs384.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/legacy/rs384.pub_key");

    let validator = validator_for_sig_and_hash_algs(&RSA_OID, &SHA384_OID).unwrap();

    validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn rs512() {
    let signature = include_bytes!("../fixtures/raw_signature/legacy/rs512.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/legacy/rs512.pub_key");

    let validator = validator_for_sig_and_hash_algs(&RSA_OID, &SHA512_OID).unwrap();

    validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
}

#[test]
// #[cfg_attr(all(target_arch = "wasm32", not(target_os = "wasi")), wasm_bindgen_test)] // SHA1 not
// implemented
#[cfg(not(target_arch = "wasm32"))]
fn sha1() {
    let signature = include_bytes!("../fixtures/raw_signature/legacy/sha1.raw_sig");
    let pub_key = include_bytes!("../fixtures/raw_signature/legacy/sha1.pub_key");

    let validator = validator_for_sig_and_hash_algs(&RSA_OID, &SHA1_OID).unwrap();

    validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
}

#[allow(dead_code)]
fn ans1_oid_bcder_oid(asn1_oid: &asn1_rs::Oid) -> bcder::Oid {
    const TEST_FAIL: Oid = bcder::Oid(OctetString::from_static(&[0, 0, 0, 0]));

    let asn1_oid_str = asn1_oid.to_id_string();

    bcder::Oid::from_str(&asn1_oid_str).unwrap_or(TEST_FAIL.to_owned())
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn test_get_by_sig_and_alg() {
    use crate::raw_signature::oids::*;

    let rsa_oid = ans1_oid_bcder_oid(&RSA_OID).unwrap();
    let rsa_pss_oid = ans1_oid_bcder_oid(&RSA_PSS_OID).unwrap();
    let ec_pubic_key_oid = ans1_oid_bcder_oid(&EC_PUBLICKEY_OID).unwrap();
    let ed25519_oid = ans1_oid_bcder_oid(&ED25519_OID).unwrap();
    let sha256 = ans1_oid_bcder_oid(&SHA256_OID).unwrap();
    let sha384 = ans1_oid_bcder_oid(&SHA384_OID).unwrap();
    let sha512 = ans1_oid_bcder_oid(&SHA512_OID).unwrap();

    assert!(validator_for_sig_and_hash_algs(&rsa_oid, &sha256).is_some());
    assert!(validator_for_sig_and_hash_algs(&rsa_oid, &sha384).is_some());
    assert!(validator_for_sig_and_hash_algs(&rsa_oid, &sha512).is_some());

    assert!(validator_for_sig_and_hash_algs(&rsa_pss_oid, &sha256).is_some());
    assert!(validator_for_sig_and_hash_algs(&rsa_pss_oid, &sha384).is_some());
    assert!(validator_for_sig_and_hash_algs(&rsa_pss_oid, &sha512).is_some());

    assert!(validator_for_sig_and_hash_algs(&ec_pubic_key_oid, &sha256).is_some());
    assert!(validator_for_sig_and_hash_algs(&ec_pubic_key_oid, &sha384).is_some());
    assert!(validator_for_sig_and_hash_algs(&ec_pubic_key_oid, &sha512).is_some());

    assert!(validator_for_sig_and_hash_algs(&ed25519_oid, &sha512).is_some());

    // test negative case
    const TEST_FAIL: Oid = bcder::Oid(OctetString::from_static(&[0, 0, 0, 0]));
    assert!(validator_for_sig_and_hash_algs(&TEST_FAIL, &sha512).is_none());
}
