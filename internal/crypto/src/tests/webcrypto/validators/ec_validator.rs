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

use crate::{
    raw_signature::{RawSignatureValidationError, RawSignatureValidator},
    webcrypto::validators::EcValidator,
};

const SAMPLE_DATA: &'static [u8] = b"some sample content to sign";

#[test]
fn es256() {
    let signature = include_bytes!("../../fixtures/raw_signature/es256.raw_sig");
    let pub_key = include_bytes!("../../fixtures/raw_signature/es256.pub_key");

    EcValidator::Es256
        .validate(signature, SAMPLE_DATA, &pub_key)
        .unwrap();
}

#[test]
fn es384() {
    let signature = include_bytes!("../../fixtures/raw_signature/es384.raw_sig");
    let pub_key = include_bytes!("../../fixtures/raw_signature/es384.pub_key");

    EcValidator::Es384
        .validate(signature, SAMPLE_DATA, &pub_key)
        .unwrap();
}

// #[test]
// fn es512() {
//     let signature =
// include_bytes!("../../fixtures/raw_signature/es512.raw_sig");

// let pub_key = include_bytes!("../../fixtures/raw_signature/es512.pub_key");

//     EcValidator::Es512
//         .validate(signature, SAMPLE_DATA, &pub_key)
//         .unwrap();
// }

#[test]
fn es256_bad_signature() {
    let mut signature = include_bytes!("../../fixtures/raw_signature/es256.raw_sig").to_vec();
    assert_ne!(signature[10], 10);
    signature[10] = 10;

    let pub_key = include_bytes!("../../fixtures/raw_signature/es256.pub_key");

    assert_eq!(
        EcValidator::Es256
            .validate(&signature, SAMPLE_DATA, &pub_key)
            .unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[test]
fn es256_bad_data() {
    let signature = include_bytes!("../../fixtures/raw_signature/es256.raw_sig");
    let pub_key = include_bytes!("../../fixtures/raw_signature/es256.pub_key");

    let mut data = SAMPLE_DATA.to_vec();
    data[10] = 0;

    assert_eq!(
        EcValidator::Es256
            .validate(signature, &data, &pub_key)
            .unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}