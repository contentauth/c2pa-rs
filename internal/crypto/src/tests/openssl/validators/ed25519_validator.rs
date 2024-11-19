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

use crate::{
    openssl::validators::Ed25519Validator,
    raw_signature::{RawSignatureValidationError, RawSignatureValidator},
};

const SAMPLE_DATA: &[u8] = b"some sample content to sign";

#[test]
fn good() {
    let signature = include_bytes!("../../fixtures/raw_signature/ed25519.raw_sig");

    let cert = include_bytes!("../../fixtures/raw_signature/ed25519.pub");
    let cert = openssl::x509::X509::from_pem(cert).unwrap();
    let pub_key = cert.public_key().unwrap().public_key_to_der().unwrap();

    Ed25519Validator {}
        .validate(signature, SAMPLE_DATA, &pub_key)
        .unwrap();
}

#[test]
fn bad_data() {
    let signature = include_bytes!("../../fixtures/raw_signature/ed25519.raw_sig");

    let cert = include_bytes!("../../fixtures/raw_signature/ed25519.pub");
    let cert = openssl::x509::X509::from_pem(cert).unwrap();
    let pub_key = cert.public_key().unwrap().public_key_to_der().unwrap();

    let mut data = SAMPLE_DATA.to_vec();
    data[5] = 10;
    data[6] = 11;

    assert_eq!(
        Ed25519Validator {}
            .validate(signature, &data, &pub_key)
            .unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}
