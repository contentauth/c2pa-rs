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

use openssl::x509::X509;

use crate::{
    openssl::validators::RsaValidator,
    raw_signature::{RawSignatureValidationError, RawSignatureValidator},
};

const SAMPLE_DATA: &[u8] = b"some sample content to sign";

#[test]
fn ps256() {
    let signature = include_bytes!("../../fixtures/raw_signature/ps256.raw_sig");

    let cert = include_bytes!("../../fixtures/raw_signature/ps256.pub");
    let cert = X509::from_pem(cert).unwrap();
    let pub_key = cert.public_key().unwrap();
    let pub_key = pub_key.public_key_to_der().unwrap();

    RsaValidator::Ps256
        .validate(signature, SAMPLE_DATA, &pub_key)
        .unwrap();
}

#[test]
fn ps256_bad_signature() {
    let mut signature = include_bytes!("../../fixtures/raw_signature/ps256.raw_sig").to_vec();
    assert_ne!(signature[10], 10);
    signature[10] = 10;

    let cert = include_bytes!("../../fixtures/raw_signature/ps256.pub");
    let cert = X509::from_pem(cert).unwrap();
    let pub_key = cert.public_key().unwrap().public_key_to_der().unwrap();

    assert_eq!(
        RsaValidator::Ps256
            .validate(&signature, SAMPLE_DATA, &pub_key)
            .unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[test]
fn ps256_bad_data() {
    let signature = include_bytes!("../../fixtures/raw_signature/ps256.raw_sig");

    let cert = include_bytes!("../../fixtures/raw_signature/ps256.pub");
    let cert = X509::from_pem(cert).unwrap();
    let pub_key = cert.public_key().unwrap().public_key_to_der().unwrap();

    let mut data = SAMPLE_DATA.to_vec();
    data[10] = 0;

    assert_eq!(
        RsaValidator::Ps256
            .validate(signature, &data, &pub_key)
            .unwrap_err(),
        RawSignatureValidationError::SignatureMismatch
    );
}

#[test]
fn ps384() {
    let signature = include_bytes!("../../fixtures/raw_signature/ps384.raw_sig");

    let cert = include_bytes!("../../fixtures/raw_signature/ps384.pub");
    let cert = X509::from_pem(cert).unwrap();
    let pub_key = cert.public_key().unwrap().public_key_to_der().unwrap();

    RsaValidator::Ps384
        .validate(signature, SAMPLE_DATA, &pub_key)
        .unwrap();
}

#[test]
fn ps512() {
    let signature = include_bytes!("../../fixtures/raw_signature/ps512.raw_sig");

    let cert = include_bytes!("../../fixtures/raw_signature/ps512.pub");
    let cert = X509::from_pem(cert).unwrap();
    let pub_key = cert.public_key().unwrap().public_key_to_der().unwrap();

    RsaValidator::Ps512
        .validate(signature, SAMPLE_DATA, &pub_key)
        .unwrap();
}
