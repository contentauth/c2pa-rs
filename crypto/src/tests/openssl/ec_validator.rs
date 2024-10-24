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
    openssl::EcValidator, tests::openssl::temp_signer, validator::CoseValidator, Signer, SigningAlg,
};

#[test]
fn sign_and_validate_es256() {
    let signer = temp_signer::get_ec_signer(SigningAlg::Es256, None);

    let data = b"some sample content to sign";
    println!("data len = {}", data.len());

    let signature = signer.sign(data).unwrap();
    println!("signature.len = {}", signature.len());
    assert!(signature.len() >= 64);
    assert!(signature.len() <= signer.reserve_size());

    let cert_bytes = include_bytes!("../fixtures/test_certs/es256.pub");

    let signcert = openssl::x509::X509::from_pem(cert_bytes).unwrap();
    let pub_key = signcert.public_key().unwrap().public_key_to_der().unwrap();

    let validator = EcValidator::new(SigningAlg::Es256);
    assert!(validator.validate(&signature, data, &pub_key).unwrap());
}

#[test]
fn sign_and_validate_es384() {
    let signer = temp_signer::get_ec_signer(SigningAlg::Es384, None);

    let data = b"some sample content to sign";
    println!("data len = {}", data.len());

    let signature = signer.sign(data).unwrap();
    println!("signature.len = {}", signature.len());
    assert!(signature.len() >= 64);
    assert!(signature.len() <= signer.reserve_size());

    let cert_bytes = include_bytes!("../fixtures/test_certs/es384.pub");

    let signcert = openssl::x509::X509::from_pem(cert_bytes).unwrap();
    let pub_key = signcert.public_key().unwrap().public_key_to_der().unwrap();

    let validator = EcValidator::new(SigningAlg::Es384);
    assert!(validator.validate(&signature, data, &pub_key).unwrap());
}

#[test]
fn sign_and_validate_es512() {
    let signer = temp_signer::get_ec_signer(SigningAlg::Es512, None);

    let data = b"some sample content to sign";
    println!("data len = {}", data.len());

    let signature = signer.sign(data).unwrap();
    println!("signature.len = {}", signature.len());
    assert!(signature.len() >= 64);
    assert!(signature.len() <= signer.reserve_size());

    let cert_bytes = include_bytes!("../fixtures/test_certs/es512.pub");

    let signcert = openssl::x509::X509::from_pem(cert_bytes).unwrap();
    let pub_key = signcert.public_key().unwrap().public_key_to_der().unwrap();

    let validator = EcValidator::new(SigningAlg::Es512);
    assert!(validator.validate(&signature, data, &pub_key).unwrap());
}

#[test]
fn bad_sig_es256() {
    let signer = temp_signer::get_ec_signer(SigningAlg::Es256, None);

    let data = b"some sample content to sign";
    println!("data len = {}", data.len());
    let mut signature = signer.sign(data).unwrap();

    signature.push(10);

    let cert_bytes = include_bytes!("../fixtures/test_certs/es256.pub");
    let signcert = openssl::x509::X509::from_pem(cert_bytes).unwrap();
    let pub_key = signcert.public_key().unwrap().public_key_to_der().unwrap();

    let validator = EcValidator::new(SigningAlg::Es256);
    let validated = validator.validate(&signature, data, &pub_key);
    assert!(validated.is_err());
}

#[test]
fn bad_data_es256() {
    let signer = temp_signer::get_ec_signer(SigningAlg::Es256, None);

    let mut data = b"some sample content to sign".to_vec();
    println!("data len = {}", data.len());
    let signature = signer.sign(&data).unwrap();

    data[5] = 10;
    data[6] = 11;

    let cert_bytes = include_bytes!("../fixtures/test_certs/es256.pub");
    let signcert = openssl::x509::X509::from_pem(cert_bytes).unwrap();
    let pub_key = signcert.public_key().unwrap().public_key_to_der().unwrap();

    let validator = EcValidator::new(SigningAlg::Es256);
    assert!(!validator.validate(&signature, &data, &pub_key).unwrap());
}
