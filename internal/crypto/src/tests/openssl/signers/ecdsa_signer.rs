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

use openssl::x509::X509;

use crate::{
    openssl::{signers::signer_from_cert_chain_and_private_key, validators::EcdsaValidator},
    raw_signature::RawSignatureValidator,
    SigningAlg,
};

#[test]
fn es256() {
    let cert_chain = include_bytes!("../../fixtures/raw_signature/es256.pub");
    let private_key = include_bytes!("../../fixtures/raw_signature/es256.priv");

    let signer =
        signer_from_cert_chain_and_private_key(cert_chain, private_key, SigningAlg::Es256, None)
            .unwrap();

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());

    let cert = X509::from_pem(cert_chain).unwrap();
    let pub_key = cert.public_key().unwrap();
    let pub_key = pub_key.public_key_to_der().unwrap();

    EcdsaValidator::Es256
        .validate(&signature, data, &pub_key)
        .unwrap();
}

#[test]
fn es384() {
    let cert_chain = include_bytes!("../../fixtures/raw_signature/es384.pub");
    let private_key = include_bytes!("../../fixtures/raw_signature/es384.priv");

    let signer =
        signer_from_cert_chain_and_private_key(cert_chain, private_key, SigningAlg::Es384, None)
            .unwrap();

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());

    let cert = X509::from_pem(cert_chain).unwrap();
    let pub_key = cert.public_key().unwrap();
    let pub_key = pub_key.public_key_to_der().unwrap();

    EcdsaValidator::Es384
        .validate(&signature, data, &pub_key)
        .unwrap();
}

#[test]
fn es512() {
    let cert_chain = include_bytes!("../../fixtures/raw_signature/es512.pub");
    let private_key = include_bytes!("../../fixtures/raw_signature/es512.priv");

    let signer =
        signer_from_cert_chain_and_private_key(cert_chain, private_key, SigningAlg::Es512, None)
            .unwrap();

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());

    let cert = X509::from_pem(cert_chain).unwrap();
    let pub_key = cert.public_key().unwrap();
    let pub_key = pub_key.public_key_to_der().unwrap();

    EcdsaValidator::Es512
        .validate(&signature, data, &pub_key)
        .unwrap();
}
