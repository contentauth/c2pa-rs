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
    openssl::{signers::signer_from_cert_chain_and_private_key, validators::Ed25519Validator},
    raw_signature::{async_signer_from_cert_chain_and_private_key, RawSignatureValidator},
    SigningAlg,
};

#[test]
fn ed25519() {
    let cert_chain = include_bytes!("../../fixtures/raw_signature/ed25519.pub");
    let private_key = include_bytes!("../../fixtures/raw_signature/ed25519.priv");

    let signer =
        signer_from_cert_chain_and_private_key(cert_chain, private_key, SigningAlg::Ed25519, None)
            .unwrap();

    let data = b"some sample content to sign";
    let signature = signer.sign(data).unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());

    let cert = X509::from_pem(cert_chain).unwrap();
    let pub_key = cert.public_key().unwrap();
    let pub_key = pub_key.public_key_to_der().unwrap();

    Ed25519Validator {}
        .validate(&signature, data, &pub_key)
        .unwrap();
}

#[actix::test]
async fn ed25519_async() {
    let cert_chain = include_bytes!("../../fixtures/raw_signature/ed25519.pub");
    let private_key = include_bytes!("../../fixtures/raw_signature/ed25519.priv");

    let signer = async_signer_from_cert_chain_and_private_key(
        cert_chain,
        private_key,
        SigningAlg::Ed25519,
        None,
    )
    .unwrap();

    let data = b"some sample content to sign";
    let signature = signer.sign(data.to_vec()).await.unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());

    let cert = X509::from_pem(cert_chain).unwrap();
    let pub_key = cert.public_key().unwrap();
    let pub_key = pub_key.public_key_to_der().unwrap();

    Ed25519Validator {}
        .validate(&signature, data, &pub_key)
        .unwrap();
}
