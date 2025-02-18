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

#![allow(unused)] // test fns appear unused on WASM

#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::raw_signature::{
    async_signer_from_cert_chain_and_private_key, validator_for_signing_alg, SigningAlg,
};

#[cfg_attr(not(target_arch = "wasm32"), actix::test)]
// #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
async fn es256() {
    let cert_chain = include_bytes!("../fixtures/raw_signature/es256.pub");
    let private_key = include_bytes!("../fixtures/raw_signature/es256.priv");

    let signer = async_signer_from_cert_chain_and_private_key(
        cert_chain,
        private_key,
        SigningAlg::Es256,
        None,
    )
    .unwrap();

    let data = b"some sample content to sign";
    let signature = signer.sign(data.to_vec()).await.unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());

    let pub_key = include_bytes!("../fixtures/raw_signature/es256.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Es256).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[cfg_attr(not(target_arch = "wasm32"), actix::test)]
// #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
async fn es384() {
    let cert_chain = include_bytes!("../fixtures/raw_signature/es384.pub");
    let private_key = include_bytes!("../fixtures/raw_signature/es384.priv");

    let signer = async_signer_from_cert_chain_and_private_key(
        cert_chain,
        private_key,
        SigningAlg::Es384,
        None,
    )
    .unwrap();

    let data = b"some sample content to sign";
    let signature = signer.sign(data.to_vec()).await.unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());

    let pub_key = include_bytes!("../fixtures/raw_signature/es384.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Es384).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[cfg_attr(not(target_arch = "wasm32"), actix::test)]
// #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
async fn es512() {
    let cert_chain = include_bytes!("../fixtures/raw_signature/es512.pub");
    let private_key = include_bytes!("../fixtures/raw_signature/es512.priv");

    let signer = async_signer_from_cert_chain_and_private_key(
        cert_chain,
        private_key,
        SigningAlg::Es512,
        None,
    )
    .unwrap();

    let data = b"some sample content to sign";
    let signature = signer.sign(data.to_vec()).await.unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());

    let pub_key = include_bytes!("../fixtures/raw_signature/es512.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Es512).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[cfg_attr(not(target_arch = "wasm32"), actix::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn ed25519() {
    let cert_chain = include_bytes!("../fixtures/raw_signature/ed25519.pub");
    let private_key = include_bytes!("../fixtures/raw_signature/ed25519.priv");

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

    let pub_key = include_bytes!("../fixtures/raw_signature/ed25519.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ed25519).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[cfg_attr(not(target_arch = "wasm32"), actix::test)]
// #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn ps256() {
    let cert_chain = include_bytes!("../fixtures/raw_signature/ps256.pub");
    let private_key = include_bytes!("../fixtures/raw_signature/ps256.priv");

    let signer = async_signer_from_cert_chain_and_private_key(
        cert_chain,
        private_key,
        SigningAlg::Ps256,
        None,
    )
    .unwrap();

    let data = b"some sample content to sign";
    let signature = signer.sign(data.to_vec()).await.unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());

    let pub_key = include_bytes!("../fixtures/raw_signature/ps256.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ps256).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[cfg_attr(not(target_arch = "wasm32"), actix::test)]
// #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn ps384() {
    let cert_chain = include_bytes!("../fixtures/raw_signature/ps384.pub");
    let private_key = include_bytes!("../fixtures/raw_signature/ps384.priv");

    let signer = async_signer_from_cert_chain_and_private_key(
        cert_chain,
        private_key,
        SigningAlg::Ps384,
        None,
    )
    .unwrap();

    let data = b"some sample content to sign";
    let signature = signer.sign(data.to_vec()).await.unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());

    let pub_key = include_bytes!("../fixtures/raw_signature/ps384.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ps384).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}

#[cfg_attr(not(target_arch = "wasm32"), actix::test)]
// #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn ps512() {
    let cert_chain = include_bytes!("../fixtures/raw_signature/ps512.pub");
    let private_key = include_bytes!("../fixtures/raw_signature/ps512.priv");

    let signer = async_signer_from_cert_chain_and_private_key(
        cert_chain,
        private_key,
        SigningAlg::Ps512,
        None,
    )
    .unwrap();

    let data = b"some sample content to sign";
    let signature = signer.sign(data.to_vec()).await.unwrap();

    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());

    let pub_key = include_bytes!("../fixtures/raw_signature/ps512.pub_key");

    let validator = validator_for_signing_alg(SigningAlg::Ps512).unwrap();
    validator.validate(&signature, data, pub_key).unwrap();
}
