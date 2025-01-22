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

#![allow(clippy::unwrap_used)] // This mod is only used in test code.

use async_trait::async_trait;
use c2pa_crypto::raw_signature::{
    async_signer_from_cert_chain_and_private_key, signer_from_cert_chain_and_private_key,
    AsyncRawSigner, SigningAlg,
};

use crate::{signer::RawSignerWrapper, AsyncSigner, Result, Signer};

/// Creates a [`Signer`] instance for testing purposes using test credentials.
pub(crate) fn test_signer(alg: SigningAlg) -> Box<dyn Signer> {
    let (cert_chain, private_key) = cert_chain_and_private_key_for_alg(alg);

    Box::new(RawSignerWrapper(
        signer_from_cert_chain_and_private_key(&cert_chain, &private_key, alg, None).unwrap(),
    ))
}

/// Creates an [`AsyncSigner`] instance for testing purposes using test credentials.
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
pub(crate) fn async_test_signer(alg: SigningAlg) -> Box<dyn AsyncSigner + Sync + Send> {
    let (cert_chain, private_key) = cert_chain_and_private_key_for_alg(alg);

    Box::new(AsyncRawSignerWrapper(
        async_signer_from_cert_chain_and_private_key(&cert_chain, &private_key, alg, None).unwrap(),
    ))
}

/// Creates an [`AsyncSigner`] instance for testing purposes using test credentials.
#[cfg(target_arch = "wasm32")]
pub(crate) fn async_test_signer(alg: SigningAlg) -> Box<dyn AsyncSigner> {
    let (cert_chain, private_key) = cert_chain_and_private_key_for_alg(alg);

    Box::new(AsyncRawSignerWrapper(
        async_signer_from_cert_chain_and_private_key(&cert_chain, &private_key, alg, None).unwrap(),
    ))
}

fn cert_chain_and_private_key_for_alg(alg: SigningAlg) -> (Vec<u8>, Vec<u8>) {
    match alg {
        SigningAlg::Ps256 => (
            include_bytes!("../../tests/fixtures/certs/ps256.pub").to_vec(),
            include_bytes!("../../tests/fixtures/certs/ps256.pem").to_vec(),
        ),

        SigningAlg::Ps384 => (
            include_bytes!("../../tests/fixtures/certs/ps384.pub").to_vec(),
            include_bytes!("../../tests/fixtures/certs/ps384.pem").to_vec(),
        ),

        SigningAlg::Ps512 => (
            include_bytes!("../../tests/fixtures/certs/ps512.pub").to_vec(),
            include_bytes!("../../tests/fixtures/certs/ps512.pem").to_vec(),
        ),

        SigningAlg::Es256 => (
            include_bytes!("../../tests/fixtures/certs/es256.pub").to_vec(),
            include_bytes!("../../tests/fixtures/certs/es256.pem").to_vec(),
        ),

        SigningAlg::Es384 => (
            include_bytes!("../../tests/fixtures/certs/es384.pub").to_vec(),
            include_bytes!("../../tests/fixtures/certs/es384.pem").to_vec(),
        ),

        SigningAlg::Es512 => (
            include_bytes!("../../tests/fixtures/certs/es512.pub").to_vec(),
            include_bytes!("../../tests/fixtures/certs/es512.pem").to_vec(),
        ),

        SigningAlg::Ed25519 => (
            include_bytes!("../../tests/fixtures/certs/ed25519.pub").to_vec(),
            include_bytes!("../../tests/fixtures/certs/ed25519.pem").to_vec(),
        ),
    }
}

#[cfg(not(target_arch = "wasm32"))]
struct AsyncRawSignerWrapper(Box<dyn AsyncRawSigner + Sync + Send>);

#[allow(dead_code)] // TEMPORARY: Not used on WASM
#[cfg(target_arch = "wasm32")]
struct AsyncRawSignerWrapper(Box<dyn AsyncRawSigner>);

#[allow(dead_code)] // TEMPORARY: Not used on WASM
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl AsyncSigner for AsyncRawSignerWrapper {
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        self.0.sign(data).await.map_err(|e| e.into())
    }

    fn alg(&self) -> SigningAlg {
        self.0.alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        self.0.cert_chain().map_err(|e| e.into())
    }

    fn reserve_size(&self) -> usize {
        self.0.reserve_size()
    }

    async fn ocsp_val(&self) -> Option<Vec<u8>> {
        self.0.ocsp_response().await
    }

    fn time_authority_url(&self) -> Option<String> {
        self.0.time_stamp_service_url()
    }

    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        self.0.time_stamp_request_headers()
    }

    fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.0
            .time_stamp_request_body(message)
            .map_err(|e| e.into())
    }

    async fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        self.0
            .send_time_stamp_request(message)
            .await
            .map(|r| r.map_err(|e| e.into()))
    }

    fn async_raw_signer(&self) -> Box<&dyn AsyncRawSigner> {
        Box::new(&*self.0)
    }
}
