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

use crate::{
    crypto::raw_signature::{
        async_signer_from_cert_chain_and_private_key, signer_from_cert_chain_and_private_key,
        AsyncRawSigner, SigningAlg,
    },
    http::AsyncHttpResolver,
    signer::{BoxedAsyncSigner, BoxedSigner, RawSignerWrapper},
    AsyncSigner, Result,
};

/// Creates a [`Signer`] instance for testing purposes using test credentials.
pub(crate) fn test_signer(alg: SigningAlg) -> BoxedSigner {
    let (cert_chain, private_key) = cert_chain_and_private_key_for_alg(alg);

    Box::new(RawSignerWrapper(
        signer_from_cert_chain_and_private_key(cert_chain, private_key, alg, None).unwrap(),
    ))
}

/// Creates a [`Signer`] instance for testing purposes using test credentials.
#[cfg(feature = "file_io")] // the only test using this now is file based
pub(crate) fn test_cawg_signer(
    alg: SigningAlg,
    referenced_assertions: &[&str],
) -> Result<BoxedSigner> {
    let (cert_chain, private_key) = cert_chain_and_private_key_for_alg(alg);

    let c2pa_raw_signer =
        signer_from_cert_chain_and_private_key(cert_chain, private_key, alg, None).unwrap();
    let cawg_raw_signer =
        signer_from_cert_chain_and_private_key(cert_chain, private_key, alg, None).unwrap();

    let mut ia_signer = crate::identity::builder::IdentityAssertionSigner::new(c2pa_raw_signer);

    let x509_holder = crate::identity::x509::X509CredentialHolder::from_raw_signer(cawg_raw_signer);
    let mut iab =
        crate::identity::builder::IdentityAssertionBuilder::for_credential_holder(x509_holder);
    iab.add_referenced_assertions(referenced_assertions);

    ia_signer.add_identity_assertion(iab);
    Ok(Box::new(ia_signer))
}

/// Creates an [`AsyncSigner`] instance for testing purposes using test credentials.
#[allow(dead_code)]
pub(crate) fn async_test_signer(alg: SigningAlg) -> BoxedAsyncSigner {
    let (cert_chain, private_key) = cert_chain_and_private_key_for_alg(alg);

    Box::new(AsyncRawSignerWrapper(
        async_signer_from_cert_chain_and_private_key(cert_chain, private_key, alg, None).unwrap(),
    ))
}

pub(crate) fn cert_chain_and_private_key_for_alg(
    alg: SigningAlg,
) -> (&'static [u8], &'static [u8]) {
    match alg {
        SigningAlg::Ps256 => (
            include_bytes!("../../tests/fixtures/certs/ps256.pub"),
            include_bytes!("../../tests/fixtures/certs/ps256.pem"),
        ),

        SigningAlg::Ps384 => (
            include_bytes!("../../tests/fixtures/certs/ps384.pub"),
            include_bytes!("../../tests/fixtures/certs/ps384.pem"),
        ),

        SigningAlg::Ps512 => (
            include_bytes!("../../tests/fixtures/certs/ps512.pub"),
            include_bytes!("../../tests/fixtures/certs/ps512.pem"),
        ),

        SigningAlg::Es256 => (
            include_bytes!("../../tests/fixtures/certs/es256.pub"),
            include_bytes!("../../tests/fixtures/certs/es256.pem"),
        ),

        SigningAlg::Es384 => (
            include_bytes!("../../tests/fixtures/certs/es384.pub"),
            include_bytes!("../../tests/fixtures/certs/es384.pem"),
        ),

        SigningAlg::Es512 => (
            include_bytes!("../../tests/fixtures/certs/es512.pub"),
            include_bytes!("../../tests/fixtures/certs/es512.pem"),
        ),

        SigningAlg::Ed25519 => (
            include_bytes!("../../tests/fixtures/certs/ed25519.pub"),
            include_bytes!("../../tests/fixtures/certs/ed25519.pem"),
        ),
    }
}

#[cfg(not(target_arch = "wasm32"))]
type BoxedAsyncRawSigner = Box<dyn AsyncRawSigner + Sync + Send>;

#[cfg(target_arch = "wasm32")]
type BoxedAsyncRawSigner = Box<dyn AsyncRawSigner>;

#[allow(dead_code)] // TEMPORARY: Not used on WASM
struct AsyncRawSignerWrapper(BoxedAsyncRawSigner);

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

    async fn send_timestamp_request(
        &self,
        http_resolver: &(dyn AsyncHttpResolver + Sync),
        message: &[u8],
    ) -> Option<Result<Vec<u8>>> {
        self.0
            .send_time_stamp_request(http_resolver, message)
            .await
            .map(|r| r.map_err(|e| e.into()))
    }

    fn async_raw_signer(&self) -> Option<Box<&dyn AsyncRawSigner>> {
        Some(Box::new(&*self.0))
    }
}
