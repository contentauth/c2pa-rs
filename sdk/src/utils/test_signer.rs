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

// This mod is only used in test code, so panic and unwrap are used.
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

use async_trait::async_trait;
use c2pa_raw_crypto::{signer_from_private_key, RawSigner, SigningAlg};

use crate::{
    crypto::{cert_chain_pem_to_der, cose::cose_reserve_size},
    signer::{BoxedAsyncSigner, BoxedSigner, RawSignerWrapper},
    AsyncSigner, Result,
};

/// Creates a [`Signer`] instance for testing purposes using test credentials.
pub(crate) fn test_signer(alg: SigningAlg) -> BoxedSigner {
    let (cert_chain, private_key) = cert_chain_and_private_key_for_alg(alg);

    Box::new(RawSignerWrapper::new(
        signer_from_private_key(private_key, alg).unwrap(),
        cert_chain_pem_to_der(cert_chain).unwrap(),
        None,
    ))
}

/// Creates a [`Signer`] instance for testing purposes using test credentials.
#[cfg(feature = "file_io")] // the only test using this now is file based
pub(crate) fn test_cawg_signer(
    alg: SigningAlg,
    referenced_assertions: &[&str],
) -> Result<BoxedSigner> {
    let (cert_chain, private_key) = cert_chain_and_private_key_for_alg(alg);
    let cert_chain_der = cert_chain_pem_to_der(cert_chain).unwrap();

    let c2pa_raw_signer = signer_from_private_key(private_key, alg).unwrap();
    let cawg_raw_signer = signer_from_private_key(private_key, alg).unwrap();

    let mut ia_signer = crate::identity::builder::IdentityAssertionSigner::new(
        c2pa_raw_signer,
        cert_chain_der.clone(),
    );

    let x509_holder = crate::identity::x509::X509CredentialHolder::from_raw_signer(
        cawg_raw_signer,
        cert_chain_der,
    );
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

    Box::new(AsyncRawSignerWrapper {
        signer: signer_from_private_key(private_key, alg).unwrap(),
        cert_chain: cert_chain_pem_to_der(cert_chain).unwrap(),
    })
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

        _ => panic!("unsupported test signing algorithm: {alg}"),
    }
}

#[cfg(not(target_arch = "wasm32"))]
type BoxedRawSigner = Box<dyn RawSigner + Sync + Send>;

#[cfg(target_arch = "wasm32")]
type BoxedRawSigner = Box<dyn RawSigner>;

/// Adapts a synchronous [`RawSigner`] into an [`AsyncSigner`] for tests.
#[allow(dead_code)] // TEMPORARY: Not used on WASM
struct AsyncRawSignerWrapper {
    signer: BoxedRawSigner,
    cert_chain: Vec<Vec<u8>>,
}

#[allow(dead_code)] // TEMPORARY: Not used on WASM
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl AsyncSigner for AsyncRawSignerWrapper {
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        self.signer.sign(&data).map_err(|e| e.into())
    }

    fn alg(&self) -> SigningAlg {
        self.signer.alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.cert_chain.clone())
    }

    fn reserve_size(&self) -> usize {
        cose_reserve_size(
            self.signer.max_signature_size(),
            &self.cert_chain,
            false,
            None,
        )
    }
}
