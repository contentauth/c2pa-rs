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

use core::str;

use async_trait::async_trait;
use rsa::{
    pkcs8::DecodePrivateKey,
    pss::SigningKey,
    sha2::{Sha256, Sha384, Sha512},
    signature::{RandomizedSigner, SignatureEncoding},
    RsaPrivateKey,
};

use crate::{signer::ConfigurableSigner, AsyncSigner, Error, Result, Signer, SigningAlg};

// Implements `Signer` trait using rsa crate implementation of
// SHA256 + RSA encryption.  This implementation is only used for cross
// target compatible signer used in testing both sync and WASM async unit tests.
pub struct RsaWasmSigner {
    signcerts: Vec<Vec<u8>>,
    pkey: RsaPrivateKey,

    certs_size: usize,
    timestamp_size: usize,

    alg: SigningAlg,
    tsa_url: Option<String>,
}

impl ConfigurableSigner for RsaWasmSigner {
    fn from_signcert_and_pkey(
        signcert: &[u8],
        pkey: &[u8],
        alg: SigningAlg,
        tsa_url: Option<String>,
    ) -> Result<Self> {
        let mut signcerts = Vec::new();
        for pem in x509_parser::pem::Pem::iter_from_buffer(signcert) {
            let pem =
                pem.map_err(|_e| Error::OtherError("Reading next PEM block failed".into()))?;

            signcerts.push(pem.contents);
        }
        let pem_str = str::from_utf8(pkey)
            .map_err(|_e| Error::OtherError("Reading PKEY PEM block failed".into()))?;
        let pk = RsaPrivateKey::from_pkcs8_pem(pem_str).map_err(|e| Error::OtherError(e.into()))?;

        let signer = RsaWasmSigner {
            signcerts,
            pkey: pk,
            certs_size: signcert.len(),
            timestamp_size: 10000, /* todo: call out to TSA to get actual timestamp and use that size */
            alg,
            tsa_url,
        };

        Ok(signer)
    }
}

impl Signer for RsaWasmSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();

        match self.alg {
            SigningAlg::Ps256 => {
                let s = rsa::pss::SigningKey::<Sha256>::new(self.pkey.clone());

                let sig = s.sign_with_rng(&mut rng, data);

                Ok(sig.to_bytes().to_vec())
            }
            SigningAlg::Ps384 => {
                let s = SigningKey::<Sha384>::new(self.pkey.clone());

                let sig = s.sign_with_rng(&mut rng, data);

                Ok(sig.to_bytes().to_vec())
            }
            SigningAlg::Ps512 => {
                let s = SigningKey::<Sha512>::new(self.pkey.clone());

                let sig = s.sign_with_rng(&mut rng, data);

                Ok(sig.to_bytes().to_vec())
            }
            _ => return Err(Error::UnsupportedType),
        }
    }

    fn reserve_size(&self) -> usize {
        1024 + self.certs_size + self.timestamp_size // the Cose_Sign1 contains complete certs and timestamps so account for size
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.signcerts.clone())
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }

    fn ocsp_val(&self) -> Option<Vec<u8>> {
        None
    }
}

pub struct RsaWasmSignerAsync {
    signer: Box<dyn Signer>,
}

impl RsaWasmSignerAsync {
    #[allow(dead_code)]
    pub fn new() -> Self {
        let cert_bytes = include_bytes!("../../tests/fixtures/certs/rs256.pub");
        let key_bytes = include_bytes!("../../tests/fixtures/certs/rs256.pem");

        Self {
            signer: Box::new(
                RsaWasmSigner::from_signcert_and_pkey(
                    cert_bytes,
                    key_bytes,
                    SigningAlg::Ps256,
                    None,
                )
                .expect("test signer configuration error"),
            ),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AsyncSigner for RsaWasmSignerAsync {
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        web_sys::console::debug_1(&"Signing with RsaWasmSignerAsync".into());

        self.signer.sign(&data)
    }

    fn alg(&self) -> SigningAlg {
        self.signer.alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        self.signer.certs()
    }

    fn reserve_size(&self) -> usize {
        self.signer.reserve_size()
    }

    async fn send_timestamp_request(&self, _message: &[u8]) -> Option<Result<Vec<u8>>> {
        None
    }
}

#[allow(unused_imports)]
#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use asn1_rs::FromDer;
    use rsa::{
        pss::{Signature, VerifyingKey},
        sha2::{Digest, Sha256},
        signature::{Keypair, Verifier},
        RsaPrivateKey,
    };

    use super::*;
    use crate::{
        utils::test::{fixture_path, temp_signer},
        Signer, SigningAlg,
    };

    #[test]
    fn sign_ps256() {
        let cert_bytes = include_bytes!("../../tests/fixtures/certs/rs256.pub");
        let key_bytes = include_bytes!("../../tests/fixtures/certs/rs256.pem");

        let signer =
            RsaWasmSigner::from_signcert_and_pkey(cert_bytes, key_bytes, SigningAlg::Ps256, None)
                .unwrap();

        let data = b"some sample content to sign";

        let sig = signer.sign(data).unwrap();
        println!("signature len = {}", sig.len());
        assert!(sig.len() <= signer.reserve_size());

        let sk = rsa::pss::SigningKey::<Sha256>::new(signer.pkey.clone());
        let vk = sk.verifying_key();

        let signature: Signature = sig.as_slice().try_into().unwrap();
        assert!(vk.verify(data, &signature).is_ok());
    }
}
