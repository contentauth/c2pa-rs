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

#![deny(missing_docs)]

//! Temporary async signing instances for testing purposes.
//!
//! This is only a demonstration async Signer that is used to test
//! the asynchronous signing of claims.
//! This module should be used only for testing purposes.

#[cfg(feature = "openssl_sign")]
use crate::SigningAlg;

#[cfg(feature = "openssl_sign")]
fn get_local_signer(alg: SigningAlg) -> Box<dyn crate::Signer> {
    let cert_dir = crate::utils::test::fixture_path("certs");

    match alg {
        SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512 => {
            let (s, _k) = super::temp_signer::get_rsa_signer(&cert_dir, alg, None);
            Box::new(s)
        }
        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => {
            let (s, _k) = super::temp_signer::get_ec_signer(&cert_dir, alg, None);
            Box::new(s)
        }
        SigningAlg::Ed25519 => {
            let (s, _k) = super::temp_signer::get_ed_signer(&cert_dir, alg, None);
            Box::new(s)
        }
    }
}

#[cfg(feature = "openssl_sign")]
pub struct AsyncSignerAdapter {
    alg: SigningAlg,
    certs: Vec<Vec<u8>>,
    reserve_size: usize,
    tsa_url: Option<String>,
    ocsp_val: Option<Vec<u8>>,
}

#[cfg(feature = "openssl_sign")]
impl AsyncSignerAdapter {
    pub fn new(alg: SigningAlg) -> Self {
        let signer = get_local_signer(alg);

        AsyncSignerAdapter {
            alg,
            certs: signer.certs().unwrap_or_default(),
            reserve_size: signer.reserve_size(),
            tsa_url: signer.time_authority_url(),
            ocsp_val: signer.ocsp_val(),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "openssl_sign")]
#[async_trait::async_trait]
impl crate::AsyncSigner for AsyncSignerAdapter {
    async fn sign(&self, data: Vec<u8>) -> crate::error::Result<Vec<u8>> {
        let signer = get_local_signer(self.alg);
        signer.sign(&data)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn certs(&self) -> crate::Result<Vec<Vec<u8>>> {
        let mut output: Vec<Vec<u8>> = Vec::new();
        for v in &self.certs {
            output.push(v.clone());
        }
        Ok(output)
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }

    fn ocsp_val(&self) -> Option<Vec<u8>> {
        self.ocsp_val.clone()
    }
}
