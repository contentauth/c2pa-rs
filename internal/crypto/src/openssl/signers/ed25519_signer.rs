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

use openssl::{
    pkey::{PKey, Private},
    sign::Signer,
    x509::X509,
};

use crate::{
    openssl::{cert_chain::check_chain_order, OpenSslMutex},
    raw_signature::{RawSigner, RawSignerError},
    time_stamp::TimeStampProvider,
    SigningAlg,
};

/// Implements `RawSigner` trait using OpenSSL's implementation of
/// Edwards Curve encryption.
pub struct Ed25519Signer {
    cert_chain: Vec<X509>,
    cert_chain_len: usize,

    private_key: PKey<Private>,

    time_stamp_service_url: Option<String>,
    time_stamp_size: usize,
}

impl Ed25519Signer {
    pub(crate) fn from_cert_chain_and_private_key(
        cert_chain: &[u8],
        private_key: &[u8],
        time_stamp_service_url: Option<String>,
    ) -> Result<Self, RawSignerError> {
        let _openssl = OpenSslMutex::acquire()?;

        let cert_chain = X509::stack_from_pem(cert_chain)?;
        let cert_chain_len = cert_chain.len();

        if !check_chain_order(&cert_chain) {
            return Err(RawSignerError::InvalidSigningCredentials(
                "certificate chain in incorrect order".to_string(),
            ));
        }

        let private_key = PKey::private_key_from_pem(private_key)?;

        Ok(Ed25519Signer {
            cert_chain,
            cert_chain_len,

            private_key,

            time_stamp_service_url,
            time_stamp_size: 10000,
            // TO DO: Call out to time stamp service to get actual time stamp and use that size?
        })
    }
}

impl RawSigner for Ed25519Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        let _openssl = OpenSslMutex::acquire()?;

        let mut signer = Signer::new_without_digest(&self.private_key)?;

        Ok(signer.sign_oneshot_to_vec(data)?)
    }

    fn alg(&self) -> SigningAlg {
        SigningAlg::Ed25519
    }

    fn reserve_size(&self) -> usize {
        1024 + self.cert_chain_len + self.time_stamp_size
    }

    fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError> {
        let _openssl = OpenSslMutex::acquire()?;

        self.cert_chain
            .iter()
            .map(|cert| {
                cert.to_der()
                    .map_err(|e| RawSignerError::OpenSslError(e.to_string()))
            })
            .collect()
    }
}

impl TimeStampProvider for Ed25519Signer {
    fn time_stamp_service_url(&self) -> Option<String> {
        self.time_stamp_service_url.clone()
    }
}
