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

use ed25519_dalek::{pkcs8::DecodePrivateKey, SigningKey};
use x509_parser::{error::PEMError, pem::Pem};

use crate::{
    raw_signature::{RawSigner, RawSignerError, SigningAlg},
    time_stamp::TimeStampProvider,
};

/// Implements `RawSigner` trait using `ed25519_dalek` crate's implementation of
/// Edwards Curve encryption.
pub struct Ed25519Signer {
    #[allow(dead_code)]
    cert_chain: Vec<Vec<u8>>,
    cert_chain_len: usize,

    signing_key: SigningKey,

    time_stamp_service_url: Option<String>,
    time_stamp_size: usize,
}

impl Ed25519Signer {
    pub(crate) fn from_cert_chain_and_private_key(
        cert_chain: &[u8],
        private_key: &[u8],
        time_stamp_service_url: Option<String>,
    ) -> Result<Self, RawSignerError> {
        let cert_chain = Pem::iter_from_buffer(cert_chain)
            .map(|r| match r {
                Ok(pem) => Ok(pem.contents),
                Err(e) => Err(e),
            })
            .collect::<Result<Vec<Vec<u8>>, PEMError>>()
            .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))?;

        let cert_chain_len = cert_chain.iter().fold(0usize, |sum, c| sum + c.len());

        let private_key_pem = std::str::from_utf8(private_key).map_err(|e| {
            RawSignerError::InvalidSigningCredentials(format!("invalid private key: {e}"))
        })?;

        let signing_key = SigningKey::from_pkcs8_pem(private_key_pem).map_err(|e| {
            RawSignerError::InvalidSigningCredentials(format!("invalid private key: {e}"))
        })?;

        Ok(Ed25519Signer {
            cert_chain,
            cert_chain_len,

            signing_key,

            time_stamp_service_url,
            time_stamp_size: 10000,
            // TO DO: Call out to time stamp service to get actual time stamp and use that size?
        })
    }
}

impl RawSigner for Ed25519Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        use ed25519_dalek::Signer;

        Ok(self
            .signing_key
            .try_sign(data)
            .map_err(|e| RawSignerError::InternalError(format!("signature error: {e}")))?
            .to_vec())
    }

    fn alg(&self) -> SigningAlg {
        SigningAlg::Ed25519
    }

    fn reserve_size(&self) -> usize {
        1024 + self.cert_chain_len + self.time_stamp_size
    }

    fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError> {
        Ok(self.cert_chain.clone())
    }
}

impl TimeStampProvider for Ed25519Signer {
    fn time_stamp_service_url(&self) -> Option<String> {
        self.time_stamp_service_url.clone()
    }
}
