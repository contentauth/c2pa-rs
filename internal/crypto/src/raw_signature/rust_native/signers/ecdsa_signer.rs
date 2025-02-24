// Copyright 2025 Adobe. All rights reserved.
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

use ecdsa::signature::Signer;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};
use pkcs8::DecodePrivateKey;
use x509_parser::{error::PEMError, pem::Pem};

use crate::{
    raw_signature::{RawSigner, RawSignerError, SigningAlg},
    time_stamp::TimeStampProvider,
};

// Rust native does not support Es512
enum EcdsaSigningAlg {
    Es256,
    Es384,
}

// Signing keys for ES256 and ES384 are different types
pub enum EcdsaSigningKey {
    Es256(P256SigningKey),
    Es384(P384SigningKey),
}

pub struct EcdsaSigner {
    alg: EcdsaSigningAlg,

    cert_chain: Vec<Vec<u8>>,
    cert_chain_len: usize,

    signing_key: EcdsaSigningKey,

    time_stamp_service_url: Option<String>,
    time_stamp_size: usize,
}

impl EcdsaSigner {
    pub(crate) fn from_cert_chain_and_private_key(
        cert_chain: &[u8],
        private_key: &[u8],
        algorithm: SigningAlg,
        time_stamp_service_url: Option<String>,
    ) -> Result<Self, RawSignerError> {
        let cert_chain = Pem::iter_from_buffer(cert_chain)
            .map(|r| match r {
                Ok(pem) => Ok(pem.contents),
                Err(e) => Err(e),
            })
            .collect::<Result<Vec<Vec<u8>>, PEMError>>()
            .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))?;

        let cert_chain_len = cert_chain.len();

        let private_key_pem = std::str::from_utf8(private_key).map_err(|e| {
            RawSignerError::InvalidSigningCredentials(format!("invalid private key: {e}"))
        })?;

        let (signing_key, alg) = match algorithm {
            SigningAlg::Es256 => {
                let key = P256SigningKey::from_pkcs8_pem(private_key_pem).map_err(|e| {
                    RawSignerError::InvalidSigningCredentials(format!(
                        "invalid ES256 private key: {e}"
                    ))
                })?;
                (EcdsaSigningKey::Es256(key), EcdsaSigningAlg::Es256)
            }
            SigningAlg::Es384 => {
                let key = P384SigningKey::from_pkcs8_pem(private_key_pem).map_err(|e| {
                    RawSignerError::InvalidSigningCredentials(format!(
                        "invalid ES384 private key: {e}"
                    ))
                })?;
                (EcdsaSigningKey::Es384(key), EcdsaSigningAlg::Es384)
            }
            SigningAlg::Es512 => {
                return Err(RawSignerError::InvalidSigningCredentials(
                    "Rust Crypto does not support Es512, only OpenSSL".to_string(),
                ))
            }
            _ => {
                return Err(RawSignerError::InvalidSigningCredentials(
                    "Unsupported algorithm".to_string(),
                ))
            }
        };

        Ok(EcdsaSigner {
            alg,
            cert_chain,
            cert_chain_len,
            signing_key,
            time_stamp_service_url,
            time_stamp_size: 10000,
        })
    }
}

impl RawSigner for EcdsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        match self.signing_key {
            EcdsaSigningKey::Es256(ref key) => {
                let signature: P256Signature = key.sign(data);
                Ok(signature.to_vec())
            }
            EcdsaSigningKey::Es384(ref key) => {
                let signature: P384Signature = key.sign(data);
                Ok(signature.to_vec())
            }
        }
    }

    fn alg(&self) -> SigningAlg {
        match self.alg {
            EcdsaSigningAlg::Es256 => SigningAlg::Es256,
            EcdsaSigningAlg::Es384 => SigningAlg::Es384,
        }
    }

    fn reserve_size(&self) -> usize {
        1024 + self.cert_chain_len + self.time_stamp_size
    }

    fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError> {
        Ok(self.cert_chain.clone())
    }
}

impl TimeStampProvider for EcdsaSigner {
    fn time_stamp_service_url(&self) -> Option<String> {
        self.time_stamp_service_url.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw_signature::SigningAlg;

    #[test]
    fn test_es512_not_supported() {
        let cert_chain = include_bytes!("../../../tests/fixtures/raw_signature/es512.pub");
        let private_key = include_bytes!("../../../tests/fixtures/raw_signature/es512.priv");
        let algorithm = SigningAlg::Es512;
        let time_stamp_service_url = None;

        let result = EcdsaSigner::from_cert_chain_and_private_key(
            cert_chain,
            private_key,
            algorithm,
            time_stamp_service_url,
        );

        assert!(result.is_err());
        if let Err(RawSignerError::InvalidSigningCredentials(err_msg)) = result {
            assert_eq!(err_msg, "Rust Crypto does not support Es512, only OpenSSL");
        } else {
            unreachable!("Expected InvalidSigningCredentials error");
        }
    }

    #[test]
    fn test_other_not_supported() {
        let cert_chain = include_bytes!("../../../tests/fixtures/raw_signature/ps256.pub");
        let private_key = include_bytes!("../../../tests/fixtures/raw_signature/ps256.priv");
        let algorithm = SigningAlg::Ps256;
        let time_stamp_service_url = None;

        let result = EcdsaSigner::from_cert_chain_and_private_key(
            cert_chain,
            private_key,
            algorithm,
            time_stamp_service_url,
        );

        assert!(result.is_err());
        if let Err(RawSignerError::InvalidSigningCredentials(err_msg)) = result {
            assert_eq!(err_msg, "Unsupported algorithm");
        } else {
            unreachable!("Expected InvalidSigningCredentials error");
        }
    }
}
