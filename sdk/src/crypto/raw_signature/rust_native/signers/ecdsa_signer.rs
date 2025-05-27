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

use std::str::FromStr;

use asn1_rs::{Any, BitString, DerSequence, FromDer, Sequence};
use der::{Decode, Encode};
use ecdsa::signature::Signer;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};
use p521::ecdsa::{Signature as P512Signature, SigningKey as P512SigningKey};
use pkcs8::{DecodePrivateKey, ObjectIdentifier, PrivateKeyInfo};
use x509_parser::{error::PEMError, pem::Pem};

use crate::crypto::{
    raw_signature::{
        oids::{EC_PUBLICKEY_OID, SECP521R1_OID},
        RawSigner, RawSignerError, SigningAlg,
    },
    time_stamp::TimeStampProvider,
};

enum EcdsaSigningAlg {
    Es256,
    Es384,
    Es512,
}

// Signing keys for ES256, ES384, and ES512 are different types
pub enum EcdsaSigningKey {
    Es256(P256SigningKey),
    Es384(P384SigningKey),
    Es512(P512SigningKey),
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

        let cert_chain_len = cert_chain.iter().fold(0usize, |sum, c| sum + c.len());

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
                let key = es512_from_pkcs8_pem(private_key_pem)?;
                (EcdsaSigningKey::Es512(key), EcdsaSigningAlg::Es512)
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
            EcdsaSigningKey::Es512(ref key) => {
                let signature: P512Signature = key.sign(data);
                Ok(signature.to_vec())
            }
        }
    }

    fn alg(&self) -> SigningAlg {
        match self.alg {
            EcdsaSigningAlg::Es256 => SigningAlg::Es256,
            EcdsaSigningAlg::Es384 => SigningAlg::Es384,
            EcdsaSigningAlg::Es512 => SigningAlg::Es512,
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

#[derive(DerSequence)]
struct ECPrivateKey<'a> {
    version: u32,
    private_key: &'a [u8], // OCTET STRING content
    parameters: Option<Any<'a>>,
    public_key: Option<BitString<'a>>,
}

fn es512_from_pkcs8_pem(private_key_pem: &str) -> Result<P512SigningKey, RawSignerError> {
    let pem = pem::parse(private_key_pem).map_err(|e| {
        RawSignerError::InvalidSigningCredentials(format!("invalid ES512 private key PEM: {e}"))
    })?;
    let pk_info = PrivateKeyInfo::try_from(pem.contents()).map_err(|e| {
        RawSignerError::InvalidSigningCredentials(format!("invalid ES512 PKCS#8 structure: {e}"))
    })?;

    // Check OID is id-ecPublicKey (1.2.840.10045.2.1)
    if pk_info.algorithm.oid.as_bytes() != EC_PUBLICKEY_OID.as_bytes() {
        return Err(RawSignerError::InvalidSigningCredentials(format!(
            "Unexpected OID: {}, expected id-ecPublicKey {}",
            pk_info.algorithm.oid, EC_PUBLICKEY_OID
        )));
    }

    let params = pk_info
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| {
            RawSignerError::InvalidSigningCredentials("Missing algorithm parameters".to_string())
        })?
        .to_der()
        .map_err(|_| {
            RawSignerError::InvalidSigningCredentials(
                "Algorithm parameters are not a valid OID".to_string(),
            )
        })?;
    // Parse the parameters as an ASN.1 OID
    let curve_oid = ObjectIdentifier::from_der(&params).map_err(|_| {
        RawSignerError::InvalidSigningCredentials(
            "Algorithm parameters are not a valid OID".to_string(),
        )
    })?;

    // Parse ECPrivateKey ASN.1 structure using asn1-rs
    let ec_private_key = ECPrivateKey::from_der(pk_info.private_key).map_err(|e| {
        RawSignerError::InvalidSigningCredentials(format!("invalid ES512 ECPrivateKey ASN.1: {e}"))
    })?;

    // Check version is 1
    if ec_private_key.1.version != 1 {
        return Err(RawSignerError::InvalidSigningCredentials(format!(
            "ECPrivateKey ASN.1 version is {}, expected 1",
            ec_private_key.1.version
        )));
    }

    P512SigningKey::from_slice(ec_private_key.1.private_key).map_err(|e| {
        RawSignerError::InvalidSigningCredentials(format!("invalid ES512 private key: {e}"))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::crypto::raw_signature::SigningAlg;

    #[test]
    fn test_es512_supported() {
        let cert_chain =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es512.pub");
        let private_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es512.priv");
        let algorithm = SigningAlg::Es512;
        let time_stamp_service_url = None;

        let result = EcdsaSigner::from_cert_chain_and_private_key(
            cert_chain,
            private_key,
            algorithm,
            time_stamp_service_url,
        );

        assert!(result.is_ok());
        if let Ok(ecdsa_signer) = result {
            assert_eq!(ecdsa_signer.alg(), SigningAlg::Es512);
        } else {
            unreachable!("Expected InvalidSigningCredentials error");
        }
    }

    #[test]
    fn test_other_not_supported() {
        let cert_chain =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps256.pub");
        let private_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps256.priv");
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
