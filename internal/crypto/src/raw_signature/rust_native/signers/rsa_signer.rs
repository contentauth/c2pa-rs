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

use der::{pem::PemLabel, SecretDocument};
use num_bigint_dig::BigUint;
use rsa::{
    pkcs8::PrivateKeyInfo,
    pss::SigningKey,
    sha2::{Sha256, Sha384, Sha512},
    signature::{RandomizedSigner, SignatureEncoding},
    RsaPrivateKey,
};
use x509_parser::{error::PEMError, pem::Pem};

use crate::{
    raw_signature::{RawSigner, RawSignerError, SigningAlg},
    time_stamp::TimeStampProvider,
};

enum RsaSigningAlg {
    Ps256,
    Ps384,
    Ps512,
}

/// Implements [`RawSigner`] trait using `rsa` crate's implementation of SHA256
/// + RSA encryption.
pub(crate) struct RsaSigner {
    alg: RsaSigningAlg,

    cert_chain: Vec<Vec<u8>>,
    cert_chain_len: usize,

    private_key: RsaPrivateKey,

    time_stamp_service_url: Option<String>,
    time_stamp_size: usize,
}

impl RsaSigner {
    pub(crate) fn from_cert_chain_and_private_key(
        cert_chain: &[u8],
        private_key: &[u8],
        alg: SigningAlg,
        time_stamp_service_url: Option<String>,
    ) -> Result<Self, RawSignerError> {
        let cert_chain = Pem::iter_from_buffer(cert_chain)
            .map(|r| match r {
                Ok(pem) => Ok(pem.contents),
                Err(e) => Err(e),
            })
            .collect::<Result<Vec<Vec<u8>>, PEMError>>()
            .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))?;

        // TO DO: check_chain_order(&cert_chain).await?;

        let cert_chain_len = cert_chain.len();

        let pem_str = std::str::from_utf8(private_key)
            .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))?;

        let (label, private_key_der) = SecretDocument::from_pem(pem_str)
            .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))?;

        PrivateKeyInfo::validate_pem_label(label)
            .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))?;

        let pki = PrivateKeyInfo::try_from(private_key_der.as_bytes())
            .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))?;

        // TO DO: Check for correct OID here.
        // eprintln!(
        //     "TO DO: Check for correct OID here: {oid}",
        //     oid = &pki.algorithm.oid
        // );

        let pkcs1_key = pkcs1::RsaPrivateKey::try_from(pki.private_key)
            .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))?;

        // Multi-prime RSA keys not currently supported
        if pkcs1_key.version() != pkcs1::Version::TwoPrime {
            return Err(RawSignerError::InvalidSigningCredentials(
                "multi-prime RSA keys not supported".to_string(),
            ));
        }

        let n = BigUint::from_bytes_be(pkcs1_key.modulus.as_bytes());
        let e = BigUint::from_bytes_be(pkcs1_key.public_exponent.as_bytes());
        let d = BigUint::from_bytes_be(pkcs1_key.private_exponent.as_bytes());
        let prime1 = BigUint::from_bytes_be(pkcs1_key.prime1.as_bytes());
        let prime2 = BigUint::from_bytes_be(pkcs1_key.prime2.as_bytes());
        let primes = vec![prime1, prime2];
        let private_key = RsaPrivateKey::from_components(n, e, d, primes)
            .map_err(|e| RawSignerError::InvalidSigningCredentials(e.to_string()))?;

        let alg: RsaSigningAlg = match alg {
            SigningAlg::Ps256 => RsaSigningAlg::Ps256,
            SigningAlg::Ps384 => RsaSigningAlg::Ps384,
            SigningAlg::Ps512 => RsaSigningAlg::Ps512,
            _ => {
                return Err(RawSignerError::InternalError(
                    "RsaSigner should be used only for SigningAlg::Ps***".to_string(),
                ));
            }
        };

        Ok(RsaSigner {
            alg,
            cert_chain,
            private_key,
            cert_chain_len,
            time_stamp_service_url,
            time_stamp_size: 10000,
            // TO DO: Call out to time stamp service to get actual time stamp and use that size?
        })
    }
}

impl RawSigner for RsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        let mut rng = rand::thread_rng();

        match self.alg {
            RsaSigningAlg::Ps256 => {
                let s = rsa::pss::SigningKey::<Sha256>::new(self.private_key.clone());

                let sig = s.sign_with_rng(&mut rng, data);

                Ok(sig.to_bytes().to_vec())
            }

            RsaSigningAlg::Ps384 => {
                let s = SigningKey::<Sha384>::new(self.private_key.clone());

                let sig = s.sign_with_rng(&mut rng, data);

                Ok(sig.to_bytes().to_vec())
            }

            RsaSigningAlg::Ps512 => {
                let s = SigningKey::<Sha512>::new(self.private_key.clone());

                let sig = s.sign_with_rng(&mut rng, data);

                Ok(sig.to_bytes().to_vec())
            }
        }
    }

    fn reserve_size(&self) -> usize {
        1024 + self.cert_chain_len + self.time_stamp_size
    }

    fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError> {
        Ok(self.cert_chain.clone())
    }

    fn alg(&self) -> SigningAlg {
        match self.alg {
            RsaSigningAlg::Ps256 => SigningAlg::Ps256,
            RsaSigningAlg::Ps384 => SigningAlg::Ps384,
            RsaSigningAlg::Ps512 => SigningAlg::Ps512,
        }
    }
}

impl TimeStampProvider for RsaSigner {
    fn time_stamp_service_url(&self) -> Option<String> {
        self.time_stamp_service_url.clone()
    }
}
