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
    ec::EcKey,
    hash::MessageDigest,
    pkey::{PKey, Private},
    sign::Signer,
    x509::X509,
};

use crate::{
    ec_utils::{der_to_p1363, ec_curve_from_private_key_der},
    raw_signature::{
        openssl::{cert_chain::check_chain_order, OpenSslMutex},
        RawSigner, RawSignerError, SigningAlg,
    },
    time_stamp::TimeStampProvider,
};

enum EcdsaSigningAlg {
    Es256,
    Es384,
    Es512,
}

/// Implements `Signer` trait using OpenSSL's implementation of
/// ECDSA encryption.
pub struct EcdsaSigner {
    alg: EcdsaSigningAlg,

    cert_chain: Vec<Vec<u8>>,
    cert_chain_len: usize,

    private_key: EcKey<Private>,

    time_stamp_service_url: Option<String>,
    time_stamp_size: usize,
}

impl EcdsaSigner {
    pub(crate) fn from_cert_chain_and_private_key(
        cert_chain: &[u8],
        private_key: &[u8],
        alg: SigningAlg,
        time_stamp_service_url: Option<String>,
    ) -> Result<Self, RawSignerError> {
        let alg = match alg {
            SigningAlg::Es256 => EcdsaSigningAlg::Es256,
            SigningAlg::Es384 => EcdsaSigningAlg::Es384,
            SigningAlg::Es512 => EcdsaSigningAlg::Es512,
            _ => {
                return Err(RawSignerError::InternalError(
                    "EcdsaSigner should be used only for SigningAlg::Es***".to_string(),
                ));
            }
        };

        let _openssl = OpenSslMutex::acquire()?;

        let cert_chain = X509::stack_from_pem(cert_chain)?;

        if !check_chain_order(&cert_chain) {
            return Err(RawSignerError::InvalidSigningCredentials(
                "certificate chain in incorrect order".to_string(),
            ));
        }

        // certs in DER format
        let cert_chain = cert_chain
            .iter()
            .map(|cert| {
                cert.to_der().map_err(|_| {
                    RawSignerError::CryptoLibraryError(
                        "could not encode certificate to DER".to_string(),
                    )
                })
            })
            .collect::<Result<Vec<_>, RawSignerError>>()?;

        // get the actual length of the certificate chain
        let cert_chain_len = cert_chain.iter().fold(0usize, |sum, c| sum + c.len());

        let private_key = EcKey::private_key_from_pem(private_key)?;

        Ok(EcdsaSigner {
            alg,
            cert_chain,
            cert_chain_len,
            private_key,
            time_stamp_service_url,
            time_stamp_size: 10000,
            // TO DO: Call out to time stamp service to get actual time stamp and use that size?
        })
    }
}

impl RawSigner for EcdsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        let _openssl = OpenSslMutex::acquire()?;

        let private_key = PKey::from_ec_key(self.private_key.clone())?;

        let pkcs8_private_key = private_key.private_key_to_pkcs8().map_err(|_| {
            RawSignerError::InvalidSigningCredentials("unsupported EC curve".to_string())
        })?;

        let curve = ec_curve_from_private_key_der(&pkcs8_private_key).ok_or(
            RawSignerError::InvalidSigningCredentials("unsupported EC curve".to_string()),
        )?;

        let sig_len = curve.p1363_sig_len();

        let mut signer = match self.alg {
            EcdsaSigningAlg::Es256 => Signer::new(MessageDigest::sha256(), &private_key)?,
            EcdsaSigningAlg::Es384 => Signer::new(MessageDigest::sha384(), &private_key)?,
            EcdsaSigningAlg::Es512 => Signer::new(MessageDigest::sha512(), &private_key)?,
        };

        signer.update(data)?;

        let der_sig = signer.sign_to_vec()?;
        der_to_p1363(&der_sig, sig_len)
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
        let _openssl = OpenSslMutex::acquire()?;

        self.cert_chain
            .iter()
            .map(|cert| cert.to_der().map_err(|e| e.into()))
            .collect()
    }
}

impl TimeStampProvider for EcdsaSigner {
    fn time_stamp_service_url(&self) -> Option<String> {
        self.time_stamp_service_url.clone()
    }
}
