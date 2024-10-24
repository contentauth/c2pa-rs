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

use openssl::{ec::EcKey, hash::MessageDigest, pkey::PKey};

use crate::{validator::CoseValidator, Error, Result, SigningAlg};

pub struct EcValidator {
    alg: SigningAlg,
}

impl EcValidator {
    pub fn new(alg: SigningAlg) -> Self {
        EcValidator { alg }
    }
}

impl CoseValidator for EcValidator {
    fn validate(&self, sig: &[u8], data: &[u8], pkey: &[u8]) -> Result<bool> {
        let _openssl = super::OpenSslMutex::acquire()?;

        let public_key = EcKey::public_key_from_der(pkey).map_err(|_err| Error::CoseSignature)?;
        let key = PKey::from_ec_key(public_key).map_err(wrap_openssl_err)?;

        let mut verifier = match self.alg {
            SigningAlg::Es256 => openssl::sign::Verifier::new(MessageDigest::sha256(), &key)?,
            SigningAlg::Es384 => openssl::sign::Verifier::new(MessageDigest::sha384(), &key)?,
            SigningAlg::Es512 => openssl::sign::Verifier::new(MessageDigest::sha512(), &key)?,
            _ => return Err(Error::UnsupportedType),
        };

        // is this an expected P1363 sig size
        let sig_der = if sig.len() == 64 || sig.len() == 96 || sig.len() == 132 {
            if sig.len()
                != match self.alg {
                    SigningAlg::Es256 => 64,
                    SigningAlg::Es384 => 96,
                    SigningAlg::Es512 => 132,
                    _ => return Err(Error::UnsupportedType),
                }
            {
                return Err(Error::CoseSignature);
            }

            // convert P1363 sig to DER sig
            let sig_len = sig.len() / 2;
            let r = openssl::bn::BigNum::from_slice(&sig[0..sig_len])
                .map_err(|_err| Error::CoseSignature)?;
            let s = openssl::bn::BigNum::from_slice(&sig[sig_len..])
                .map_err(|_err| Error::CoseSignature)?;

            let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_private_components(r, s)
                .map_err(|_err| Error::CoseSignature)?;

            ecdsa_sig.to_der().map_err(|_err| Error::CoseSignature)?
        } else {
            sig.to_vec()
        };

        verifier.update(data).map_err(wrap_openssl_err)?;
        verifier
            .verify(&sig_der)
            .map_err(|_err| Error::CoseSignature)
    }
}

fn wrap_openssl_err(err: openssl::error::ErrorStack) -> Error {
    Error::OpenSslError(err)
}
