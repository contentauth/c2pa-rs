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

use c2pa_crypto::{openssl::OpenSslMutex, SigningAlg};
use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa};

use crate::{validator::CoseValidator, Error, Result};

pub struct RsaValidator {
    alg: SigningAlg,
}

impl RsaValidator {
    pub fn new(alg: SigningAlg) -> Self {
        RsaValidator { alg }
    }
}

impl CoseValidator for RsaValidator {
    fn validate(&self, sig: &[u8], data: &[u8], pkey: &[u8]) -> Result<bool> {
        let _openssl = OpenSslMutex::acquire()?;

        let rsa = Rsa::public_key_from_der(pkey)?;

        // rebuild RSA keys to eliminate incompatible values
        let n = rsa.n().to_owned()?;
        let e = rsa.e().to_owned()?;

        let new_rsa = Rsa::from_public_components(n, e)?;

        let pkey = PKey::from_rsa(new_rsa)?;

        let mut verifier = match self.alg {
            SigningAlg::Ps256 => {
                let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha256(), &pkey)?;
                verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?; // use C2PA recommended padding
                verifier.set_rsa_mgf1_md(MessageDigest::sha256())?;
                verifier
            }
            SigningAlg::Ps384 => {
                let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha384(), &pkey)?;
                verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?; // use C2PA recommended padding
                verifier.set_rsa_mgf1_md(MessageDigest::sha384())?;
                verifier
            }
            SigningAlg::Ps512 => {
                let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha512(), &pkey)?;
                verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?; // use C2PA recommended padding
                verifier.set_rsa_mgf1_md(MessageDigest::sha512())?;
                verifier
            }
            // "rs256" => openssl::sign::Verifier::new(MessageDigest::sha256(), &pkey)?,
            // "rs384" => openssl::sign::Verifier::new(MessageDigest::sha384(), &pkey)?,
            // "rs512" => openssl::sign::Verifier::new(MessageDigest::sha512(), &pkey)?,
            _ => return Err(Error::UnsupportedType),
        };

        verifier
            .verify_oneshot(sig, data)
            .map_err(|_err| Error::CoseSignature)
    }
}

pub struct RsaLegacyValidator {
    alg: String,
}

impl RsaLegacyValidator {
    pub fn new(alg: &str) -> Self {
        RsaLegacyValidator {
            alg: alg.to_string(),
        }
    }
}

impl CoseValidator for RsaLegacyValidator {
    fn validate(&self, sig: &[u8], data: &[u8], pkey: &[u8]) -> Result<bool> {
        let rsa = Rsa::public_key_from_der(pkey)?;

        // rebuild RSA keys to eliminate incompatible values
        let n = rsa.n().to_owned()?;
        let e = rsa.e().to_owned()?;

        let new_rsa = Rsa::from_public_components(n, e)?;

        let pkey = PKey::from_rsa(new_rsa)?;

        let mut verifier = match self.alg.as_ref() {
            "sha1" => openssl::sign::Verifier::new(MessageDigest::sha1(), &pkey)?,
            "rsa256" => openssl::sign::Verifier::new(MessageDigest::sha256(), &pkey)?,
            "rsa384" => openssl::sign::Verifier::new(MessageDigest::sha384(), &pkey)?,
            "rsa512" => openssl::sign::Verifier::new(MessageDigest::sha512(), &pkey)?,
            _ => return Err(Error::UnsupportedType),
        };

        verifier
            .verify_oneshot(sig, data)
            .map_err(|_err| Error::CoseSignature)
    }
}
