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
    hash::MessageDigest,
    pkey::PKey,
    rsa::{Padding, Rsa},
    sign::Verifier,
};

use crate::raw_signature::{
    openssl::OpenSslMutex, RawSignatureValidationError, RawSignatureValidator,
};

/// An `RsaValidator` can validate raw signatures with one of the RSA-PSS
/// signature algorithms.
#[non_exhaustive]
pub enum RsaValidator {
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    Ps256,

    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    Ps384,

    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    Ps512,
}

impl RawSignatureValidator for RsaValidator {
    fn validate(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        let _openssl = OpenSslMutex::acquire()?;
        let rsa = Rsa::public_key_from_der(public_key)?;

        // Rebuild RSA keys to eliminate incompatible values.
        let n = rsa.n().to_owned()?;
        let e = rsa.e().to_owned()?;

        let new_rsa = Rsa::from_public_components(n, e)?;
        let public_key = PKey::from_rsa(new_rsa)?;

        let mut verifier = match self {
            Self::Ps256 => {
                let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)?;
                verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
                verifier.set_rsa_mgf1_md(MessageDigest::sha256())?;
                verifier
            }

            Self::Ps384 => {
                let mut verifier = Verifier::new(MessageDigest::sha384(), &public_key)?;
                verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
                verifier.set_rsa_mgf1_md(MessageDigest::sha384())?;

                verifier
            }

            Self::Ps512 => {
                let mut verifier = Verifier::new(MessageDigest::sha512(), &public_key)?;
                verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
                verifier.set_rsa_mgf1_md(MessageDigest::sha512())?;
                verifier
            }
        };

        if verifier.verify_oneshot(sig, data)? {
            Ok(())
        } else {
            Err(RawSignatureValidationError::SignatureMismatch)
        }
    }
}
