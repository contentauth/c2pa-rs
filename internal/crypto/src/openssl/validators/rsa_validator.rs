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

#[cfg(feature = "boringssl")]
use boring as openssl;
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rsa::{Padding, Rsa},
    sign::Verifier,
};

use crate::{
    openssl::OpenSslMutex,
    raw_signature::{RawSignatureValidationError, RawSignatureValidator},
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
        let rsa = match Rsa::public_key_from_der(public_key) {
            Ok(rsa) => rsa,
            #[cfg(not(feature = "boringssl"))]
            Err(err) => return Err(err.into()),
            #[cfg(feature = "boringssl")]
            Err(err) => {
                use boring::bn::BigNum;
                use pkcs8::der::asn1::BitStringRef;

                // BoringSSL can't parse RSA-PSS parameters. This doesn't matter, because
                // OpenSSL can't parse them either, and the C2PA SDK throws away
                // "incompatible values" anyway.

                // It's safe to ignore PSS parameters in signature verification:
                // - the digest algorithm can't be changed, because the same algorithm is used
                //   for the message digest.
                // - the mask parameter is always MGF1
                // - salt len defaults to hash output len, and the salt is never used directly,
                //   only hashed.
                //
                // They're checked in this implementation anyway.

                let pk = pkcs8::SubjectPublicKeyInfo::<pkcs1::RsaPssParams<'_>, BitStringRef<'_>>::try_from(public_key)
                    .ok()
                    .filter(|spki| {
                        // OID for RSASSA-PSS ASN.1
                        spki.algorithm.oid
                            == pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10")
                    })
                    .and_then(|spki| {
                        let pss = spki.algorithm.parameters?;
                        let required_salt_len = match self {
                            Self::Ps256 => 32,
                            Self::Ps384 => 48,
                            Self::Ps512 => 64,
                        };
                        // OID for MGF1 ASN.1
                        if pss.salt_len != required_salt_len || pss.mask_gen.oid != pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8") {
                            return None;
                        }
                        pkcs1::RsaPublicKey::try_from(spki.subject_public_key.raw_bytes()).ok()
                    })
                    .ok_or(err)?;

                let n = BigNum::from_slice(pk.modulus.as_bytes())?;
                let e = BigNum::from_slice(pk.public_exponent.as_bytes())?;
                Rsa::from_public_components(n, e)?
            }
        };

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
