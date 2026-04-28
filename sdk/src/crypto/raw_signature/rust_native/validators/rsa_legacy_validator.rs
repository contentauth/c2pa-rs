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

use rsa::{
    pkcs1v15::{Signature, VerifyingKey},
    sha2::{Sha256, Sha384, Sha512},
    signature::Verifier,
    RsaPublicKey,
};
use spki::SubjectPublicKeyInfoRef;
use x509_parser::der_parser::ber::parse_ber_sequence;

use super::rsa_validator::biguint_val;
use crate::crypto::raw_signature::{RawSignatureValidationError, RawSignatureValidator};

/// An `RsaLegacyValidator` can validate raw signatures with an RSA signature
/// algorithm that is not supported directly by C2PA. (Some RFC 3161 time stamp
/// providers issue these signatures, which is why it's supported here.)
pub(crate) enum RsaLegacyValidator {
    Rsa256,
    Rsa384,
    Rsa512,
}

impl RawSignatureValidator for RsaLegacyValidator {
    fn validate(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        let signature: Signature = sig
            .try_into()
            .map_err(|_| RawSignatureValidationError::InvalidSignature)?;

        let spki = SubjectPublicKeyInfoRef::try_from(public_key)
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        let (_, seq) = parse_ber_sequence(spki.subject_public_key.raw_bytes())
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        let seq_items = seq
            .as_sequence()
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;
        if seq_items.len() < 2 {
            return Err(RawSignatureValidationError::InvalidPublicKey);
        }

        let modulus = biguint_val(&seq_items[0]);
        let exp = biguint_val(&seq_items[1]);

        let public_key = RsaPublicKey::new(modulus, exp)
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        let result = match self {
            Self::Rsa256 => {
                let vk = VerifyingKey::<Sha256>::new(public_key);
                vk.verify(data, &signature)
            }

            Self::Rsa384 => {
                let vk = VerifyingKey::<Sha384>::new(public_key);
                vk.verify(data, &signature)
            }

            Self::Rsa512 => {
                let vk = VerifyingKey::<Sha512>::new(public_key);
                vk.verify(data, &signature)
            }
        };

        result.map_err(|_| RawSignatureValidationError::SignatureMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::raw_signature::RawSignatureValidator;

    // SPKI DER with rsaEncryption OID and an empty inner BER SEQUENCE.
    // parse_ber_sequence succeeds (valid BER) but the guard rejects it because
    // fewer than 2 elements (modulus + exponent) are present.
    const RSA_SPKI_EMPTY_SEQUENCE: &[u8] = &[
        0x30, 0x14, // SEQUENCE (20 bytes)
        0x30, 0x0d, // AlgorithmIdentifier (13 bytes)
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // OID rsaEncryption
        0x05, 0x00, // NULL parameters
        0x03, 0x03, // BIT STRING (3 bytes)
        0x00, // 0 unused bits
        0x30, 0x00, // inner SEQUENCE — empty
    ];

    // Same structure but with one INTEGER only (modulus present, exponent missing).
    const RSA_SPKI_SINGLE_ELEMENT_SEQUENCE: &[u8] = &[
        0x30, 0x17, // SEQUENCE (23 bytes)
        0x30, 0x0d, // AlgorithmIdentifier (13 bytes)
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // OID rsaEncryption
        0x05, 0x00, // NULL parameters
        0x03, 0x06, // BIT STRING (6 bytes)
        0x00, // 0 unused bits
        0x30, 0x03, // inner SEQUENCE (3 bytes, 1 element)
        0x02, 0x01, 0x01, // INTEGER value 1 (modulus only)
    ];

    // 512 zero bytes: accepted by rsa::pkcs1v15::Signature::try_from (only empty slices
    // are rejected); content correctness is checked at verify time, after our guard fires.
    const DUMMY_SIG_512: &[u8] = &[0u8; 512];

    const SAMPLE_DATA: &[u8] = b"some sample content to sign";

    #[test]
    fn rsa256_empty_sequence_public_key_rejected() {
        assert_eq!(
            RsaLegacyValidator::Rsa256
                .validate(DUMMY_SIG_512, SAMPLE_DATA, RSA_SPKI_EMPTY_SEQUENCE)
                .unwrap_err(),
            RawSignatureValidationError::InvalidPublicKey
        );
    }

    #[test]
    fn rsa256_single_element_sequence_public_key_rejected() {
        assert_eq!(
            RsaLegacyValidator::Rsa256
                .validate(DUMMY_SIG_512, SAMPLE_DATA, RSA_SPKI_SINGLE_ELEMENT_SEQUENCE)
                .unwrap_err(),
            RawSignatureValidationError::InvalidPublicKey
        );
    }
}
