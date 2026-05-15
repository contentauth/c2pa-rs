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

use rsa::{
    pss::{Signature, VerifyingKey},
    sha2::{Sha256, Sha384, Sha512},
    signature::Verifier,
    BigUint, RsaPublicKey,
};
use spki::SubjectPublicKeyInfoRef;
use x509_parser::der_parser::ber::{parse_ber_sequence, BerObject};

use crate::crypto::raw_signature::{RawSignatureValidationError, RawSignatureValidator};

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
            Self::Ps256 => {
                let vk = VerifyingKey::<Sha256>::new(public_key);
                vk.verify(data, &signature)
            }
            Self::Ps384 => {
                let vk = VerifyingKey::<Sha384>::new(public_key);
                vk.verify(data, &signature)
            }
            Self::Ps512 => {
                let vk = VerifyingKey::<Sha512>::new(public_key);
                vk.verify(data, &signature)
            }
        };

        result.map_err(|_| RawSignatureValidationError::SignatureMismatch)
    }
}

pub(super) fn biguint_val(ber_object: &BerObject) -> BigUint {
    ber_object
        .as_biguint()
        .map(|x| x.to_u32_digits())
        .map(rsa::BigUint::new)
        .unwrap_or_default()
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

    // 512 zero bytes: accepted by rsa::pss::Signature::try_from (only empty slices are
    // rejected); content correctness is checked at verify time, after our guard fires.
    const DUMMY_SIG_512: &[u8] = &[0u8; 512];

    const SAMPLE_DATA: &[u8] = b"some sample content to sign";

    #[test]
    fn ps256_empty_sequence_public_key_rejected() {
        assert_eq!(
            RsaValidator::Ps256
                .validate(DUMMY_SIG_512, SAMPLE_DATA, RSA_SPKI_EMPTY_SEQUENCE)
                .unwrap_err(),
            RawSignatureValidationError::InvalidPublicKey
        );
    }

    #[test]
    fn ps256_single_element_sequence_public_key_rejected() {
        assert_eq!(
            RsaValidator::Ps256
                .validate(DUMMY_SIG_512, SAMPLE_DATA, RSA_SPKI_SINGLE_ELEMENT_SEQUENCE)
                .unwrap_err(),
            RawSignatureValidationError::InvalidPublicKey
        );
    }
}
