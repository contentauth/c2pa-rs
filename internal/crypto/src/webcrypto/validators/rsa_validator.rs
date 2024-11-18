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
    pss::Signature,
    sha2::{Sha256, Sha384, Sha512},
    signature::Verifier,
    BigUint, RsaPublicKey,
};
use spki::SubjectPublicKeyInfoRef;
use x509_parser::der_parser::ber::{parse_ber_sequence, BerObject};

use crate::raw_signature::{RawSignatureValidationError, RawSignatureValidator};

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

        let (_, seq) = parse_ber_sequence(&spki.subject_public_key.raw_bytes())
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        let modulus = biguint_val(&seq[0]);
        let exp = biguint_val(&seq[1]);

        let public_key = RsaPublicKey::new(modulus, exp)
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        let result = match self {
            Self::Ps256 => {
                let vk = rsa::pss::VerifyingKey::<Sha256>::new(public_key);
                vk.verify(&data, &signature)
            }
            Self::Ps384 => {
                let vk = rsa::pss::VerifyingKey::<Sha384>::new(public_key);
                vk.verify(&data, &signature)
            }
            Self::Ps512 => {
                let vk = rsa::pss::VerifyingKey::<Sha512>::new(public_key);
                vk.verify(&data, &signature)
            }
        };

        result.map_err(|_| RawSignatureValidationError::SignatureMismatch)
    }
}

fn biguint_val(ber_object: &BerObject) -> BigUint {
    ber_object
        .as_biguint()
        .map(|x| x.to_u32_digits())
        .map(rsa::BigUint::new)
        .unwrap_or_default()
}
