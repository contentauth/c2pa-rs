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
use x509_parser::der_parser::ber::{parse_ber_sequence /* BerObject */};

use super::rsa_validator::biguint_val;
use crate::raw_signature::{RawSignatureValidationError, RawSignatureValidator};

/// An `RsaLegacyValidator` can validate raw signatures with an RSA signature
/// algorithm that is not supported directly by C2PA. (Some RFC 3161 time stamp
/// providers issue these signatures, which is why it's supported here.)
pub(crate) enum RsaLegacyValidator {
    Sha1,
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

        let (_, seq) = parse_ber_sequence(&spki.subject_public_key.raw_bytes())
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        let modulus = biguint_val(&seq[0]);
        let exp = biguint_val(&seq[1]);

        let public_key = RsaPublicKey::new(modulus, exp)
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        let result = match self {
            Self::Sha1 => {
                unimplemented!();
            }

            Self::Rsa256 => {
                let vk = VerifyingKey::<Sha256>::new(public_key);
                vk.verify(&data, &signature)
            }

            Self::Rsa384 => {
                let vk = VerifyingKey::<Sha384>::new(public_key);
                vk.verify(&data, &signature)
            }

            Self::Rsa512 => {
                let vk = VerifyingKey::<Sha512>::new(public_key);
                vk.verify(&data, &signature)
            }
        };

        result.map_err(|_| RawSignatureValidationError::SignatureMismatch)
    }
}
