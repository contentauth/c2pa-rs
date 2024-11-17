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

use ecdsa::{signature::Verifier as EcdsaVerifier, Signature as EcdsaSignature};
use spki::DecodePublicKey;
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use p384::ecdsa::VerifyingKey as P384VerifyingKey;

use crate::raw_signature::{RawSignatureValidationError, RawSignatureValidator};

/// An `EcValidator` can validate raw signatures with one of the ECDSA signature
/// algorithms.
pub enum EcValidator {
    /// ECDSA with SHA-256
    Es256,

    /// ECDSA with SHA-384
    Es384,
    // ECDSA with SHA-512
    // Es512, // not yet implemented (check with Colin)
}

impl RawSignatureValidator for EcValidator {
    fn validate(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        let result = match self {
            Self::Es256 => {
                let vk = P256VerifyingKey::from_public_key_der(public_key)
                    .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

                let signature = EcdsaSignature::from_slice(sig)
                    .map_err(|_| RawSignatureValidationError::InvalidSignature)?;

                vk.verify(&data, &signature)
            }

            Self::Es384 => {
                let vk = P384VerifyingKey::from_public_key_der(public_key)
                    .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

                let signature = EcdsaSignature::from_slice(sig)
                    .map_err(|_| RawSignatureValidationError::InvalidSignature)?;

                vk.verify(&data, &signature)
            }
        };

        match result {
            Ok(_) => Ok(()),
            Err(err) => {
                web_sys::console::debug_2(
                    &"ECDSA validation failed:".into(),
                    &err.to_string().into(),
                );

                Err(RawSignatureValidationError::SignatureMismatch)
            }
        }
    }
}
