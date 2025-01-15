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

use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use x509_parser::{prelude::FromDer, public_key::PublicKey, x509::SubjectPublicKeyInfo};

use crate::raw_signature::{RawSignatureValidationError, RawSignatureValidator};

/// An `Ed25519Validator` can validate raw signatures with the Ed25519 signature
/// algorithm.
pub struct Ed25519Validator {}

impl RawSignatureValidator for Ed25519Validator {
    fn validate(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        let (_, public_key) = SubjectPublicKeyInfo::from_der(&public_key)
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        let public_key = public_key
            .parsed()
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        let PublicKey::Unknown(public_key) = public_key else {
            return Err(RawSignatureValidationError::InvalidPublicKey);
        };

        if public_key.len() != PUBLIC_KEY_LENGTH {
            return Err(RawSignatureValidationError::InvalidPublicKey);
        }

        let mut public_key_slice: [u8; PUBLIC_KEY_LENGTH] = Default::default();
        public_key_slice.copy_from_slice(&public_key);

        let vk = VerifyingKey::from_bytes(&public_key_slice)
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        let ed_sig = Signature::from_slice(sig)
            .map_err(|_| RawSignatureValidationError::InvalidSignature)?;

        match vk.verify(&data, &ed_sig) {
            Ok(_) => Ok(()),
            Err(_) => Err(RawSignatureValidationError::SignatureMismatch),
        }
    }
}
