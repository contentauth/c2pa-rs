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
use spki::SubjectPublicKeyInfoRef;

use crate::{oids::ED25519_OID, RawSignatureValidationError, RawSignatureValidator};

/// Validates raw signatures with the Ed25519 signature algorithm.
pub(crate) struct Ed25519Validator {}

impl RawSignatureValidator for Ed25519Validator {
    fn validate(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        let spki = SubjectPublicKeyInfoRef::try_from(public_key)
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        if spki.algorithm.oid.as_bytes() != ED25519_OID.as_bytes() {
            return Err(RawSignatureValidationError::InvalidPublicKey);
        }

        let public_key = spki.subject_public_key.raw_bytes();
        if public_key.len() != PUBLIC_KEY_LENGTH {
            return Err(RawSignatureValidationError::InvalidPublicKey);
        }

        let mut public_key_slice: [u8; PUBLIC_KEY_LENGTH] = Default::default();
        public_key_slice.copy_from_slice(public_key);

        let vk = VerifyingKey::from_bytes(&public_key_slice)
            .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

        let ed_sig = Signature::from_slice(sig)
            .map_err(|_| RawSignatureValidationError::InvalidSignature)?;

        match vk.verify(data, &ed_sig) {
            Ok(_) => Ok(()),
            Err(_) => Err(RawSignatureValidationError::SignatureMismatch),
        }
    }
}
