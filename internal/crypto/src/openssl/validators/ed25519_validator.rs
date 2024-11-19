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

use openssl::{pkey::PKey, sign::Verifier};

use crate::{
    openssl::OpenSslMutex,
    raw_signature::{RawSignatureValidationError, RawSignatureValidator},
};

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
        let _openssl = OpenSslMutex::acquire()?;

        let public_key = PKey::public_key_from_der(public_key)?;

        if Verifier::new_without_digest(&public_key)?.verify_oneshot(sig, data)? {
            Ok(())
        } else {
            Err(RawSignatureValidationError::SignatureMismatch)
        }
    }
}
