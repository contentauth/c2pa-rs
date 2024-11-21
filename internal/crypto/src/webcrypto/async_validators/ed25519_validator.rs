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

use async_trait::async_trait;

use crate::{
    raw_signature::{RawSignatureValidationError, RawSignatureValidator},
    webcrypto::AsyncRawSignatureValidator,
};

/// An `Ed25519Validator` can validate raw signatures with the Ed25519 signature
/// algorithm.
pub struct Ed25519Validator {}

#[async_trait]
impl AsyncRawSignatureValidator for Ed25519Validator {
    async fn validate_async(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        // Sync and async cases are identical for Ed25519.

        let sync_validator = crate::webcrypto::validators::Ed25519Validator {};
        sync_validator.validate(sig, data, public_key)
    }
}
