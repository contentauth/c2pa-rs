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

use async_trait::async_trait;

use crate::{
    raw_signature::{RawSignatureValidationError, RawSignatureValidator},
    webcrypto::AsyncRawSignatureValidator,
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

#[async_trait(?Send)]
impl AsyncRawSignatureValidator for RsaValidator {
    async fn validate_async(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        // Sync and async cases are identical for RSA.

        let sync_validator = match self {
            Self::Ps256 => crate::webcrypto::validators::RsaValidator::Ps256,
            Self::Ps384 => crate::webcrypto::validators::RsaValidator::Ps384,
            Self::Ps512 => crate::webcrypto::validators::RsaValidator::Ps512,
        };

        sync_validator.validate(sig, data, public_key)
    }
}
