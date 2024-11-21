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

/// An `RsaLegacyValidator` can validate raw signatures with an RSA signature
/// algorithm that is not supported directly by C2PA. (Some RFC 3161 time stamp
/// providers issue these signatures, which is why it's supported here.)
pub(crate) enum RsaLegacyValidator {
    Rsa256,
    Rsa384,
    Rsa512,
}

#[async_trait]
impl AsyncRawSignatureValidator for RsaLegacyValidator {
    async fn validate_async(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        // Sync and async cases are identical for RSA.

        let sync_validator = match self {
            Self::Rsa256 => crate::webcrypto::validators::RsaLegacyValidator::Rsa256,
            Self::Rsa384 => crate::webcrypto::validators::RsaLegacyValidator::Rsa384,
            Self::Rsa512 => crate::webcrypto::validators::RsaLegacyValidator::Rsa512,
        };

        sync_validator.validate(sig, data, public_key)
    }
}
