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

#![allow(missing_docs)] // REMOVE once this becomes `pub(crate)`

use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Verifier};

use crate::{
    openssl::OpenSslMutex,
    raw_signature::{RawSignatureValidationError, RawSignatureValidator},
};

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
        pkey: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        let _openssl = OpenSslMutex::acquire()?;
        let rsa = Rsa::public_key_from_der(pkey)?;

        // Rebuild RSA keys to eliminate incompatible values.
        let n = rsa.n().to_owned()?;
        let e = rsa.e().to_owned()?;

        let new_rsa = Rsa::from_public_components(n, e)?;
        let public_key = PKey::from_rsa(new_rsa)?;

        let mut verifier = match self {
            Self::Sha1 => Verifier::new(MessageDigest::sha1(), &public_key)?,
            Self::Rsa256 => Verifier::new(MessageDigest::sha256(), &public_key)?,
            Self::Rsa384 => Verifier::new(MessageDigest::sha384(), &public_key)?,
            Self::Rsa512 => Verifier::new(MessageDigest::sha512(), &public_key)?,
        };

        if verifier.verify_oneshot(sig, data)? {
            Ok(())
        } else {
            Err(RawSignatureValidationError::SignatureMismatch)
        }
    }
}
