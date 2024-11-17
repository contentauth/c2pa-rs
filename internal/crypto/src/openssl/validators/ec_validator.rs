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

use openssl::{
    bn::BigNum, ec::EcKey, ecdsa::EcdsaSig, hash::MessageDigest, pkey::PKey, sign::Verifier,
};

use crate::{
    openssl::OpenSslMutex,
    raw_signature::{RawSignatureValidationError, RawSignatureValidator},
};

/// An `EcValidator` can validate raw signatures with one of the ECDSA signature
/// algorithms.
pub enum EcValidator {
    /// ECDSA with SHA-256
    Es256,

    /// ECDSA with SHA-384
    Es384,

    /// ECDSA with SHA-512
    Es512,
}

impl RawSignatureValidator for EcValidator {
    fn validate(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        let _openssl = OpenSslMutex::acquire()?;

        let public_key = EcKey::public_key_from_der(public_key)?;
        let key = PKey::from_ec_key(public_key)?;

        let mut verifier = match self {
            Self::Es256 => Verifier::new(MessageDigest::sha256(), &key)?,
            Self::Es384 => Verifier::new(MessageDigest::sha384(), &key)?,
            Self::Es512 => Verifier::new(MessageDigest::sha512(), &key)?,
        };

        // We may need to convert a P1363 signature to a DER signature if the signature
        // matches one of the expected P1363 signature sizes.
        let is_p1363 = match self {
            Self::Es256 => sig.len() == 64,
            Self::Es384 => sig.len() == 96,
            Self::Es512 => sig.len() == 132,
        };

        let sig_der = if is_p1363 {
            // Convert P1363 signature to DER signature.
            let sig_len = sig.len() / 2;

            let r = BigNum::from_slice(&sig[0..sig_len])?;
            let s = BigNum::from_slice(&sig[sig_len..])?;
            EcdsaSig::from_private_components(r, s)?.to_der()?
        } else {
            sig.to_vec()
        };

        verifier.update(data)?;

        if verifier.verify(&sig_der)? {
            Ok(())
        } else {
            Err(RawSignatureValidationError::SignatureMismatch)
        }
    }
}
