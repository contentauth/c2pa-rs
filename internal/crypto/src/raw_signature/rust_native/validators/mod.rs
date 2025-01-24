// Copyright 2025 Adobe. All rights reserved.
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

//! This module binds Rust native logic for generating raw signatures to this
//! crate's [`RawSignatureValidator`] trait.

use async_trait::async_trait;
use bcder::Oid;

use crate::raw_signature::{
    oids::*, AsyncRawSignatureValidator, RawSignatureValidationError, RawSignatureValidator,
    SigningAlg,
};

mod ecdsa_validator;
pub(crate) use ecdsa_validator::EcdsaValidator;

mod ed25519_validator;
pub(crate) use ed25519_validator::Ed25519Validator;

mod rsa_legacy_validator;
pub(crate) use rsa_legacy_validator::RsaLegacyValidator;

mod rsa_validator;
pub(crate) use rsa_validator::RsaValidator;

struct AsyncRawSignatureValidatorAdapter {
    validator: Box<Box<dyn RawSignatureValidator>>,
}

impl AsyncRawSignatureValidatorAdapter {
    fn new(validator: Box<Box<dyn RawSignatureValidator>>) -> Self {
        Self { validator }
    }
}

#[async_trait(?Send)]
impl AsyncRawSignatureValidator for AsyncRawSignatureValidatorAdapter {
    async fn validate_async(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        self.validator.validate(sig, data, public_key)
    }
}

/// Return an async validator for the given signing algorithm.
pub(crate) fn async_validator_for_signing_alg(
    alg: SigningAlg,
) -> Option<Box<dyn AsyncRawSignatureValidator>> {
    let validator = validator_for_signing_alg(alg)?;

    Some(Box::new(AsyncRawSignatureValidatorAdapter::new(
        validator.into(),
    )))
}

/// Return a built-in async signature validator for the requested signature
/// algorithm as identified by OID.
pub(crate) fn async_validator_for_sig_and_hash_algs(
    sig_alg: &Oid,
    hash_alg_or_curve: &Oid,
) -> Option<Box<dyn AsyncRawSignatureValidator>> {
    let validator = validator_for_sig_and_hash_algs(sig_alg, hash_alg_or_curve)?;

    Some(Box::new(AsyncRawSignatureValidatorAdapter::new(
        validator.into(),
    )))
}

/// Return a validator for the given signing algorithm.
pub fn validator_for_signing_alg(alg: SigningAlg) -> Option<Box<dyn RawSignatureValidator>> {
    match alg {
        SigningAlg::Ed25519 => Some(Box::new(Ed25519Validator {})),
        SigningAlg::Ps256 => Some(Box::new(RsaValidator::Ps256)),
        SigningAlg::Ps384 => Some(Box::new(RsaValidator::Ps384)),
        SigningAlg::Ps512 => Some(Box::new(RsaValidator::Ps512)),
        SigningAlg::Es256 => Some(Box::new(EcdsaValidator::Es256)),
        SigningAlg::Es384 => Some(Box::new(EcdsaValidator::Es384)),
        SigningAlg::Es512 => Some(Box::new(EcdsaValidator::Es512)),
        _ => None,
    }
}

/// Select validator based on signing algorithm and hash type or EC curve.
pub(crate) fn validator_for_sig_and_hash_algs(
    sig_alg: &Oid,
    hash_alg_or_curve: &Oid,
) -> Option<Box<dyn RawSignatureValidator>> {
    // Handle legacy RSA.
    if sig_alg.as_ref() == RSA_OID.as_bytes() {
        if hash_alg_or_curve.as_ref() == SHA256_OID.as_bytes() {
            return Some(Box::new(RsaLegacyValidator::Rsa256));
        } else if hash_alg_or_curve.as_ref() == SHA384_OID.as_bytes() {
            return Some(Box::new(RsaLegacyValidator::Rsa384));
        } else if hash_alg_or_curve.as_ref() == SHA512_OID.as_bytes() {
            return Some(Box::new(RsaLegacyValidator::Rsa512));
        }
    }

    // Handle RSS-PSS.
    if sig_alg.as_ref() == RSA_PSS_OID.as_bytes() {
        if hash_alg_or_curve.as_ref() == SHA256_WITH_RSAENCRYPTION_OID.as_bytes() {
            return Some(Box::new(RsaValidator::Ps256));
        } else if hash_alg_or_curve.as_ref() == SHA384_WITH_RSAENCRYPTION_OID.as_bytes() {
            return Some(Box::new(RsaValidator::Ps384));
        } else if hash_alg_or_curve.as_ref() == SHA512_WITH_RSAENCRYPTION_OID.as_bytes() {
            return Some(Box::new(RsaValidator::Ps512));
        }
    }

    // Handle elliptical curve and hash combinations.
    if sig_alg.as_ref() == ECDSA_WITH_SHA256_OID.as_bytes() {
        return Some(Box::new(EcdsaValidator::Es256));
    } else if sig_alg.as_ref() == ECDSA_WITH_SHA384_OID.as_bytes() {
        return Some(Box::new(EcdsaValidator::Es384));
    } else if sig_alg.as_ref() == ECDSA_WITH_SHA512_OID.as_bytes() {
        return Some(Box::new(EcdsaValidator::Es512));
    }

    // Handle ED25519.
    if sig_alg.as_ref() == ED25519_OID.as_bytes() {
        return Some(Box::new(Ed25519Validator {}));
    }

    None
}
