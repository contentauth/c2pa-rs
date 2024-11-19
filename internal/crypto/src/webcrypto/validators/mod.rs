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

//! This module binds [`SubtleCrypto`] logic for validating raw signatures to
//! this crate's [`RawSignatureValidator`] trait.

use bcder::Oid;

use crate::{
    raw_signature::{oids::*, RawSignatureValidator},
    SigningAlg,
};

mod ecdsa_validator;
pub use ecdsa_validator::EcdsaValidator;

mod ed25519_validator;
pub use ed25519_validator::Ed25519Validator;

mod rsa_legacy_validator;
pub(crate) use rsa_legacy_validator::RsaLegacyValidator;

mod rsa_validator;
pub use rsa_validator::RsaValidator;

/// Return a validator for the given signing algorithm.
pub fn validator_for_signing_alg(alg: SigningAlg) -> Option<Box<dyn RawSignatureValidator>> {
    match alg {
        SigningAlg::Es256 => Some(Box::new(EcdsaValidator::Es256)),
        SigningAlg::Es384 => Some(Box::new(EcdsaValidator::Es384)),
        SigningAlg::Es512 => None, /* why is this unimplemented? */
        SigningAlg::Ed25519 => Some(Box::new(Ed25519Validator {})),
        SigningAlg::Ps256 => Some(Box::new(RsaValidator::Ps256)),
        SigningAlg::Ps384 => Some(Box::new(RsaValidator::Ps384)),
        SigningAlg::Ps512 => Some(Box::new(RsaValidator::Ps512)),
    }
}

pub(crate) fn validator_for_sig_and_hash_algs(
    sig_alg: &Oid,
    hash_alg: &Oid,
) -> Option<Box<dyn RawSignatureValidator>> {
    if sig_alg.as_ref() == RSA_OID.as_bytes()
        || sig_alg.as_ref() == SHA256_WITH_RSAENCRYPTION_OID.as_bytes()
        || sig_alg.as_ref() == SHA384_WITH_RSAENCRYPTION_OID.as_bytes()
        || sig_alg.as_ref() == SHA512_WITH_RSAENCRYPTION_OID.as_bytes()
    {
        if hash_alg.as_ref() == SHA256_OID.as_bytes() {
            return Some(Box::new(RsaLegacyValidator::Rsa256));
        } else if hash_alg.as_ref() == SHA384_OID.as_bytes() {
            return Some(Box::new(RsaLegacyValidator::Rsa384));
        } else if hash_alg.as_ref() == SHA512_OID.as_bytes() {
            return Some(Box::new(RsaLegacyValidator::Rsa512));
        }
    }

    None
}
