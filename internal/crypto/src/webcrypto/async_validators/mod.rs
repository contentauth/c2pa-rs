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

use bcder::Oid;

use crate::{
    raw_signature::{oids::*, AsyncRawSignatureValidator},
    SigningAlg,
};

/// Return an async validator for the given signing algorithm.
pub fn async_validator_for_signing_alg(
    alg: SigningAlg,
) -> Option<Box<dyn AsyncRawSignatureValidator>> {
    match alg {
        SigningAlg::Es256 => Some(Box::new(EcdsaValidator::Es256)),
        SigningAlg::Es384 => Some(Box::new(EcdsaValidator::Es384)),
        SigningAlg::Es512 => Some(Box::new(EcdsaValidator::Es512)),
        SigningAlg::Ed25519 => Some(Box::new(Ed25519Validator {})),
        SigningAlg::Ps256 => Some(Box::new(RsaValidator::Ps256)),
        SigningAlg::Ps384 => Some(Box::new(RsaValidator::Ps384)),
        SigningAlg::Ps512 => Some(Box::new(RsaValidator::Ps512)),
    }
}

/// Return a built-in async signature validator for the requested signature
/// algorithm as identified by OID.
///
/// TEMPORARILY PUBLIC: This will become `pub(crate)` once time stamp code moves
/// into c2pa-crypto.
pub fn async_validator_for_sig_and_hash_algs(
    sig_alg: &Oid,
    hash_alg: &Oid,
) -> Option<Box<dyn AsyncRawSignatureValidator>> {
    if sig_alg.as_ref() == RSA_OID.as_bytes()
        || sig_alg.as_ref() == SHA256_WITH_RSAENCRYPTION_OID.as_bytes()
        || sig_alg.as_ref() == SHA384_WITH_RSAENCRYPTION_OID.as_bytes()
        || sig_alg.as_ref() == SHA512_WITH_RSAENCRYPTION_OID.as_bytes()
    {
        if hash_alg.as_ref() == SHA1_OID.as_bytes() {
            return None; // not supported
        } else if hash_alg.as_ref() == SHA256_OID.as_bytes() {
            return Some(Box::new(RsaLegacyValidator::Rsa256));
        } else if hash_alg.as_ref() == SHA384_OID.as_bytes() {
            return Some(Box::new(RsaLegacyValidator::Rsa384));
        } else if hash_alg.as_ref() == SHA512_OID.as_bytes() {
            return Some(Box::new(RsaLegacyValidator::Rsa512));
        }
    } else if sig_alg.as_ref() == EC_PUBLICKEY_OID.as_bytes()
        || sig_alg.as_ref() == ECDSA_WITH_SHA256_OID.as_bytes()
        || sig_alg.as_ref() == ECDSA_WITH_SHA384_OID.as_bytes()
        || sig_alg.as_ref() == ECDSA_WITH_SHA512_OID.as_bytes()
    {
        if hash_alg.as_ref() == SHA256_OID.as_bytes() {
            return async_validator_for_signing_alg(SigningAlg::Es256);
        } else if hash_alg.as_ref() == SHA384_OID.as_bytes() {
            return async_validator_for_signing_alg(SigningAlg::Es384);
        } else if hash_alg.as_ref() == SHA512_OID.as_bytes() {
            return async_validator_for_signing_alg(SigningAlg::Es512);
        }
    } else if sig_alg.as_ref() == ED25519_OID.as_bytes() {
        return async_validator_for_signing_alg(SigningAlg::Ed25519);
    }

    None
}

pub(crate) mod ecdsa_validator;
use ecdsa_validator::EcdsaValidator;

pub(crate) mod ed25519_validator;
use ed25519_validator::Ed25519Validator;

pub(crate) mod rsa_legacy_validator;
use rsa_legacy_validator::RsaLegacyValidator;

pub(crate) mod rsa_validator;
use rsa_validator::RsaValidator;
