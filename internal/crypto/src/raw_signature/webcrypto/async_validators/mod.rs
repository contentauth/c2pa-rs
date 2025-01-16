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

use crate::raw_signature::{oids::*, AsyncRawSignatureValidator, SigningAlg};

/// Return an async validator for the given signing algorithm.
pub fn async_validator_for_signing_alg(
    alg: SigningAlg,
) -> Option<Box<dyn AsyncRawSignatureValidator>> {
    match alg {
        SigningAlg::Es256 => Some(Box::new(EcdsaValidator::Es256)),
        SigningAlg::Es384 => Some(Box::new(EcdsaValidator::Es384)),
        SigningAlg::Es512 => Some(Box::new(EcdsaValidator::Es512)),
        _ => None,
    }
}

/// Return a built-in async signature validator for the requested signature
/// algorithm as identified by OID.
pub(crate) fn async_validator_for_sig_and_hash_algs(
    sig_alg: &Oid,
    hash_alg: &Oid,
) -> Option<Box<dyn AsyncRawSignatureValidator>> {
    if sig_alg.as_ref() == EC_PUBLICKEY_OID.as_bytes()
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
    }

    None
}

pub(crate) mod ecdsa_validator;
use ecdsa_validator::EcdsaValidator;
