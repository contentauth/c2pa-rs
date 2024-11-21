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
use bcder::Oid;

use crate::{
    raw_signature::{oids::*, RawSignatureValidationError},
    SigningAlg,
};

/// An `AsyncRawSignatureValidator` implementation checks a signature encoded
/// using a specific signature algorithm and a private/public key pair.
///
/// IMPORTANT: This signature is typically embedded in a wrapper provided by
/// another signature mechanism. In the C2PA ecosystem, this wrapper is
/// typically COSE, but `AsyncRawSignatureValidator` does not implement COSE.
///
/// The WASM implementation of `c2pa-crypto` also implements
/// [`RawSignatureValidator`] (the synchronous version), but some encryption
/// algorithms are not fully supported. When possible, it's preferable to use
/// this implementation.
///
/// [`RawSignatureValidator`]: crate::raw_signature::RawSignatureValidator
#[async_trait]
pub trait AsyncRawSignatureValidator {
    /// Return `true` if the signature `sig` is valid for the raw content `data`
    /// and the public key `public_key`.
    async fn validate_async(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError>;
}

/// Return an async validator for the given signing and hash algorithm.
pub fn async_validator_for_signing_alg(
    alg: SigningAlg,
) -> Option<Box<dyn AsyncRawSignatureValidator>> {
    match alg {
        // SigningAlg::Es256 => Some(Box::new(EcdsaValidator::Es256)),
        // SigningAlg::Es384 => Some(Box::new(EcdsaValidator::Es384)),
        // SigningAlg::Es512 => Some(Box::new(EcdsaValidator::Es512)),
        SigningAlg::Ed25519 => Some(Box::new(Ed25519Validator {})),
        SigningAlg::Ps256 => Some(Box::new(RsaValidator::Ps256)),
        SigningAlg::Ps384 => Some(Box::new(RsaValidator::Ps384)),
        SigningAlg::Ps512 => Some(Box::new(RsaValidator::Ps512)),
        _ => unimplemented!(),
    }
}

/// Return a built-in async signature validator for the requested signature
/// algorithm as identified by OID.
///
/// TEMPORARILY PUBLIC: This will become `pub(crate)` once time stamp code moves
/// into c2pa-crypto.
pub fn async_validator_for_sig_and_hash_algs(
    sig_alg: &Oid,
    _hash_alg: &Oid,
) -> Option<Box<dyn AsyncRawSignatureValidator>> {
    if sig_alg.as_ref() == RSA_OID.as_bytes()
        || sig_alg.as_ref() == SHA256_WITH_RSAENCRYPTION_OID.as_bytes()
        || sig_alg.as_ref() == SHA384_WITH_RSAENCRYPTION_OID.as_bytes()
        || sig_alg.as_ref() == SHA512_WITH_RSAENCRYPTION_OID.as_bytes()
    {
        unimplemented!();
        // // TO REVIEW: Do we need any of the RSA-PSS algorithms for this use
        // case?

        // // Not sure yet if we'll need legacy validators for WASM.
        // #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
        // if let Some(validator) =
        //     crate::webcrypto::validators::validator_for_sig_and_hash_algs(sig_alg, hash_alg)
        // {
        //     return Some(validator);
        // }
    } else if sig_alg.as_ref() == EC_PUBLICKEY_OID.as_bytes()
        || sig_alg.as_ref() == ECDSA_WITH_SHA256_OID.as_bytes()
        || sig_alg.as_ref() == ECDSA_WITH_SHA384_OID.as_bytes()
        || sig_alg.as_ref() == ECDSA_WITH_SHA512_OID.as_bytes()
    {
        unimplemented!();
        // if hash_alg.as_ref() == SHA256_OID.as_bytes() {
        //     return validator_for_signing_alg(SigningAlg::Es256);
        // } else if hash_alg.as_ref() == SHA384_OID.as_bytes() {
        //     return validator_for_signing_alg(SigningAlg::Es384);
        // } else if hash_alg.as_ref() == SHA512_OID.as_bytes() {
        //     return validator_for_signing_alg(SigningAlg::Es512);
        // }
    } else if sig_alg.as_ref() == ED25519_OID.as_bytes() {
        return async_validator_for_signing_alg(SigningAlg::Ed25519);
    }

    None
}

pub(crate) mod ed25519_validator;
use ed25519_validator::Ed25519Validator;

pub(crate) mod rsa_validator;
use rsa_validator::RsaValidator;
