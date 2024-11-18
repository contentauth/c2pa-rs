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

//! This module binds OpenSSL logic for validating raw signatures to this
//! crate's [`RawSignatureValidator`] trait.

use crate::{raw_signature::RawSignatureValidator, SigningAlg};

mod ec_validator;
pub use ec_validator::EcValidator;

mod ed25519_validator;
pub use ed25519_validator::Ed25519Validator;

// mod rsa_validator;
// pub use rsa_validator::{RsaLegacyValidator, RsaValidator}; // ???

/// Return a validator for the given signing algorithm.
pub fn validator_for_signing_alg(alg: SigningAlg) -> Option<Box<dyn RawSignatureValidator>> {
    match alg {
        SigningAlg::Es256 => Some(Box::new(EcValidator::Es256)),
        SigningAlg::Es384 => Some(Box::new(EcValidator::Es384)),
        SigningAlg::Es512 => Some(Box::new(EcValidator::Es512)),
        SigningAlg::Ed25519 => Some(Box::new(Ed25519Validator {})),
        _ => unimplemented!(),
    }
}
