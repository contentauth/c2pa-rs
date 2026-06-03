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

//! This module binds OpenSSL logic for generating raw signatures to this
//! crate's [`RawSigner`] trait.

use crate::{RawSigner, RawSignerError, SigningAlg};

mod ecdsa_signer;
mod ed25519_signer;
mod rsa_signer;

/// Returns a built-in [`RawSigner`] instance using using OpenSSL's
/// implementation of each of the supported encryption algorithms.
///
/// May return an `Err` response if the private key is invalid.
pub(crate) fn signer_from_private_key(
    private_key: &[u8],
    alg: SigningAlg,
) -> Result<Box<dyn RawSigner + Send + Sync>, RawSignerError> {
    match alg {
        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => Ok(Box::new(
            ecdsa_signer::EcdsaSigner::from_private_key(private_key, alg)?,
        )),

        SigningAlg::Ed25519 => Ok(Box::new(ed25519_signer::Ed25519Signer::from_private_key(
            private_key,
        )?)),

        SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512 => Ok(Box::new(
            rsa_signer::RsaSigner::from_private_key(private_key, alg)?,
        )),
    }
}
