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

use crate::crypto::raw_signature::{RawSigner, RawSignerError, SigningAlg};

mod ecdsa_signer;
mod ed25519_signer;
mod rsa_signer;

/// Return a built-in [`RawSigner`] instance using the provided signing
/// certificate and private key.
///
/// Which signers are available may vary depending on the platform and which
/// crate features were enabled.
///
/// Returns `None` if the signing algorithm is unsupported. May return an `Err`
/// response if the certificate chain or private key are invalid.
pub(crate) fn signer_from_cert_chain_and_private_key(
    cert_chain: &[u8],
    private_key: &[u8],
    alg: SigningAlg,
    time_stamp_service_url: Option<String>,
) -> Result<Box<dyn RawSigner + Send + Sync>, RawSignerError> {
    match alg {
        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => Ok(Box::new(
            ecdsa_signer::EcdsaSigner::from_cert_chain_and_private_key(
                cert_chain,
                private_key,
                alg,
                time_stamp_service_url,
            )?,
        )),

        SigningAlg::Ed25519 => Ok(Box::new(
            ed25519_signer::Ed25519Signer::from_cert_chain_and_private_key(
                cert_chain,
                private_key,
                time_stamp_service_url,
            )?,
        )),

        SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512 => Ok(Box::new(
            rsa_signer::RsaSigner::from_cert_chain_and_private_key(
                cert_chain,
                private_key,
                alg,
                time_stamp_service_url,
            )?,
        )),
    }
}
