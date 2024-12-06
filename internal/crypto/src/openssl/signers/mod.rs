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

use crate::{
    raw_signature::{RawSigner, RawSignerError},
    SigningAlg,
};

/// Return a built-in [`RawSigner`] instance using the provided signing
/// certificate and private key.
///
/// Which signers are available may vary depending on the platform and which
/// crate features were enabled.
///
/// Returns `None` if the signing algorithm is unsupported. May return an `Err`
/// response if the certificate chain or private key are invalid.
pub fn signer_from_cert_chain_and_private_key(
    _cert_chain: &[u8],
    _private_key: &[u8],
    _alg: SigningAlg,
) -> Option<Result<Box<dyn RawSigner>, RawSignerError>> {
    // TEMPORARY: None implemented yet.
    None
}
