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

use ed25519_dalek::{pkcs8::DecodePrivateKey, SigningKey};

use crate::{RawSigner, RawSignerError, SigningAlg};

/// Implements `RawSigner` trait using `ed25519_dalek` crate's implementation of
/// Edwards Curve encryption.
pub(crate) struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    pub(crate) fn from_private_key(private_key: &[u8]) -> Result<Self, RawSignerError> {
        let private_key_pem = std::str::from_utf8(private_key).map_err(|e| {
            RawSignerError::InvalidSigningCredentials(format!("invalid private key: {e}"))
        })?;

        let signing_key = SigningKey::from_pkcs8_pem(private_key_pem).map_err(|e| {
            RawSignerError::InvalidSigningCredentials(format!("invalid private key: {e}"))
        })?;

        Ok(Ed25519Signer { signing_key })
    }
}

impl RawSigner for Ed25519Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        use ed25519_dalek::Signer;

        Ok(self
            .signing_key
            .try_sign(data)
            .map_err(|e| RawSignerError::InternalError(format!("signature error: {e}")))?
            .to_vec())
    }

    fn alg(&self) -> SigningAlg {
        SigningAlg::Ed25519
    }

    /// An Ed25519 signature is always 64 bytes.
    fn max_signature_size(&self) -> usize {
        64
    }
}
