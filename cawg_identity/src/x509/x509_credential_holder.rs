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

use c2pa_crypto::{
    cose::{sign, TimeStampStorage},
    raw_signature::RawSigner,
};

use crate::{
    builder::{CredentialHolder, IdentityBuilderError},
    SignerPayload,
};

/// An implementation of [`CredentialHolder`] that generates COSE signatures
/// using X.509 credentials as specified in [§8.2, X.509 certificates and COSE
/// signatures].
///
/// [`SignatureVerifier`]: crate::SignatureVerifier
/// [§8.2, X.509 certificates and COSE signatures]: https://cawg.io/identity/1.1-draft/#_x_509_certificates_and_cose_signatures
pub struct X509CredentialHolder(Box<dyn RawSigner + Sync + Send + 'static>);

impl X509CredentialHolder {
    /// Create an `X509CredentialHolder` instance by wrapping an instance of
    /// [`RawSigner`].
    ///
    /// The [`RawSigner`] implementation actually holds (or has access to)
    /// the relevant certificates and private key material.
    ///
    /// [`RawSigner`]: c2pa_crypto::raw_signature::RawSigner
    pub fn from_raw_signer(signer: Box<dyn RawSigner + Sync + Send + 'static>) -> Self {
        Self(signer)
    }
}

impl CredentialHolder for X509CredentialHolder {
    fn sig_type(&self) -> &'static str {
        super::CAWG_X509_SIG_TYPE
    }

    fn reserve_size(&self) -> usize {
        self.0.reserve_size()
    }

    fn sign(&self, signer_payload: &SignerPayload) -> Result<Vec<u8>, IdentityBuilderError> {
        // TO DO: Check signing cert (see signing_cert_valid in c2pa-rs's cose_sign).

        let mut sp_cbor: Vec<u8> = vec![];
        ciborium::into_writer(signer_payload, &mut sp_cbor)
            .map_err(|e| IdentityBuilderError::CborGenerationError(e.to_string()))?;

        sign(
            self.0.as_ref(),
            &sp_cbor,
            None,
            TimeStampStorage::V2_sigTst2_CTT,
        )
        .map_err(|e| IdentityBuilderError::SignerError(e.to_string()))
    }
}
