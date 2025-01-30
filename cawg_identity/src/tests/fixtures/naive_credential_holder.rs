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

//! Naive implementation of credential-handling traits for
//! proof-of-concept/testing purposes.
//!
//! The "signature" in this example is simply the CBOR encoding
//! of the `signer_payload` struct. This is really intended to test
//! the signature mechanism, not to be a meaningful signature itself.
//!
//! Not suitable for production use.

use std::fmt::Debug;

use async_trait::async_trait;

use crate::{
    builder::{AsyncCredentialHolder, CredentialHolder, IdentityBuilderError},
    SignatureVerifier, SignerPayload, ValidationError,
};

pub(crate) struct NaiveCredentialHolder {}

impl CredentialHolder for NaiveCredentialHolder {
    fn sig_type(&self) -> &'static str {
        "INVALID.identity.naive_credential"
    }

    fn reserve_size(&self) -> usize {
        1000
    }

    fn sign(&self, signer_payload: &SignerPayload) -> Result<Vec<u8>, IdentityBuilderError> {
        // Naive implementation simply serializes SignerPayload
        // in CBOR format and calls it a "signature."
        let mut result: Vec<u8> = vec![];
        ciborium::into_writer(signer_payload, &mut result)?;
        Ok(result)
    }
}

#[derive(Debug)]
pub(crate) struct NaiveAsyncCredentialHolder {}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AsyncCredentialHolder for NaiveAsyncCredentialHolder {
    fn sig_type(&self) -> &'static str {
        "INVALID.identity.naive_credential"
    }

    fn reserve_size(&self) -> usize {
        1000
    }

    async fn sign(&self, signer_payload: &SignerPayload) -> Result<Vec<u8>, IdentityBuilderError> {
        // Naive implementation simply serializes SignerPayload
        // in CBOR format and calls it a "signature."
        let mut result: Vec<u8> = vec![];
        ciborium::into_writer(signer_payload, &mut result)?;
        Ok(result)
    }
}

pub(crate) struct NaiveSignatureVerifier {}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureVerifier for NaiveSignatureVerifier {
    type Error = ();
    type Output = ();

    async fn check_signature(
        &self,
        signer_payload: &SignerPayload,
        signature: &[u8],
    ) -> Result<Self::Output, ValidationError<Self::Error>> {
        let mut signer_payload_cbor: Vec<u8> = vec![];
        ciborium::into_writer(signer_payload, &mut signer_payload_cbor)
            .map_err(|_| ValidationError::InternalError("CBOR serialization error".to_string()))?;

        if signer_payload_cbor != signature {
            Err(ValidationError::InvalidSignature)
        } else {
            Ok(())
        }
    }
}
