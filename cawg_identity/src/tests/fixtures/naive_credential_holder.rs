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

use std::fmt::{Debug, Formatter};

use async_trait::async_trait;

use crate::{
    builder::CredentialHolder, identity_assertion::VerifiedIdentities, NamedActor,
    SignatureHandler, SignerPayload, ValidationError, ValidationResult, VerifiedIdentity,
};

pub(crate) struct NaiveCredentialHolder {}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl CredentialHolder for NaiveCredentialHolder {
    fn sig_type(&self) -> &'static str {
        "INVALID.identity.naive_credential"
    }

    fn reserve_size(&self) -> usize {
        1000
    }

    async fn sign(&self, signer_payload: &SignerPayload) -> c2pa::Result<Vec<u8>> {
        // Naive implementation simply serializes SignerPayload
        // in CBOR format and calls it a "signature."
        let mut result: Vec<u8> = vec![];

        match ciborium::into_writer(signer_payload, &mut result) {
            Ok(()) => Ok(result),
            Err(_) => Err(c2pa::Error::ClaimEncoding),
        }
    }
}

pub(crate) struct NaiveSignatureHandler {}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureHandler for NaiveSignatureHandler {
    fn can_handle_sig_type(sig_type: &str) -> bool {
        sig_type == "INVALID.identity.naive_credential"
    }

    async fn check_signature<'a>(
        &self,
        signer_payload: &SignerPayload,
        signature: &'a [u8],
    ) -> ValidationResult<Box<dyn NamedActor<'a>>> {
        let mut signer_payload_cbor: Vec<u8> = vec![];
        ciborium::into_writer(signer_payload, &mut signer_payload_cbor)
            .map_err(|_| ValidationError::UnexpectedError)?;

        if signer_payload_cbor != signature {
            Err(ValidationError::InvalidSignature)
        } else {
            Ok(Box::new(NaiveNamedActor {}))
        }
    }
}

pub(crate) struct NaiveNamedActor {}

impl<'a> NamedActor<'a> for NaiveNamedActor {
    fn display_name(&self) -> Option<String> {
        Some("Credential for internal testing purposes only".to_string())
    }

    fn is_trusted(&self) -> bool {
        false
    }

    fn verified_identities(&self) -> VerifiedIdentities {
        Box::new(NaiveVerifiedIdentities(self))
    }
}

impl Debug for NaiveNamedActor {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str("NaiveNamedActor (for internal testing purposes only)")
    }
}

#[allow(unused)] // .0 not necessarily referenced
pub(crate) struct NaiveVerifiedIdentities<'a>(&'a NaiveNamedActor);

impl<'a> Iterator for NaiveVerifiedIdentities<'a> {
    type Item = Box<&'a dyn VerifiedIdentity>;

    fn next(&mut self) -> Option<Box<&'a dyn VerifiedIdentity>> {
        None
    }
}
