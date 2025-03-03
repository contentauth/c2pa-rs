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
use c2pa::{AsyncDynamicAssertion, DynamicAssertion, DynamicAssertionContent, PreliminaryClaim};
use serde_bytes::ByteBuf;

use super::{CredentialHolder, IdentityBuilderError};
use crate::{builder::AsyncCredentialHolder, IdentityAssertion, SignerPayload};

/// An `IdentityAssertionBuilder` gathers together the necessary components
/// for an identity assertion. When added to an [`IdentityAssertionSigner`],
/// it ensures that the proper data is added to the final C2PA Manifest.
///
/// Use this when the overall C2PA Manifest signing path is synchronous.
/// Note that this may limit the available set of credential holders.
///
/// Prefer [`AsyncIdentityAssertionBuilder`] when the C2PA Manifest signing
/// path is asynchronous or any network calls will be made by the
/// [`CredentialHolder`] implementation.
///
/// [`IdentityAssertionSigner`]: crate::builder::IdentityAssertionSigner
pub struct IdentityAssertionBuilder {
    credential_holder: Box<dyn CredentialHolder>,
    // referenced_assertions: Vec<MumbleSomething>,
}

impl IdentityAssertionBuilder {
    /// Create an `IdentityAssertionBuilder` for the given `CredentialHolder`
    /// instance.
    pub fn for_credential_holder<CH: CredentialHolder + 'static>(credential_holder: CH) -> Self {
        Self {
            credential_holder: Box::new(credential_holder),
        }
    }
}

impl DynamicAssertion for IdentityAssertionBuilder {
    fn label(&self) -> String {
        "cawg.identity".to_string()
    }

    fn reserve_size(&self) -> c2pa::Result<usize> {
        Ok(self.credential_holder.reserve_size())
        // TO DO: Credential holder will state reserve size for signature.
        // Add additional size for CBOR wrapper outside signature.
    }

    fn content(
        &self,
        _label: &str,
        size: Option<usize>,
        claim: &PreliminaryClaim,
    ) -> c2pa::Result<DynamicAssertionContent> {
        // TO DO: Better filter for referenced assertions.
        // For now, just require hard binding.

        // TO DO: Update to respond correctly when identity assertions refer to each
        // other.
        let referenced_assertions = claim
            .assertions()
            .filter(|a| a.url().contains("c2pa.assertions/c2pa.hash."))
            .cloned()
            .collect();

        let signer_payload = SignerPayload {
            referenced_assertions,
            sig_type: self.credential_holder.sig_type().to_owned(),
        };

        let signature_result = self.credential_holder.sign(&signer_payload);

        finalize_identity_assertion(signer_payload, size, signature_result)
    }
}

/// An `AsyncIdentityAssertionBuilder` gathers together the necessary components
/// for an identity assertion. When added to an
/// [`AsyncIdentityAssertionSigner`], it ensures that the proper data is added
/// to the final C2PA Manifest.
///
/// Use this when the overall C2PA Manifest signing path is asynchronous.
///
/// [`AsyncIdentityAssertionSigner`]: crate::builder::AsyncIdentityAssertionSigner
pub struct AsyncIdentityAssertionBuilder {
    #[cfg(not(target_arch = "wasm32"))]
    credential_holder: Box<dyn AsyncCredentialHolder + Sync + Send>,

    #[cfg(target_arch = "wasm32")]
    credential_holder: Box<dyn AsyncCredentialHolder>,
    // referenced_assertions: Vec<MumbleSomething>,
}

impl AsyncIdentityAssertionBuilder {
    /// Create an `AsyncIdentityAssertionBuilder` for the given
    /// `AsyncCredentialHolder` instance.
    pub fn for_credential_holder<CH: AsyncCredentialHolder + 'static>(
        credential_holder: CH,
    ) -> Self {
        Self {
            credential_holder: Box::new(credential_holder),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AsyncDynamicAssertion for AsyncIdentityAssertionBuilder {
    fn label(&self) -> String {
        "cawg.identity".to_string()
    }

    fn reserve_size(&self) -> c2pa::Result<usize> {
        Ok(self.credential_holder.reserve_size())
        // TO DO: Credential holder will state reserve size for signature.
        // Add additional size for CBOR wrapper outside signature.
    }

    async fn content(
        &self,
        _label: &str,
        size: Option<usize>,
        claim: &PreliminaryClaim,
    ) -> c2pa::Result<DynamicAssertionContent> {
        // TO DO: Better filter for referenced assertions.
        // For now, just require hard binding.

        // TO DO: Update to respond correctly when identity assertions refer to each
        // other.
        let referenced_assertions = claim
            .assertions()
            .filter(|a| a.url().contains("c2pa.assertions/c2pa.hash."))
            .cloned()
            .collect();

        let signer_payload = SignerPayload {
            referenced_assertions,
            sig_type: self.credential_holder.sig_type().to_owned(),
        };

        let signature_result = self.credential_holder.sign(&signer_payload).await;

        finalize_identity_assertion(signer_payload, size, signature_result)
    }
}

fn finalize_identity_assertion(
    signer_payload: SignerPayload,
    size: Option<usize>,
    signature_result: Result<Vec<u8>, IdentityBuilderError>,
) -> c2pa::Result<DynamicAssertionContent> {
    // TO DO: Think through how errors map into c2pa::Error.
    let signature = signature_result.map_err(|e| c2pa::Error::BadParam(e.to_string()))?;

    let mut ia = IdentityAssertion {
        signer_payload,
        signature,
        pad1: vec![],
        pad2: None,
    };

    let mut assertion_cbor: Vec<u8> = vec![];
    ciborium::into_writer(&ia, &mut assertion_cbor)
        .map_err(|e| c2pa::Error::BadParam(e.to_string()))?;
    // TO DO: Think through how errors map into c2pa::Error.

    if let Some(assertion_size) = size {
        if assertion_cbor.len() > assertion_size {
            // TO DO: Think about how to signal this in such a way that
            // the AsyncCredentialHolder implementor understands the problem.
            return Err(c2pa::Error::BadParam(format!("Serialized assertion is {len} bytes, which exceeds the planned size of {assertion_size} bytes", len = assertion_cbor.len())));
        }

        ia.pad1 = vec![0u8; assertion_size - assertion_cbor.len() - 15];

        assertion_cbor.clear();
        ciborium::into_writer(&ia, &mut assertion_cbor)
            .map_err(|e| c2pa::Error::BadParam(e.to_string()))?;
        // TO DO: Think through how errors map into c2pa::Error.

        ia.pad2 = Some(ByteBuf::from(vec![
            0u8;
            assertion_size - assertion_cbor.len() - 6
        ]));

        assertion_cbor.clear();
        ciborium::into_writer(&ia, &mut assertion_cbor)
            .map_err(|e| c2pa::Error::BadParam(e.to_string()))?;
        // TO DO: Think through how errors map into c2pa::Error.

        // TO DO: See if this approach ever fails. IMHO it "should" work for all cases.
        assert_eq!(assertion_size, assertion_cbor.len());
    }

    Ok(DynamicAssertionContent::Cbor(assertion_cbor))
}
