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

use std::collections::HashSet;

use async_trait::async_trait;
use serde_bytes::ByteBuf;

use super::{CredentialHolder, IdentityBuilderError};
use crate::{
    dynamic_assertion::{
        AsyncDynamicAssertion, DynamicAssertion, DynamicAssertionContent, PartialClaim,
    },
    identity::{builder::AsyncCredentialHolder, IdentityAssertion, SignerPayload},
};

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
/// [`IdentityAssertionSigner`]: crate::identity::builder::IdentityAssertionSigner
pub struct IdentityAssertionBuilder {
    credential_holder: Box<dyn CredentialHolder + Sync + Send>,
    referenced_assertions: HashSet<String>,
    roles: Vec<String>,
}

impl IdentityAssertionBuilder {
    /// Create an `IdentityAssertionBuilder` for the given `CredentialHolder`
    /// instance.
    pub fn for_credential_holder<CH: CredentialHolder + 'static + Send + Sync>(
        credential_holder: CH,
    ) -> Self {
        Self {
            credential_holder: Box::new(credential_holder),
            referenced_assertions: HashSet::new(),
            roles: vec![],
        }
    }

    /// Add assertion labels to consider as referenced_assertions.
    ///
    /// If any of these labels match assertions that are present in the partial
    /// claim submitted during signing, they will be added to the
    /// `referenced_assertions` list for this identity assertion.
    pub fn add_referenced_assertions(&mut self, labels: &[&str]) {
        for label in labels {
            self.referenced_assertions.insert(label.to_string());
        }
    }

    /// Add roles to attach to the named actor for this identity assertion.
    ///
    /// See [§5.1.2, “Named actor roles,”] for more information.
    ///
    /// [§5.1.2, “Named actor roles,”]: https://cawg.io/identity/1.1-draft/#_named_actor_roles
    pub fn add_roles(&mut self, roles: &[&str]) {
        for role in roles {
            self.roles.push(role.to_string());
        }
    }
}

impl DynamicAssertion for IdentityAssertionBuilder {
    fn label(&self) -> String {
        "cawg.identity".to_string()
    }

    fn reserve_size(&self) -> crate::Result<usize> {
        Ok(self.credential_holder.reserve_size())
        // TO DO: Credential holder will state reserve size for signature.
        // Add additional size for CBOR wrapper outside signature.
    }

    fn content(
        &self,
        _label: &str,
        size: Option<usize>,
        claim: &PartialClaim,
    ) -> crate::Result<DynamicAssertionContent> {
        // TO DO: Update to respond correctly when identity assertions refer to each
        // other.
        let referenced_assertions = claim
            .assertions()
            .filter(|a| {
                // Always accept the hard binding assertion.
                if a.url().contains("c2pa.assertions/c2pa.hash.") {
                    return true;
                }

                let label = if let Some((_, label)) = a.url().rsplit_once('/') {
                    label.to_string()
                } else {
                    a.url()
                };

                self.referenced_assertions.contains(&label)
            })
            .cloned()
            .collect();

        let signer_payload = SignerPayload {
            referenced_assertions,
            sig_type: self.credential_holder.sig_type().to_owned(),
            roles: self.roles.clone(),
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
/// [`AsyncIdentityAssertionSigner`]: crate::identity::builder::AsyncIdentityAssertionSigner
pub struct AsyncIdentityAssertionBuilder {
    #[cfg(not(target_arch = "wasm32"))]
    credential_holder: Box<dyn AsyncCredentialHolder + Sync + Send>,

    #[cfg(target_arch = "wasm32")]
    credential_holder: Box<dyn AsyncCredentialHolder>,

    referenced_assertions: HashSet<String>,
    roles: Vec<String>,
}

impl AsyncIdentityAssertionBuilder {
    /// Create an `AsyncIdentityAssertionBuilder` for the given
    /// `AsyncCredentialHolder` instance.
    pub fn for_credential_holder<CH: AsyncCredentialHolder + 'static>(
        credential_holder: CH,
    ) -> Self {
        Self {
            credential_holder: Box::new(credential_holder),
            referenced_assertions: HashSet::new(),
            roles: vec![],
        }
    }

    /// Add assertion labels to consider as referenced_assertions.
    ///
    /// If any of these labels match assertions that are present in the partial
    /// claim submitted during signing, they will be added to the
    /// `referenced_assertions` list for this identity assertion.
    pub fn add_referenced_assertions(&mut self, labels: &[&str]) {
        for label in labels {
            self.referenced_assertions.insert(label.to_string());
        }
    }

    /// Add roles to attach to the named actor for this identity assertion.
    ///
    /// See [§5.1.2, “Named actor roles,”] for more information.
    ///
    /// [§5.1.2, “Named actor roles,”]: https://cawg.io/identity/1.1-draft/#_named_actor_roles
    pub fn add_roles(&mut self, roles: &[&str]) {
        for role in roles {
            self.roles.push(role.to_string());
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AsyncDynamicAssertion for AsyncIdentityAssertionBuilder {
    fn label(&self) -> String {
        "cawg.identity".to_string()
    }

    fn reserve_size(&self) -> crate::Result<usize> {
        Ok(self.credential_holder.reserve_size())
        // TO DO: Credential holder will state reserve size for signature.
        // Add additional size for CBOR wrapper outside signature.
    }

    async fn content(
        &self,
        _label: &str,
        size: Option<usize>,
        claim: &PartialClaim,
    ) -> crate::Result<DynamicAssertionContent> {
        // TO DO: Update to respond correctly when identity assertions refer to each
        // other.
        let referenced_assertions = claim
            .assertions()
            .filter(|a| {
                // Always accept the hard binding assertion.
                if a.url().contains("c2pa.assertions/c2pa.hash.") {
                    return true;
                }

                let label = if let Some((_, label)) = a.url().rsplit_once('/') {
                    label.to_string()
                } else {
                    a.url()
                };

                self.referenced_assertions.contains(&label)
            })
            .cloned()
            .collect();

        let signer_payload = SignerPayload {
            referenced_assertions,
            sig_type: self.credential_holder.sig_type().to_owned(),
            roles: self.roles.clone(),
        };

        let signature_result = self.credential_holder.sign(&signer_payload).await;

        finalize_identity_assertion(signer_payload, size, signature_result)
    }
}

fn finalize_identity_assertion(
    signer_payload: SignerPayload,
    size: Option<usize>,
    signature_result: Result<Vec<u8>, IdentityBuilderError>,
) -> crate::Result<DynamicAssertionContent> {
    // TO DO: Think through how errors map into crate::Error.
    let signature = signature_result.map_err(|e| crate::Error::BadParam(e.to_string()))?;

    let mut ia = IdentityAssertion {
        signer_payload,
        signature,
        pad1: vec![],
        pad2: None,
    };

    let mut assertion_cbor: Vec<u8> = vec![];
    ciborium::into_writer(&ia, &mut assertion_cbor)
        .map_err(|e| crate::Error::BadParam(e.to_string()))?;
    // TO DO: Think through how errors map into crate::Error.

    if let Some(assertion_size) = size {
        if assertion_cbor.len() > assertion_size {
            // TO DO: Think about how to signal this in such a way that
            // the AsyncCredentialHolder implementor understands the problem.
            return Err(crate::Error::BadParam(format!("Serialized assertion is {len} bytes, which exceeds the planned size of {assertion_size} bytes", len = assertion_cbor.len())));
        }

        ia.pad1 = vec![0u8; assertion_size - assertion_cbor.len() - 15];

        assertion_cbor.clear();
        ciborium::into_writer(&ia, &mut assertion_cbor)
            .map_err(|e| crate::Error::BadParam(e.to_string()))?;
        // TO DO: Think through how errors map into crate::Error.

        ia.pad2 = Some(ByteBuf::from(vec![
            0u8;
            assertion_size - assertion_cbor.len() - 6
        ]));

        assertion_cbor.clear();
        ciborium::into_writer(&ia, &mut assertion_cbor)
            .map_err(|e| crate::Error::BadParam(e.to_string()))?;
        // TO DO: Think through how errors map into crate::Error.

        // TO DO: See if this approach ever fails. IMHO it "should" work for all cases.
        assert_eq!(assertion_size, assertion_cbor.len());
    }

    Ok(DynamicAssertionContent::Cbor(assertion_cbor))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::{Cursor, Seek};

    use c2pa_status_tracker::StatusTracker;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::{
        identity::{
            builder::{
                AsyncIdentityAssertionBuilder, AsyncIdentityAssertionSigner,
                IdentityAssertionBuilder, IdentityAssertionSigner,
            },
            tests::fixtures::{
                manifest_json, parent_json, NaiveAsyncCredentialHolder, NaiveCredentialHolder,
                NaiveSignatureVerifier,
            },
            IdentityAssertion, ToCredentialSummary,
        },
        Builder, Reader, SigningAlg,
    };

    const TEST_IMAGE: &[u8] = include_bytes!("../../../tests/fixtures/CA.jpg");
    const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../tests/fixtures/thumbnail.jpg");

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    #[cfg_attr(target_os = "wasi", wstd::test)]
    async fn simple_case() {
        // NOTE: This needs to be async for now because the verification side is
        // async-only.

        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::from_json(&manifest_json()).unwrap();
        builder
            .add_ingredient_from_stream(parent_json(), format, &mut source)
            .unwrap();

        builder
            .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
            .unwrap();

        let mut signer = IdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

        let nch = NaiveCredentialHolder {};
        let iab = IdentityAssertionBuilder::for_credential_holder(nch);
        signer.add_identity_assertion(iab);

        builder
            .sign(&signer, format, &mut source, &mut dest)
            .unwrap();

        // Read back the Manifest that was generated.
        dest.rewind().unwrap();

        let manifest_store = Reader::from_stream(format, &mut dest).unwrap();
        assert_eq!(manifest_store.validation_status(), None);

        let manifest = manifest_store.active_manifest().unwrap();
        let mut st = StatusTracker::default();
        let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

        // Should find exactly one identity assertion.
        let ia = ia_iter.next().unwrap().unwrap();
        assert!(ia_iter.next().is_none());
        drop(ia_iter);

        // And that identity assertion should be valid for this manifest.
        let nsv = NaiveSignatureVerifier {};
        let naive_credential = ia.validate(manifest, &mut st, &nsv).await.unwrap();

        let nc_summary = naive_credential.to_summary();
        let nc_json = serde_json::to_string(&nc_summary).unwrap();
        assert_eq!(nc_json, "{}");
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    #[cfg_attr(target_os = "wasi", wstd::test)]
    async fn simple_case_async() {
        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::from_json(&manifest_json()).unwrap();
        builder
            .add_ingredient_from_stream(parent_json(), format, &mut source)
            .unwrap();

        builder
            .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
            .unwrap();

        let mut signer = AsyncIdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

        let nch = NaiveAsyncCredentialHolder {};
        let iab = AsyncIdentityAssertionBuilder::for_credential_holder(nch);
        signer.add_identity_assertion(iab);

        builder
            .sign_async(&signer, format, &mut source, &mut dest)
            .await
            .unwrap();

        // Read back the Manifest that was generated.
        dest.rewind().unwrap();

        let manifest_store = Reader::from_stream(format, &mut dest).unwrap();
        assert_eq!(manifest_store.validation_status(), None);

        let manifest = manifest_store.active_manifest().unwrap();
        let mut st = StatusTracker::default();
        let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

        // Should find exactly one identity assertion.
        let ia = ia_iter.next().unwrap().unwrap();
        assert!(ia_iter.next().is_none());
        drop(ia_iter);

        // And that identity assertion should be valid for this manifest.
        let nsv = NaiveSignatureVerifier {};
        let naive_credential = ia.validate(manifest, &mut st, &nsv).await.unwrap();

        let nc_summary = naive_credential.to_summary();
        let nc_json = serde_json::to_string(&nc_summary).unwrap();
        assert_eq!(nc_json, "{}");
    }
}
