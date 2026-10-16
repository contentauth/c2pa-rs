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

use std::{collections::HashSet, sync::Arc};

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
    /// Maximum signature length that fits the complete assertion reservation.
    ///
    /// Accounts for the actual signer payload and CBOR byte-string headers.
    /// The payload is only known at content-generation time; `reserve_size`
    /// on a credential holder reserves the entire assertion, not just its signature.
    pub fn signature_capacity(
        signer_payload: &SignerPayload,
        assertion_size: usize,
    ) -> crate::Result<usize> {
        if assertion_size > isize::MAX as usize {
            return Err(crate::Error::BadParam(
                "identity assertion reservation exceeds addressable size".into(),
            ));
        }
        let assertion = IdentityAssertion {
            signer_payload: signer_payload.clone(),
            signature: vec![],
            pad1: vec![],
            pad2: None,
            label: None,
        };
        let base_size = c2pa_cbor::to_vec(&assertion)?.len();
        let empty_header = c2pa_cbor::to_vec(&0usize)?.len();
        let encoded_budget = assertion_size
            .checked_sub(base_size)
            .and_then(|remaining| remaining.checked_add(empty_header))
            .ok_or_else(|| {
                crate::Error::BadParam(
                    "identity assertion reservation cannot fit the signer payload".into(),
                )
            })?;
        max_byte_string_payload(encoded_budget)
    }

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

        if let Some(size) = size {
            Self::signature_capacity(&signer_payload, size)?;
        }
        let signature_result = self.credential_holder.sign(&signer_payload);

        finalize_identity_assertion(signer_payload, size, signature_result)
    }
}

/// Allows an [`IdentityAssertionSigner`] to hand out shared clones of a single
/// [`IdentityAssertionBuilder`] each time [`dynamic_assertions()`] is called,
/// so that the same builder can service both the placeholder-reservation and
/// content-writing passes of a split signing operation.
///
/// [`IdentityAssertionSigner`]: crate::identity::builder::IdentityAssertionSigner
/// [`dynamic_assertions()`]: crate::Signer::dynamic_assertions
impl DynamicAssertion for Arc<IdentityAssertionBuilder> {
    fn label(&self) -> String {
        self.as_ref().label()
    }

    fn reserve_size(&self) -> crate::Result<usize> {
        self.as_ref().reserve_size()
    }

    fn content(
        &self,
        label: &str,
        size: Option<usize>,
        claim: &PartialClaim,
    ) -> crate::Result<DynamicAssertionContent> {
        self.as_ref().content(label, size, claim)
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

// SAFETY: On wasm32, there is no threading, so Send is trivially safe
#[cfg(target_arch = "wasm32")]
unsafe impl Send for AsyncIdentityAssertionBuilder {}

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

        if let Some(size) = size {
            IdentityAssertionBuilder::signature_capacity(&signer_payload, size)?;
        }
        let signature_result = self.credential_holder.sign(&signer_payload).await;

        finalize_identity_assertion(signer_payload, size, signature_result)
    }
}

/// Allows an [`AsyncIdentityAssertionSigner`] to hand out shared clones of a
/// single [`AsyncIdentityAssertionBuilder`] each time [`dynamic_assertions()`]
/// is called, so that the same builder can service both the
/// placeholder-reservation and content-writing passes of a split signing
/// operation.
///
/// [`AsyncIdentityAssertionSigner`]: crate::identity::builder::AsyncIdentityAssertionSigner
/// [`dynamic_assertions()`]: crate::AsyncSigner::dynamic_assertions
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AsyncDynamicAssertion for Arc<AsyncIdentityAssertionBuilder> {
    fn label(&self) -> String {
        self.as_ref().label()
    }

    fn reserve_size(&self) -> crate::Result<usize> {
        self.as_ref().reserve_size()
    }

    async fn content(
        &self,
        label: &str,
        size: Option<usize>,
        claim: &PartialClaim,
    ) -> crate::Result<DynamicAssertionContent> {
        self.as_ref().content(label, size, claim).await
    }
}

// CBOR uint and byte-string length headers have the same encoded width. Measuring
// the uint header avoids allocating a trial signature/padding buffer during sizing.
fn max_byte_string_payload(encoded_budget: usize) -> crate::Result<usize> {
    if encoded_budget == 0 {
        return Err(crate::Error::BadParam(
            "no room for a CBOR byte string".into(),
        ));
    }
    let (mut low, mut high) = (0, encoded_budget);
    while low < high {
        let candidate = low + (high - low) / 2 + 1;
        let header = c2pa_cbor::to_vec(&candidate)?.len();
        if candidate
            .checked_add(header)
            .is_some_and(|size| size <= encoded_budget)
        {
            low = candidate;
        } else {
            high = candidate - 1;
        }
    }
    Ok(low)
}

fn finalize_identity_assertion(
    signer_payload: SignerPayload,
    size: Option<usize>,
    signature_result: Result<Vec<u8>, IdentityBuilderError>,
) -> crate::Result<DynamicAssertionContent> {
    if size.is_some_and(|size| size > isize::MAX as usize) {
        return Err(crate::Error::BadParam(
            "identity assertion reservation exceeds addressable size".into(),
        ));
    }
    // TO DO: Think through how errors map into crate::Error.
    let signature = signature_result.map_err(|e| crate::Error::BadParam(e.to_string()))?;

    let mut ia = IdentityAssertion {
        signer_payload,
        signature,
        pad1: vec![],
        pad2: None,
        label: None,
    };

    let mut assertion_cbor: Vec<u8> = vec![];
    c2pa_cbor::to_writer(&mut assertion_cbor, &ia)
        .map_err(|e| crate::Error::BadParam(e.to_string()))?;
    // TO DO: Think through how errors map into crate::Error.

    if let Some(assertion_size) = size {
        if assertion_size < assertion_cbor.len() {
            // TO DO: Think about how to signal this in such a way that
            // the AsyncCredentialHolder implementor understands the problem.
            return Err(crate::Error::BadParam(format!("Serialized assertion is {len} bytes, which exceeds the planned size of {assertion_size} bytes", len = assertion_cbor.len())));
        }

        let empty_header = c2pa_cbor::to_vec(&0usize)?.len();
        // One padding string covers ordinary lengths. The second bridges holes
        // where CBOR length headers grow (e.g. a 23-byte string becoming 24).
        for with_pad2 in [false, true] {
            ia.pad2 = with_pad2.then(|| ByteBuf::from(Vec::new()));
            let base_size = c2pa_cbor::to_vec(&ia)?.len();
            let Some(encoded_budget) = assertion_size
                .checked_sub(base_size)
                .and_then(|gap| gap.checked_add(empty_header))
            else {
                continue;
            };
            let pad1_len = max_byte_string_payload(encoded_budget)?;
            let pad1_header = c2pa_cbor::to_vec(&pad1_len)?.len();
            let remainder = encoded_budget
                .checked_sub(pad1_len)
                .and_then(|remaining| remaining.checked_sub(pad1_header))
                .ok_or_else(|| {
                    crate::Error::BadParam("identity assertion padding exceeds reservation".into())
                })?;
            if !with_pad2 && remainder != 0 {
                continue;
            }
            ia.pad1.try_reserve_exact(pad1_len).map_err(|e| {
                crate::Error::BadParam(format!("identity assertion padding allocation failed: {e}"))
            })?;
            ia.pad1.resize(pad1_len, 0);
            if with_pad2 {
                let budget = remainder.checked_add(empty_header).ok_or_else(|| {
                    crate::Error::BadParam("identity assertion padding size overflow".into())
                })?;
                let pad2_len = max_byte_string_payload(budget)?;
                let mut pad2 = Vec::new();
                pad2.try_reserve_exact(pad2_len).map_err(|e| {
                    crate::Error::BadParam(format!(
                        "identity assertion padding allocation failed: {e}"
                    ))
                })?;
                pad2.resize(pad2_len, 0);
                ia.pad2 = Some(ByteBuf::from(pad2));
            }
            assertion_cbor = c2pa_cbor::to_vec(&ia)?;
            if assertion_cbor.len() != assertion_size {
                return Err(crate::Error::BadParam(format!(
                    "Padded assertion is {len} bytes, expected {assertion_size} bytes",
                    len = assertion_cbor.len()
                )));
            }
            return Ok(DynamicAssertionContent::Cbor(assertion_cbor));
        }
        return Err(crate::Error::BadParam(
            "identity assertion cannot exactly fill reservation".into(),
        ));
    }

    Ok(DynamicAssertionContent::Cbor(assertion_cbor))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::{Cursor, Seek};

    use c2pa_macros::c2pa_test_async;
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
            IdentityAssertion, SignerPayload, ToCredentialSummary,
        },
        status_tracker::StatusTracker,
        Builder, Reader, SigningAlg,
    };

    const TEST_IMAGE: &[u8] = include_bytes!("../../../tests/fixtures/CA.jpg");
    const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../tests/fixtures/thumbnail.jpg");

    #[c2pa_test_async]
    async fn simple_case() {
        // NOTE: This needs to be async for now because the verification side is
        // async-only.

        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::default().with_definition(manifest_json()).unwrap();
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

        let manifest_store = Reader::default().with_stream(format, &mut dest).unwrap();
        // The naive credential's sig_type is unrecognized by the default Reader,
        // which must surface it as a failure.
        assert!(manifest_store
            .validation_status()
            .unwrap()
            .iter()
            .any(|s| s.code() == "cawg.identity.sig_type.unknown"));

        let manifest = manifest_store.active_manifest().unwrap();
        let mut st = StatusTracker::default();
        let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

        // Should find exactly one identity assertion.
        let ia = ia_iter.next().unwrap().unwrap();
        assert!(ia_iter.next().is_none());
        drop(ia_iter);

        let label = ia.label.as_ref().unwrap();
        assert!(label.ends_with("cawg.identity"));
        assert!(label.contains("/c2pa.assertions/"));

        // And that identity assertion should be valid for this manifest.
        let nsv = NaiveSignatureVerifier {};
        let naive_credential = ia.validate(manifest, &mut st, &nsv).await.unwrap();

        let nc_summary = naive_credential.to_summary();
        let nc_json = serde_json::to_string(&nc_summary).unwrap();
        assert_eq!(nc_json, "{}");
    }

    #[c2pa_test_async]
    async fn simple_case_async() {
        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::default().with_definition(manifest_json()).unwrap();
        builder
            .add_ingredient_from_stream_async(parent_json(), format, &mut source)
            .await
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

        let manifest_store = Reader::default().with_stream(format, &mut dest).unwrap();
        // The naive credential's sig_type is unrecognized by the default Reader,
        // which must surface it as a failure.
        assert!(manifest_store
            .validation_status()
            .unwrap()
            .iter()
            .any(|s| s.code() == "cawg.identity.sig_type.unknown"));

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

    /// A reservation must hold at least the unpadded assertion. Any larger
    /// reservation is filled exactly; there is no fixed padding allowance.
    #[test]
    fn rejects_reserve_size_that_is_too_small() {
        use super::{finalize_identity_assertion, DynamicAssertionContent};

        let signer_payload = SignerPayload {
            referenced_assertions: vec![],
            sig_type: "INVALID.identity.naive_credential".to_owned(),
            roles: vec![],
        };

        let DynamicAssertionContent::Cbor(unpadded) =
            finalize_identity_assertion(signer_payload.clone(), None, Ok(vec![])).unwrap()
        else {
            panic!("expected CBOR content");
        };
        let unpadded_len = unpadded.len();

        for size in [0usize, 1, unpadded_len - 1, usize::MAX] {
            match finalize_identity_assertion(signer_payload.clone(), Some(size), Ok(vec![])) {
                Err(crate::Error::BadParam(_)) => {}
                Err(e) => panic!("expected BadParam, got {e:?}"),
                Ok(_) => panic!("a reserve size that is too small must be rejected"),
            }
        }

        // Sizes below the former 15-byte padding allowance now fill exactly.
        for size in [unpadded_len, unpadded_len + 1, unpadded_len + 14] {
            let DynamicAssertionContent::Cbor(bytes) =
                finalize_identity_assertion(signer_payload.clone(), Some(size), Ok(vec![]))
                    .unwrap()
            else {
                panic!("expected CBOR content");
            };
            assert_eq!(bytes.len(), size);
        }
    }

    #[test]
    fn padding_and_capacity_cover_cbor_boundaries_without_panics() {
        use super::{finalize_identity_assertion, DynamicAssertionContent};
        use crate::HashedUri;

        let payload = SignerPayload {
            referenced_assertions: vec![HashedUri::new(
                "self#jumbf=c2pa.assertions/c2pa.hash.data".into(),
                Some("sha256".into()),
                &[1; 32],
            )],
            sig_type: "test.capacity".into(),
            roles: vec!["cawg.publisher".into()],
        };
        for signature_len in [0, 1, 23, 24, 255, 256, 65535, 65536] {
            let signature = vec![0xa5; signature_len];
            let DynamicAssertionContent::Cbor(unpadded) =
                finalize_identity_assertion(payload.clone(), None, Ok(signature.clone())).unwrap()
            else {
                panic!("expected CBOR")
            };
            for gap in (0..=40).chain([255, 256, 257, 258, 65535, 65536, 65537]) {
                let size = unpadded.len() + gap;
                let result = std::panic::catch_unwind(|| {
                    finalize_identity_assertion(payload.clone(), Some(size), Ok(signature.clone()))
                });
                assert!(result.is_ok(), "sized finalization must not panic");
                let result = result.unwrap().unwrap();
                let DynamicAssertionContent::Cbor(bytes) = result else {
                    panic!("expected CBOR")
                };
                assert_eq!(bytes.len(), size);
                let restored: IdentityAssertion = c2pa_cbor::from_slice(&bytes).unwrap();
                assert_eq!(restored.signature, signature);
                assert!(restored.pad1.iter().all(|b| *b == 0));
                assert!(restored
                    .pad2
                    .as_ref()
                    .is_none_or(|p| p.iter().all(|b| *b == 0)));

                let capacity =
                    IdentityAssertionBuilder::signature_capacity(&payload, size).unwrap();
                assert!(capacity >= signature_len);
                let DynamicAssertionContent::Cbor(at_capacity) =
                    finalize_identity_assertion(payload.clone(), None, Ok(vec![0; capacity]))
                        .unwrap()
                else {
                    panic!("expected CBOR")
                };
                assert!(at_capacity.len() <= size);
                let DynamicAssertionContent::Cbor(above_capacity) =
                    finalize_identity_assertion(payload.clone(), None, Ok(vec![0; capacity + 1]))
                        .unwrap()
                else {
                    panic!("expected CBOR")
                };
                assert!(above_capacity.len() > size);
            }
            for size in [0, unpadded.len() - 1, usize::MAX] {
                let result = std::panic::catch_unwind(|| {
                    finalize_identity_assertion(payload.clone(), Some(size), Ok(signature.clone()))
                });
                assert!(result.is_ok(), "invalid budgets must not panic");
                assert!(result.unwrap().is_err());
            }
        }
        assert!(IdentityAssertionBuilder::signature_capacity(&payload, 0).is_err());
        assert!(IdentityAssertionBuilder::signature_capacity(&payload, usize::MAX).is_err());
    }
}
