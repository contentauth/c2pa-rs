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

#![deny(missing_docs)]

use std::slice::Iter;

use async_trait::async_trait;

use crate::{hashed_uri::HashedUri, Result};

/// The type of content that can be returned by a [`DynamicAssertion`] content call.
pub enum DynamicAssertionContent {
    /// The assertion is a CBOR-encoded binary blob.
    Cbor(Vec<u8>),

    /// The assertion is a JSON-encoded string.
    Json(String),

    /// The assertion is a binary blob with a content type.
    Binary(String, Vec<u8>),
}

/// A `DynamicAssertion` is an assertion that has the ability to adjust
/// its content based on other assertions within the overall [`Manifest`].
///
/// Use `DynamicAssertion` when the overall signing path is synchronous.
///
/// [`Manifest`]: crate::Manifest
pub trait DynamicAssertion {
    /// Return the preferred label for this assertion.
    ///
    /// Note that the label may be adjusted in case multiple assertions
    /// return the same preferred label (i.e. a `_2`, `_3`, etc. suffix
    /// may be added).
    fn label(&self) -> String;

    /// Return the expected size of the final assertion content in bytes.
    ///
    /// This function will be called by the [`Builder`] API if the hard
    /// binding assertion in use requires that the assertion size be locked
    /// down in order to complete file layout (i.e. when using a data hash
    /// assertion).
    ///
    /// [`Builder`]: crate::Builder
    fn reserve_size(&self) -> Result<usize>;

    /// Return the final assertion content.
    ///
    /// The `label` parameter will contain the final assigned label for
    /// this assertion.
    ///
    /// If the hard binding assertion requires that the assertion size
    /// be predicted in advance, then `size` will contain the number of bytes
    /// specified by a previous call to `reserve_size`. In that case, the
    /// resulting binary content *MUST* exactly match the specified size;
    /// otherwise, the overall manifest generation process will fail.
    ///
    /// The `claim` structure will contain information about the preliminary
    /// C2PA claim as known at the time of this call.
    fn content(
        &self,
        label: &str,
        size: Option<usize>,
        claim: &PartialClaim,
    ) -> Result<DynamicAssertionContent>;
}

/// An `AsyncDynamicAssertion` is an assertion that has the ability
/// to adjust its content based on other assertions within the
/// overall [`Manifest`].
///
/// Use `AsyncDynamicAssertion` when the overall signing path is asynchronous.
///
/// [`Manifest`]: crate::Manifest
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait AsyncDynamicAssertion: Sync + Send {
    /// Return the preferred label for this assertion.
    ///
    /// Note that the label may be adjusted in case multiple assertions
    /// return the same preferred label (i.e. a `_2`, `_3`, etc. suffix
    /// may be added).
    fn label(&self) -> String;

    /// Return the expected size of the final assertion content in bytes.
    ///
    /// This function will be called by the [`Builder`] API if the hard
    /// binding assertion in use requires that the assertion size be locked
    /// down in order to complete file layout (i.e. when using a data hash
    /// assertion).
    ///
    /// [`Builder`]: crate::Builder
    fn reserve_size(&self) -> Result<usize>;

    /// Return the final assertion content.
    ///
    /// The `label` parameter will contain the final assigned label for
    /// this assertion.
    ///
    /// If the hard binding assertion requires that the assertion size
    /// be predicted in advance, then `size` will contain the number of bytes
    /// specified by a previous call to `reserve_size`. In that case, the
    /// resulting binary content *MUST* exactly match the specified size;
    /// otherwise, the overall manifest generation process will fail.
    ///
    /// The `claim` structure will contain information about the preliminary
    /// C2PA claim as known at the time of this call.
    async fn content(
        &self,
        label: &str,
        size: Option<usize>,
        claim: &PartialClaim,
    ) -> Result<DynamicAssertionContent>;
}

/// An `AsyncDynamicAssertion` is an assertion that has the ability
/// to adjust its content based on other assertions within the
/// overall [`Manifest`].
///
/// Use `AsyncDynamicAssertion` when the overall signing path is asynchronous.
///
/// [`Manifest`]: crate::Manifest
#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait AsyncDynamicAssertion {
    /// Return the preferred label for this assertion.
    ///
    /// Note that the label may be adjusted in case multiple assertions
    /// return the same preferred label (i.e. a `_2`, `_3`, etc. suffix
    /// may be added).
    fn label(&self) -> String;

    /// Return the expected size of the final assertion content in bytes.
    ///
    /// This function will be called by the [`Builder`] API if the hard
    /// binding assertion in use requires that the assertion size be locked
    /// down in order to complete file layout (i.e. when using a data hash
    /// assertion).
    ///
    /// [`Builder`]: crate::Builder
    fn reserve_size(&self) -> Result<usize>;

    /// Return the final assertion content.
    ///
    /// The `label` parameter will contain the final assigned label for
    /// this assertion.
    ///
    /// If the hard binding assertion requires that the assertion size
    /// be predicted in advance, then `size` will contain the number of bytes
    /// specified by a previous call to `reserve_size`. In that case, the
    /// resulting binary content *MUST* exactly match the specified size;
    /// otherwise, the overall manifest generation process will fail.
    ///
    /// The `claim` structure will contain information about the preliminary
    /// C2PA claim as known at the time of this call.
    async fn content(
        &self,
        label: &str,
        size: Option<usize>,
        claim: &PartialClaim,
    ) -> Result<DynamicAssertionContent>;
}

/// Describes information from the preliminary C2PA Claim that may
/// be helpful in constructing the final content of a [`AsyncDynamicAssertion`].
#[derive(Debug, Default, Eq, PartialEq)]
pub struct PartialClaim {
    assertion_uris: Vec<HashedUri>,
}

impl PartialClaim {
    /// Return an iterator over the assertions in this Claim.
    pub fn assertions(&self) -> Iter<HashedUri> {
        self.assertion_uris.iter()
    }

    pub(crate) fn add_assertion(&mut self, assertion: &HashedUri) {
        self.assertion_uris.push(assertion.clone());
    }
}
