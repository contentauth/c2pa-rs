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

use std::slice::Iter;

use c2pa_status_tracker::StatusTracker;
use serde::Serialize;

use crate::{HashedUri, Manifest, ManifestAssertion, Result};

/// A `ReaderConfig` allows a caller to provide additional information
/// to a [`Reader`] about how the `Reader` should handle specific edge
/// cases.
///
/// [`Reader`]: crate::Reader
#[derive(Default)]
pub struct ReaderConfig {
    assertion_readers: Vec<Box<dyn AssertionReader + 'static>>,
}

impl ReaderConfig {
    /// Adds an [`AssertionReader`] to this configuration.
    ///
    /// This configures the reader to process one or more C2PA assertion
    /// types that are not automatically handled by this crate.
    pub fn add_assertion_reader<T: AssertionReader + 'static>(&mut self, assertion_reader: T) {
        self.assertion_readers.push(Box::new(assertion_reader));
    }
}

/// An implementation of `AssertionReader` extends this crate to add
/// knowledge of one or more C2PA assertion types that are not automatically
/// handled by this crate.
pub trait AssertionReader {
    // TO DO: Add an Async variant of this trait once we agree
    // on basics.

    /// Return `true` if this implementation can process an assertion of the given type.
    fn can_process_assertion_with_label(&self, label: &str) -> bool;

    /// Check the validity of a [`ManifestAssertion`] and return a
    /// [`Serialize`]-able summary of what was found.
    ///
    /// ## Errors vs Validation Status
    ///
    /// The implementation should, to the maximum extent possible,
    /// report validation errors (including parsing and network errors)
    /// by adding entries to the provided [`StatusTracker`] instance.
    ///
    /// Returning an `Err` result will cause the overall validation process
    /// to fail and should be used only as a last resort.
    ///
    /// In the event of more typical error conditions, the implementation
    /// should return as much of the data as is available and may omit data
    /// that was inaccessible or unavailable.
    fn validate(
        &self,
        manifest: &ReaderManifest,
        assertion: &ManifestAssertion,
        log: Box<&'static mut dyn StatusTracker>,
        // ^^ PROBLEM: StatusTracker can't be made into an object
    ) -> Result<Box<dyn Serialize>>;
    // ^^ PROBLEM: Serialize can't be made into an object
}

/// A `ReaderManifest` contains a preliminary description of a C2PA Manifest which can be inspected by the [`AssertionReader`] in its [`validate`] method.
///
/// [`validate`]: AssertionReader::validate
pub struct ReaderManifest<'a> {
    manifest: &'a Manifest, // private: could be replaced by anything
}

impl<'a> ReaderManifest<'a> {
    /// Return an iterator over the assertions in this manifest.
    pub fn assertions(&'a self) -> Iter<'a, HashedUri> {
        todo!();
    }
}
