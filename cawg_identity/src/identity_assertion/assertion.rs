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

/// This struct represents the raw content of the identity assertion.
///
/// Use [`AsyncIdentityAssertionBuilder`] and -- at your option,
/// [`AsyncIdentityAssertionSigner`] -- to ensure correct construction of a new
/// identity assertion.
///
/// [`AsyncIdentityAssertionBuilder`]: crate::builder::AsyncIdentityAssertionBuilder
/// [`AsyncIdentityAssertionSigner`]: crate::builder::AsyncIdentityAssertionSigner

#[deprecated(since = "0.14.0", note = "Moved to c2pa::identity::IdentityAssertion")]
pub use c2pa::identity::IdentityAssertion;
