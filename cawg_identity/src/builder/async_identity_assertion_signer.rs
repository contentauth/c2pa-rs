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

/// An `AsyncIdentityAssertionSigner` extends the [`AsyncSigner`] interface to
/// add zero or more identity assertions to a C2PA [`Manifest`] that is being
/// produced.
///
/// [`AsyncSigner`]: c2pa::AsyncSigner
/// [`Manifest`]: c2pa::Manifest
#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::builder::AsyncIdentityAssertionSigner"
)]
pub use c2pa::identity::builder::AsyncIdentityAssertionSigner;
