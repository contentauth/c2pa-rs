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

/// A `BuiltInSignatureVerifier` is an implementation of `SignatureVerifier`
/// that can read all of the signature types that are supported by this SDK.
#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::BuiltInSignatureVerifier"
)]
pub use c2pa::identity::BuiltInSignatureVerifier;
