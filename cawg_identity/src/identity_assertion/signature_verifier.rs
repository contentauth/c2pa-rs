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

/// A `SignatureVerifier` can read one or more kinds of signature from an
/// identity assertion, assess the validity of the signature, and return
/// information about the corresponding credential subject.
///
/// The associated type `Output` describes the information which can be derived
/// from the credential and signature.
/// The `Output` result type from `SignatureVerifier::check_signature` may be
/// called upon to summarize its contents in a form suitable for JSON or similar
/// serialization.
///
/// This report is kept separate from any `Serialize` implementation
/// because that original credential type may have a native serialization that
/// is not suitable for summarizaton.
///
/// This trait allows the credential type to reshape its output into a suitable
/// summary form.
#[deprecated(since = "0.14.0", note = "Moved to c2pa::identity::SignatureVerifier")]
pub use c2pa::identity::SignatureVerifier;
/// The `Output` result type from [`SignatureVerifier::check_signature`] may be
/// called upon to summarize its contents in a form suitable for JSON or similar
/// serialization.
///
/// This report is kept separate from any `Serialize` implementation
/// because that original credential type may have a native serialization that
/// is not suitable for summarizaton.
///
/// This trait allows the credential type to reshape its output into a suitable
/// summary form.
#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::ToCredentialSummary"
)]
pub use c2pa::identity::ToCredentialSummary;
