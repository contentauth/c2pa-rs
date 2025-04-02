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

use crate::{
    claim_aggregation::IcaSignatureVerifier, x509::X509SignatureVerifier, BuiltInSignatureVerifier,
};

/// Create a `BuiltInSignatureVerifier` that is configured to read the
/// credentials used in test.
pub(crate) fn default_built_in_signature_verifier() -> BuiltInSignatureVerifier {
    BuiltInSignatureVerifier {
        ica_verifier: IcaSignatureVerifier {},
        x509_verifier: X509SignatureVerifier {},
    }
}
