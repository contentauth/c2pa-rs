// Copyright 2026 Adobe. All rights reserved.
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

#![deny(unfulfilled_lint_expectations)]

use c2pa::{
    crypto::{cose::CertificateInfo, ocsp::OcspResponse},
    identity::claim_aggregation::{IcaCredential, VerifiedIdentity},
};

#[test]
fn downstream_chrono_apis_emit_deprecation_diagnostics() {
    // Each expectation fails compilation if that downstream warning disappears.
    #[expect(deprecated)]
    let _ = c2pa::crypto::cose::signing_time_from_sign1;

    #[expect(deprecated)]
    let _ = c2pa::crypto::cose::signing_time_from_sign1_async;

    #[expect(deprecated)]
    let _ = c2pa::crypto::time_stamp::verify_time_stamp;

    #[expect(deprecated)]
    let _ = c2pa::crypto::time_stamp::verify_time_stamp_async;

    #[expect(deprecated)]
    let _ = |info: &CertificateInfo| info.date;

    #[expect(deprecated)]
    let _ = |response: &OcspResponse| response.next_update;

    #[expect(deprecated)]
    let _ = |response: &OcspResponse| response.revoked_at;

    #[expect(deprecated)]
    let _ = |identity: &VerifiedIdentity| identity.verified_at;

    #[expect(deprecated)]
    let _ = |credential: &IcaCredential| credential.valid_from;

    #[expect(deprecated)]
    let _ = |credential: &IcaCredential| credential.valid_until;
}
