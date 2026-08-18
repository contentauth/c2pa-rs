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

//! Contains implementations of [`AsyncCredentialHolder`] and
//! [`SignatureVerifier`] for the X.509 certificates credential type described
//! as specified in [§8.2, X.509 certificates and COSE signatures].
//!
//! [`AsyncCredentialHolder`]: crate::identity::builder::AsyncCredentialHolder
//! [`SignatureVerifier`]: crate::identity::SignatureVerifier
//! [§8.2, X.509 certificates and COSE signatures]: https://cawg.io/identity/1.3/#_x_509_certificates_and_cose_signatures

mod async_x509_credential_holder;
pub use async_x509_credential_holder::AsyncX509CredentialHolder;

mod x509_credential_holder;
pub use x509_credential_holder::X509CredentialHolder;

mod x509_signature_verifier;
pub use x509_signature_verifier::{X509SignatureInfo, X509SignatureReport, X509SignatureVerifier};

use crate::{status_tracker::StatusTracker, validation_status};

pub(crate) const CAWG_X509_SIG_TYPE: &str = "cawg.x509.cose";

/// Rewrites the C2PA-oriented status codes emitted by the shared
/// [`crate::crypto::cose`] signature validation code into the CAWG X.509-specific
/// codes defined in [§8.2.2, "Validating the COSE signature,"] of the CAWG
/// identity assertion specification, version 1.3.
///
/// The `crypto::cose` validation code is shared with C2PA claim signature
/// validation and must keep emitting the original C2PA status codes, so this
/// function rewrites the codes after the fact instead. Only log items added to
/// `status_tracker` at index `first_new_item` or later are considered, so that
/// log items unrelated to this X.509 signature check (for example, an earlier
/// step in identity assertion validation) are left untouched.
///
/// [§8.2.2, "Validating the COSE signature,"]: https://cawg.io/identity/1.3/#_validating_the_cose_signature
pub(crate) fn remap_x509_cose_status_codes(
    status_tracker: &mut StatusTracker,
    first_new_item: usize,
) {
    for item in status_tracker.logged_items_mut()[first_new_item..].iter_mut() {
        let Some(old_code) = item.validation_status.as_deref() else {
            continue;
        };

        let new_code = match old_code {
            validation_status::ALGORITHM_UNSUPPORTED => "cawg.x509.algorithm.unsupported",
            validation_status::SIGNING_CREDENTIAL_TRUSTED => "cawg.x509.credential.trusted",

            validation_status::SIGNING_CREDENTIAL_UNTRUSTED
            | validation_status::SIGNING_CREDENTIAL_INVALID => "cawg.x509.credential.untrusted",

            validation_status::SIGNING_CREDENTIAL_EXPIRED => "cawg.x509.signature.outside_validity",

            validation_status::CLAIM_SIGNATURE_MISMATCH => "cawg.x509.signature.mismatch",

            _ => continue,
        };

        item.validation_status = Some(new_code.into());
    }
}
