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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{log_item, status_tracker::StatusTracker};

    fn status_of(tracker: &StatusTracker, index: usize) -> &str {
        tracker.logged_items()[index]
            .validation_status
            .as_ref()
            .unwrap()
            .as_ref()
    }

    #[test]
    fn remaps_known_c2pa_codes() {
        let mut st = StatusTracker::default();

        log_item!("l", "d", "f")
            .validation_status(validation_status::ALGORITHM_UNSUPPORTED)
            .informational(&mut st);

        log_item!("l", "d", "f")
            .validation_status(validation_status::SIGNING_CREDENTIAL_TRUSTED)
            .success(&mut st);

        log_item!("l", "d", "f")
            .validation_status(validation_status::SIGNING_CREDENTIAL_UNTRUSTED)
            .informational(&mut st);

        log_item!("l", "d", "f")
            .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID)
            .informational(&mut st);

        log_item!("l", "d", "f")
            .validation_status(validation_status::SIGNING_CREDENTIAL_EXPIRED)
            .informational(&mut st);

        log_item!("l", "d", "f")
            .validation_status(validation_status::CLAIM_SIGNATURE_MISMATCH)
            .informational(&mut st);

        remap_x509_cose_status_codes(&mut st, 0);

        assert_eq!(status_of(&st, 0), "cawg.x509.algorithm.unsupported");
        assert_eq!(status_of(&st, 1), "cawg.x509.credential.trusted");
        assert_eq!(status_of(&st, 2), "cawg.x509.credential.untrusted");
        assert_eq!(status_of(&st, 3), "cawg.x509.credential.untrusted");
        assert_eq!(status_of(&st, 4), "cawg.x509.signature.outside_validity");
        assert_eq!(status_of(&st, 5), "cawg.x509.signature.mismatch");
    }

    #[test]
    fn leaves_unrelated_and_missing_codes_untouched() {
        let mut st = StatusTracker::default();

        // A code that isn't produced by `crypto::cose` must be left alone.
        log_item!("l", "d", "f")
            .validation_status("cawg.identity.pad.invalid")
            .informational(&mut st);

        // A log item with no validation status at all must not panic and must
        // be left alone.
        log_item!("l", "d", "f").informational(&mut st);

        remap_x509_cose_status_codes(&mut st, 0);

        assert_eq!(status_of(&st, 0), "cawg.identity.pad.invalid");
        assert!(st.logged_items()[1].validation_status.is_none());
    }

    #[test]
    fn ignores_items_before_first_new_item() {
        let mut st = StatusTracker::default();

        log_item!("l", "d", "f")
            .validation_status(validation_status::SIGNING_CREDENTIAL_TRUSTED)
            .success(&mut st);

        let first_new_item = st.logged_items().len();

        log_item!("l", "d", "f")
            .validation_status(validation_status::SIGNING_CREDENTIAL_UNTRUSTED)
            .informational(&mut st);

        remap_x509_cose_status_codes(&mut st, first_new_item);

        // The item logged before `first_new_item` must be untouched, even
        // though its code would otherwise be remapped.
        assert_eq!(
            status_of(&st, 0),
            validation_status::SIGNING_CREDENTIAL_TRUSTED
        );
        assert_eq!(status_of(&st, 1), "cawg.x509.credential.untrusted");
    }
}
