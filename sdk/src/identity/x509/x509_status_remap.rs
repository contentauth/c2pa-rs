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

use crate::{status_tracker::StatusTracker, validation_status};

/// A guard that, when dropped, rewrites any C2PA-oriented status codes
/// logged into the wrapped [`StatusTracker`] since the guard was constructed
/// into their CAWG X.509-specific equivalents defined in [§8.2.2, "Validating
/// the COSE signature,"] of the CAWG identity assertion specification,
/// version 1.3.
///
/// The `crypto::cose` validation code is shared with C2PA claim signature
/// validation and must keep emitting the original C2PA status codes, so this
/// guard rewrites the codes after the fact instead. Construct one (via
/// [`Self::new`]) immediately before performing an X.509 COSE signature check
/// using the shared `crypto::cose` validation code, then let it fall out of
/// scope once the check completes -- typically by closing the block it was
/// constructed in. The remap then applies to exactly the log items logged
/// during that scope, however the check exits it (normal return, early
/// return, or `?`), without relying on a separately tracked index that a
/// later, unrelated statement could accidentally be separated from.
///
/// [§8.2.2, "Validating the COSE signature,"]: https://cawg.io/identity/1.3/#_validating_the_cose_signature
pub(crate) struct X509StatusRemapGuard<'a> {
    status_tracker: &'a mut StatusTracker,
    first_new_item: usize,
}

impl<'a> X509StatusRemapGuard<'a> {
    /// Starts a new guard scope: log items added to `status_tracker` from
    /// this point on will be remapped when the guard is dropped.
    pub(crate) fn new(status_tracker: &'a mut StatusTracker) -> Self {
        let first_new_item = status_tracker.logged_items().len();
        Self {
            status_tracker,
            first_new_item,
        }
    }

    /// Returns the wrapped [`StatusTracker`] for use within the guard's scope.
    pub(crate) fn status_tracker(&mut self) -> &mut StatusTracker {
        self.status_tracker
    }
}

impl Drop for X509StatusRemapGuard<'_> {
    fn drop(&mut self) {
        remap_x509_cose_status_codes(self.status_tracker, self.first_new_item);
    }
}

/// Rewrites the log items in `status_tracker` at index `first_new_item` or
/// later, per [`X509StatusRemapGuard`]. Not exported: called only from that
/// guard's `Drop` impl.
fn remap_x509_cose_status_codes(status_tracker: &mut StatusTracker, first_new_item: usize) {
    for item in status_tracker.logged_items_mut()[first_new_item..].iter_mut() {
        let Some(old_code) = item.validation_status.as_deref() else {
            continue;
        };

        let new_code = match old_code {
            validation_status::ALGORITHM_UNSUPPORTED => {
                validation_status::CAWG_X509_ALGORITHM_UNSUPPORTED
            }

            validation_status::SIGNING_CREDENTIAL_TRUSTED => {
                validation_status::CAWG_X509_CREDENTIAL_TRUSTED
            }

            validation_status::SIGNING_CREDENTIAL_UNTRUSTED => {
                validation_status::CAWG_X509_CREDENTIAL_UNTRUSTED
            }

            // A certificate profile violation (invalid EKU, unsupported
            // algorithm, disallowed self-signed certificate, etc.) is a
            // distinct condition from a chain of trust simply not being
            // established, so it gets its own code rather than being folded
            // into `CAWG_X509_CREDENTIAL_UNTRUSTED`. See the doc comment on
            // `CAWG_X509_CREDENTIAL_INVALID`.
            validation_status::SIGNING_CREDENTIAL_INVALID => {
                validation_status::CAWG_X509_CREDENTIAL_INVALID
            }

            validation_status::SIGNING_CREDENTIAL_EXPIRED => {
                validation_status::CAWG_X509_SIGNATURE_OUTSIDE_VALIDITY
            }

            validation_status::CLAIM_SIGNATURE_MISMATCH => {
                validation_status::CAWG_X509_SIGNATURE_MISMATCH
            }

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

        assert_eq!(
            status_of(&st, 0),
            validation_status::CAWG_X509_ALGORITHM_UNSUPPORTED
        );
        assert_eq!(
            status_of(&st, 1),
            validation_status::CAWG_X509_CREDENTIAL_TRUSTED
        );
        assert_eq!(
            status_of(&st, 2),
            validation_status::CAWG_X509_CREDENTIAL_UNTRUSTED
        );
        // A certificate profile violation (`SIGNING_CREDENTIAL_INVALID`) gets its
        // own code, distinct from a chain of trust simply not being established
        // (`SIGNING_CREDENTIAL_UNTRUSTED`, checked just above).
        assert_eq!(
            status_of(&st, 3),
            validation_status::CAWG_X509_CREDENTIAL_INVALID
        );
        assert_eq!(
            status_of(&st, 4),
            validation_status::CAWG_X509_SIGNATURE_OUTSIDE_VALIDITY
        );
        assert_eq!(
            status_of(&st, 5),
            validation_status::CAWG_X509_SIGNATURE_MISMATCH
        );
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
    fn remap_guard_only_remaps_items_logged_during_its_scope() {
        let mut st = StatusTracker::default();

        // Logged before the guard is constructed: must be untouched, even
        // though its code would otherwise be remapped.
        log_item!("l", "d", "f")
            .validation_status(validation_status::SIGNING_CREDENTIAL_UNTRUSTED)
            .informational(&mut st);

        {
            let mut guard = X509StatusRemapGuard::new(&mut st);

            log_item!("l", "d", "f")
                .validation_status(validation_status::SIGNING_CREDENTIAL_TRUSTED)
                .success(guard.status_tracker());
        } // `guard` drops here, remapping only the item logged above.

        assert_eq!(
            status_of(&st, 0),
            validation_status::SIGNING_CREDENTIAL_UNTRUSTED
        );
        assert_eq!(
            status_of(&st, 1),
            validation_status::CAWG_X509_CREDENTIAL_TRUSTED
        );
    }
}
