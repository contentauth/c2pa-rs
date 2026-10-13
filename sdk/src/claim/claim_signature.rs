// Copyright 2022 Adobe. All rights reserved.
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

use async_generic::async_generic;
use coset::CoseSign1;

use crate::{
    claim::Claim,
    cose_validator::{get_signing_info, get_signing_info_async},
    crypto::cose::{get_ocsp_der, parse_cose_sign1, CertificateInfo},
    error::Result,
    settings::Settings,
    status_tracker::{ErrorBehavior, StatusTracker},
};

impl Claim {
    /// Returns the `COSE_Sign1_Tagged` structure found in the claim signature box.
    pub fn cose_sign1(&self) -> Result<CoseSign1> {
        let sig = self.signature_val();
        let data = self.data()?;
        let mut validation_log =
            StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

        let sign1 = parse_cose_sign1(sig, &data, &mut validation_log)?;
        Ok(sign1)
    }

    /// Return information about the signature
    #[async_generic]
    pub fn signature_info(&self) -> Option<CertificateInfo> {
        let sig = self.signature_val();
        let data = self.data().ok()?;
        let mut validation_log =
            StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

        if _sync {
            Some(get_signing_info(sig, &data, &mut validation_log, false))
        } else {
            Some(get_signing_info_async(sig, &data, &mut validation_log, false).await)
        }
    }

    /// Get the signing certificate chain as PEM bytes
    pub fn get_cert_chain(&self, settings: &Settings) -> Result<Vec<u8>> {
        let sig = self.signature_val();
        let data = self.data()?;
        let mut validation_log =
            StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

        let vi = get_signing_info(
            sig,
            &data,
            &mut validation_log,
            settings.verify.verify_timestamp_trust,
        );

        Ok(vi.cert_chain)
    }

    /// Checks whether or not ocsp values are present in claim
    pub fn has_ocsp_vals(&self) -> bool {
        if !self.certificate_status_assertions().is_empty() {
            return false;
        }

        let data = match self.data() {
            Ok(data) => data,
            Err(_) => return false,
        };

        let sig = self.signature_val().clone();
        let mut validation_log = StatusTracker::default();

        let sign1 = match parse_cose_sign1(&sig, &data, &mut validation_log) {
            Ok(sign1) => sign1,
            Err(_) => return false,
        };

        get_ocsp_der(&sign1).is_some()
    }
}
