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
use c2pa_status_tracker::{
    log_item,
    validation_codes::{TIMESTAMP_MISMATCH, TIMESTAMP_OUTSIDE_VALIDITY},
    StatusTracker,
};
use coset::CoseSign1;

use crate::{
    asn1::rfc3161::TstInfo,
    cose::{cert_chain_from_sign1, check_certificate_profile, CertificateTrustPolicy, CoseError},
    time_stamp::TimeStampError,
};

/// A `Verifier` reads a COSE signature and reports on its validity.
///
/// It can provide different levels of verification depending on the enum value
/// chosen.
#[derive(Debug)]
pub enum Verifier<'a> {
    /// Use a [`CertificateTrustPolicy`] to validate the signing certificate's
    /// profile against C2PA requirements _and_ validate the certificate's
    /// membership against a trust configuration.
    VerifyTrustPolicy(&'a CertificateTrustPolicy),

    /// Validate the certificate's membership against a trust configuration, but
    /// do not against any trust list. The [`CertificateTrustPolicy`] is used to
    /// enforce EKU (Extended Key Usage) policy only.
    VerifyCertificateProfileOnly(&'a CertificateTrustPolicy),

    /// Ignore both trust configuration and trust lists.
    IgnoreProfileAndTrustPolicy,
}

impl Verifier<'_> {
    /// Verify certificate profile if so configured.
    ///
    /// TO DO: This might not need to be public after refactoring.
    #[async_generic]
    pub fn verify_profile(
        &self,
        sign1: &CoseSign1,
        tst_info_res: &Result<TstInfo, CoseError>,
        validation_log: &mut impl StatusTracker,
    ) -> Result<(), CoseError> {
        let ctp = match self {
            Self::VerifyTrustPolicy(ctp) => *ctp,
            Self::VerifyCertificateProfileOnly(ctp) => *ctp,
            Self::IgnoreProfileAndTrustPolicy => {
                return Ok(());
            }
        };

        let certs = cert_chain_from_sign1(&sign1)?;
        let end_entity_cert_der = &certs[0];

        match tst_info_res {
            Ok(tst_info) => Ok(check_certificate_profile(
                end_entity_cert_der,
                ctp,
                validation_log,
                Some(tst_info),
            )?),

            Err(CoseError::NoTimeStampToken) => Ok(check_certificate_profile(
                end_entity_cert_der,
                ctp,
                validation_log,
                None,
            )?),

            Err(CoseError::TimeStampError(TimeStampError::InvalidData)) => {
                log_item!(
                    "Cose_Sign1",
                    "timestamp did not match signed data",
                    "verify_cose"
                )
                .validation_status(TIMESTAMP_MISMATCH)
                .failure_no_throw(validation_log, TimeStampError::InvalidData);

                Err(TimeStampError::InvalidData.into())
            }

            Err(CoseError::TimeStampError(TimeStampError::ExpiredCertificate)) => {
                log_item!(
                    "Cose_Sign1",
                    "timestamp certificate outside of validity",
                    "verify_cose"
                )
                .validation_status(TIMESTAMP_OUTSIDE_VALIDITY)
                .failure_no_throw(validation_log, TimeStampError::ExpiredCertificate);

                Err(TimeStampError::ExpiredCertificate.into())
            }

            Err(e) => {
                log_item!("Cose_Sign1", "error parsing timestamp", "verify_cose")
                    .failure_no_throw(validation_log, e);

                // Frustratingly, we can't clone CoseError. The likely cases are already handled
                // above, so we'll call this an internal error.

                Err(CoseError::InternalError(e.to_string()))
            }
        }
    }
}
