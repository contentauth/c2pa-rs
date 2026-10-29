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
use log::error;

use crate::{
    claim::Claim,
    context::Context,
    cose_sign::{cose_sign, cose_sign_async},
    cose_validator::{check_ocsp_status, check_ocsp_status_async, verify_cose, verify_cose_async},
    crypto::cose::{
        fetch_and_check_ocsp_response, fetch_and_check_ocsp_response_async, parse_cose_sign1,
        TimeStampStorage,
    },
    error::{Error, Result},
    settings::{builder::OcspFetchScope, Settings},
    status_tracker::{ErrorBehavior, StatusTracker},
    store::Store,
    AsyncSigner, Signer,
};

impl Store {
    /// Return OCSP info if available
    // Currently only called from manifest_store behind a feature flag but this is allowable
    // anywhere so allow dead code here for future uses to compile
    #[allow(dead_code)]
    #[async_generic]
    pub fn get_ocsp_status(&self, context: &Context) -> Option<String> {
        let claim = self
            .provenance_claim()
            .ok_or(Error::ProvenanceMissing)
            .ok()?;

        let sig = claim.signature_val();
        let data = claim.data().ok()?;
        let mut validation_log =
            StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

        let sign1 = parse_cose_sign1(sig, &data, &mut validation_log).ok()?;
        let ocsp_status = if _sync {
            check_ocsp_status(
                &sign1,
                &data,
                &self.ctp,
                None,
                None,
                &mut validation_log,
                context,
            )
        } else {
            check_ocsp_status_async(
                &sign1,
                &data,
                &self.ctp,
                None,
                None,
                &mut validation_log,
                context,
            )
            .await
        };
        if let Ok(info) = ocsp_status {
            if let Some(revoked_at) = &info.revoked_at {
                Some(format!(
                    "Certificate Status: Revoked, revoked at: {revoked_at}"
                ))
            } else {
                Some(format!(
                    "Certificate Status: Good, next update: {}",
                    info.next_update
                ))
            }
        } else {
            None
        }
    }

    /// Sign the claim and return signature.
    #[async_generic(async_signature(
        &self,
        claim: &Claim,
        signer: &dyn AsyncSigner,
        box_size: usize,
        settings: &Settings,
    ))]
    pub fn sign_claim(
        &self,
        claim: &Claim,
        signer: &dyn Signer,
        box_size: usize,
        settings: &Settings,
    ) -> Result<Vec<u8>> {
        let claim_bytes = claim.data()?;

        // no verification of timestamp trust while signing
        let mut adjusted_settings = settings.clone();
        adjusted_settings.verify.verify_timestamp_trust = false;

        let tss = if claim.version() > 1 {
            TimeStampStorage::V2_sigTst2_CTT
        } else {
            TimeStampStorage::V1_sigTst
        };

        let result = if _sync {
            if signer.direct_cose_handling() {
                // Let the signer do all the COSE processing and return the structured COSE data.
                return signer.sign(&claim_bytes); // do not verify remote signers (we never did)
            } else {
                cose_sign(signer, &claim_bytes, box_size, tss, &adjusted_settings)
            }
        } else {
            if signer.direct_cose_handling() {
                // Let the signer do all the COSE processing and return the structured COSE data.
                return signer.sign(claim_bytes.clone()).await;
            // do not verify remote signers (we never did)
            } else {
                cose_sign_async(signer, &claim_bytes, box_size, tss, settings).await
            }
        };
        match result {
            Ok(sig) => {
                // Sanity check: Ensure that this signature is valid.
                let verify_after_sign = settings.verify.verify_after_sign;

                if verify_after_sign {
                    let mut cose_log =
                        StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

                    let result = if _sync {
                        verify_cose(
                            &sig,
                            &claim_bytes,
                            b"",
                            false,
                            &self.ctp,
                            None,
                            &mut cose_log,
                            &adjusted_settings,
                        )
                    } else {
                        verify_cose_async(
                            &sig,
                            &claim_bytes,
                            b"",
                            false,
                            &self.ctp,
                            None,
                            &mut cose_log,
                            &adjusted_settings,
                        )
                        .await
                    };
                    if let Err(err) = result {
                        error!("Signature that was just generated does not validate: {err:#?}");
                        return Err(err);
                    }
                }

                Ok(sig)
            }
            Err(e) => Err(e),
        }
    }

    /// Retrieves all manifest labels that need to fetch ocsp responses.
    pub fn get_manifest_labels_for_ocsp(&self, settings: &Settings) -> Vec<String> {
        let labels = match settings.builder.certificate_status_fetch {
            Some(ocsp_fetch) => match ocsp_fetch {
                OcspFetchScope::All => self.claims.clone(),
                OcspFetchScope::Active => {
                    if let Some(active_label) = self.provenance_label() {
                        vec![active_label]
                    } else {
                        Vec::new()
                    }
                }
            },
            None => Vec::new(),
        };

        match settings.builder.certificate_status_should_override {
            Some(should_override) => {
                if !should_override {
                    labels
                        .into_iter()
                        .filter(|label| {
                            self.get_claim(label)
                                .is_some_and(|claim| !claim.has_ocsp_vals())
                        })
                        .collect()
                } else {
                    labels
                }
            }
            _ => Vec::new(),
        }
    }

    /// Fetches ocsp response ders from the specified manifests.
    ///
    /// # Arguments
    /// * `manifest_labels` - Vector of manifest labels to check for ocsp responses
    /// * `validation_log` - Status tracker for logging validation events
    ///
    /// # Returns
    /// A `Result` containing tuples of manifest labels and their associated ocsp response
    #[async_generic(async_signature(
        &self,
        manifest_labels: Vec<String>,
        validation_log: &mut StatusTracker,
        context: &Context,
    ))]
    pub fn get_ocsp_response_ders(
        &self,
        manifest_labels: Vec<String>,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let mut oscp_response_ders = Vec::new();

        let mut adjusted_settings = context.settings().clone();
        let original_trust_val = adjusted_settings.verify.verify_timestamp_trust;

        for manifest_label in manifest_labels {
            if let Some(claim) = self.get_claim(&manifest_label) {
                let sig = claim.signature_val().clone();
                let data = claim.data()?;

                // no timestamp trust checks for 1.x manifests
                if claim.version() == 1 {
                    adjusted_settings.verify.verify_timestamp_trust = false;
                }

                let sign1 = parse_cose_sign1(&sig, &data, validation_log)?;

                let ocsp_response_der = if _sync {
                    fetch_and_check_ocsp_response(
                        &sign1,
                        &data,
                        &self.ctp,
                        None,
                        validation_log,
                        context,
                    )?
                    .ocsp_der
                } else {
                    fetch_and_check_ocsp_response_async(
                        &sign1,
                        &data,
                        &self.ctp,
                        None,
                        validation_log,
                        context,
                    )
                    .await?
                    .ocsp_der
                };

                if !ocsp_response_der.is_empty() {
                    oscp_response_ders.push((manifest_label, ocsp_response_der));
                }
            }
            adjusted_settings.verify.verify_timestamp_trust = original_trust_val;
        }

        Ok(oscp_response_ders)
    }
}
