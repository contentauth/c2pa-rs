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

use async_trait::async_trait;
use c2pa_crypto::{
    cose::{parse_cose_sign1, CertificateInfo, CoseError, Verifier},
    raw_signature::RawSignatureValidationError,
};
use c2pa_status_tracker::{log_current_item, StatusTracker};
use coset::CoseSign1;
use serde::Serialize;

use crate::{
    identity_assertion::signature_verifier::ToCredentialSummary, SignatureVerifier, SignerPayload,
    ValidationError,
};

/// An implementation of [`SignatureVerifier`] that supports COSE signatures
/// generated from X.509 credentials as specified in [§8.2, X.509 certificates
/// and COSE signatures].
///
/// [`SignatureVerifier`]: crate::SignatureVerifier
/// [§8.2, X.509 certificates and COSE signatures]: https://cawg.io/identity/1.1-draft/#_x_509_certificates_and_cose_signatures
pub struct X509SignatureVerifier {
    // TO DO (CAI-7980): Add option to configure trust roots and trusted signers.
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureVerifier for X509SignatureVerifier {
    type Error = CoseError;
    type Output = X509SignatureInfo;

    async fn check_signature(
        &self,
        signer_payload: &SignerPayload,
        signature: &[u8],
        status_tracker: &mut StatusTracker,
    ) -> Result<Self::Output, ValidationError<Self::Error>> {
        if signer_payload.sig_type != super::CAWG_X509_SIG_TYPE {
            log_current_item!(
                "unsupported signature type",
                "X509SignatureVerifier::check_signature"
            )
            .validation_status("cawg.identity.sig_type.unknown")
            .failure_no_throw(
                status_tracker,
                ValidationError::<CoseError>::UnknownSignatureType(signer_payload.sig_type.clone()),
            );

            return Err(ValidationError::UnknownSignatureType(
                signer_payload.sig_type.clone(),
            ));
        }

        let mut signer_payload_cbor: Vec<u8> = vec![];
        ciborium::into_writer(signer_payload, &mut signer_payload_cbor)
            .map_err(|_| ValidationError::InternalError("CBOR serialization error".to_string()))?;

        // TO DO: Add options for trust list and certificate policy config.
        let verifier = Verifier::IgnoreProfileAndTrustPolicy;

        // TO DO: Figure out how to provide a validation log.
        let mut validation_log = StatusTracker::default();

        let cose_sign1 = parse_cose_sign1(signature, &signer_payload_cbor, &mut validation_log)?;

        let cert_info = verifier
            .verify_signature_async(signature, &signer_payload_cbor, &[], &mut validation_log)
            .await
            .map_err(|e| match e {
                CoseError::RawSignatureValidationError(
                    RawSignatureValidationError::SignatureMismatch,
                ) => ValidationError::InvalidSignature,

                e => ValidationError::SignatureError(e),
            })?;

        Ok(X509SignatureInfo {
            signer_payload: signer_payload.clone(),
            cose_sign1,
            cert_info,
        })
    }
}

/// Contains information the X.509 certificate chain and the COSE signature that
/// was used to generate this identity assertion signature.
#[derive(Debug)]
pub struct X509SignatureInfo {
    /// The signer payload that was used to generate the signature.
    pub signer_payload: SignerPayload,

    /// Parsed COSE signature.
    pub cose_sign1: CoseSign1,

    /// Information about the X.509 certificate chain.
    pub cert_info: CertificateInfo,
}

impl ToCredentialSummary for X509SignatureInfo {
    type CredentialSummary = X509SignatureReport;

    fn to_summary(&self) -> Self::CredentialSummary {
        X509SignatureReport::from_x509_signature_info(self)
    }
}

// #[derive(Serialize)] <- uncomment once the type is populated
#[doc(hidden)]
#[derive(Serialize)]
pub struct X509SignatureReport {
    pub signer_payload: SignerPayload,
    pub signature_info: c2pa::SignatureInfo,
}

impl X509SignatureReport {
    fn from_x509_signature_info(info: &X509SignatureInfo) -> Self {
        X509SignatureReport {
            signer_payload: info.signer_payload.clone(),
            signature_info: c2pa::SignatureInfo {
                alg: info.cert_info.alg,
                issuer: info.cert_info.issuer_org.clone(),
                time: info.cert_info.date.map(|d| d.to_rfc3339()),
                cert_serial_number: info
                    .cert_info
                    .cert_serial_number
                    .as_ref()
                    .map(|s| s.to_string()),
                cert_chain: String::from_utf8(info.cert_info.cert_chain.to_vec())
                    .unwrap_or_default(),
                revocation_status: info.cert_info.revocation_status,
            },
        }
    }
}
