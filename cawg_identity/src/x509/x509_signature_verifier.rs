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
use c2pa_status_tracker::{log_item, StatusTracker};
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
pub struct X509SignatureVerifier {}

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
            // TO DO: Where would we get assertion label?
            log_item!(
                "NEED TO FIND LABEL".to_owned(),
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
            cose_sign1,
            cert_info,
        })
    }
}

/// Contains information the X.509 certificate chain and the COSE signature that
/// was used to generate this identity assertion signature.
#[derive(Debug)]
pub struct X509SignatureInfo {
    /// Parsed COSE signature.
    pub cose_sign1: CoseSign1,

    /// Information about the X.509 certificate chain.
    pub cert_info: CertificateInfo,
}

impl ToCredentialSummary for X509SignatureInfo {
    type CredentialSummary = X509SignatureReport;

    fn to_summary(&self) -> Self::CredentialSummary {
        X509SignatureReport {}
    }
}

// #[derive(Serialize)] <- uncomment once the type is populated
#[doc(hidden)]
pub struct X509SignatureReport {}

impl Serialize for X509SignatureReport {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        todo!("X509SignatureReport type not defined yet");
    }
}
