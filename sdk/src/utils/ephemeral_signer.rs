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

//! Ephemeral self-signed certificate generation for testing and local C2PA
//! manifests.
//!
//! Generates a certificate authority (CA) and an end-entity (EE) certificate
//! signed by that CA, and returns an [`EphemeralSigner`] that implements
//! [`Signer`](crate::Signer) and holds the full certificate chain (EE then CA)
//! in DER form.
//!
//! **WARNING:** These certificates are for testing and local use only and will
//! not be considered trusted in the C2PA conformance sense.

use asn1_rs::FromDer;
use x509_parser::prelude::X509Certificate;

use crate::{
    crypto::raw_signature::{signer_from_cert_chain_and_private_key, RawSigner, SigningAlg},
    utils::ephemeral_cert,
    Error, Result, Signer,
};

/// A [`Signer`](crate::Signer) that holds an ephemeral CA + end-entity
/// certificate chain.
///
/// The full certificate chain (end-entity first, then CA) is stored as DER and
/// returned from [`Signer::certs`](crate::Signer::certs). Signing is performed
/// by the end-entity key.
///
/// **WARNING:** These certificates are for testing and local use only and will
/// not be considered trusted in the C2PA conformance sense.
pub struct EphemeralSigner {
    /// Raw signer (EE key) used for signing.
    pub(crate) raw_signer: Box<dyn RawSigner>,

    /// Full certificate chain in DER: end-entity then CA.
    pub(crate) cert_chain_der: Vec<Vec<u8>>,
}

impl EphemeralSigner {
    /// Generates an ephemeral self-signed CA and an end-entity certificate
    /// signed by that CA, and returns an [`EphemeralSigner`] that
    /// implements [`Signer`](crate::Signer).
    ///
    /// The signer holds the full certificate chain (EE then CA) in DER form and
    /// returns it from [`Signer::certs`](crate::Signer::certs).
    ///
    /// The CA and EE use Ed25519 and the same parameter style as used for C2PA
    /// manifest signing (e.g. Digital Signature and EmailProtection usage).
    /// The EE certificate subject/common name and SAN are set from
    /// `ee_cert_name`.
    ///
    /// **WARNING:** These certificates are for testing and local use only and
    /// will not be considered trusted in the C2PA conformance sense.
    ///
    /// # Arguments
    ///
    /// * `ee_cert_name` - Subject/common name and SAN for the end-entity
    ///   certificate (e.g. `"c2pa-archive.local"`).
    ///
    /// # Errors
    ///
    /// Returns an error if certificate or key generation fails, or if the raw
    /// signer cannot be created from the generated credentials.
    pub fn new(ee_cert_name: impl Into<String>) -> Result<Self> {
        let ee_cert_name = ee_cert_name.into();

        let chain = ephemeral_cert::generate_ephemeral_chain(&ee_cert_name)?;

        // Full chain as DER: end-entity first, then CA (per C2PA / Signer convention).
        let cert_chain_der = vec![chain.ee_der.clone(), chain.ca_der.clone()];

        // Ensure each certificate is valid X.509 DER (same format COSE x5chain
        // expects).
        for (i, der) in cert_chain_der.iter().enumerate() {
            X509Certificate::from_der(der).map_err(|e| {
                Error::OtherError(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("ephemeral cert chain entry {i} is not valid X.509 DER: {e}"),
                )))
            })?;
        }

        // PEM chain and key for the raw signer (newline between certs so both are
        // parsed).
        let cert_chain_pem = format!(
            "{}\n{}",
            ephemeral_cert::der_to_pem(&chain.ee_der),
            ephemeral_cert::der_to_pem(&chain.ca_der)
        );

        let raw_signer = signer_from_cert_chain_and_private_key(
            cert_chain_pem.as_bytes(),
            chain.ee_private_key_pem.as_bytes(),
            SigningAlg::Ed25519,
            None,
        )
        .map_err(|e| Error::OtherError(Box::new(e)))?;

        // Ensure the raw signer's chain matches our DER chain (PEM decode must equal
        // our DER).
        let raw_chain = raw_signer
            .cert_chain()
            .map_err(|e| Error::OtherError(Box::new(e)))?;

        if raw_chain.len() != cert_chain_der.len() {
            return Err(Error::OtherError(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "ephemeral cert chain length mismatch: raw_signer has {}, cert_chain_der has {}",
                    raw_chain.len(),
                    cert_chain_der.len()
                ),
            ))));
        }

        for (i, (a, b)) in raw_chain.iter().zip(cert_chain_der.iter()).enumerate() {
            if a != b {
                return Err(Error::OtherError(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "ephemeral cert chain entry {i} differs between raw_signer and cert_chain_der (PEM decode vs our DER)"
                    ),
                ))));
            }
        }

        Ok(EphemeralSigner {
            raw_signer,
            cert_chain_der,
        })
    }
}

impl Signer for EphemeralSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.raw_signer.sign(data).map_err(|e| e.into())
    }

    fn alg(&self) -> SigningAlg {
        self.raw_signer.alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.cert_chain_der.clone())
    }

    fn reserve_size(&self) -> usize {
        self.raw_signer.reserve_size()
    }

    fn ocsp_val(&self) -> Option<Vec<u8>> {
        self.raw_signer.ocsp_response()
    }

    fn time_authority_url(&self) -> Option<String> {
        self.raw_signer.time_stamp_service_url()
    }

    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        self.raw_signer.time_stamp_request_headers()
    }

    fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.raw_signer
            .time_stamp_request_body(message)
            .map_err(|e| e.into())
    }

    fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        self.raw_signer
            .send_time_stamp_request(message)
            .map(|r| r.map_err(|e| e.into()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use coset::iana::{self, EnumI64};

    use super::*;
    use crate::{
        claim::Claim,
        cose_sign::{cose_sign, sign_claim},
        cose_validator::verify_cose,
        crypto::cose::{
            cert_chain_from_sign1, parse_cose_sign1, CertificateTrustPolicy, TimeStampStorage,
        },
        settings::Settings,
        status_tracker::StatusTracker,
        Signer,
    };

    /// Diagnostic: produce COSE bytes with EphemeralSigner (no verify), then
    /// inspect the parsed protected header to see why cert_chain_from_sign1
    /// fails.
    #[test]
    fn ephemeral_signer_protected_header_inspection() {
        let signer = EphemeralSigner::new("c2pa-archive.local").unwrap();
        let mut claim = Claim::new("ephemeral_inspect", Some("contentauth"), 1);
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let mut settings = Settings::default();
        settings.verify.verify_trust = false;

        let tss = TimeStampStorage::V1_sigTst;

        let cose_bytes = cose_sign(&signer, &claim_bytes, signer.reserve_size(), tss, &settings)
            .expect("cose_sign with EphemeralSigner");

        let mut log = StatusTracker::default();
        let sign1 = parse_cose_sign1(&cose_bytes, &claim_bytes, &mut log)
            .expect("parse COSE from EphemeralSigner");

        let rest = &sign1.protected.header.rest;
        let x5_label = iana::HeaderParameter::X5Chain.to_i64();

        let has_x5_in_rest = rest.iter().any(|(label, _)| {
            *label == coset::Label::Int(x5_label) || *label == coset::Label::Text("x5chain".into())
        });

        assert!(
            has_x5_in_rest,
            "x5chain should appear in protected.header.rest after parse; rest = {:?}",
            rest.iter().map(|(l, _)| l).collect::<Vec<_>>()
        );
    }

    /// Same flow as signature_from_ephemeral_signer_is_valid but split: get
    /// bytes via cose_sign, then run verify_cose on those bytes. Inspect
    /// whether the bytes parse with x5chain before calling verify_cose.
    #[test]
    fn ephemeral_signer_cose_sign_then_verify_cose() {
        let signer = EphemeralSigner::new("c2pa-archive.local").unwrap();
        let mut claim = Claim::new("ephemeral_sig_test", Some("contentauth"), 1);
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let mut settings = Settings::default();
        settings.verify.verify_trust = false;

        let tss = TimeStampStorage::V1_sigTst;

        let cose_bytes = cose_sign(&signer, &claim_bytes, signer.reserve_size(), tss, &settings)
            .expect("cose_sign with EphemeralSigner");

        let mut log = StatusTracker::default();
        let sign1 = parse_cose_sign1(&cose_bytes, &claim_bytes, &mut log).expect("parse COSE");
        let _chain = cert_chain_from_sign1(&sign1)
            .expect("cert_chain_from_sign1 on same bytes as inspection test");

        let mut validation_log = StatusTracker::default();
        let ctp = CertificateTrustPolicy::default();

        let result = verify_cose(
            &cose_bytes,
            &claim_bytes,
            b"",
            false,
            &ctp,
            None,
            &mut validation_log,
            &settings,
        );

        let info = result.expect("verify_cose on same bytes");
        assert!(info.validated, "signature must be validated");
    }

    /// Signs a minimal claim with [`EphemeralSigner`] and verifies the COSE
    /// signature (cert chain in protected header and signature over the
    /// claim).
    #[test]
    fn signature_from_ephemeral_signer_is_valid() {
        let signer = EphemeralSigner::new("c2pa-archive.local").unwrap();

        let mut claim = Claim::new("ephemeral_sig_test", Some("contentauth"), 1);
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let mut settings = Settings::default();
        settings.verify.verify_trust = false;

        let cose_bytes = sign_claim(&claim_bytes, &signer, signer.reserve_size(), &settings)
            .expect("sign_claim with EphemeralSigner");

        let mut validation_log = StatusTracker::default();
        let ctp = CertificateTrustPolicy::default();

        let result = verify_cose(
            &cose_bytes,
            &claim_bytes,
            b"",
            false,
            &ctp,
            None,
            &mut validation_log,
            &settings,
        );

        let info = result.expect("signature from EphemeralSigner must verify");
        assert!(
            info.validated,
            "EphemeralSigner signature must be validated"
        );
    }

    /// EphemeralSigner must place the full cert chain (EE + CA) in the COSE
    /// signature.
    #[test]
    fn ephemeral_signer_cose_chain_is_valid() {
        let signer = EphemeralSigner::new("c2pa-archive.local").expect("ephemeral signer");

        assert_eq!(
            signer.certs().unwrap().len(),
            2,
            "EphemeralSigner must hold EE + CA in cert_chain_der"
        );

        let mut claim = crate::claim::Claim::new("ephemeral_chain_test", Some("contentauth"), 1);
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let mut settings = Settings::default();
        settings.verify.verify_trust = false;

        let cose_bytes =
            crate::cose_sign::sign_claim(&claim_bytes, &signer, signer.reserve_size(), &settings)
                .expect("sign_claim with EphemeralSigner");

        let mut validation_log = StatusTracker::default();

        let sign1 = parse_cose_sign1(&cose_bytes, &claim_bytes, &mut validation_log)
            .expect("parse COSE produced by EphemeralSigner");

        let chain = cert_chain_from_sign1(&sign1)
            .expect("cert chain must be present in COSE signed by EphemeralSigner");

        assert_eq!(
            chain.len(),
            2,
            "COSE must contain full chain (EE + CA); got {} cert(s)",
            chain.len()
        );
    }
}
