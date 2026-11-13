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

use std::borrow::Cow;

use chrono::{DateTime, Utc};
pub use contentauth_pki::x509::profile::CertificateProfileError;
use contentauth_pki::x509::profile::{self, ProfilePolicy};
use web_time::SystemTime;

use crate::{
    crypto::{asn1::rfc3161::TstInfo, cose::CertificateTrustPolicy},
    log_item,
    status_tracker::StatusTracker,
    validation_results::validation_codes::*,
};

/// The use of a certificate, independent of its trust-anchor association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CertificateRole {
    ClaimSigner,
    CawgIdentity,
    TimestampSigner,
    DelegatedOcspResponder,
}

impl CertificateRole {
    pub(crate) fn check_profile(
        self,
        certificate_der: &[u8],
        policy: &CertificateTrustPolicy,
        validation_log: &mut StatusTracker,
        timestamp: Option<&TstInfo>,
    ) -> Result<(), CertificateProfileError> {
        let mut policy = Cow::Borrowed(policy);

        match self {
            Self::ClaimSigner => check_claim_signing_eku(certificate_der, validation_log)?,
            // Preserve CAWG's existing profile and configured purposes. Its
            // long-term identity-purpose policy is tracked in #3077.
            Self::CawgIdentity => {}
            Self::TimestampSigner | Self::DelegatedOcspResponder => {
                let policy = policy.to_mut();

                policy.clear_ekus();

                policy.add_mandatory_ekus(match self {
                    Self::TimestampSigner => b"1.3.6.1.5.5.7.3.8",
                    _ => b"1.3.6.1.5.5.7.3.9",
                });
            }
        }

        check_end_entity_certificate_profile_with_sdk_policy(
            certificate_der,
            &policy,
            validation_log,
            timestamp,
        )
    }

    pub(crate) fn check_purpose(
        self,
        certificate_der: &[u8],
        validation_log: &mut StatusTracker,
    ) -> Result<(), CertificateProfileError> {
        match self {
            Self::ClaimSigner => check_claim_signing_eku(certificate_der, validation_log),
            Self::CawgIdentity => Ok(()),
            Self::TimestampSigner | Self::DelegatedOcspResponder => self.check_profile(
                certificate_der,
                &CertificateTrustPolicy::new(),
                validation_log,
                None,
            ),
        }
    }
}

fn check_claim_signing_eku(
    certificate_der: &[u8],
    validation_log: &mut StatusTracker,
) -> Result<(), CertificateProfileError> {
    let result = profile::check_disallowed_ekus(
        certificate_der,
        &["1.3.6.1.5.5.7.3.8", "1.3.6.1.5.5.7.3.9"],
    );

    if let Err(error) = &result {
        log_item!(
            "",
            "certificate cannot authorize claim signing",
            "check_claim_signing_eku"
        )
        .validation_status(SIGNING_CREDENTIAL_INVALID)
        .failure_no_throw(validation_log, error);
    }

    result
}

/// Check the end-entity profile with SDK-selected policy, time and reporting.
///
/// Use [`ProfilePolicy::check_certificate`] with an explicit
/// [`ProfilePolicy`] whose `end_entity` field is `true`. Select role/EKU policy
/// and validation time in the host, and map profile failures to host reporting.
#[deprecated(
    note = "Use contentauth_pki::x509::profile::ProfilePolicy::check_certificate (end_entity = true) with host-selected validation time/reporting."
)]
pub fn check_end_entity_certificate_profile(
    certificate_der: &[u8],
    ctp: &CertificateTrustPolicy,
    validation_log: &mut StatusTracker,
    timestamp: Option<&TstInfo>,
) -> Result<(), CertificateProfileError> {
    check_end_entity_certificate_profile_with_sdk_policy(
        certificate_der,
        ctp,
        validation_log,
        timestamp,
    )
}

/// Check the certificate profile with SDK-selected policy, time and reporting.
///
/// Use [`ProfilePolicy::check_certificate`] with an explicit
/// [`ProfilePolicy`] whose `end_entity` field is `false`. Select role/EKU policy
/// and validation time in the host, and map profile failures to host reporting.
#[deprecated(
    note = "Use contentauth_pki::x509::profile::ProfilePolicy::check_certificate (end_entity = false) with host-selected validation time/reporting."
)]
pub fn check_certificate_profile(
    certificate_der: &[u8],
    ctp: &CertificateTrustPolicy,
    validation_log: &mut StatusTracker,
    timestamp: Option<&TstInfo>,
) -> Result<(), CertificateProfileError> {
    check_certificate_profile_with_sdk_policy(certificate_der, ctp, validation_log, timestamp)
}

pub(crate) fn check_end_entity_certificate_profile_with_sdk_policy(
    certificate_der: &[u8],
    ctp: &CertificateTrustPolicy,
    validation_log: &mut StatusTracker,
    timestamp: Option<&TstInfo>,
) -> Result<(), CertificateProfileError> {
    check_profile(certificate_der, ctp, validation_log, timestamp, true)
}

fn check_certificate_profile_with_sdk_policy(
    certificate_der: &[u8],
    ctp: &CertificateTrustPolicy,
    validation_log: &mut StatusTracker,
    timestamp: Option<&TstInfo>,
) -> Result<(), CertificateProfileError> {
    check_profile(certificate_der, ctp, validation_log, timestamp, false)
}

fn check_profile(
    certificate_der: &[u8],
    ctp: &CertificateTrustPolicy,
    validation_log: &mut StatusTracker,
    timestamp: Option<&TstInfo>,
    end_entity: bool,
) -> Result<(), CertificateProfileError> {
    let time = if let Some(timestamp) = timestamp {
        let time: DateTime<Utc> = timestamp.gen_time.clone().into();

        time.timestamp()
    } else {
        SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map_err(|_| CertificateProfileError::InternalError("system time invalid".into()))?
            .as_secs() as i64
    };

    let policy = ProfilePolicy {
        allowed_ekus: ctp.allowed_ekus(),
        mandatory_ekus: ctp.mandatory_ekus(),
        allow_email_protection_when_empty: true,
        allow_specialty_purposes: true,
        end_entity,
    };

    policy
        .check_certificate(certificate_der, time)
        .map(|_| ())
        .map_err(|error| {
            if let Some(description) = error.diagnostic {
                let status = if error.kind == CertificateProfileError::CertificateNotValidAtTime {
                    SIGNING_CREDENTIAL_EXPIRED
                } else {
                    SIGNING_CREDENTIAL_INVALID
                };

                log_item!("", description, "check_certificate_profile")
                    .validation_status(status)
                    .failure_no_throw(validation_log, &error.kind);
            }

            error.kind
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use rasn::{types::Any, Decoder, Encoder};
    use rasn_pkix::Certificate;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;
    use x509_parser::{pem::Pem, prelude::FromDer};

    use super::check_end_entity_certificate_profile_with_sdk_policy as check_end_entity_certificate_profile;
    use crate::{
        crypto::cose::CertificateTrustPolicy,
        status_tracker::StatusTracker,
        utils::ephemeral_cert::generate_ephemeral_chain,
        validation_results::validation_codes::{
            SIGNING_CREDENTIAL_EXPIRED, SIGNING_CREDENTIAL_INVALID,
        },
    };

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn expired_cert() {
        let ctp = CertificateTrustPolicy::default();
        let mut validation_log = StatusTracker::default();

        let cert_der = x509_der_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/cose/rsa-pss256_key-expired.pub"
        ));

        assert!(
            check_end_entity_certificate_profile(&cert_der, &ctp, &mut validation_log, None)
                .is_err()
        );

        assert!(!validation_log.logged_items().is_empty());

        assert_eq!(
            validation_log.logged_items()[0].validation_status,
            Some(SIGNING_CREDENTIAL_EXPIRED.into())
        );
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn cert_algorithms() {
        let ctp = CertificateTrustPolicy::default();

        let mut validation_log = StatusTracker::default();

        let es256_cert = x509_der_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es256.pub"
        ));

        let es384_cert = x509_der_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es384.pub"
        ));

        let es512_cert = x509_der_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es512.pub"
        ));

        let ps256_cert = x509_der_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps256.pub"
        ));

        check_end_entity_certificate_profile(&es256_cert, &ctp, &mut validation_log, None).unwrap();
        check_end_entity_certificate_profile(&es384_cert, &ctp, &mut validation_log, None).unwrap();
        check_end_entity_certificate_profile(&es512_cert, &ctp, &mut validation_log, None).unwrap();
        check_end_entity_certificate_profile(&ps256_cert, &ctp, &mut validation_log, None).unwrap();
    }

    // https://datatracker.ietf.org/doc/html/rfc8410#section-3
    // Ed25519 spec: "For all of the OIDs, the parameters MUST be absent."
    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn ed25519_algorithm_parameters_must_be_absent() {
        let der_null = Any::new(vec![0x05, 0x00]);
        let ctp = CertificateTrustPolicy::default();

        let chain = generate_ephemeral_chain("ed25519-profile.local").unwrap();

        let mut validation_log = StatusTracker::default();

        check_end_entity_certificate_profile(&chain.ee_der, &ctp, &mut validation_log, None)
            .unwrap();

        let assert_rejected = |cert: &Certificate, expected_description: &str| {
            let der = rasn::der::encode(cert).unwrap();
            let mut validation_log = StatusTracker::default();

            assert!(
                check_end_entity_certificate_profile(&der, &ctp, &mut validation_log, None)
                    .is_err()
            );

            let item = &validation_log.logged_items()[0];

            assert_eq!(
                item.validation_status,
                Some(SIGNING_CREDENTIAL_INVALID.into())
            );

            assert_eq!(item.description, expected_description);
        };

        // Parameters in the subject public key info algorithm.
        let mut cert: Certificate = rasn::der::decode(&chain.ee_der).unwrap();

        cert.tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters = Some(der_null.clone());

        assert_rejected(
            &cert,
            "certificate Ed25519 public key parameters must be absent",
        );

        // Parameters in both the outer and the signed (tbsCertificate) signature algorithm.
        let mut cert: Certificate = rasn::der::decode(&chain.ee_der).unwrap();
        cert.signature_algorithm.parameters = Some(der_null.clone());
        cert.tbs_certificate.signature.parameters = Some(der_null.clone());

        assert_rejected(
            &cert,
            "certificate Ed25519 signature algorithm parameters must be absent",
        );
    }

    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.3
    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn signature_algorithm_must_match_tbs_signature() {
        let der_null = Any::new(vec![0x05, 0x00]);
        let ctp = CertificateTrustPolicy::default();

        let chain = generate_ephemeral_chain("ed25519-profile.local").unwrap();

        let expected =
            "certificate signature algorithm does not match tbsCertificate signature algorithm";

        // Parameters only in the outer signature algorithm.
        let mut cert: Certificate = rasn::der::decode(&chain.ee_der).unwrap();
        cert.signature_algorithm.parameters = Some(der_null.clone());

        // Parameters only in the signed (tbsCertificate) signature algorithm.
        let mut cert_inner: Certificate = rasn::der::decode(&chain.ee_der).unwrap();
        cert_inner.tbs_certificate.signature.parameters = Some(der_null);

        for cert in [cert, cert_inner] {
            let der = rasn::der::encode(&cert).unwrap();
            let mut validation_log = StatusTracker::default();

            assert!(
                check_end_entity_certificate_profile(&der, &ctp, &mut validation_log, None)
                    .is_err()
            );

            let item = &validation_log.logged_items()[0];

            assert_eq!(
                item.validation_status,
                Some(SIGNING_CREDENTIAL_INVALID.into())
            );

            assert_eq!(item.description, expected);
        }
    }

    // C2PA Trust Model, Certificate Profiles: "Certificates used to sign C2PA
    // manifests shall assert the digitalSignature bit. The keyCertSign bit shall
    // only be asserted if the cA boolean is asserted."
    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn end_entity_key_usage() {
        let ctp = CertificateTrustPolicy::default();

        for (cert_pem, expected_description) in [
            (
                include_bytes!("../../../tests/fixtures/crypto/cose/ku_keycertsign_not_ca.pub")
                    .as_slice(),
                "certificate asserts keyCertSign key usage but is not a CA",
            ),
            (
                include_bytes!("../../../tests/fixtures/crypto/cose/ku_nonrepudiation_only.pub")
                    .as_slice(),
                "certificate missing digitalSignature key usage",
            ),
        ] {
            let mut validation_log = StatusTracker::default();

            assert!(check_end_entity_certificate_profile(
                &x509_der_from_pem(cert_pem),
                &ctp,
                &mut validation_log,
                None
            )
            .is_err());

            let item = &validation_log.logged_items()[0];

            assert_eq!(
                item.validation_status,
                Some(SIGNING_CREDENTIAL_INVALID.into())
            );

            assert_eq!(item.description, expected_description);
        }

        // A time-stamping certificate may assert nonRepudiation without
        // digitalSignature (RFC 3161, section 2.3).
        let mut validation_log = StatusTracker::default();

        check_end_entity_certificate_profile(
            &x509_der_from_pem(include_bytes!(
                "../../../tests/fixtures/crypto/cose/ku_nonrepudiation_tsa.pub"
            )),
            &ctp,
            &mut validation_log,
            None,
        )
        .unwrap();
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn ocsp_signing_allows_nonrepudiation_without_digital_signature() {
        let chain = generate_ephemeral_chain("ocsp-key-usage.local").unwrap();
        let mut cert: Certificate = rasn::der::decode(&chain.ee_der).unwrap();

        // KeyUsage BIT STRING with only nonRepudiation asserted.
        extension(&mut cert, &[2, 5, 29, 15], vec![0x03, 0x02, 0x06, 0x40]);

        extension(
            &mut cert,
            &[2, 5, 29, 37],
            rasn::der::encode(&vec![oid(&[1, 3, 6, 1, 5, 5, 7, 3, 9])]).unwrap(),
        );

        let ctp = CertificateTrustPolicy::default();
        let mut validation_log = StatusTracker::default();

        assert_eq!(
            check_end_entity_certificate_profile(
                &rasn::der::encode(&cert).unwrap(),
                &ctp,
                &mut validation_log,
                None,
            ),
            Ok(())
        );

        assert!(validation_log.logged_items().is_empty());

        // The same key usage must still be rejected for manifest signing.
        extension(
            &mut cert,
            &[2, 5, 29, 37],
            rasn::der::encode(&vec![oid(&[1, 3, 6, 1, 5, 5, 7, 3, 4])]).unwrap(),
        );

        let mut validation_log = StatusTracker::default();

        assert_eq!(
            check_end_entity_certificate_profile(
                &rasn::der::encode(&cert).unwrap(),
                &ctp,
                &mut validation_log,
                None,
            ),
            Err(super::CertificateProfileError::InvalidCertificate)
        );

        let item = &validation_log.logged_items()[0];

        assert_eq!(
            item.validation_status,
            Some(SIGNING_CREDENTIAL_INVALID.into())
        );

        assert_eq!(
            item.description,
            "certificate missing digitalSignature key usage"
        );
    }

    fn x509_der_from_pem(cert_pem: &[u8]) -> Vec<u8> {
        let mut pems = Pem::iter_from_buffer(cert_pem);
        let pem = pems.next().unwrap().unwrap();

        pem.contents
    }

    fn profile_cert() -> Certificate {
        rasn::der::decode(&x509_der_from_pem(include_bytes!(
            "../../../tests/fixtures/certs/ed25519.pub"
        )))
        .unwrap()
    }

    fn oid(value: &[u32]) -> rasn::types::ObjectIdentifier {
        rasn::types::ObjectIdentifier::new(value.to_vec()).unwrap()
    }

    fn extension(cert: &mut Certificate, id: &[u32], value: Vec<u8>) {
        let extensions = cert.tbs_certificate.extensions.as_mut().unwrap();

        let existing = extensions
            .iter_mut()
            .find(|e| e.extn_id == oid(id))
            .unwrap();

        existing.extn_value = value.into();
    }

    fn assert_profile_error(cert: &Certificate, expected: super::CertificateProfileError) {
        // These mutations test profile validation, not certificate signature verification.
        let der = rasn::der::encode(cert).unwrap();
        let mut log = StatusTracker::default();

        let result = super::check_certificate_profile_with_sdk_policy(
            &der,
            &CertificateTrustPolicy::default(),
            &mut log,
            None,
        );

        assert_eq!(result, Err(expected));
    }

    #[test]
    fn malformed_version_algorithm_curve_and_unique_ids_are_rejected() {
        let mut log = StatusTracker::default();

        assert_eq!(
            check_end_entity_certificate_profile(
                b"invalid DER",
                &CertificateTrustPolicy::default(),
                &mut log,
                None,
            ),
            Err(super::CertificateProfileError::InvalidCertificate)
        );

        assert!(log.has_status(SIGNING_CREDENTIAL_INVALID));

        let mut cert = profile_cert();
        cert.tbs_certificate.version = rasn_pkix::Version::V2;

        assert_profile_error(
            &cert,
            super::CertificateProfileError::InvalidCertificateVersion,
        );

        let mut cert = profile_cert();
        cert.signature_algorithm.algorithm = oid(&[1, 2, 3, 4]);
        cert.tbs_certificate.signature = cert.signature_algorithm.clone();

        assert_profile_error(&cert, super::CertificateProfileError::UnsupportedAlgorithm);

        for issuer in [false, true] {
            let mut cert = profile_cert();

            if issuer {
                cert.tbs_certificate.issuer_unique_id =
                    Some(rasn::types::BitString::from_slice(&[1]));
            } else {
                cert.tbs_certificate.subject_unique_id =
                    Some(rasn::types::BitString::from_slice(&[1]));
            }

            assert_profile_error(&cert, super::CertificateProfileError::InvalidCertificate);
        }

        for parameters in [
            None,
            Some(Any::new(vec![5, 0])),
            Some(Any::new(rasn::der::encode(&oid(&[1, 2, 3, 4])).unwrap())),
        ] {
            let mut cert = profile_cert();

            cert.tbs_certificate.subject_public_key_info.algorithm =
                rasn_pkix::AlgorithmIdentifier {
                    algorithm: oid(&[1, 2, 840, 10045, 2, 1]),
                    parameters,
                };

            assert_profile_error(&cert, super::CertificateProfileError::InvalidCertificate);
        }
    }

    #[test]
    fn eku_combinations_and_required_extensions_are_enforced() {
        for ekus in [
            vec![oid(&[2, 5, 29, 37, 0])],
            vec![oid(&[1, 2, 3, 4])],
            vec![
                oid(&[1, 3, 6, 1, 5, 5, 7, 3, 8]),
                oid(&[1, 3, 6, 1, 5, 5, 7, 3, 9]),
            ],
            vec![
                oid(&[1, 3, 6, 1, 5, 5, 7, 3, 8]),
                oid(&[1, 3, 6, 1, 5, 5, 7, 3, 4]),
            ],
        ] {
            let mut cert = profile_cert();

            extension(
                &mut cert,
                &[2, 5, 29, 37],
                rasn::der::encode(&ekus).unwrap(),
            );

            assert_profile_error(&cert, super::CertificateProfileError::InvalidCertificate);
        }

        for removed in [&[2, 5, 29, 35][..], &[2, 5, 29, 15], &[2, 5, 29, 37]] {
            let mut cert = profile_cert();

            cert.tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .retain(|e| e.extn_id != oid(removed));

            assert_profile_error(&cert, super::CertificateProfileError::InvalidCertificate);
        }

        for usage in [vec![3, 2, 2, 0x84], vec![3, 2, 0, 0]] {
            let mut cert = profile_cert();
            extension(&mut cert, &[2, 5, 29, 15], usage);

            assert_profile_error(&cert, super::CertificateProfileError::InvalidCertificate);
        }

        for critical in [false, true] {
            let mut cert = profile_cert();

            cert.tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .push(rasn_pkix::Extension {
                    extn_id: oid(&[1, 2, 3, 4]),
                    critical,
                    extn_value: vec![5, 0].into(),
                });

            let mut log = StatusTracker::default();

            let result = super::check_certificate_profile_with_sdk_policy(
                &rasn::der::encode(&cert).unwrap(),
                &CertificateTrustPolicy::default(),
                &mut log,
                None,
            );

            assert_eq!(result.is_err(), critical);
            assert_eq!(log.has_status(SIGNING_CREDENTIAL_INVALID), critical);
        }
    }

    #[test]
    fn mandatory_ekus_are_reported_and_ca_is_not_an_end_entity() {
        let mut ctp = CertificateTrustPolicy::default();
        ctp.add_mandatory_ekus(b"1.3.6.1.5.5.7.3.8");

        let cert = profile_cert();
        let mut log = StatusTracker::default();

        assert_eq!(
            check_end_entity_certificate_profile(
                &rasn::der::encode(&cert).unwrap(),
                &ctp,
                &mut log,
                None,
            ),
            Err(super::CertificateProfileError::InvalidEku)
        );

        assert!(log.has_status(SIGNING_CREDENTIAL_INVALID));

        assert!(log
            .logged_items()
            .iter()
            .any(|item| item.description == "certificate missing mandatory EKU"));

        let mut cert = profile_cert();
        extension(&mut cert, &[2, 5, 29, 19], vec![0x30, 3, 1, 1, 0xff]);
        extension(&mut cert, &[2, 5, 29, 15], vec![3, 2, 1, 6]);

        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .retain(|e| e.extn_id != oid(&[2, 5, 29, 37]));

        let der = rasn::der::encode(&cert).unwrap();
        let mut log = StatusTracker::default();

        assert_eq!(
            check_end_entity_certificate_profile(&der, &ctp, &mut log, None),
            Err(super::CertificateProfileError::InvalidEku)
        );

        assert!(log.has_status(SIGNING_CREDENTIAL_INVALID));

        assert!(log
            .logged_items()
            .iter()
            .any(|item| item.description == "certificate missing mandatory EKU"));

        ctp.clear_ekus();
        let mut log = StatusTracker::default();

        assert_eq!(
            check_end_entity_certificate_profile(&der, &ctp, &mut log, None),
            Err(super::CertificateProfileError::InvalidCertificate)
        );

        assert!(log
            .logged_items()
            .iter()
            .any(|item| item.description == "expected end-entity certificate"));

        cert.tbs_certificate.issuer = cert.tbs_certificate.subject.clone();

        assert_profile_error(&cert, super::CertificateProfileError::SelfSignedCertificate);
    }

    #[test]
    fn mandatory_ekus_reject_other_allowed_purposes() {
        let claim_signing = oid(&[1, 3, 6, 1, 4, 1, 62558, 2, 1]);
        let email = oid(&[1, 3, 6, 1, 5, 5, 7, 3, 4]);
        let timestamp = oid(&[1, 3, 6, 1, 5, 5, 7, 3, 8]);
        let ocsp = oid(&[1, 3, 6, 1, 5, 5, 7, 3, 9]);

        for required in [&timestamp, &ocsp] {
            for purposes in [
                vec![claim_signing.clone()],
                vec![email.clone()],
                vec![email.clone(), claim_signing.clone()],
                vec![timestamp.clone()],
                vec![ocsp.clone()],
            ] {
                let mut cert = profile_cert();

                extension(
                    &mut cert,
                    &[2, 5, 29, 37],
                    rasn::der::encode(&purposes).unwrap(),
                );

                let mut ctp = CertificateTrustPolicy::default();
                ctp.add_mandatory_ekus(required.to_string().as_bytes());

                let mut log = StatusTracker::default();

                let result = check_end_entity_certificate_profile(
                    &rasn::der::encode(&cert).unwrap(),
                    &ctp,
                    &mut log,
                    None,
                );

                if purposes.contains(required) {
                    assert_eq!(result, Ok(()));
                    assert!(!log.has_status(SIGNING_CREDENTIAL_INVALID));
                } else {
                    assert_eq!(result, Err(super::CertificateProfileError::InvalidEku));
                    assert!(log.has_status(SIGNING_CREDENTIAL_INVALID));

                    assert!(log
                        .logged_items()
                        .iter()
                        .any(|item| { item.description == "certificate missing mandatory EKU" }));
                }
            }
        }
    }

    #[test]
    fn role_eku_matrix() {
        let email = oid(&[1, 3, 6, 1, 5, 5, 7, 3, 4]);
        let document = oid(&[1, 3, 6, 1, 5, 5, 7, 3, 36]);
        let microsoft = oid(&[1, 3, 6, 1, 4, 1, 311, 76, 59, 1, 9]);
        let claim = oid(&[1, 3, 6, 1, 4, 1, 62558, 2, 1]);
        let timestamp = oid(&[1, 3, 6, 1, 5, 5, 7, 3, 8]);
        let ocsp = oid(&[1, 3, 6, 1, 5, 5, 7, 3, 9]);
        let any = oid(&[2, 5, 29, 37, 0]);

        for purposes in [
            vec![email.clone()],
            vec![document.clone()],
            vec![microsoft],
            vec![claim.clone()],
            vec![email.clone(), claim],
            vec![timestamp.clone()],
            vec![ocsp.clone()],
            vec![timestamp.clone(), email.clone()],
            vec![timestamp.clone(), ocsp.clone()],
            vec![any],
            vec![],
        ] {
            let mut cert = profile_cert();
            extension(
                &mut cert,
                &[2, 5, 29, 37],
                rasn::der::encode(&purposes).unwrap(),
            );

            let der = rasn::der::encode(&cert).unwrap();

            for use_defaults in [false, true] {
                for configured in [
                    None,
                    Some(""),
                    Some("1.3.6.1.5.5.7.3.36"),
                    Some("1.3.6.1.5.5.7.3.8\n1.3.6.1.5.5.7.3.9"),
                ] {
                    let mut policy = CertificateTrustPolicy::new();

                    if use_defaults {
                        policy.add_default_valid_ekus();
                    }

                    if let Some(configured) = configured {
                        policy.add_valid_ekus(configured.as_bytes());
                    }

                    let mut log = StatusTracker::default();

                    let result = super::CertificateRole::ClaimSigner
                        .check_profile(&der, &policy, &mut log, None);

                    let specialty = purposes.contains(&timestamp) || purposes.contains(&ocsp);

                    let allowed = !specialty
                        && !purposes.is_empty()
                        && purposes[0] != oid(&[2, 5, 29, 37, 0])
                        && (use_defaults
                            || (configured.unwrap_or_default().is_empty()
                                && purposes.contains(&email))
                            || (configured == Some("1.3.6.1.5.5.7.3.36")
                                && purposes.contains(&document)));

                    assert_eq!(
                        result.is_ok(),
                        allowed,
                        "{purposes:?}, {use_defaults}, {configured:?}"
                    );

                    assert_eq!(log.has_status(SIGNING_CREDENTIAL_INVALID), !allowed);

                    if specialty {
                        assert_eq!(result, Err(super::CertificateProfileError::InvalidEku));
                    }

                    let mut identity_log = StatusTracker::default();

                    let identity_result = super::CertificateRole::CawgIdentity.check_profile(
                        &der,
                        &policy,
                        &mut identity_log,
                        None,
                    );

                    let mut generic_log = StatusTracker::default();

                    let generic_result =
                        check_end_entity_certificate_profile(&der, &policy, &mut generic_log, None);

                    assert_eq!(identity_result, generic_result);

                    assert_eq!(
                        identity_log.has_status(SIGNING_CREDENTIAL_INVALID),
                        generic_log.has_status(SIGNING_CREDENTIAL_INVALID)
                    );

                    for (role, required) in [
                        (super::CertificateRole::TimestampSigner, &timestamp),
                        (super::CertificateRole::DelegatedOcspResponder, &ocsp),
                    ] {
                        let mut log = StatusTracker::default();

                        let result = role.check_profile(&der, &policy, &mut log, None);

                        let allowed = purposes.len() == 1 && purposes[0] == *required;

                        assert_eq!(result.is_ok(), allowed);
                        assert_eq!(log.has_status(SIGNING_CREDENTIAL_INVALID), !allowed);

                        if purposes.len() == 1 && purposes[0] == email {
                            assert_eq!(result, Err(super::CertificateProfileError::InvalidEku));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn rsa_public_key_shape_size_and_exponent_are_checked() {
        for key in [
            vec![0x30, 0],
            vec![0x30, 3, 2, 1, 3],
            vec![0x30, 6, 2, 1, 3, 2, 1, 3],
        ] {
            let mut cert = profile_cert();

            cert.tbs_certificate.subject_public_key_info.algorithm =
                rasn_pkix::AlgorithmIdentifier {
                    algorithm: oid(&[1, 2, 840, 113549, 1, 1, 1]),
                    parameters: Some(Any::new(vec![5, 0])),
                };

            cert.tbs_certificate
                .subject_public_key_info
                .subject_public_key = rasn::types::BitString::from_slice(&key);

            let der = rasn::der::encode(&cert).unwrap();

            assert_eq!(
                super::check_certificate_profile_with_sdk_policy(
                    &der,
                    &CertificateTrustPolicy::default(),
                    &mut StatusTracker::default(),
                    None
                ),
                Err(super::CertificateProfileError::InvalidCertificate)
            );
        }

        #[derive(rasn::AsnType, rasn::Encode, rasn::Decode)]
        struct RsaKey {
            modulus: rasn::types::Integer,
            exponent: rasn::types::Integer,
        }

        let mut cert: Certificate = rasn::der::decode(&x509_der_from_pem(include_bytes!(
            "../../../tests/fixtures/certs/ps256.pub"
        )))
        .unwrap();

        let key: RsaKey = rasn::der::decode(
            cert.tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_raw_slice(),
        )
        .unwrap();

        let invalid = RsaKey {
            modulus: key.modulus,
            exponent: 2.into(),
        };

        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key =
            rasn::types::BitString::from_slice(&rasn::der::encode(&invalid).unwrap());

        assert_profile_error(&cert, super::CertificateProfileError::InvalidCertificate);
    }

    #[test]
    fn pss_parameters_require_matching_supported_hashes() {
        #[derive(rasn::AsnType, rasn::Encode)]
        struct PssParameters {
            #[rasn(tag(explicit(0)))]
            hash: rasn_pkix::AlgorithmIdentifier,
            #[rasn(tag(explicit(1)))]
            mask: rasn_pkix::AlgorithmIdentifier,
        }

        for (hash, mask_hash, valid) in [
            (
                vec![2, 16, 840, 1, 101, 3, 4, 2, 1],
                vec![2, 16, 840, 1, 101, 3, 4, 2, 1],
                true,
            ),
            (
                vec![2, 16, 840, 1, 101, 3, 4, 2, 2],
                vec![2, 16, 840, 1, 101, 3, 4, 2, 2],
                true,
            ),
            (
                vec![2, 16, 840, 1, 101, 3, 4, 2, 3],
                vec![2, 16, 840, 1, 101, 3, 4, 2, 3],
                true,
            ),
            (vec![1, 3, 14, 3, 2, 26], vec![1, 3, 14, 3, 2, 26], false),
            (
                vec![2, 16, 840, 1, 101, 3, 4, 2, 1],
                vec![2, 16, 840, 1, 101, 3, 4, 2, 2],
                false,
            ),
        ] {
            let hash_alg = rasn_pkix::AlgorithmIdentifier {
                algorithm: oid(&hash),
                parameters: None,
            };

            let mask_alg = rasn_pkix::AlgorithmIdentifier {
                algorithm: oid(&mask_hash),
                parameters: None,
            };

            let params = rasn::der::encode(&PssParameters {
                hash: hash_alg,
                mask: rasn_pkix::AlgorithmIdentifier {
                    algorithm: oid(&[1, 2, 840, 113549, 1, 1, 8]),
                    parameters: Some(Any::new(rasn::der::encode(&mask_alg).unwrap())),
                },
            })
            .unwrap();

            let mut cert = profile_cert();

            cert.signature_algorithm = rasn_pkix::AlgorithmIdentifier {
                algorithm: oid(&[1, 2, 840, 113549, 1, 1, 10]),
                parameters: Some(Any::new(params)),
            };

            cert.tbs_certificate.signature = cert.signature_algorithm.clone();

            let mut log = StatusTracker::default();

            let result = super::check_certificate_profile_with_sdk_policy(
                &rasn::der::encode(&cert).unwrap(),
                &CertificateTrustPolicy::default(),
                &mut log,
                None,
            );

            assert_eq!(
                result.is_ok(),
                valid,
                "{hash:?} / {mask_hash:?}: {result:?}"
            );

            assert_eq!(log.has_status(SIGNING_CREDENTIAL_INVALID), !valid);
        }

        let mut cert = profile_cert();

        cert.signature_algorithm = rasn_pkix::AlgorithmIdentifier {
            algorithm: oid(&[1, 2, 840, 113549, 1, 1, 10]),
            parameters: None,
        };

        cert.tbs_certificate.signature = cert.signature_algorithm.clone();

        assert_profile_error(&cert, super::CertificateProfileError::InvalidCertificate);
    }

    fn timestamp_at(seconds: i64) -> crate::crypto::asn1::rfc3161::TstInfo {
        use bcder::decode::Constructed;

        #[derive(rasn::AsnType, rasn::Encode)]
        struct Imprint {
            algorithm: rasn_pkix::AlgorithmIdentifier,
            digest: rasn::types::OctetString,
        }

        #[derive(rasn::AsnType, rasn::Encode)]
        struct Timestamp {
            version: rasn::types::Integer,
            policy: rasn::types::ObjectIdentifier,
            imprint: Imprint,
            serial: rasn::types::Integer,
            time: rasn::types::GeneralizedTime,
        }

        let bytes = rasn::der::encode(&Timestamp {
            version: 1.into(),
            policy: oid(&[1, 2, 3]),
            imprint: Imprint {
                algorithm: rasn_pkix::AlgorithmIdentifier {
                    algorithm: oid(&[2, 16, 840, 1, 101, 3, 4, 2, 1]),
                    parameters: None,
                },
                digest: vec![0; 32].into(),
            },
            serial: 1.into(),
            time: chrono::DateTime::from_timestamp(seconds, 0).unwrap().into(),
        })
        .unwrap();

        Constructed::decode(
            bytes.as_slice(),
            bcder::Mode::Der,
            crate::crypto::asn1::rfc3161::TstInfo::take_from,
        )
        .unwrap()
    }

    #[test]
    fn supplied_timestamp_checks_both_validity_boundaries_inclusively() {
        let cert = profile_cert();
        let der = rasn::der::encode(&cert).unwrap();
        let (_, parsed) = x509_parser::prelude::X509Certificate::from_der(&der).unwrap();
        let start = parsed.validity().not_before.timestamp();
        let end = parsed.validity().not_after.timestamp();
        let ctp = CertificateTrustPolicy::default();

        for (time, valid) in [
            (start - 1, false),
            (start, true),
            (end, true),
            (end + 1, false),
        ] {
            let timestamp = timestamp_at(time);
            let mut log = StatusTracker::default();

            let result =
                check_end_entity_certificate_profile(&der, &ctp, &mut log, Some(&timestamp));

            if valid {
                assert_eq!(result, Ok(()));
                assert!(!log.has_any_error());
            } else {
                assert_eq!(
                    result,
                    Err(super::CertificateProfileError::CertificateNotValidAtTime)
                );

                assert!(log.has_status(SIGNING_CREDENTIAL_EXPIRED));
                assert_eq!(log.logged_items()[0].description, "certificate expired");
            }
        }
    }

    #[test]
    fn malformed_pss_parameter_structures_fail_closed() {
        let sha256 = rasn_pkix::AlgorithmIdentifier {
            algorithm: oid(&[2, 16, 840, 1, 101, 3, 4, 2, 1]),
            parameters: None,
        };

        let hash = rasn::der::encode(&sha256).unwrap();
        let mut malformed = vec![
            vec![5, 0],
            vec![0x30, 0],
            vec![0x30, 2, 0xa1, 0],
            vec![0x30, 2, 0xa0, 0],
        ];

        for tag in [0xa0, 0x81, 0xa1] {
            let second = if tag == 0xa1 {
                vec![tag, 0]
            } else {
                vec![tag, 2, 5, 0]
            };

            let mut body = vec![0xa0, hash.len() as u8];
            body.extend_from_slice(&hash);
            body.extend_from_slice(&second);

            let mut sequence = vec![0x30, body.len() as u8];
            sequence.extend_from_slice(&body);

            malformed.push(sequence);
        }

        for params in malformed {
            let mut cert = profile_cert();

            cert.signature_algorithm = rasn_pkix::AlgorithmIdentifier {
                algorithm: oid(&[1, 2, 840, 113549, 1, 1, 10]),
                parameters: Some(Any::new(params)),
            };

            cert.tbs_certificate.signature = cert.signature_algorithm.clone();

            let result = super::check_certificate_profile_with_sdk_policy(
                &rasn::der::encode(&cert).unwrap(),
                &CertificateTrustPolicy::default(),
                &mut StatusTracker::default(),
                None,
            );

            assert_eq!(
                result,
                Err(super::CertificateProfileError::InvalidCertificate)
            );
        }
    }

    #[test]
    fn recognized_critical_extensions_do_not_look_like_unknown_extensions() {
        use x509_parser::extensions::ParsedExtension;

        let fixtures = [
            (
                vec![2, 5, 29, 33],
                vec![0x30, 10, 0x30, 8, 6, 2, 42, 3, 6, 2, 42, 4],
                "PolicyMappings",
            ),
            (
                vec![2, 5, 29, 30],
                [
                    &[0x30, 17, 0xa0, 15, 0x30, 13, 0x82, 11][..],
                    b"example.com",
                ]
                .concat(),
                "NameConstraints",
            ),
            (
                vec![2, 5, 29, 36],
                vec![0x30, 3, 0x80, 1, 0],
                "PolicyConstraints",
            ),
            (vec![2, 5, 29, 54], vec![2, 1, 0], "InhibitAnyPolicy"),
            (
                vec![2, 16, 840, 1, 113730, 1, 1],
                vec![3, 2, 0, 0x80],
                "NSCertType",
            ),
            (vec![2, 5, 29, 20], vec![2, 1, 1], "CRLNumber"),
            (vec![2, 5, 29, 21], vec![10, 1, 0], "ReasonCode"),
            (
                vec![2, 5, 29, 24],
                [&[0x18, 15][..], b"20200101000000Z"].concat(),
                "InvalidityDate",
            ),
        ];

        for (id, value, expected) in fixtures {
            let mut cert = profile_cert();
            let id = oid(&id);

            cert.tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .push(rasn_pkix::Extension {
                    extn_id: id.clone(),
                    critical: true,
                    extn_value: value.into(),
                });

            let der = rasn::der::encode(&cert).unwrap();
            let (_, parsed) = x509_parser::prelude::X509Certificate::from_der(&der).unwrap();

            let parsed_extension = parsed
                .extensions()
                .iter()
                .find(|extension| extension.oid.to_id_string() == id.to_string())
                .unwrap();

            let actual = match parsed_extension.parsed_extension() {
                ParsedExtension::PolicyMappings(_) => "PolicyMappings",
                ParsedExtension::NameConstraints(_) => "NameConstraints",
                ParsedExtension::PolicyConstraints(_) => "PolicyConstraints",
                ParsedExtension::InhibitAnyPolicy(_) => "InhibitAnyPolicy",
                ParsedExtension::NSCertType(_) => "NSCertType",
                ParsedExtension::CRLNumber(_) => "CRLNumber",
                ParsedExtension::ReasonCode(_) => "ReasonCode",
                ParsedExtension::InvalidityDate(_) => "InvalidityDate",
                other => panic!("unexpected extension: {other:?}"),
            };

            assert_eq!(actual, expected);

            let mut log = StatusTracker::default();

            check_end_entity_certificate_profile(
                &der,
                &CertificateTrustPolicy::default(),
                &mut log,
                None,
            )
            .unwrap();

            assert!(!log.has_any_error(), "{expected}");
        }
    }
}
