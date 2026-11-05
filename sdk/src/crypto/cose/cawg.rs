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

use asn1_rs::FromDer;
use async_generic::async_generic;
use chrono::{DateTime, Utc};
use coset::CoseSign1;
use x509_parser::{
    der_parser::oid,
    extensions::{ExtendedKeyUsage, ParsedExtension},
    prelude::X509Certificate,
};

use super::{
    cert_chain_from_sign1, get_cose_tst_info, parse_cose_sign1, validate_cose_tst_info,
    CertificateInfo, CertificateTrustError, CertificateTrustPolicy, CoseError, TimeStampStorage,
    Verifier,
};
use crate::{
    crypto::{
        asn1::rfc3161::TstInfo,
        time_stamp::{verify_time_stamp, TimeStampError},
    },
    log_item,
    status_tracker::StatusTracker,
    validation_status,
};

// The first instant outside 31 March 2027, in UTC.
const INTERIM_TRUST_END: i64 = 1_806_537_600;
const DOCUMENT_SIGNING: &str = "1.3.6.1.5.5.7.3.36";
const SMIME_POLICIES: [&str; 6] = [
    "2.23.140.1.5.2.2",
    "2.23.140.1.5.2.3",
    "2.23.140.1.5.3.2",
    "2.23.140.1.5.3.3",
    "2.23.140.1.5.4.2",
    "2.23.140.1.5.4.3",
];

fn interim_certificate_is_acceptable(
    certificate_der: &[u8],
    now: DateTime<Utc>,
    trusted_timestamp: Option<&TstInfo>,
    policy: &CertificateTrustPolicy,
) -> Result<bool, CoseError> {
    let (_, certificate) = X509Certificate::from_der(certificate_der)
        .map_err(|_| CertificateTrustError::InvalidCertificate)?;
    let eku = certificate
        .extended_key_usage()
        .map_err(|_| CertificateTrustError::InvalidEku)?
        .ok_or(CertificateTrustError::InvalidEku)?;

    // Either accepted purpose can establish trust; documentSigning is not an
    // interim purpose, including when a certificate also has emailProtection.
    let document_signing = ExtendedKeyUsage {
        any: false,
        server_auth: false,
        client_auth: false,
        code_signing: false,
        email_protection: false,
        time_stamping: false,
        ocsp_signing: false,
        other: vec![oid!(1.3.6 .1 .5 .5 .7 .3 .36)],
    };
    if eku
        .value
        .other
        .iter()
        .any(|oid| oid.to_id_string() == DOCUMENT_SIGNING)
        && policy.has_allowed_eku(&document_signing).is_some()
    {
        return Ok(true);
    }

    // Other configured purposes keep their existing profile/trust rules.
    if !eku.value.email_protection {
        return Ok(true);
    }

    if !(now.timestamp() < INTERIM_TRUST_END
        || trusted_timestamp.is_some_and(|tst| {
            let time: DateTime<Utc> = tst.gen_time.clone().into();
            time.timestamp() < INTERIM_TRUST_END
        }))
    {
        return Ok(false);
    }

    let mut found = false;
    for extension in certificate.extensions() {
        if extension.oid.to_id_string() != "2.5.29.32" {
            continue;
        }

        match extension.parsed_extension() {
            ParsedExtension::CertificatePolicies(policies) if !found => {
                found = true;
                if !policies.iter().any(|policy| {
                    SMIME_POLICIES.contains(&policy.policy_id.to_id_string().as_str())
                }) {
                    return Ok(false);
                }
            }
            // Duplicate or malformed certificatePolicies must not grant trust.
            _ => return Err(CertificateTrustError::InvalidCertificate.into()),
        }
    }

    Ok(found)
}

/// Only this path may promote an assertion-local timestamp to trusted signing
/// time. In particular, a legacy timestamp or a caller-provided TstInfo is not
/// sufficient evidence for the CAWG interim cutoff.
pub(crate) fn trusted_cawg_timestamp(
    sign1: &CoseSign1,
    data: &[u8],
    policy: &CertificateTrustPolicy,
    validation_log: &mut StatusTracker,
) -> Option<TstInfo> {
    let mut timestamp_sign1 = sign1.clone();
    // A legacy header must not shadow a usable sigTst2 header.
    if timestamp_sign1
        .unprotected
        .rest
        .iter()
        .any(|(label, _)| *label == coset::Label::Text("sigTst2".into()))
    {
        timestamp_sign1
            .unprotected
            .rest
            .retain(|(label, _)| *label != coset::Label::Text("sigTst".into()));
    }

    let (_, storage) = get_cose_tst_info(&timestamp_sign1)?;
    if storage != TimeStampStorage::V2_sigTst2_CTT {
        log_item!("", "CAWG requires a v2 timestamp", "trusted_cawg_timestamp")
            .validation_status("cawg.x509.time_stamp.malformed")
            .informational(validation_log);
        return None;
    }

    let mut timestamp_log = StatusTracker::default();
    let result = validate_cose_tst_info(&timestamp_sign1, data, policy, &mut timestamp_log, true);
    checked_timestamp(result.ok(), timestamp_log, validation_log)
}

pub(crate) fn trusted_cawg_timestamp_token(
    token: &[u8],
    signature: &[u8],
    policy: &CertificateTrustPolicy,
    validation_log: &mut StatusTracker,
) -> Option<TstInfo> {
    let mut timestamp_log = StatusTracker::default();
    let result: Result<_, TimeStampError> =
        verify_time_stamp(token, signature, policy, &mut timestamp_log, true);
    checked_timestamp(result.ok(), timestamp_log, validation_log)
}

fn checked_timestamp(
    result: Option<TstInfo>,
    mut timestamp_log: StatusTracker,
    validation_log: &mut StatusTracker,
) -> Option<TstInfo> {
    // Some profile checks also report failure through the tracker. Do not
    // promote a timestamp whose certificate failed one of those checks.
    let profile_invalid = timestamp_log.has_status(validation_status::SIGNING_CREDENTIAL_INVALID);
    if result.is_none() || profile_invalid {
        timestamp_log.remove_status_since(0, validation_status::TIMESTAMP_TRUSTED);
        timestamp_log.remove_status_since(0, validation_status::TIMESTAMP_VALIDATED);
        if !timestamp_log.has_status(validation_status::TIMESTAMP_UNTRUSTED)
            && !timestamp_log.has_status(validation_status::TIMESTAMP_MISMATCH)
            && !timestamp_log.has_status(validation_status::TIMESTAMP_OUTSIDE_VALIDITY)
            && !timestamp_log.has_status(validation_status::TIMESTAMP_MALFORMED)
        {
            log_item!(
                "",
                "CAWG timestamp could not be validated",
                "checked_timestamp"
            )
            .validation_status(validation_status::TIMESTAMP_MALFORMED)
            .informational(&mut timestamp_log);
        }
    }
    for item in timestamp_log.logged_items_mut() {
        if item.kind == crate::status_tracker::LogKind::Failure {
            item.kind = crate::status_tracker::LogKind::Informational;
        }

        item.validation_status = match item.validation_status.as_deref() {
            Some(validation_status::TIMESTAMP_MALFORMED) => {
                Some("cawg.x509.time_stamp.malformed".into())
            }
            Some(validation_status::TIMESTAMP_MISMATCH) => {
                Some("cawg.x509.time_stamp.mismatch".into())
            }
            Some(validation_status::TIMESTAMP_UNTRUSTED)
            | Some(validation_status::SIGNING_CREDENTIAL_INVALID)
            | Some(validation_status::ALGORITHM_UNSUPPORTED) => {
                Some("cawg.x509.time_stamp.untrusted".into())
            }
            Some(validation_status::TIMESTAMP_VALIDATED) => {
                Some("cawg.x509.time_stamp.validated".into())
            }
            Some(validation_status::TIMESTAMP_TRUSTED) => {
                Some("cawg.x509.time_stamp.trusted".into())
            }
            Some(validation_status::TIMESTAMP_OUTSIDE_VALIDITY)
            | Some(validation_status::SIGNING_CREDENTIAL_EXPIRED)
            | Some(validation_status::CLAIM_SIGNATURE_OUTSIDE_VALIDITY) => {
                Some("cawg.x509.time_stamp.outside_validity".into())
            }
            _ => item.validation_status.clone(),
        };
    }

    validation_log.append(&timestamp_log);
    if profile_invalid {
        None
    } else {
        result
    }
}

impl Verifier<'_> {
    #[async_generic]
    pub(crate) fn verify_cawg_signature(
        &self,
        signature: &[u8],
        data: &[u8],
        manifest_timestamp: Option<&TstInfo>,
        validation_log: &mut StatusTracker,
    ) -> Result<CertificateInfo, CoseError> {
        let sign1 = parse_cose_sign1(signature, data, validation_log)?;
        let timestamp = match self {
            Self::VerifyTrustPolicy(policy)
            | Self::VerifyTrustPolicyFor(policy, _)
            | Self::VerifyCertificateProfileOnly(policy) => {
                trusted_cawg_timestamp(&sign1, data, policy, validation_log)
            }
            Self::IgnoreProfileAndTrustPolicy => None,
        };
        if timestamp.is_none() && manifest_timestamp.is_some() {
            for status in [
                "cawg.x509.time_stamp.trusted",
                "cawg.x509.time_stamp.validated",
            ] {
                log_item!(
                    "",
                    "using the associated manifest timestamp",
                    "verify_cawg_signature"
                )
                .validation_status(status)
                .success(validation_log);
            }
        }

        let timestamp = timestamp.as_ref().or(manifest_timestamp);
        let log_start = validation_log.logged_items().len();
        let info = if _sync {
            self.verify_signature(signature, data, &[], timestamp, validation_log)?
        } else {
            self.verify_signature_async(signature, data, &[], timestamp, validation_log)
                .await?
        };

        if let Self::VerifyTrustPolicy(policy) | Self::VerifyTrustPolicyFor(policy, _) = self {
            let certificates = cert_chain_from_sign1(&sign1)?;
            let mut effective_policy = policy.clone();
            let anchor_type = match self {
                Self::VerifyTrustPolicyFor(_, kind) => *kind,
                _ => super::TrustAnchorType::Manifest,
            };
            if let Some(anchor) = validation_log.logged_items()[log_start..]
                .iter()
                .filter(|item| {
                    item.validation_status.as_deref()
                        == Some(validation_status::SIGNING_CREDENTIAL_TRUSTED)
                })
                .find_map(|item| {
                    policy.get_anchor_set(anchor_type, item.trust_list_uri.as_deref()?)
                })
            {
                if let Some(config) = &anchor.trust_config {
                    effective_policy.to_mut().add_valid_ekus(config.as_bytes());
                }
            }

            let acceptable = interim_certificate_is_acceptable(
                &certificates[0],
                Utc::now(),
                timestamp,
                &effective_policy,
            );
            if !matches!(acceptable, Ok(true))
                && validation_log.logged_items()[log_start..]
                    .iter()
                    .any(|item| {
                        item.validation_status.as_deref()
                            == Some(validation_status::SIGNING_CREDENTIAL_TRUSTED)
                    })
            {
                validation_log
                    .remove_status_since(log_start, validation_status::SIGNING_CREDENTIAL_TRUSTED);
                let error = match acceptable {
                    Err(error) => error,
                    _ => CertificateTrustError::CertificateNotTrusted.into(),
                };
                log_item!(
                    "",
                    "certificate does not satisfy the CAWG X.509 trust model",
                    "verify_cawg_signature"
                )
                .validation_status(validation_status::SIGNING_CREDENTIAL_UNTRUSTED)
                .failure_no_throw(validation_log, error);
            }
        }

        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use rasn_pkix::{Certificate, Extension};

    use super::*;

    fn oid(value: &str) -> rasn::types::ObjectIdentifier {
        rasn::types::ObjectIdentifier::new(
            value
                .split('.')
                .map(|part| part.parse().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn certificate(policies: &[&str], purposes: &[&str]) -> Certificate {
        let pem = x509_parser::pem::Pem::iter_from_buffer(include_bytes!(
            "../../../tests/fixtures/certs/ed25519.pub"
        ))
        .next()
        .unwrap()
        .unwrap();
        let mut certificate: Certificate = rasn::der::decode(&pem.contents).unwrap();
        let extensions = certificate.tbs_certificate.extensions.as_mut().unwrap();
        extensions.retain(|ext| ext.extn_id != oid("2.5.29.32") && ext.extn_id != oid("2.5.29.37"));
        extensions.push(Extension {
            extn_id: oid("2.5.29.37"),
            critical: false,
            extn_value: rasn::der::encode(&purposes.iter().map(|s| oid(s)).collect::<Vec<_>>())
                .unwrap()
                .into(),
        });

        if !policies.is_empty() {
            #[derive(rasn::AsnType, rasn::Encode)]
            struct Policy {
                id: rasn::types::ObjectIdentifier,
            }

            extensions.push(Extension {
                extn_id: oid("2.5.29.32"),
                critical: false,
                extn_value: rasn::der::encode(
                    &policies
                        .iter()
                        .map(|s| Policy { id: oid(s) })
                        .collect::<Vec<_>>(),
                )
                .unwrap()
                .into(),
            });
        }

        certificate
    }

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).unwrap()
    }

    fn timestamp_at(seconds: i64) -> TstInfo {
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
            policy: oid("1.2.3"),
            imprint: Imprint {
                algorithm: rasn_pkix::AlgorithmIdentifier {
                    algorithm: oid("2.16.840.1.101.3.4.2.1"),
                    parameters: None,
                },
                digest: vec![0; 32].into(),
            },
            serial: 1.into(),
            time: at(seconds).into(),
        })
        .unwrap();
        bcder::decode::Constructed::decode(bytes.as_slice(), bcder::Mode::Der, TstInfo::take_from)
            .unwrap()
    }

    const EMAIL: &str = "1.3.6.1.5.5.7.3.4";

    #[test]
    fn all_six_interim_policies_are_accepted() {
        for policy in SMIME_POLICIES {
            let der = rasn::der::encode(&certificate(&[policy], &[EMAIL])).unwrap();
            assert!(
                interim_certificate_is_acceptable(
                    &der,
                    at(INTERIM_TRUST_END - 1),
                    None,
                    &CertificateTrustPolicy::default(),
                )
                .unwrap(),
                "{policy}"
            );
        }
    }

    #[test]
    fn mailbox_legacy_missing_and_unrelated_policies_are_not_accepted() {
        for policies in [
            vec![],
            vec!["2.23.140.1.5.1.1"],
            vec!["2.23.140.1.5.1.2"],
            vec!["2.23.140.1.5.1.3"],
            vec!["2.23.140.1.5.2.1"],
            vec!["2.23.140.1.5.3.1"],
            vec!["2.23.140.1.5.4.1"],
            vec!["1.2.3.4"],
        ] {
            let der = rasn::der::encode(&certificate(&policies, &[EMAIL])).unwrap();
            assert!(
                !interim_certificate_is_acceptable(
                    &der,
                    at(INTERIM_TRUST_END - 1),
                    None,
                    &CertificateTrustPolicy::default(),
                )
                .unwrap(),
                "{policies:?}"
            );
        }
    }

    #[test]
    fn malformed_and_duplicate_policies_fail_closed() {
        let mut cert = certificate(&[SMIME_POLICIES[0]], &[EMAIL]);
        let extensions = cert.tbs_certificate.extensions.as_mut().unwrap();
        let extension = extensions
            .iter()
            .find(|e| e.extn_id == oid("2.5.29.32"))
            .unwrap()
            .clone();
        extensions.push(extension);
        assert!(interim_certificate_is_acceptable(
            &rasn::der::encode(&cert).unwrap(),
            at(INTERIM_TRUST_END - 1),
            None,
            &CertificateTrustPolicy::default(),
        )
        .is_err());
        let extensions = cert.tbs_certificate.extensions.as_mut().unwrap();
        extensions.pop();
        extensions
            .iter_mut()
            .find(|e| e.extn_id == oid("2.5.29.32"))
            .unwrap()
            .extn_value = vec![0x30, 0x01, 0].into();
        assert!(interim_certificate_is_acceptable(
            &rasn::der::encode(&cert).unwrap(),
            at(INTERIM_TRUST_END - 1),
            None,
            &CertificateTrustPolicy::default(),
        )
        .is_err());
    }

    #[test]
    fn cutoff_includes_the_whole_utc_day_and_uses_only_attested_time() {
        let der = rasn::der::encode(&certificate(&[SMIME_POLICIES[0]], &[EMAIL])).unwrap();
        let policy = CertificateTrustPolicy::default();
        for now in [
            INTERIM_TRUST_END - 86_400,
            INTERIM_TRUST_END - 1,
            INTERIM_TRUST_END,
        ] {
            assert_eq!(
                interim_certificate_is_acceptable(&der, at(now), None, &policy).unwrap(),
                now < INTERIM_TRUST_END,
            );
            for time in [
                INTERIM_TRUST_END - 86_400,
                INTERIM_TRUST_END - 1,
                INTERIM_TRUST_END,
            ] {
                assert_eq!(
                    interim_certificate_is_acceptable(
                        &der,
                        at(now),
                        Some(&timestamp_at(time)),
                        &policy,
                    )
                    .unwrap(),
                    now < INTERIM_TRUST_END || time < INTERIM_TRUST_END,
                );
            }
        }
    }

    #[test]
    fn document_signing_is_not_an_interim_purpose_including_mixed_eku() {
        for purposes in [vec![DOCUMENT_SIGNING], vec![EMAIL, DOCUMENT_SIGNING]] {
            let der = rasn::der::encode(&certificate(&[], &purposes)).unwrap();
            assert!(interim_certificate_is_acceptable(
                &der,
                at(INTERIM_TRUST_END + 1),
                None,
                &CertificateTrustPolicy::default(),
            )
            .unwrap());
        }

        for purpose in [
            "1.3.6.1.5.5.7.3.8",
            "1.3.6.1.5.5.7.3.9",
            "1.3.6.1.4.1.62558.2.1",
        ] {
            let der = rasn::der::encode(&certificate(&[SMIME_POLICIES[0]], &[purpose])).unwrap();
            assert!(interim_certificate_is_acceptable(
                &der,
                at(INTERIM_TRUST_END - 1),
                None,
                &CertificateTrustPolicy::default(),
            )
            .unwrap());
        }

        let der = rasn::der::encode(&certificate(&[], &[EMAIL, DOCUMENT_SIGNING])).unwrap();
        let mut policy = CertificateTrustPolicy::new();
        policy.clear_ekus();
        policy.add_valid_ekus(EMAIL.as_bytes());
        assert!(
            !interim_certificate_is_acceptable(&der, at(INTERIM_TRUST_END - 1), None, &policy,)
                .unwrap()
        );
    }

    fn pem(der: &[u8]) -> Vec<u8> {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            crate::crypto::base64::encode(der),
        )
        .into_bytes()
    }

    fn signed_cose(policies: &[&str], purposes: &[&str], data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        signed_cose_with_certificate(&certificate(policies, purposes), data)
    }

    fn signed_cose_with_certificate(certificate: &Certificate, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let der = rasn::der::encode(certificate).unwrap();
        let key = c2pa_raw_crypto::signer_from_private_key(
            include_bytes!("../../../tests/fixtures/certs/ed25519.pem"),
            c2pa_raw_crypto::SigningAlg::Ed25519,
        )
        .unwrap();
        let chain = vec![der.clone()];
        let signature = super::super::sign(
            &super::super::RawSignerCoseSigner::new(key.as_ref(), &chain),
            data,
            None,
            TimeStampStorage::V2_sigTst2_CTT,
            &crate::Context::new(),
        )
        .unwrap();
        (signature, pem(&der))
    }

    #[c2pa_macros::c2pa_test_async]
    async fn policy_is_enforced_by_both_cawg_apis_but_not_the_shared_verifier() {
        use std::borrow::Cow;

        let mut cases: Vec<_> = SMIME_POLICIES.iter().map(|policy| vec![*policy]).collect();
        cases.extend([vec!["2.23.140.1.5.1.2"], vec![]]);
        for policies in cases {
            let (signature, certificate) = signed_cose(&policies, &[EMAIL], b"payload");
            let mut policy = CertificateTrustPolicy::default();
            policy.add_end_entity_credentials(&certificate).unwrap();
            let verifier = Verifier::VerifyTrustPolicyFor(
                Cow::Owned(policy),
                super::super::TrustAnchorType::CAWG,
            );
            let timestamp = timestamp_at(1_767_225_600);
            for asynchronous in [false, true] {
                let mut log = StatusTracker::default();
                if asynchronous {
                    verifier
                        .verify_cawg_signature_async(
                            &signature,
                            b"payload",
                            Some(&timestamp),
                            &mut log,
                        )
                        .await
                        .unwrap();
                } else {
                    verifier
                        .verify_cawg_signature(&signature, b"payload", Some(&timestamp), &mut log)
                        .unwrap();
                }

                assert_eq!(
                    log.has_status(validation_status::SIGNING_CREDENTIAL_TRUSTED),
                    policies
                        .first()
                        .is_some_and(|policy| SMIME_POLICIES.contains(policy)),
                    "{log:?}",
                );
                let mut shared_log = StatusTracker::default();
                verifier
                    .verify_signature(
                        &signature,
                        b"payload",
                        &[],
                        Some(&timestamp),
                        &mut shared_log,
                    )
                    .unwrap();
                assert!(shared_log.has_status(validation_status::SIGNING_CREDENTIAL_TRUSTED));
            }
        }
    }

    #[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
    fn timestamped_sign1(time: &[u8]) -> (CoseSign1, Vec<u8>) {
        let (signature, _) = signed_cose(&[SMIME_POLICIES[0]], &[EMAIL], b"payload");
        let mut sign1 =
            parse_cose_sign1(&signature, b"payload", &mut StatusTracker::default()).unwrap();
        let tsa = add_timestamp(&mut sign1, time);
        (sign1, tsa)
    }

    #[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
    fn add_timestamp(sign1: &mut CoseSign1, time: &[u8]) -> Vec<u8> {
        use coset::{cbor::value::Value, Label};

        use crate::crypto::time_stamp::verify::message_imprint_regression::build_token_at;

        let signature_cbor = coset::cbor::Value::Bytes(sign1.signature.clone());
        let mut bytes = Vec::new();
        coset::cbor::into_writer(&signature_cbor, &mut bytes).unwrap();
        let data = super::super::sigtst::cose_countersign_data(&bytes, &sign1.protected);
        let token = build_token_at(&data, time);
        let cert = crate::crypto::time_stamp::tsa_signer_cert_der_from_token(&token)
            .unwrap()
            .unwrap();
        sign1.unprotected.rest.push((
            Label::Text("sigTst2".into()),
            Value::Map(vec![(
                Value::Text("tstTokens".into()),
                Value::Array(vec![Value::Map(vec![(
                    Value::Text("val".into()),
                    Value::Bytes(token),
                )])]),
            )]),
        ));
        pem(&cert)
    }

    #[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
    #[test]
    fn only_a_trusted_associated_v2_timestamp_can_extend_interim_trust() {
        use super::super::TrustAnchorType;

        for (time, accepted) in [
            (b"20270330000000Z".as_slice(), true),
            (b"20270331235959Z".as_slice(), true),
            (b"20270401000000Z".as_slice(), false),
        ] {
            let (mut sign1, tsa) = timestamped_sign1(time);
            let leaf = cert_chain_from_sign1(&sign1).unwrap().remove(0);
            for kind in [
                TrustAnchorType::Manifest,
                TrustAnchorType::CAWG,
                TrustAnchorType::TSA,
            ] {
                let mut policy = CertificateTrustPolicy::default();
                policy
                    .add_trust_anchors(&tsa, "test:tsa", kind, None)
                    .unwrap();
                let mut log = StatusTracker::default();
                let timestamp = trusted_cawg_timestamp(&sign1, b"payload", &policy, &mut log);
                assert_eq!(timestamp.is_some(), kind == TrustAnchorType::TSA, "{log:?}");
                for now in [
                    INTERIM_TRUST_END - 86_400,
                    INTERIM_TRUST_END - 1,
                    INTERIM_TRUST_END,
                ] {
                    assert_eq!(
                        interim_certificate_is_acceptable(
                            &leaf,
                            at(now),
                            timestamp.as_ref(),
                            &policy,
                        )
                        .unwrap(),
                        now < INTERIM_TRUST_END || (kind == TrustAnchorType::TSA && accepted),
                    );
                }
                assert!(!log.has_status(validation_status::TIMESTAMP_TRUSTED));
            }

            let mut policy = CertificateTrustPolicy::default();
            policy
                .add_trust_anchors(&tsa, "test:tsa", TrustAnchorType::TSA, None)
                .unwrap();
            sign1.signature[0] ^= 1;
            let mut log = StatusTracker::default();
            assert!(trusted_cawg_timestamp(&sign1, b"payload", &policy, &mut log).is_none());
            assert!(log.has_status("cawg.x509.time_stamp.mismatch"), "{log:?}");
            sign1.signature[0] ^= 1;
            sign1.unprotected.rest.last_mut().unwrap().0 = coset::Label::Text("sigTst".into());
            assert!(trusted_cawg_timestamp(&sign1, b"payload", &policy, &mut log).is_none());
            assert!(log.has_status("cawg.x509.time_stamp.malformed"));
        }
    }

    #[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
    #[test]
    fn manifest_timestamp_requires_the_signed_assertion_and_valid_claim_signature() {
        use coset::TaggedCborSerializable;

        use crate::{claim::Claim, store::Store};

        let mut claim = Claim::new("test", None, 1);
        let uri = claim
            .add_assertion(&crate::assertions::Actions::new())
            .unwrap();
        claim.build().unwrap();
        let label = uri.url().rsplit('/').next().unwrap().to_string();
        let data = claim.data().unwrap();
        let (signature, _) = signed_cose(&[], &[DOCUMENT_SIGNING], &data);
        let mut sign1 = parse_cose_sign1(&signature, &data, &mut StatusTracker::default()).unwrap();
        let tsa = add_timestamp(&mut sign1, b"20270331235959Z");
        sign1.payload = None;
        claim.set_signature_val(sign1.to_tagged_vec().unwrap());
        let mut store = Store::new();
        store
            .add_trust_anchor(&tsa, "test:tsa", super::super::TrustAnchorType::TSA, None)
            .unwrap();
        let mut log = StatusTracker::default();
        let timestamp = store
            .trusted_cawg_timestamp_for_assertion(&claim, &label, &mut log)
            .unwrap()
            .unwrap();
        let time: DateTime<Utc> = timestamp.gen_time.into();
        assert_eq!(time.timestamp(), INTERIM_TRUST_END - 1);
        assert!(store
            .trusted_cawg_timestamp_for_assertion(&claim, "cawg.identity", &mut log)
            .unwrap()
            .is_none());
        claim.set_title(Some("tampered signed claim".into()));
        assert!(store
            .trusted_cawg_timestamp_for_assertion(&claim, &label, &mut log)
            .unwrap()
            .is_none());
    }

    #[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
    #[c2pa_macros::c2pa_test_async]
    async fn manifest_only_timestamp_is_used_during_cawg_identity_decoding() {
        use coset::TaggedCborSerializable;

        use crate::{
            assertions::{DataHash, UserCbor},
            claim::Claim,
            identity::{IdentityAssertion, SignerPayload},
            manifest::StoreOptions,
            settings::{Settings, TrustAnchor, TrustListKind},
            store::Store,
            Context, Manifest,
        };

        let mut claim = Claim::new("manifest timestamp test", None, 1);
        let binding = claim
            .add_assertion(&DataHash::new("asset", "sha256"))
            .unwrap();
        let signer_payload = SignerPayload {
            referenced_assertions: vec![binding],
            sig_type: "cawg.x509.cose".into(),
            roles: Vec::new(),
        };
        let mut payload_bytes = Vec::new();
        c2pa_cbor::to_writer(&mut payload_bytes, &signer_payload).unwrap();
        let mut identity_certificate = certificate(&[SMIME_POLICIES[0]], &[EMAIL]);
        // Expired at validation time, but valid at the manifest's attested time.
        identity_certificate.tbs_certificate.validity.not_before =
            rasn_pkix::Time::General(at(1_735_689_600).into());
        identity_certificate.tbs_certificate.validity.not_after =
            rasn_pkix::Time::General(at(1_767_312_000).into());
        let (identity_signature, identity_pem) =
            signed_cose_with_certificate(&identity_certificate, &payload_bytes);
        let identity_sign1 = parse_cose_sign1(
            &identity_signature,
            &payload_bytes,
            &mut StatusTracker::default(),
        )
        .unwrap();
        assert!(get_cose_tst_info(&identity_sign1).is_none());
        let identity = IdentityAssertion {
            signer_payload,
            signature: identity_signature,
            pad1: Vec::new(),
            pad2: None,
            label: None,
        };
        let mut identity_bytes = Vec::new();
        c2pa_cbor::to_writer(&mut identity_bytes, &identity).unwrap();
        claim
            .add_assertion(&UserCbor::new("cawg.identity", identity_bytes))
            .unwrap();
        claim.build().unwrap();

        let data = claim.data().unwrap();
        let (signature, _) = signed_cose(&[], &[DOCUMENT_SIGNING], &data);
        let mut sign1 = parse_cose_sign1(&signature, &data, &mut StatusTracker::default()).unwrap();
        let tsa = add_timestamp(&mut sign1, b"20260101000000Z");
        sign1.payload = None;
        claim.set_signature_val(sign1.to_tagged_vec().unwrap());

        for trust_timestamp in [false, true] {
            let mut settings = Settings::default();
            settings.core.decode_identity_assertions = true;
            settings.trust.anchors = Some(vec![
                TrustAnchor {
                    trust_anchors: String::new(),
                    trust_uri: Some("test:identity".into()),
                    trust_kind: TrustListKind::CAWG,
                    trust_config: None,
                    allowed_list: Some(String::from_utf8(identity_pem.clone()).unwrap()),
                    trusted_ica_issuers: None,
                },
                TrustAnchor {
                    trust_anchors: if trust_timestamp {
                        String::from_utf8(tsa.clone()).unwrap()
                    } else {
                        String::new()
                    },
                    trust_uri: Some("test:tsa".into()),
                    trust_kind: TrustListKind::TSA,
                    trust_config: None,
                    allowed_list: None,
                    trusted_ica_issuers: None,
                },
            ]);
            let context = Context::new().with_settings(settings).unwrap();
            let mut store = Store::from_context(&context);
            store.commit_claim(claim.clone()).unwrap();
            for asynchronous in [false, true] {
                let mut log = StatusTracker::default();
                if asynchronous {
                    Manifest::from_store_async(
                        &store,
                        claim.label(),
                        &mut StoreOptions::default(),
                        &mut log,
                        &context,
                    )
                    .await
                    .unwrap();
                } else {
                    Manifest::from_store(
                        &store,
                        claim.label(),
                        &mut StoreOptions::default(),
                        &mut log,
                        &context,
                    )
                    .unwrap();
                }

                assert_eq!(
                    log.has_status(validation_status::CAWG_X509_CREDENTIAL_TRUSTED),
                    trust_timestamp,
                    "{log:?}",
                );
                assert_eq!(
                    log.has_status("cawg.x509.time_stamp.trusted"),
                    trust_timestamp
                );
                assert_eq!(
                    log.has_status("cawg.x509.time_stamp.validated"),
                    trust_timestamp
                );
                assert_eq!(
                    log.has_status(validation_status::CAWG_X509_SIGNATURE_OUTSIDE_VALIDITY),
                    !trust_timestamp,
                    "{log:?}",
                );
            }
        }
    }

    #[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
    #[test]
    fn timestamp_assertion_is_verified_against_the_referenced_claim_not_just_its_label() {
        use crate::{
            assertions::TimeStamp, claim::Claim,
            crypto::time_stamp::verify::message_imprint_regression::build_token_at, store::Store,
        };

        let mut claim = Claim::new("test", None, 1);
        let uri = claim
            .add_assertion(&crate::assertions::Actions::new())
            .unwrap();
        claim.build().unwrap();
        let label = uri.url().rsplit('/').next().unwrap().to_string();
        let data = claim.data().unwrap();
        let (signature, _) = signed_cose(&[], &[DOCUMENT_SIGNING], &data);
        let sign1 = parse_cose_sign1(&signature, &data, &mut StatusTracker::default()).unwrap();
        claim.set_signature_val(signature);

        for correct_imprint in [false, true] {
            let token = build_token_at(
                if correct_imprint {
                    &sign1.signature
                } else {
                    b"another claim's signature"
                },
                b"20270331235959Z",
            );
            let cert = crate::crypto::time_stamp::tsa_signer_cert_der_from_token(&token)
                .unwrap()
                .unwrap();
            let mut assertion = TimeStamp::new();
            assertion.add_timestamp(claim.label(), &token);
            let mut source = Claim::new("timestamp", None, 1);
            source.add_assertion(&assertion).unwrap();
            let mut store = Store::new();
            store.commit_claim(source).unwrap();
            store
                .add_trust_anchor(
                    &pem(&cert),
                    "test:tsa",
                    super::super::TrustAnchorType::TSA,
                    None,
                )
                .unwrap();
            let mut log = StatusTracker::default();
            assert_eq!(
                store
                    .trusted_cawg_timestamp_for_assertion(&claim, &label, &mut log)
                    .unwrap()
                    .is_some(),
                correct_imprint,
                "{log:?}",
            );
        }
    }

    #[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
    #[test]
    fn malformed_timestamp_containers_are_ignored_and_legacy_does_not_shadow_v2() {
        use coset::{cbor::value::Value, Label};
        let (sign1, tsa) = timestamped_sign1(b"20270331235959Z");
        let mut policy = CertificateTrustPolicy::default();
        policy
            .add_trust_anchors(&tsa, "test:tsa", super::super::TrustAnchorType::TSA, None)
            .unwrap();

        let mut with_legacy = sign1.clone();
        with_legacy
            .unprotected
            .rest
            .insert(0, (Label::Text("sigTst".into()), Value::Null));
        assert!(trusted_cawg_timestamp(
            &with_legacy,
            b"payload",
            &policy,
            &mut StatusTracker::default(),
        )
        .is_some());

        for value in [
            Value::Null,
            Value::Map(vec![(
                Value::Text("tstTokens".into()),
                Value::Array(vec![]),
            )]),
            Value::Map(vec![(
                Value::Text("tstTokens".into()),
                Value::Array(vec![
                    Value::Map(vec![(Value::Text("val".into()), Value::Bytes(vec![]))]),
                    Value::Map(vec![(Value::Text("val".into()), Value::Bytes(vec![]))]),
                ]),
            )]),
        ] {
            let mut malformed = sign1.clone();
            malformed.unprotected.rest.last_mut().unwrap().1 = value;
            let mut log = StatusTracker::default();
            assert!(trusted_cawg_timestamp(&malformed, b"payload", &policy, &mut log).is_none());
            assert!(log.has_status("cawg.x509.time_stamp.malformed"), "{log:?}");
            assert!(!log.has_status("cawg.x509.time_stamp.trusted"));
            assert!(!log.has_status("cawg.x509.time_stamp.validated"));
        }
    }
}
