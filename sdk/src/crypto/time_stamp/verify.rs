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

use asn1_rs::FromDer;
use async_generic::async_generic;
use contentauth_pki::{
    sdk_compat::verified_timestamp_info,
    timestamp::verification::{
        signer_certificate_from_token, ParsedTimestamp, VerificationError, VerificationErrorKind,
        VerificationStage,
    },
};

use crate::{
    crypto::{
        asn1::rfc3161::TstInfo,
        cose::{CertificateRole, CertificateTrustPolicy, TrustAnchorType},
        time_stamp::TimeStampError,
    },
    log_item,
    status_tracker::StatusTracker,
    validation_status::{
        TIMESTAMP_MALFORMED, TIMESTAMP_MISMATCH, TIMESTAMP_OUTSIDE_VALIDITY, TIMESTAMP_TRUSTED,
        TIMESTAMP_UNTRUSTED, TIMESTAMP_VALIDATED,
    },
};

#[cfg(all(test, feature = "openssl", not(target_arch = "wasm32")))]
const TIMESTAMP_OID_STR: &str = "1.3.6.1.5.5.7.3.8";

fn report_crypto_failure(error: &VerificationError, log: &mut StatusTracker) {
    let status = match (&error.stage, &error.kind) {
        (VerificationStage::SignerIdentifier, _) => return,
        (VerificationStage::Certificates | VerificationStage::Signature, _) => TIMESTAMP_UNTRUSTED,
        (VerificationStage::MessageImprint, VerificationErrorKind::UnsupportedAlgorithm) => {
            TIMESTAMP_UNTRUSTED
        }
        (VerificationStage::MessageImprint, _)
        | (VerificationStage::SignedAttributes, VerificationErrorKind::InvalidData) => {
            TIMESTAMP_MISMATCH
        }
        _ => TIMESTAMP_MALFORMED,
    };

    log_item!("", error.diagnostic, "verify_time_stamp")
        .validation_status(status)
        .informational(log);
}

/// Verify timestamp cryptography, temporal validity and SDK-selected TSA policy.
///
/// The reusable crate supplies authenticated facts, not an accepted signing time.
/// Legacy callers may explicitly skip profile/trust checks as before. Both APIs
/// perform deterministic cryptography synchronously; async does not add I/O.
#[async_generic]
pub fn verify_time_stamp(
    ts: &[u8],
    data: &[u8],
    ctp: &CertificateTrustPolicy,
    validation_log: &mut StatusTracker,
    verify_trust: bool,
) -> Result<TstInfo, TimeStampError> {
    let parsed = ParsedTimestamp::parse(ts).map_err(|error| {
        report_crypto_failure(&error, validation_log);
        // The historical verifier intentionally normalized envelope failures.
        if error.stage == VerificationStage::Envelope {
            TimeStampError::DecodeError("unable to find signed data".into())
        } else {
            error.into()
        }
    })?;
    let mut last_err = TimeStampError::InvalidData;
    let mut current_validation_log = StatusTracker::default();

    for candidate in parsed.verify_signatures() {
        current_validation_log = StatusTracker::default();
        let signed = match candidate {
            Ok(signed) => signed,
            Err(error) => {
                if error.kind != VerificationErrorKind::NoMatchingCertificate {
                    report_crypto_failure(&error, &mut current_validation_log);
                    last_err = error.into();
                }

                continue;
            }
        };
        let mut common_name = String::new();
        if let Ok((_, certificate)) =
            x509_parser::certificate::X509Certificate::from_der(signed.signer_certificate())
        {
            for rdn in certificate.subject().iter_common_name() {
                if let Ok(name) = rdn.as_str() {
                    common_name.push_str(name);
                }
            }
        }

        let signing_time = signed.generation_time().timestamp();
        let (not_before, not_after) = signed.signer_validity();
        let accuracy_margin = signed.accuracy_seconds();
        if !(signing_time >= not_before.saturating_sub(accuracy_margin)
            && signing_time <= not_after.saturating_add(accuracy_margin))
        {
            log_item!(
                "",
                "timestamp signer outside of certificate validity",
                "verify_time_stamp"
            )
            .validation_status(TIMESTAMP_OUTSIDE_VALIDITY)
            .informational(&mut current_validation_log);
            last_err = TimeStampError::ExpiredCertificate;
            continue;
        }

        let verified = match signed.verify_message_imprint(data) {
            Ok(verified) => verified,
            Err(error) => {
                if error.kind == VerificationErrorKind::InvalidData {
                    log_item!(
                        "",
                        format!("timestamp message digest did not match: {}", &common_name),
                        "verify_time_stamp"
                    )
                    .validation_status(TIMESTAMP_MISMATCH)
                    .informational(&mut current_validation_log);
                } else {
                    report_crypto_failure(&error, &mut current_validation_log);
                }

                last_err = error.into();
                continue;
            }
        };
        log_item!(
            "",
            format!("timestamp message digest matched: {}", &common_name),
            "verify_time_stamp"
        )
        .validation_status(TIMESTAMP_VALIDATED)
        .success(&mut current_validation_log);

        let tst = verified_timestamp_info(&verified);
        let cert_ders = verified.signature().certificates();
        let cert_pos = verified.signature().signer_certificate_index();
        // the certificate must be on the trust list to be considered valid
        if verify_trust {
            // Order certificates from leaf to root before trust validation
            let ordered_cert_ders = order_certificates_leaf_to_root(cert_ders, cert_pos)?;

            let mut profile_log = StatusTracker::default();

            let profile_result = CertificateRole::TimestampSigner.check_profile(
                &ordered_cert_ders[0],
                &CertificateTrustPolicy::new(),
                &mut profile_log,
                Some(&tst),
            );

            let profile_failed = profile_result.is_err()
                || profile_log
                    .logged_items()
                    .iter()
                    .any(|item| item.kind == crate::status_tracker::LogKind::Failure);

            // The shared profile checker uses claim-signer failure codes. TSA
            // failures reject only the timestamp (C2PA 2.5, section 14.8.2).
            for item in profile_log.logged_items_mut() {
                item.kind = crate::status_tracker::LogKind::Informational;
                item.validation_status = Some(
                    if item.validation_status.as_deref()
                        == Some(crate::validation_status::SIGNING_CREDENTIAL_EXPIRED)
                    {
                        TIMESTAMP_OUTSIDE_VALIDITY
                    } else {
                        TIMESTAMP_UNTRUSTED
                    }
                    .into(),
                );
            }

            current_validation_log.append(&profile_log);

            if profile_failed {
                log_item!(
                    "",
                    format!("timestamp cert untrusted: {}", &common_name),
                    "verify_time_stamp"
                )
                .validation_status(TIMESTAMP_UNTRUSTED)
                .informational(&mut current_validation_log);

                last_err = TimeStampError::Untrusted;
                continue;
            }

            // Per C2PA §14.4.3, the private credential store applies only to
            // manifest signers, never to time-stamps; drop it before checking
            // timestamp trust so a private entry cannot act as a TSA. C2PA also
            // keeps TSA anchors separate from signer anchors, so restrict the
            // check to TSA anchors - a signer anchor must not vouch for a token.
            let mut ts_ctp = ctp.clone();
            ts_ctp.clear_end_entity_credentials();

            match ts_ctp.check_certificate_trust_for(
                Some(TrustAnchorType::TSA),
                &ordered_cert_ders[0..],
                &ordered_cert_ders[0],
                Some(signing_time),
            ) {
                Err(_) => {
                    log_item!(
                        "",
                        format!("timestamp cert untrusted: {}", &common_name),
                        "verify_time_stamp"
                    )
                    .validation_status(TIMESTAMP_UNTRUSTED)
                    .informational(&mut current_validation_log);

                    last_err = TimeStampError::Untrusted;
                    continue;
                }
                Ok((_trust_type, trust_uri)) => {
                    log_item!(
                        "",
                        format!(
                            "timestamp cert trusted: {}, trust list: {}",
                            &common_name, &trust_uri
                        ),
                        "verify_time_stamp"
                    )
                    .validation_status(TIMESTAMP_TRUSTED)
                    .set_trust_list_uri(&trust_uri)
                    .success(&mut current_validation_log);

                    validation_log.append(&current_validation_log);
                    return Ok(tst);
                }
            }
        } else {
            // this is the 1.x backward compatibility case, since there were no trust lists for timestamps
            log_item!(
                "",
                format!("legacy timestamp cert trusted: {}", &common_name),
                "verify_time_stamp"
            )
            .validation_status(TIMESTAMP_TRUSTED)
            .success(&mut current_validation_log);

            // If we find a valid value, we're done.
            validation_log.append(&current_validation_log);
            return Ok(tst);
        }
    }

    validation_log.append(&current_validation_log);
    Err(last_err)
}

/// Extract the first TSA signer's certificate without verifying or trusting it.
/// Supports issuer/serial and strictly decoded subject-key-identifier signer IDs.
pub fn tsa_signer_cert_der_from_token(ts: &[u8]) -> Result<Option<Vec<u8>>, TimeStampError> {
    signer_certificate_from_token(ts).map_err(Into::into)
}

#[cfg(all(test, feature = "openssl", not(target_arch = "wasm32")))]
fn generalized_time_to_datetime<T: Into<chrono::DateTime<chrono::Utc>>>(
    gt: T,
) -> chrono::DateTime<chrono::Utc> {
    gt.into()
}

/// Order certificates from leaf to root based on the signer certificate position
fn order_certificates_leaf_to_root(
    cert_ders: &[Vec<u8>],
    leaf_cert_pos: usize,
) -> Result<Vec<Vec<u8>>, TimeStampError> {
    if leaf_cert_pos >= cert_ders.len() {
        return Err(TimeStampError::DecodeError(
            "invalid leaf certificate position".to_string(),
        ));
    }

    let parsed_certs: Result<Vec<_>, _> = cert_ders
        .iter()
        .map(|cert_der| x509_parser::certificate::X509Certificate::from_der(cert_der))
        .collect();

    let parsed_certs = match parsed_certs {
        Ok(certs) => certs,
        Err(_) => {
            return Err(TimeStampError::DecodeError(
                "failed to parse certificates".to_string(),
            ));
        }
    };

    let mut ordered_certs = Vec::new();
    let mut used_indices = std::collections::HashSet::new();

    // Start with the provided signer certificate position
    ordered_certs.push(cert_ders[leaf_cert_pos].clone());
    used_indices.insert(leaf_cert_pos);

    let mut current_cert_index = leaf_cert_pos;

    for _ in 0..cert_ders.len() {
        let current_cert = &parsed_certs[current_cert_index].1;
        let mut found_next = false;

        // Find the next certificate in the chain (try to match issuer and subject name)
        for (i, (_, next_cert)) in parsed_certs.iter().enumerate() {
            if used_indices.contains(&i) {
                continue;
            }

            if current_cert.issuer() == next_cert.subject() {
                ordered_certs.push(cert_ders[i].clone());
                used_indices.insert(i);
                current_cert_index = i;
                found_next = true;
                break;
            }
        }

        if !found_next {
            // No more certificates could be included in this chain.
            break;
        }
    }

    Ok(ordered_certs)
}

#[cfg(test)]
#[path = "rsa_pss_ski_regression.rs"]
mod rsa_pss_ski_regression;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    #[test]
    fn malformed_tokens_are_reported_and_empty_chains_are_rejected() {
        use super::*;
        let mut log = StatusTracker::default();
        assert!(matches!(
            verify_time_stamp(
                b"not DER",
                b"",
                &CertificateTrustPolicy::default(),
                &mut log,
                false
            ),
            Err(TimeStampError::DecodeError(_))
        ));
        assert!(log.has_status(TIMESTAMP_MALFORMED));
        assert!(matches!(
            order_certificates_leaf_to_root(&[], 0),
            Err(TimeStampError::DecodeError(_))
        ));
        assert!(matches!(
            order_certificates_leaf_to_root(&[vec![0x30, 0]], 0),
            Err(TimeStampError::DecodeError(_))
        ));
        // A non-SEQUENCE is treated as an absent optional token by lookup.
        assert!(tsa_signer_cert_der_from_token(b"not DER")
            .expect("non-SEQUENCE is treated as an absent token")
            .is_none());
    }
}

/// Builds a signed RFC 3161 token locally so `verify_time_stamp` is exercised end to end.
#[cfg(all(test, feature = "openssl", not(target_arch = "wasm32")))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod message_imprint_regression {
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        ec::{EcGroup, EcKey},
        hash::{hash, MessageDigest},
        nid::Nid,
        pkey::PKey,
        sign::Signer,
        x509::{extension::ExtendedKeyUsage, X509Builder, X509NameBuilder},
    };

    use super::{generalized_time_to_datetime, verify_time_stamp};
    use crate::{
        crypto::{cose::CertificateTrustPolicy, time_stamp::TimeStampError},
        status_tracker::StatusTracker,
        validation_status::{TIMESTAMP_TRUSTED, TIMESTAMP_UNTRUSTED, TIMESTAMP_VALIDATED},
    };

    const OID_MD5: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05];
    pub(crate) const OID_SHA1: &[u8] = &[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a];
    const OID_SHA224: &[u8] = &[
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
    ];
    pub(crate) const OID_SHA256: &[u8] = &[
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ];
    const OID_SHA384: &[u8] = &[
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
    ];
    const OID_SHA512: &[u8] = &[
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
    ];
    const OID_SHA3_256: &[u8] = &[
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
    ];
    const OID_ECDSA_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    const OID_SIGNED_DATA: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    ];
    const OID_TST_INFO: &[u8] = &[
        0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04,
    ];
    const OID_POLICY: &[u8] = &[0x06, 0x03, 0x2a, 0x03, 0x04];

    // DER integer 1
    const INT_1: &[u8] = &[0x02, 0x01, 0x01];

    const DATA: &[u8] = b"claim signature bytes";

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let len = body.len();
        let mut out = vec![tag];
        if len < 0x80 {
            out.push(len as u8);
        } else if len <= 0xff {
            out.extend([0x81, len as u8]);
        } else {
            out.extend([0x82, (len >> 8) as u8, len as u8]);
        }
        out.extend_from_slice(body);
        out
    }

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    /// Returns a signed time-stamp token (genTime 2020-01-01) whose messageImprint
    /// covers `data` using the given digest.
    pub(crate) fn build_token(
        imprint_oid: &[u8],
        imprint_md: MessageDigest,
        data: &[u8],
    ) -> Vec<u8> {
        build_token_with(imprint_oid, imprint_md, data, TokenOptions::default())
    }

    pub(crate) fn build_token_at(data: &[u8], gen_time: &[u8]) -> Vec<u8> {
        build_token_with(
            OID_SHA256,
            MessageDigest::sha256(),
            data,
            TokenOptions {
                gen_time: Some(gen_time),
                profile_extensions: true,
                signed_attrs: true,
                ..Default::default()
            },
        )
    }

    #[derive(Default)]
    struct TokenOptions<'a> {
        gen_time: Option<&'a [u8]>,
        accuracy: Option<&'a [u8]>,
        signed_time: Option<(u8, &'a [u8])>,
        signed_attrs: bool,
        profile_extensions: bool,
        signer_eku: Option<&'a str>,
        omit_eku: bool,
        cms_digest: Option<(&'a [u8], MessageDigest)>,
    }

    fn test_certificate(
        purpose: Option<&str>,
        profile_extensions: bool,
        not_before: i64,
        not_after: i64,
    ) -> (PKey<openssl::pkey::Private>, openssl::x509::X509) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "Test TSA")
            .unwrap();
        let name = name.build();

        let mut cb = X509Builder::new().unwrap();
        cb.set_version(2).unwrap();
        cb.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cb.set_subject_name(&name).unwrap();
        cb.set_issuer_name(&name).unwrap();
        cb.set_pubkey(&key).unwrap();
        cb.set_not_before(&Asn1Time::from_unix(not_before).unwrap())
            .unwrap();
        cb.set_not_after(&Asn1Time::from_unix(not_after).unwrap())
            .unwrap();

        if let Some(purpose) = purpose {
            let mut eku = ExtendedKeyUsage::new();
            eku.other(purpose);
            cb.append_extension(eku.build().unwrap()).unwrap();
        }

        if profile_extensions {
            use openssl::x509::extension::{
                AuthorityKeyIdentifier, KeyUsage, SubjectKeyIdentifier,
            };
            cb.append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
            let ski = SubjectKeyIdentifier::new()
                .build(&cb.x509v3_context(None, None))
                .unwrap();
            cb.append_extension(ski).unwrap();
            let aki = AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&cb.x509v3_context(None, None))
                .unwrap();
            cb.append_extension(aki).unwrap();
        }

        cb.sign(&key, MessageDigest::sha256()).unwrap();
        (key, cb.build())
    }

    fn build_token_with(
        imprint_oid: &[u8],
        imprint_md: MessageDigest,
        data: &[u8],
        options: TokenOptions<'_>,
    ) -> Vec<u8> {
        let purpose = if options.omit_eku {
            None
        } else {
            Some(options.signer_eku.unwrap_or(super::TIMESTAMP_OID_STR))
        };
        let (key, cert) = test_certificate(
            purpose,
            options.profile_extensions,
            1_500_000_000,
            1_900_000_000,
        );

        let imprint_hash = hash(imprint_md, data).unwrap();
        let message_imprint = tlv(
            0x30,
            &cat(&[
                &tlv(0x30, &cat(&[imprint_oid, &[0x05, 0x00]])),
                &tlv(0x04, &imprint_hash),
            ]),
        );
        let tst_info = tlv(
            0x30,
            &cat(&[
                INT_1,
                OID_POLICY,
                &message_imprint,
                INT_1,
                &tlv(0x18, options.gen_time.unwrap_or(b"20200101000000Z")),
                options.accuracy.unwrap_or_default(),
            ]),
        );

        let (cms_oid, cms_md) = options
            .cms_digest
            .unwrap_or((OID_SHA256, MessageDigest::sha256()));
        let attributes = if options.signed_attrs {
            let mut attrs = vec![
                tlv(
                    0x30,
                    &cat(&[
                        &[
                            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03,
                        ],
                        &tlv(0x31, OID_TST_INFO),
                    ]),
                ),
                tlv(
                    0x30,
                    &cat(&[
                        &[
                            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
                        ],
                        &tlv(0x31, &tlv(0x04, &hash(cms_md, &tst_info).unwrap())),
                    ]),
                ),
            ];
            if let Some((tag, time)) = options.signed_time {
                attrs.push(tlv(
                    0x30,
                    &cat(&[
                        &[
                            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05,
                        ],
                        &tlv(0x31, &tlv(tag, time)),
                    ]),
                ));
            }
            attrs.sort();
            Some(attrs.concat())
        } else {
            None
        };

        let tbs = attributes
            .as_ref()
            .map(|attrs| tlv(0x31, attrs))
            .unwrap_or_else(|| tst_info.clone());
        let signature = Signer::new(cms_md, &key)
            .unwrap()
            .sign_oneshot_to_vec(&tbs)
            .unwrap();

        let issuer_and_serial = tlv(0x30, &cat(&[&cert.issuer_name().to_der().unwrap(), INT_1]));
        let signature_oid: &[u8] = match cms_oid {
            OID_SHA1 => &[6, 7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 1],
            OID_SHA384 => &[6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 3],
            OID_SHA512 => &[6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 4],
            _ => OID_ECDSA_SHA256,
        };

        let signer_info = tlv(
            0x30,
            &cat(&[
                INT_1,
                &issuer_and_serial,
                &tlv(0x30, cms_oid),
                &attributes
                    .as_ref()
                    .map(|attrs| tlv(0xa0, attrs))
                    .unwrap_or_default(),
                &tlv(0x30, signature_oid),
                &tlv(0x04, &signature),
            ]),
        );
        let signed_data = tlv(
            0x30,
            &cat(&[
                &[0x02, 0x01, 0x03],
                &tlv(0x31, &tlv(0x30, cms_oid)),
                &tlv(
                    0x30,
                    &cat(&[OID_TST_INFO, &tlv(0xa0, &tlv(0x04, &tst_info))]),
                ),
                &tlv(0xa0, &cert.to_der().unwrap()),
                &tlv(0x31, &signer_info),
            ]),
        );

        tlv(0x30, &cat(&[OID_SIGNED_DATA, &tlv(0xa0, &signed_data)]))
    }

    #[test]
    fn allowed_message_imprint_algorithms_are_accepted() {
        for (name, oid, md) in [
            ("SHA-256", OID_SHA256, MessageDigest::sha256()),
            ("SHA-384", OID_SHA384, MessageDigest::sha384()),
            ("SHA-512", OID_SHA512, MessageDigest::sha512()),
        ] {
            let token = build_token(oid, md, DATA);
            let mut log = StatusTracker::default();

            let result = verify_time_stamp(
                &token,
                DATA,
                &CertificateTrustPolicy::default(),
                &mut log,
                false,
            );
            assert!(result.is_ok(), "{name}: {result:?}");
            let tst = result.unwrap();

            assert_eq!(
                generalized_time_to_datetime(tst.gen_time.clone()).timestamp(),
                1_577_836_800,
                "{name}"
            );
            assert!(log.has_status(TIMESTAMP_VALIDATED), "{name}");
            assert!(log.has_status(TIMESTAMP_TRUSTED), "{name}");
        }
    }

    #[test]
    fn disallowed_message_imprint_algorithms_are_untrusted_and_ignored() {
        // Each token has a valid signature and a matching imprint; only the algorithm is
        // disallowed (C2PA 15.8.2: anything other than SHA-256/384/512).
        for (name, oid, md) in [
            ("SHA-1", OID_SHA1, MessageDigest::sha1()),
            ("SHA-224", OID_SHA224, MessageDigest::sha224()),
            ("SHA3-256", OID_SHA3_256, MessageDigest::sha3_256()),
            ("MD5", OID_MD5, MessageDigest::md5()),
        ] {
            let token = build_token(oid, md, DATA);
            let mut log = StatusTracker::default();

            let result = verify_time_stamp(
                &token,
                DATA,
                &CertificateTrustPolicy::default(),
                &mut log,
                false,
            );

            assert!(
                matches!(result, Err(TimeStampError::UnsupportedAlgorithm)),
                "{name}: {result:?}"
            );
            assert!(log.has_status(TIMESTAMP_UNTRUSTED), "{name}");
            assert!(!log.has_status(TIMESTAMP_VALIDATED), "{name}");
            assert!(!log.has_status(TIMESTAMP_TRUSTED), "{name}");
        }
    }

    #[test]
    fn mismatched_imprint_is_rejected() {
        // Guards against the positive tests passing without the imprint being compared.
        let token = build_token(OID_SHA256, MessageDigest::sha256(), DATA);
        let mut log = StatusTracker::default();

        let result = verify_time_stamp(
            &token,
            b"different data",
            &CertificateTrustPolicy::default(),
            &mut log,
            false,
        );

        assert!(matches!(result, Err(TimeStampError::InvalidData)));
        assert!(!log.has_status(TIMESTAMP_TRUSTED));
    }

    /// Regression for the private-credential-store timestamp-authority bypass.
    ///
    /// Per C2PA §14.4.3 the private credential store "shall not apply to
    /// validating time-stamps". A verifier that privately trusts a signer's
    /// own certificate must not thereby accept that certificate as a trusted
    /// time-stamping authority, whose attested time could otherwise suppress
    /// the signer certificate's expiry.
    #[test]
    fn private_credential_store_is_not_a_timestamp_authority() {
        use openssl::x509::X509;

        use super::tsa_signer_cert_der_from_token;
        use crate::crypto::cose::TrustAnchorType;

        let token = build_token_with(
            OID_SHA256,
            MessageDigest::sha256(),
            DATA,
            TokenOptions {
                profile_extensions: true,
                ..TokenOptions::default()
            },
        );
        let signer_der = tsa_signer_cert_der_from_token(&token)
            .unwrap()
            .expect("token carries its signer certificate");
        let signer_pem = X509::from_der(&signer_der).unwrap().to_pem().unwrap();

        // The TSA signer certificate is present only in the private credential
        // store, with no trust anchors. It must NOT be accepted for time-stamps.
        let mut ctp = CertificateTrustPolicy::default();
        ctp.add_end_entity_credentials(&signer_pem).unwrap();

        let mut log = StatusTracker::default();
        let result = verify_time_stamp(&token, DATA, &ctp, &mut log, true);
        assert!(
            matches!(result, Err(TimeStampError::Untrusted)),
            "private-store signer must not be a trusted TSA: {result:?}"
        );
        assert!(log.has_status(TIMESTAMP_UNTRUSTED));
        assert!(!log.has_status(TIMESTAMP_TRUSTED));

        // Positive control: the same certificate on the TSA trust list is
        // legitimately accepted, so the fix does not over-block real TSAs.
        let mut trusted_ctp = CertificateTrustPolicy::default();
        trusted_ctp
            .add_trust_anchors(
                &signer_pem,
                "http://tsa_trust_list",
                TrustAnchorType::TSA,
                None,
            )
            .unwrap();

        let mut trusted_log = StatusTracker::default();
        let trusted = verify_time_stamp(&token, DATA, &trusted_ctp, &mut trusted_log, true);
        assert!(
            trusted.is_ok(),
            "a TSA on the trust list must verify: {trusted:?}"
        );
        assert!(trusted_log.has_status(TIMESTAMP_TRUSTED));
    }

    /// A time-stamp must validate against the TSA trust list, not signer
    /// anchors: C2PA keeps those lists separate, so a token chaining only to a
    /// manifest (signer) trust anchor must not be reported trusted.
    #[test]
    fn manifest_trust_anchor_is_not_a_timestamp_authority() {
        use openssl::x509::X509;

        use super::tsa_signer_cert_der_from_token;
        use crate::crypto::cose::TrustAnchorType;

        let token = build_token_with(
            OID_SHA256,
            MessageDigest::sha256(),
            DATA,
            TokenOptions {
                profile_extensions: true,
                ..TokenOptions::default()
            },
        );
        let signer_der = tsa_signer_cert_der_from_token(&token)
            .unwrap()
            .expect("token carries its signer certificate");
        let signer_pem = X509::from_der(&signer_der).unwrap().to_pem().unwrap();

        // The TSA signer certificate is trusted only as a manifest-signer
        // anchor; it must not thereby be accepted for time-stamps.
        let mut ctp = CertificateTrustPolicy::new();
        ctp.add_trust_anchors(
            &signer_pem,
            "http://manifest_trust_list",
            TrustAnchorType::Manifest,
            None,
        )
        .unwrap();

        let mut log = StatusTracker::default();
        let result = verify_time_stamp(&token, DATA, &ctp, &mut log, true);
        assert!(
            matches!(result, Err(TimeStampError::Untrusted)),
            "a signer anchor must not vouch for a time-stamp: {result:?}"
        );
        assert!(log.has_status(TIMESTAMP_UNTRUSTED));
        assert!(!log.has_status(TIMESTAMP_TRUSTED));
    }

    fn decode_token(token: &[u8]) -> rasn_cms::SignedData {
        rasn::der::decode::<rasn_cms::SignedData>(
            rasn::der::decode::<rasn_cms::ContentInfo>(token)
                .unwrap()
                .content
                .as_bytes(),
        )
        .unwrap()
    }

    fn encode_token(sd: &rasn_cms::SignedData) -> Vec<u8> {
        tlv(
            0x30,
            &cat(&[OID_SIGNED_DATA, &tlv(0xa0, &rasn::der::encode(sd).unwrap())]),
        )
    }

    fn check_error(token: &[u8], status: &str) -> TimeStampError {
        let mut log = StatusTracker::default();
        let error = verify_time_stamp(
            token,
            DATA,
            &CertificateTrustPolicy::default(),
            &mut log,
            false,
        )
        .unwrap_err();
        assert!(log.has_status(status), "{error:?}: {log:?}");
        assert!(!log.has_status(TIMESTAMP_TRUSTED));
        error
    }

    #[test]
    fn signed_attributes_validate_all_supported_cms_digests() {
        for (oid, md) in [
            (OID_SHA1, MessageDigest::sha1()),
            (OID_SHA256, MessageDigest::sha256()),
            (OID_SHA384, MessageDigest::sha384()),
            (OID_SHA512, MessageDigest::sha512()),
        ] {
            let token = build_token_with(
                OID_SHA256,
                MessageDigest::sha256(),
                DATA,
                TokenOptions {
                    signed_attrs: true,
                    cms_digest: Some((oid, md)),
                    ..Default::default()
                },
            );
            let mut log = StatusTracker::default();
            assert_eq!(
                verify_time_stamp(
                    &token,
                    DATA,
                    &CertificateTrustPolicy::default(),
                    &mut log,
                    false
                )
                .is_ok(),
                oid != OID_SHA1,
                "{log:?}"
            );
            // SHA-1 is accepted as a CMS content digest, but EC/SHA-1
            // signatures are not supported by the signature validator.
            assert_eq!(log.has_status(TIMESTAMP_VALIDATED), oid != OID_SHA1);
        }
    }

    #[test]
    fn signed_signing_time_does_not_override_expired_tst_info_time() {
        for (tag, time) in [
            (0x17, b"210102030405Z".as_slice()),
            (0x18, b"20210102030405Z".as_slice()),
        ] {
            let token = build_token_with(
                OID_SHA256,
                MessageDigest::sha256(),
                DATA,
                TokenOptions {
                    gen_time: Some(b"20400101000000Z"),
                    signed_attrs: true,
                    signed_time: Some((tag, time)),
                    ..Default::default()
                },
            );
            let mut log = StatusTracker::default();
            let result = verify_time_stamp(
                &token,
                DATA,
                &CertificateTrustPolicy::default(),
                &mut log,
                false,
            );
            assert!(matches!(result, Err(TimeStampError::ExpiredCertificate)));
            assert!(log.has_status(crate::validation_status::TIMESTAMP_OUTSIDE_VALIDITY));
        }
        // An invalid signing-time value is ignored, not a malformed-token error.
        let token = build_token_with(
            OID_SHA256,
            MessageDigest::sha256(),
            DATA,
            TokenOptions {
                signed_attrs: true,
                signed_time: Some((0x04, b"not a time")),
                ..Default::default()
            },
        );
        let tst = verify_time_stamp(
            &token,
            DATA,
            &CertificateTrustPolicy::default(),
            &mut StatusTracker::default(),
            false,
        )
        .unwrap();
        assert_eq!(
            generalized_time_to_datetime(tst.gen_time).timestamp(),
            1_577_836_800
        );
    }

    #[test]
    fn signed_message_digest_failures_have_distinct_statuses() {
        use rasn::types::{Any, ObjectIdentifier};

        use crate::validation_status::{TIMESTAMP_MALFORMED, TIMESTAMP_MISMATCH};
        let token = build_token_with(
            OID_SHA256,
            MessageDigest::sha256(),
            DATA,
            TokenOptions {
                signed_attrs: true,
                ..Default::default()
            },
        );
        for case in 0..6 {
            let mut sd = decode_token(&token);
            let mut signer = sd.signer_infos.to_vec().remove(0).clone();
            let mut attrs: Vec<_> = signer
                .signed_attrs
                .take()
                .unwrap()
                .to_vec()
                .into_iter()
                .cloned()
                .collect();
            let pos = attrs
                .iter()
                .position(|a| {
                    a.r#type == rasn::types::Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_MESSAGE_DIGEST
                })
                .unwrap();
            match case {
                0 => {
                    attrs.remove(pos);
                }
                1 => {
                    attrs[pos].values =
                        vec![Any::new(vec![0x04, 0x01, 1]), Any::new(vec![0x04, 0x01, 2])].into()
                }
                2 => attrs[pos].values = vec![Any::new(vec![0x02, 0x01, 1])].into(),
                3 => attrs[pos].values = vec![Any::new(vec![0x04, 0x01, 1])].into(),
                5 => attrs[pos].values = Vec::<Any>::new().into(),
                _ => {
                    signer.digest_algorithm.algorithm =
                        ObjectIdentifier::new(vec![1, 2, 3, 4]).unwrap()
                }
            }
            signer.signed_attrs = Some(attrs.into());
            sd.signer_infos = vec![signer].into();
            let status = if case == 3 {
                TIMESTAMP_MISMATCH
            } else {
                TIMESTAMP_MALFORMED
            };

            let error = check_error(&encode_token(&sd), status);
            if case == 5 {
                // The cardinality guard rejects an empty SET before the
                // subsequent first-value lookup can return None.
                assert!(matches!(&error, TimeStampError::DecodeError(message)
                    if message == "message digest attribute has 0 values, should have one"));
            }

            assert!(if case == 3 {
                matches!(error, TimeStampError::InvalidData)
            } else {
                matches!(error, TimeStampError::DecodeError(_))
            });
        }
    }

    #[test]
    fn token_structure_and_signature_failures_are_not_trusted() {
        use crate::validation_status::TIMESTAMP_MALFORMED;
        let token = build_token(OID_SHA256, MessageDigest::sha256(), DATA);
        let sd = decode_token(&token);
        let mut missing = sd.clone();
        missing.certificates = None;
        assert!(matches!(
            check_error(&encode_token(&missing), TIMESTAMP_UNTRUSTED),
            TimeStampError::DecodeError(_)
        ));
        assert!(
            super::tsa_signer_cert_der_from_token(&encode_token(&missing))
                .unwrap()
                .is_none()
        );
        for content in [None, Some(vec![0x30, 0].into())] {
            let mut broken = sd.clone();
            broken.encap_content_info.content = content;
            assert!(matches!(
                check_error(&encode_token(&broken), TIMESTAMP_MALFORMED),
                TimeStampError::InvalidData
            ));
        }

        let mut bad_signature = sd.clone();
        let mut signer = bad_signature.signer_infos.to_vec().remove(0).clone();
        signer.signature = vec![0].into();
        bad_signature.signer_infos = vec![signer].into();
        assert!(matches!(
            check_error(&encode_token(&bad_signature), TIMESTAMP_UNTRUSTED),
            TimeStampError::Untrusted
        ));
        let mut no_signers = sd;
        no_signers.signer_infos = Vec::<rasn_cms::SignerInfo>::new().into();
        let mut log = StatusTracker::default();
        assert!(matches!(
            verify_time_stamp(
                &encode_token(&no_signers),
                DATA,
                &CertificateTrustPolicy::default(),
                &mut log,
                false
            ),
            Err(TimeStampError::InvalidData)
        ));
        assert!(
            super::tsa_signer_cert_der_from_token(&encode_token(&no_signers))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn certificate_validity_and_accuracy_boundaries() {
        use crate::validation_status::TIMESTAMP_OUTSIDE_VALIDITY;
        for time in [b"20170101000000Z".as_slice(), b"20310101000000Z".as_slice()] {
            let token = build_token_with(
                OID_SHA256,
                MessageDigest::sha256(),
                DATA,
                TokenOptions {
                    gen_time: Some(time),
                    ..Default::default()
                },
            );
            assert!(matches!(
                check_error(&token, TIMESTAMP_OUTSIDE_VALIDITY),
                TimeStampError::ExpiredCertificate
            ));
        }
        // notBefore is 2017-07-14T02:40:00Z; one microsecond of accuracy
        // deliberately rounds up to a one-second validation margin.
        for (time, accuracy, valid) in [
            (b"20170714024000Z".as_slice(), None, true),
            (b"20300317174640Z".as_slice(), None, true),
            (b"20170714023959Z".as_slice(), None, false),
            (
                b"20170714023959Z".as_slice(),
                Some([0x30, 3, 0x81, 1, 1].as_slice()),
                true,
            ),
            (
                b"20170714023958Z".as_slice(),
                Some([0x30, 3, 0x81, 1, 1].as_slice()),
                false,
            ),
        ] {
            let token = build_token_with(
                OID_SHA256,
                MessageDigest::sha256(),
                DATA,
                TokenOptions {
                    gen_time: Some(time),
                    accuracy,
                    ..Default::default()
                },
            );
            let result = verify_time_stamp(
                &token,
                DATA,
                &CertificateTrustPolicy::default(),
                &mut StatusTracker::default(),
                false,
            );
            assert_eq!(result.is_ok(), valid, "{time:?}: {result:?}");
        }
    }

    #[test]
    fn signer_lookup_matches_issuer_serial_and_decoded_ski() {
        use rasn_cms::{CertificateChoices, SignerIdentifier};
        let token = build_token_with(
            OID_SHA256,
            MessageDigest::sha256(),
            DATA,
            TokenOptions {
                profile_extensions: true,
                ..Default::default()
            },
        );
        let expected = super::tsa_signer_cert_der_from_token(&token)
            .unwrap()
            .unwrap();
        for raw_extension in [false, true] {
            let mut sd = decode_token(&token);
            let certs = sd.certificates.as_ref().unwrap().to_vec();
            let cert = certs
                .iter()
                .find_map(|choice| match choice {
                    CertificateChoices::Certificate(cert) => Some(cert),
                    _ => None,
                })
                .expect("test token contains a certificate");
            let ski = cert.tbs_certificate.extensions.as_ref().unwrap().iter().find(|e| e.extn_id == rasn::types::Oid::JOINT_ISO_ITU_T_DS_CERTIFICATE_EXTENSION_SUBJECT_KEY_IDENTIFIER).unwrap().extn_value.clone();
            let mut signer = sd.signer_infos.to_vec().remove(0).clone();
            signer.sid = SignerIdentifier::SubjectKeyIdentifier(if raw_extension {
                ski
            } else {
                rasn::der::decode::<rasn::types::OctetString>(&ski).unwrap()
            });
            signer.version = 3.into();
            sd.signer_infos = vec![signer].into();
            let token = encode_token(&sd);
            assert_eq!(
                super::tsa_signer_cert_der_from_token(&token).unwrap(),
                if raw_extension {
                    None
                } else {
                    Some(expected.clone())
                }
            );
            let result = verify_time_stamp(
                &token,
                DATA,
                &CertificateTrustPolicy::default(),
                &mut StatusTracker::default(),
                false,
            );
            assert_eq!(result.is_ok(), !raw_extension);
        }
    }

    #[test]
    fn timestamp_trust_requires_timestamp_signing_eku() {
        use crate::{crypto::cose::TrustAnchorType, validation_status::SIGNING_CREDENTIAL_INVALID};

        for purpose in [
            Some("1.3.6.1.4.1.62558.2.1"),
            Some("1.3.6.1.5.5.7.3.1"),
            Some("1.3.6.1.5.5.7.3.4"),
            Some("1.3.6.1.5.5.7.3.9"),
            Some(super::TIMESTAMP_OID_STR),
            None,
        ] {
            let token = build_token_with(
                OID_SHA256,
                MessageDigest::sha256(),
                DATA,
                TokenOptions {
                    profile_extensions: true,
                    signer_eku: purpose,
                    omit_eku: purpose.is_none(),
                    ..Default::default()
                },
            );
            let cert = super::tsa_signer_cert_der_from_token(&token)
                .unwrap()
                .unwrap();
            let pem = openssl::x509::X509::from_der(&cert)
                .unwrap()
                .to_pem()
                .unwrap();
            let mut policy = CertificateTrustPolicy::default();
            policy
                .add_trust_anchors(&pem, "test:tsa", TrustAnchorType::TSA, None)
                .unwrap();
            let mut log = StatusTracker::default();
            let result = verify_time_stamp(&token, DATA, &policy, &mut log, true);
            assert!(log.has_status(TIMESTAMP_VALIDATED));

            if purpose == Some(super::TIMESTAMP_OID_STR) {
                assert!(result.is_ok(), "{result:?}: {log:?}");
                assert!(log.has_status(TIMESTAMP_TRUSTED));
                assert!(!log.has_status(SIGNING_CREDENTIAL_INVALID));
            } else {
                assert!(matches!(result, Err(TimeStampError::Untrusted)));
                assert!(log.has_status(TIMESTAMP_UNTRUSTED));
                assert!(!log.has_status(SIGNING_CREDENTIAL_INVALID));
                assert!(!log.has_status(TIMESTAMP_TRUSTED));
            }

            let mut assertion_log = StatusTracker::default();
            assert_eq!(
                crate::crypto::cose::trusted_cawg_timestamp_token(
                    &token,
                    DATA,
                    &policy,
                    &mut assertion_log,
                )
                .is_some(),
                purpose == Some(super::TIMESTAMP_OID_STR),
            );
            assert!(!assertion_log.has_status(SIGNING_CREDENTIAL_INVALID));
        }
    }

    #[c2pa_macros::c2pa_test_async]
    async fn rejected_tsa_does_not_invalidate_trusted_manifest() {
        use std::io::Cursor;

        use coset::{cbor::value::Value, Label, SignatureContext, TaggedCborSerializable};

        use crate::{
            crypto::cose::{
                parse_cose_sign1, sign, trusted_cawg_timestamp, RawSignerCoseSigner,
                TimeStampStorage, TrustAnchorType,
            },
            utils::{
                test::{create_test_store, create_test_streams},
                test_signer::test_signer,
            },
            validation_status::{
                CLAIM_SIGNATURE_MISMATCH, SIGNING_CREDENTIAL_EXPIRED, SIGNING_CREDENTIAL_INVALID,
            },
            Context, Reader, SigningAlg, ValidationState,
        };

        let (format, mut input, mut output) = create_test_streams("earth_apollo17.jpg");
        let mut store = create_test_store().unwrap();
        store
            .save_to_stream(
                format,
                &mut input,
                &mut output,
                test_signer(SigningAlg::Es256).as_ref(),
                &Context::new(),
            )
            .unwrap();

        const ATTESTED: i64 = 1_577_836_800; // 2020-01-01T00:00:00Z
        const START: i64 = 1_500_000_000;
        const END: i64 = 4_102_444_800; // 2100-01-01T00:00:00Z

        for (claim_case, not_before, not_after, valid_now, valid_then) in [
            ("valid", START, END, true, true),
            ("expired", START, ATTESTED + 1, false, true),
            ("future", END - 1, END, false, false),
            ("at_not_before", ATTESTED, END, true, true),
            ("before_not_before", ATTESTED + 1, END, true, false),
            ("after_not_after", START, ATTESTED - 1, false, false),
            ("bad_claim_eku", START, END, false, false),
            ("bad_claim_signature", START, END, false, false),
            ("untrusted_claim", START, END, true, true),
        ] {
            let purpose = if claim_case == "bad_claim_eku" {
                "1.3.6.1.5.5.7.3.1"
            } else {
                "1.3.6.1.4.1.62558.2.1"
            };
            let (key, cert) = test_certificate(Some(purpose), true, not_before, not_after);
            let raw_signer = c2pa_raw_crypto::signer_from_private_key(
                &key.private_key_to_pem_pkcs8().unwrap(),
                SigningAlg::Es256,
            )
            .unwrap();

            let chain = vec![cert.to_der().unwrap()];
            let data = store.provenance_claim().unwrap().data().unwrap();
            let signature = sign(
                &RawSignerCoseSigner::new(raw_signer.as_ref(), &chain),
                &data,
                None,
                TimeStampStorage::V2_sigTst2_CTT,
                &Context::new(),
            )
            .unwrap();

            for timestamp_case in [
                "wrong_eku",
                "missing_eku",
                "trusted",
                "bad_imprint",
                "untrusted",
                "bad_signature",
                "absent",
            ] {
                let mut sign1 =
                    parse_cose_sign1(&signature, &data, &mut StatusTracker::default()).unwrap();

                if claim_case == "bad_claim_signature" {
                    sign1.signature[0] ^= 1;
                }

                let mut signature_cbor = Vec::new();
                coset::cbor::into_writer(
                    &Value::Bytes(sign1.signature.clone()),
                    &mut signature_cbor,
                )
                .unwrap();

                let tbs = coset::sig_structure_data(
                    SignatureContext::CounterSignature,
                    sign1.protected.clone(),
                    None,
                    &[],
                    &signature_cbor,
                );

                let mut token = build_token_with(
                    OID_SHA256,
                    MessageDigest::sha256(),
                    if timestamp_case == "bad_imprint" {
                        b"unrelated"
                    } else {
                        &tbs
                    },
                    TokenOptions {
                        profile_extensions: true,
                        signer_eku: (timestamp_case == "wrong_eku").then_some("1.3.6.1.5.5.7.3.1"),
                        omit_eku: timestamp_case == "missing_eku",
                        ..Default::default()
                    },
                );

                let tsa = super::tsa_signer_cert_der_from_token(&token)
                    .unwrap()
                    .unwrap();

                let tsa_pem = openssl::x509::X509::from_der(&tsa)
                    .unwrap()
                    .to_pem()
                    .unwrap();

                if timestamp_case == "bad_signature" {
                    let mut signed_data = decode_token(&token);
                    let mut signer = signed_data.signer_infos.to_vec().remove(0).clone();
                    let mut signature = signer.signature.to_vec();
                    *signature.last_mut().unwrap() ^= 1;
                    signer.signature = signature.into();
                    signed_data.signer_infos = vec![signer].into();
                    token = encode_token(&signed_data);
                }

                if timestamp_case != "absent" {
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
                }

                let mut policy = CertificateTrustPolicy::default();
                let mut anchors = Vec::new();

                if claim_case != "untrusted_claim" {
                    anchors.push(serde_json::json!({
                        "trust_anchors": String::from_utf8(cert.to_pem().unwrap()).unwrap(),
                        "trust_kind": "manifest",
                        "trust_uri": "test:claim"
                    }));
                }

                if timestamp_case != "untrusted" {
                    policy
                        .add_trust_anchors(&tsa_pem, "test:tsa", TrustAnchorType::TSA, None)
                        .unwrap();
                    anchors.push(serde_json::json!({
                        "trust_anchors": String::from_utf8(tsa_pem).unwrap(),
                        "trust_kind": "tsa",
                        "trust_uri": "test:tsa"
                    }));
                }

                assert_eq!(
                    trusted_cawg_timestamp(&sign1, &data, &policy, &mut StatusTracker::default())
                        .is_some(),
                    timestamp_case == "trusted",
                    "{claim_case}/{timestamp_case}: CAWG association",
                );

                store
                    .provenance_claim_mut()
                    .unwrap()
                    .set_signature_val(sign1.to_tagged_vec().unwrap());

                let manifest = store.to_jumbf_internal(0).unwrap();
                let context = Context::new()
                    .with_settings_value("verify.ocsp_fetch", false)
                    .unwrap()
                    .with_settings_value("verify.verify_timestamp_trust", true)
                    .unwrap()
                    .with_settings_value("verify.verify_trust", true)
                    .unwrap()
                    .with_settings_value("trust.anchors", anchors)
                    .unwrap();

                for asynchronous in [false, true] {
                    let reader = Reader::from_context(
                        Context::new()
                            .with_settings(context.settings().clone())
                            .unwrap(),
                    );

                    let stream = Cursor::new(output.get_ref().clone());
                    let reader = if asynchronous {
                        reader
                            .with_manifest_data_and_stream_async(&manifest, format, stream)
                            .await
                    } else {
                        reader.with_manifest_data_and_stream(&manifest, format, stream)
                    }
                    .unwrap();

                    let expected_valid = if timestamp_case == "trusted" {
                        valid_then
                    } else {
                        valid_now
                    };

                    assert_eq!(
                        reader.validation_state(),
                        if expected_valid {
                            if claim_case == "untrusted_claim" {
                                ValidationState::Valid
                            } else {
                                ValidationState::Trusted
                            }
                        } else {
                            ValidationState::Invalid
                        },
                        "{claim_case}/{timestamp_case}, async={asynchronous}: {reader}",
                    );

                    let results =
                        serde_json::to_value(reader.validation_results().unwrap()).unwrap();

                    let active = &results["activeManifest"];
                    let has = |kind: &str, code: &str| {
                        active[kind]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|s| s["code"] == code)
                    };

                    assert_eq!(
                        has("success", TIMESTAMP_TRUSTED),
                        timestamp_case == "trusted"
                    );

                    assert_eq!(
                        has("failure", SIGNING_CREDENTIAL_INVALID),
                        claim_case == "bad_claim_eku"
                    );

                    if claim_case == "untrusted_claim" {
                        assert!(has(
                            "failure",
                            crate::validation_status::SIGNING_CREDENTIAL_UNTRUSTED
                        ));
                        assert!(!has(
                            "success",
                            crate::validation_status::SIGNING_CREDENTIAL_TRUSTED
                        ));
                    }

                    if matches!(
                        timestamp_case,
                        "wrong_eku" | "missing_eku" | "untrusted" | "bad_signature"
                    ) {
                        assert!(has("informational", TIMESTAMP_UNTRUSTED));
                    }

                    if timestamp_case == "bad_imprint" {
                        assert!(
                            has(
                                "informational",
                                crate::validation_status::TIMESTAMP_MISMATCH
                            ),
                            "{claim_case}/{timestamp_case}: {reader}",
                        );
                    }

                    if !expected_valid
                        && claim_case != "bad_claim_eku"
                        && claim_case != "bad_claim_signature"
                    {
                        assert!(has("failure", SIGNING_CREDENTIAL_EXPIRED));
                    }

                    if claim_case == "bad_claim_signature" {
                        assert!(has("failure", CLAIM_SIGNATURE_MISMATCH));
                    }
                }
            }
        }
    }

    #[test]
    fn timestamp_trust_respects_tsa_anchor_list() {
        use crate::crypto::cose::TrustAnchorType;

        let token = build_token_with(
            OID_SHA256,
            MessageDigest::sha256(),
            DATA,
            TokenOptions {
                profile_extensions: true,
                ..Default::default()
            },
        );
        let cert = super::tsa_signer_cert_der_from_token(&token)
            .unwrap()
            .unwrap();
        let pem = openssl::x509::X509::from_der(&cert)
            .unwrap()
            .to_pem()
            .unwrap();

        for kind in [TrustAnchorType::Manifest, TrustAnchorType::CAWG] {
            let mut policy = CertificateTrustPolicy::new();
            policy
                .add_trust_anchors(&pem, "test:legacy", kind, None)
                .unwrap();

            let mut log = StatusTracker::default();
            assert!(matches!(
                verify_time_stamp(&token, DATA, &policy, &mut log, true),
                Err(TimeStampError::Untrusted)
            ));
            assert!(log.has_status(TIMESTAMP_VALIDATED));
            assert!(log.has_status(TIMESTAMP_UNTRUSTED));
            assert!(!log.has_status(TIMESTAMP_TRUSTED));

            policy
                .add_trust_anchors(
                    include_bytes!(
                        "../../../tests/fixtures/crypto/raw_signature/test_cert_root_bundle.pem"
                    ),
                    "test:unrelated_tsa",
                    TrustAnchorType::TSA,
                    None,
                )
                .unwrap();
            let mut log = StatusTracker::default();
            assert!(matches!(
                verify_time_stamp(&token, DATA, &policy, &mut log, true),
                Err(TimeStampError::Untrusted)
            ));
            assert!(log.has_status(TIMESTAMP_VALIDATED));
            assert!(log.has_status(TIMESTAMP_UNTRUSTED));
            assert!(!log.has_status(TIMESTAMP_TRUSTED));

            policy
                .add_trust_anchors(&pem, "test:tsa", TrustAnchorType::TSA, None)
                .unwrap();
            let mut log = StatusTracker::default();
            let trusted_tst = verify_time_stamp(&token, DATA, &policy, &mut log, true).unwrap();
            assert_eq!(
                generalized_time_to_datetime(trusted_tst.gen_time).timestamp(),
                1_577_836_800
            );
            assert!(log.has_status(TIMESTAMP_TRUSTED));
            assert!(!log.has_status(TIMESTAMP_UNTRUSTED));
            assert!(log
                .logged_items()
                .iter()
                .any(|item| item.description.contains("test:tsa")));
        }
    }

    #[test]
    fn trust_is_separate_from_signature_and_profile_validation() {
        use crate::crypto::cose::TrustAnchorType;
        for valid_profile in [false, true] {
            let token = build_token_with(
                OID_SHA256,
                MessageDigest::sha256(),
                DATA,
                TokenOptions {
                    profile_extensions: valid_profile,
                    ..Default::default()
                },
            );
            let parsed = super::ParsedTimestamp::parse(&token).unwrap();
            parsed
                .verify_signatures()
                .next()
                .unwrap()
                .unwrap()
                .verify_message_imprint(DATA)
                .unwrap();

            let mut policy = CertificateTrustPolicy::default();
            policy.clear();
            let mut log = StatusTracker::default();
            assert!(
                matches!(
                    verify_time_stamp(&token, DATA, &policy, &mut log, true),
                    Err(TimeStampError::Untrusted)
                ),
                "{log:?}"
            );
            assert!(log.has_status(TIMESTAMP_VALIDATED));
            assert!(log.has_status(TIMESTAMP_UNTRUSTED));
            if valid_profile {
                let cert = super::tsa_signer_cert_der_from_token(&token)
                    .unwrap()
                    .unwrap();
                let pem = openssl::x509::X509::from_der(&cert)
                    .unwrap()
                    .to_pem()
                    .unwrap();
                policy
                    .add_trust_anchors(&pem, "test:tsa", TrustAnchorType::TSA, None)
                    .unwrap();
                let mut log = StatusTracker::default();
                assert!(
                    verify_time_stamp(&token, DATA, &policy, &mut log, true).is_ok(),
                    "{log:?}"
                );
                assert!(log.has_status(TIMESTAMP_TRUSTED));
            }
        }
    }

    #[test]
    fn signer_lookup_handles_missing_serial_ski_and_unsupported_cert_choices() {
        let token = build_token(OID_SHA256, MessageDigest::sha256(), DATA);
        for ski in [false, true] {
            let mut sd = decode_token(&token);
            let mut signer = sd.signer_infos.to_vec()[0].clone();
            if ski {
                signer.sid = rasn_cms::SignerIdentifier::SubjectKeyIdentifier(vec![1, 2, 3].into());
            } else if let rasn_cms::SignerIdentifier::IssuerAndSerialNumber(sn) = &mut signer.sid {
                sn.serial_number = 99.into();
            }
            sd.signer_infos = vec![signer].into();
            let token = encode_token(&sd);
            assert!(super::tsa_signer_cert_der_from_token(&token)
                .unwrap()
                .is_none());
            assert!(matches!(
                verify_time_stamp(
                    &token,
                    DATA,
                    &CertificateTrustPolicy::default(),
                    &mut StatusTracker::default(),
                    false
                ),
                Err(TimeStampError::InvalidData)
            ));
        }

        let mut sd = decode_token(&token);
        let other: rasn_cms::CertificateChoices =
            rasn::der::decode(&tlv(0xa3, &cat(&[OID_POLICY, &[0x05, 0]]))).unwrap();
        sd.certificates = Some(vec![other].into());
        let token = encode_token(&sd);
        assert!(super::tsa_signer_cert_der_from_token(&token).is_err());
        assert!(matches!(
            check_error(&token, TIMESTAMP_UNTRUSTED),
            TimeStampError::DecodeError(_)
        ));
    }

    #[test]
    fn certificate_ordering_follows_names_and_omits_unrelated_certificates() {
        fn cert(subject: &str, issuer: &str, serial: u32) -> Vec<u8> {
            let key = PKey::from_ec_key(
                EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
            )
            .unwrap();
            let name = |value: &str| {
                let mut name = X509NameBuilder::new().unwrap();
                name.append_entry_by_nid(Nid::COMMONNAME, value).unwrap();
                name.build()
            };

            let mut cert = X509Builder::new().unwrap();
            cert.set_version(2).unwrap();
            cert.set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
                .unwrap();
            cert.set_subject_name(&name(subject)).unwrap();
            cert.set_issuer_name(&name(issuer)).unwrap();
            cert.set_pubkey(&key).unwrap();
            cert.set_not_before(&Asn1Time::from_unix(1_500_000_000).unwrap())
                .unwrap();
            cert.set_not_after(&Asn1Time::from_unix(1_900_000_000).unwrap())
                .unwrap();
            cert.sign(&key, MessageDigest::sha256()).unwrap();
            cert.build().to_der().unwrap()
        }

        let leaf = cert("leaf", "intermediate", 1);
        let intermediate = cert("intermediate", "root", 2);
        let root = cert("root", "root", 3);
        let unrelated = cert("unrelated", "unrelated", 4);
        let shuffled = vec![root.clone(), unrelated, leaf.clone(), intermediate.clone()];
        assert_eq!(
            super::order_certificates_leaf_to_root(&shuffled, 2).unwrap(),
            vec![leaf.clone(), intermediate, root]
        );
        assert_eq!(
            super::order_certificates_leaf_to_root(std::slice::from_ref(&leaf), 0).unwrap(),
            vec![leaf]
        );
        let cycle_a = cert("a", "b", 5);
        let cycle_b = cert("b", "a", 6);
        assert_eq!(
            super::order_certificates_leaf_to_root(&[cycle_a.clone(), cycle_b.clone()], 0).unwrap(),
            vec![cycle_a, cycle_b]
        );
    }
}
