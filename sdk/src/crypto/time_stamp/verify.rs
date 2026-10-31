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

use std::str::FromStr;

use asn1_rs::FromDer;
use async_generic::async_generic;
use bcder::OctetString;
use c2pa_raw_crypto::validator_for_sig_and_hash_algs;
use chrono::{offset::LocalResult, DateTime, TimeZone, Utc};
use der::asn1::ObjectIdentifier;
use rasn::{prelude::*, types};
use rasn_cms::{CertificateChoices, SignerIdentifier};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use crate::{
    crypto::{
        asn1::rfc3161::{Accuracy, TstInfo},
        cose::{check_end_entity_certificate_profile, CertificateTrustPolicy, TrustAnchorType},
        time_stamp::{
            response::{signed_data_from_time_stamp_response, tst_info_from_signed_data},
            TimeStampError,
        },
    },
    log_item,
    status_tracker::StatusTracker,
    validation_status::{
        TIMESTAMP_MALFORMED, TIMESTAMP_MISMATCH, TIMESTAMP_OUTSIDE_VALIDITY, TIMESTAMP_TRUSTED,
        TIMESTAMP_UNTRUSTED, TIMESTAMP_VALIDATED,
    },
};

const TIMESTAMP_OID_STR: &str = "1.3.6.1.5.5.7.3.8";

// when signed attributes are present the digest is the DER
// encoding of the SignerInfo SignedAttributes
fn signed_attributes_digested_content(
    signer_info: &rasn_cms::SignerInfo,
) -> Result<Option<Vec<u8>>, rasn::error::EncodeError> {
    if let Some(signed_attributes) = &signer_info.signed_attrs {
        match rasn::der::encode(signed_attributes) {
            Ok(encoded) => Ok(Some(encoded)),
            Err(e) => Err(e),
        }
    } else {
        Ok(None)
    }
}

/// Decode the TimeStampToken info and verify it against the supplied data and trust policy
#[async_generic]
pub fn verify_time_stamp(
    ts: &[u8],
    data: &[u8],
    ctp: &CertificateTrustPolicy,
    validation_log: &mut StatusTracker,
    verify_trust: bool,
) -> Result<TstInfo, TimeStampError> {
    // Get the signed data frorm the timestamp data
    let Ok(Some(sd)) = signed_data_from_time_stamp_response(ts) else {
        log_item!("", "could not parse timestamp data", "verify_time_stamp")
            .validation_status(TIMESTAMP_MALFORMED)
            .informational(validation_log);

        return Err(TimeStampError::DecodeError(
            "unable to find signed data".to_string(),
        ));
    };

    // Grab the list of certs used in signing this timestamp
    let Some(certs) = &sd.certificates else {
        log_item!("", "could not parse timestamp data", "verify_time_stamp")
            .validation_status(TIMESTAMP_UNTRUSTED)
            .informational(validation_log);

        return Err(TimeStampError::DecodeError(
            "time stamp contains no certificates".to_string(),
        ));
    };
    let certs_vec = certs.to_vec();

    // Convert certs to DER format
    let cert_ders: Vec<Vec<u8>> = certs_vec
        .iter()
        .filter_map(|cc| {
            if let CertificateChoices::Certificate(c) = cc {
                rasn::der::encode(c).ok()
            } else {
                None
            }
        })
        .collect();

    if cert_ders.len() != certs.len() {
        log_item!("", "could not parse timestamp data", "verify_time_stamp")
            .validation_status(TIMESTAMP_UNTRUSTED)
            .informational(validation_log);

        return Err(TimeStampError::DecodeError(
            "time stamp certificate could not be processed".to_string(),
        ));
    }

    let mut last_err = TimeStampError::InvalidData;
    let mut current_validation_log = StatusTracker::default();

    // Look for any valid signer.
    for signer_info in sd.signer_infos.to_vec().iter() {
        current_validation_log = StatusTracker::default(); // reset for latest results

        // Find signer's cert.
        let cert_pos = match certs_vec.iter().position(|cc| {
            let c = match cc {
                CertificateChoices::Certificate(c) => c,
                _ => return false,
            };

            match &signer_info.sid {
                SignerIdentifier::IssuerAndSerialNumber(sn) => {
                    sn.issuer == c.tbs_certificate.issuer
                        && sn.serial_number == c.tbs_certificate.serial_number
                }

                SignerIdentifier::SubjectKeyIdentifier(ski) => {
                    if let Some(extensions) = &c.tbs_certificate.extensions {
                        extensions.iter().any(|e| {
                            if e.extn_id == Oid::JOINT_ISO_ITU_T_DS_CERTIFICATE_EXTENSION_SUBJECT_KEY_IDENTIFIER {
                                return *ski == e.extn_value;
                            }
                            false
                        })
                    } else {
                        false
                    }
                }
            }
        }) {
            Some(c) => c,
            None => continue,
        };
        let CertificateChoices::Certificate(cert) = certs_vec[cert_pos] else {
            continue;
        };

        // get the cert common name, use different crate since x509-certificate does
        // not parse the common name correctly
        let mut common_name = String::new();
        if let Ok((_, new_c)) =
            x509_parser::certificate::X509Certificate::from_der(&cert_ders[cert_pos])
        {
            for rdn in new_c.subject().iter_common_name() {
                if let Ok(cn) = rdn.as_str() {
                    common_name.push_str(cn);
                }
            }
        }

        // Load TstInfo. We will verify its contents below against signed
        // values.
        let Ok(Some(mut tst)) = tst_info_from_signed_data(&sd) else {
            log_item!("", "timestamp response had no TstInfo", "verify_time_stamp")
                .validation_status(TIMESTAMP_MALFORMED)
                .informational(&mut current_validation_log);

            last_err = TimeStampError::InvalidData;
            continue;
        };

        let mi = &tst.message_imprint;

        // Check for time stamp expiration.
        let mut signing_time = generalized_time_to_datetime(tst.gen_time.clone()).timestamp();

        // Check the signer info's signed attributes.
        if let Some(attributes) = &signer_info.signed_attrs {
            // If there is a signed signing time attribute use it
            if let Some(Some(attrib_signing_time)) = attributes
                .to_vec()
                .iter()
                .find(|attr| attr.r#type == Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_SIGNING_TIME)
                .map(|attr| {
                    if attr.values.len() != 1 {
                        // per CMS spec can only contain 1 signing time value
                        return None;
                    }

                    attr.values
                        .to_vec()
                        .first()
                        .and_then(|v| rasn::der::decode::<rasn_pkix::Time>(v.as_bytes()).ok())
                })
            {
                let signed_signing_time = match attrib_signing_time {
                    rasn_pkix::Time::Utc(date_time) => date_time.timestamp(),
                    rasn_pkix::Time::General(date_time) => {
                        generalized_time_to_datetime(date_time).timestamp()
                    }
                };

                if let Some(gt) = timestamp_to_generalized_time(signed_signing_time) {
                    // Use actual signed time.
                    signing_time = generalized_time_to_datetime(gt.clone()).timestamp();
                    tst.gen_time = gt;
                };
            }

            // Check that the mandatory signed message digest is self-consistent.
            match attributes
                .to_vec()
                .iter()
                .find(|attr| attr.r#type == Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_MESSAGE_DIGEST)
            {
                Some(message_digest) => {
                    // message digest attribute MUST have exactly 1 value.
                    if message_digest.values.len() != 1 {
                        log_item!(
                            "",
                            "timestamp response contained multiple message digests",
                            "verify_time_stamp"
                        )
                        .validation_status(TIMESTAMP_MALFORMED)
                        .informational(&mut current_validation_log);

                        last_err = TimeStampError::DecodeError(format!(
                            "message digest attribute has {n} values, should have one",
                            n = message_digest.values.len()
                        ));

                        continue;
                    }

                    // Get signed message digest.
                    let signed_message_digest = match message_digest.values.to_vec().first() {
                        Some(a) => match rasn::der::decode::<types::OctetString>(a.as_bytes()) {
                            Ok(os) => os.to_vec(),
                            Err(_) => {
                                log_item!(
                                    "",
                                    "timestamp could not decode signed message data",
                                    "verify_time_stamp"
                                )
                                .validation_status(TIMESTAMP_MALFORMED)
                                .informational(&mut current_validation_log);

                                last_err = TimeStampError::DecodeError(
                                    "unable to decode signed message data".to_string(),
                                );
                                continue;
                            }
                        },
                        None => {
                            log_item!("", "timestamp bad message digest", "verify_time_stamp")
                                .validation_status(TIMESTAMP_MALFORMED)
                                .informational(&mut current_validation_log);

                            last_err = TimeStampError::DecodeError(
                                "unable to decode message digest".to_string(),
                            );
                            continue;
                        }
                    };

                    // Get message digest hash algorithm.
                    let Ok(di_oid) =
                        bcder::Oid::from_str(&signer_info.digest_algorithm.algorithm.to_string())
                    else {
                        log_item!(
                            "",
                            "timestamp bad message digest algorithm",
                            "verify_time_stamp"
                        )
                        .validation_status(TIMESTAMP_MALFORMED)
                        .informational(&mut current_validation_log);

                        last_err =
                            TimeStampError::DecodeError("unsupported digest algorithm".to_string());
                        continue;
                    };

                    let digest_algorithm = match DigestAlgorithm::try_from(&di_oid) {
                        Ok(d) => d,
                        Err(_) => {
                            log_item!(
                                "",
                                "timestamp bad message digest algorithm",
                                "verify_time_stamp"
                            )
                            .validation_status(TIMESTAMP_MALFORMED)
                            .informational(&mut current_validation_log);

                            last_err = TimeStampError::DecodeError(
                                "unsupported digest algorithm".to_string(),
                            );
                            continue;
                        }
                    };

                    let mut h = digest_algorithm.digester();
                    if let Some(content) = &sd.encap_content_info.content {
                        h.update(content);
                    }

                    let digest = h.finish();

                    if signed_message_digest != digest.as_ref() {
                        log_item!("", "timestamp bad message digest", "verify_time_stamp")
                            .validation_status(TIMESTAMP_MISMATCH)
                            .informational(&mut current_validation_log);

                        last_err = TimeStampError::InvalidData;
                        continue;
                    }
                }

                None => {
                    log_item!("", "timestamp no message digest", "verify_time_stamp")
                        .validation_status(TIMESTAMP_MALFORMED)
                        .informational(&mut current_validation_log);

                    last_err = TimeStampError::DecodeError("no message imprint".to_string());
                    continue;
                }
            }
        }

        // Build CMS TBS structure to verify.  If SignedAttributes are available then
        // use those as the TBS else the TBS is the value of the ContentInfo
        let tbs = match signed_attributes_digested_content(signer_info) {
            Ok(sdc) => match sdc {
                Some(tbs) => tbs,
                None => match &sd.encap_content_info.content {
                    Some(d) => d.to_vec(),
                    None => {
                        log_item!("", "timestamp no message digest", "verify_time_stamp")
                            .validation_status(TIMESTAMP_MALFORMED)
                            .informational(&mut current_validation_log);

                        last_err = TimeStampError::DecodeError(
                            "time stamp does not contain digested content".to_string(),
                        );
                        continue;
                    }
                },
            },
            Err(_) => {
                log_item!(
                    "",
                    "timestamp signer attributes malformed",
                    "verify_time_stamp"
                )
                .validation_status(TIMESTAMP_MALFORMED)
                .informational(&mut current_validation_log);

                last_err =
                    TimeStampError::DecodeError("timestamp signer info malformed".to_string());
                continue;
            }
        };

        // hash used for signature
        let Ok(hash_alg) =
            bcder::Oid::from_str(&signer_info.digest_algorithm.algorithm.to_string())
        else {
            log_item!("", "timestamp bad hash alg", "verify_time_stamp")
                .validation_status(TIMESTAMP_MALFORMED)
                .informational(&mut current_validation_log);

            last_err = TimeStampError::DecodeError("timestamp bad tbs certificate".to_string());
            continue;
        };

        // grab signature value.
        let sig_val =
            bcder::OctetString::new(bytes::Bytes::copy_from_slice(&signer_info.signature));

        // grab the signing key
        let signing_key_der_results =
            rasn::der::encode(&cert.tbs_certificate.subject_public_key_info);

        let Ok(signing_key_der) = signing_key_der_results else {
            log_item!("", "timestamp bad signing key", "verify_time_stamp")
                .validation_status(TIMESTAMP_MALFORMED)
                .informational(&mut current_validation_log);

            last_err = TimeStampError::DecodeError("timestamp bad tbs certificate".to_string());
            continue;
        };

        // algorithm used to sign the certificate
        let Ok(sig_alg) = bcder::Oid::from_str(
            &cert
                .tbs_certificate
                .subject_public_key_info
                .algorithm
                .algorithm
                .to_string(),
        ) else {
            log_item!("", "timestamp bad tbs certificate alg", "verify_time_stamp")
                .validation_status(TIMESTAMP_MALFORMED)
                .informational(&mut current_validation_log);

            last_err = TimeStampError::DecodeError("timestamp bad tbs certificate".to_string());
            continue;
        };

        // Verify signature of time stamp signature.
        if validate_timestamp_sig(&sig_alg, &hash_alg, &sig_val, &tbs, &signing_key_der).is_err() {
            log_item!(
                "",
                "timestamp signed data did not match signature",
                "verify_time_stamp"
            )
            .validation_status(TIMESTAMP_UNTRUSTED)
            .informational(&mut current_validation_log);

            last_err = TimeStampError::Untrusted;
            continue;
        }

        // Make sure the time stamp's cert was valid for the stated signing time.
        let not_before = time_to_datetime(cert.tbs_certificate.validity.not_before).timestamp();
        let not_after = time_to_datetime(cert.tbs_certificate.validity.not_after).timestamp();
        let accuracy_margin = tst_accuracy_seconds(tst.accuracy.as_ref());

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

        // Make sure the time stamp is valid for the specified data.
        let digest_algorithm =
            match DigestAlgorithm::for_message_imprint(&mi.hash_algorithm.algorithm) {
                Some(d) => d,
                None => {
                    log_item!(
                        "",
                        "timestamp unknown message digest algorithm",
                        "verify_time_stamp"
                    )
                    .validation_status(TIMESTAMP_UNTRUSTED)
                    .informational(&mut current_validation_log);

                    last_err = TimeStampError::UnsupportedAlgorithm;
                    continue;
                }
            };

        let mut h = digest_algorithm.digester();
        h.update(data);

        let digest = h.finish();
        if digest.as_ref() == mi.hashed_message.to_bytes() {
            log_item!(
                "",
                format!("timestamp message digest matched: {}", &common_name),
                "verify_time_stamp"
            )
            .validation_status(TIMESTAMP_VALIDATED)
            .success(&mut current_validation_log);
        } else {
            log_item!(
                "",
                format!("timestamp message digest did not match: {}", &common_name),
                "verify_time_stamp"
            )
            .validation_status(TIMESTAMP_MISMATCH)
            .informational(&mut current_validation_log);

            last_err = TimeStampError::InvalidData;
            continue;
        }

        // the certificate must be on the trust list to be considered valid
        if verify_trust {
            let mut adjusted_ctp = CertificateTrustPolicy::default();

            // Order certificates from leaf to root before trust validation
            let ordered_cert_ders = order_certificates_leaf_to_root(&cert_ders, cert_pos)?;

            // make sure this is a timestamping EKU
            adjusted_ctp.clear_ekus();
            adjusted_ctp.add_mandatory_ekus(TIMESTAMP_OID_STR.as_bytes()); // timestamp signing EKU
            if check_end_entity_certificate_profile(
                &ordered_cert_ders[0],
                &adjusted_ctp,
                &mut current_validation_log,
                Some(&tst),
            )
            .is_err()
            {
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

            // A time-stamp signer must chain to a TSA trust anchor. Without a
            // TSA trust list, keep accepting any configured anchor.
            let anchor_type = ctp
                .anchor_sets()
                .any(|a| a.trust_anchor_type == TrustAnchorType::TSA)
                .then_some(TrustAnchorType::TSA);

            match ctp.check_certificate_trust_for(
                anchor_type,
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

/// Extract the TSA signer certificate (DER) from an RFC 3161 timestamp token.
/// Does not verify the token; only parses it and returns the first signer's certificate.
pub fn tsa_signer_cert_der_from_token(ts: &[u8]) -> Result<Option<Vec<u8>>, TimeStampError> {
    let Some(sd) = signed_data_from_time_stamp_response(ts)? else {
        return Ok(None);
    };
    let Some(certs) = &sd.certificates else {
        return Ok(None);
    };
    let certs_vec = certs.to_vec();
    let cert_ders: Vec<Vec<u8>> = certs_vec
        .iter()
        .filter_map(|cc| {
            if let CertificateChoices::Certificate(c) = cc {
                rasn::der::encode(c).ok()
            } else {
                None
            }
        })
        .collect();
    if cert_ders.len() != certs_vec.len() {
        return Err(TimeStampError::DecodeError(
            "time stamp certificate could not be processed".to_string(),
        ));
    }
    let Some(signer_info) = sd.signer_infos.to_vec().into_iter().next() else {
        return Ok(None);
    };
    let Some(cert_pos) = certs_vec.iter().position(|cc| {
        let c = match cc {
            CertificateChoices::Certificate(c) => c,
            _ => return false,
        };
        match &signer_info.sid {
            SignerIdentifier::IssuerAndSerialNumber(sn) => {
                sn.issuer == c.tbs_certificate.issuer
                    && sn.serial_number == c.tbs_certificate.serial_number
            }
            SignerIdentifier::SubjectKeyIdentifier(ski) => {
                if let Some(extensions) = &c.tbs_certificate.extensions {
                    extensions.iter().any(|e| {
                        if e.extn_id
                            == Oid::JOINT_ISO_ITU_T_DS_CERTIFICATE_EXTENSION_SUBJECT_KEY_IDENTIFIER
                        {
                            return *ski == e.extn_value;
                        }
                        false
                    })
                } else {
                    false
                }
            }
        }
    }) else {
        return Ok(None);
    };
    Ok(Some(cert_ders[cert_pos].clone()))
}

fn generalized_time_to_datetime<T: Into<DateTime<Utc>>>(gt: T) -> DateTime<Utc> {
    gt.into()
}

fn timestamp_to_generalized_time(dt: i64) -> Option<crate::crypto::asn1::GeneralizedTime> {
    match Utc.timestamp_opt(dt, 0) {
        // try_into fails for dates outside der's supported 1970-9999 range
        LocalResult::Single(time) => time.try_into().ok(),
        _ => None,
    }
}

/// Digest algorithm enum compatible with bcder OIDs
#[derive(Clone, Copy, Debug)]
enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    fn digester(self) -> Hasher {
        match self {
            // `Sha1` follows the `digest` 0.10 traits, while `Sha2*` follows
            // `digest` 0.11, so each `new()` must be fully qualified to the
            // matching `Digest` trait.
            DigestAlgorithm::Sha1 => Hasher::Sha1(<Sha1 as sha1::Digest>::new()),
            DigestAlgorithm::Sha256 => Hasher::Sha256(<Sha256 as sha2::Digest>::new()),
            DigestAlgorithm::Sha384 => Hasher::Sha384(<Sha384 as sha2::Digest>::new()),
            DigestAlgorithm::Sha512 => Hasher::Sha512(<Sha512 as sha2::Digest>::new()),
        }
    }

    // C2PA 13.1/15.8.2: a messageImprint must use SHA-256/384/512. SHA-1 is only tolerated for the CMS digest.
    fn for_message_imprint(oid: &bcder::Oid) -> Option<Self> {
        Self::try_from(oid)
            .ok()
            .filter(|d| !matches!(d, DigestAlgorithm::Sha1))
    }
}

impl TryFrom<&bcder::Oid> for DigestAlgorithm {
    type Error = ();

    fn try_from(oid: &bcder::Oid) -> Result<Self, Self::Error> {
        // Using der::asn1 instead of oids defined in oid.rs, because this is faster and we intend to remove x509_parser eventually.
        // Convert bcder::Oid to string, then parse as ObjectIdentifier for comparison
        let oid_str = oid.to_string();
        let const_oid = ObjectIdentifier::new(&oid_str).map_err(|_| ())?;

        // SHA-1: 1.3.14.3.2.26
        const SHA1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
        // SHA-256: 2.16.840.1.101.3.4.2.1
        const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
        // SHA-384: 2.16.840.1.101.3.4.2.2
        const SHA384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
        // SHA-512: 2.16.840.1.101.3.4.2.3
        const SHA512_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

        if const_oid == SHA1_OID {
            Ok(DigestAlgorithm::Sha1)
        } else if const_oid == SHA256_OID {
            Ok(DigestAlgorithm::Sha256)
        } else if const_oid == SHA384_OID {
            Ok(DigestAlgorithm::Sha384)
        } else if const_oid == SHA512_OID {
            Ok(DigestAlgorithm::Sha512)
        } else {
            Err(())
        }
    }
}

/// Hasher enum to hold different digest types
enum Hasher {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha1(h) => {
                use sha1::Digest;
                h.update(data);
            }
            Hasher::Sha256(h) => {
                use sha2::Digest;
                h.update(data);
            }
            Hasher::Sha384(h) => {
                use sha2::Digest;
                h.update(data);
            }
            Hasher::Sha512(h) => {
                use sha2::Digest;
                h.update(data);
            }
        }
    }

    fn finish(self) -> HasherOutput {
        match self {
            Hasher::Sha1(h) => {
                use sha1::Digest;
                HasherOutput(h.finalize().to_vec())
            }
            Hasher::Sha256(h) => {
                use sha2::Digest;
                HasherOutput(h.finalize().to_vec())
            }
            Hasher::Sha384(h) => {
                use sha2::Digest;
                HasherOutput(h.finalize().to_vec())
            }
            Hasher::Sha512(h) => {
                use sha2::Digest;
                HasherOutput(h.finalize().to_vec())
            }
        }
    }
}

/// Wrapper for hash output that implements AsRef<[u8]>
struct HasherOutput(Vec<u8>);

impl AsRef<[u8]> for HasherOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

fn time_to_datetime(t: rasn_pkix::Time) -> DateTime<Utc> {
    match t {
        rasn_pkix::Time::Utc(u) => u,
        rasn_pkix::Time::General(gt) => generalized_time_to_datetime(gt),
    }
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

/// bcder is non-negative and big-endian
fn integer_to_i64(int: &bcder::Integer) -> i64 {
    let bytes = int.as_slice();
    if bytes.is_empty() || bytes.len() > 8 {
        return 0;
    }
    let mut result = 0i64;
    for &b in bytes {
        result = (result << 8) | (b as i64);
    }
    result
}

/// Convert a TSTInfo Accuracy value to a whole-second margin (ceiling).
fn tst_accuracy_seconds(accuracy: Option<&Accuracy>) -> i64 {
    let Some(acc) = accuracy else {
        return 0;
    };
    let secs = acc.seconds.as_ref().map(integer_to_i64).unwrap_or(0);
    let millis = acc.millis.as_ref().map(integer_to_i64).unwrap_or(0);
    let micros = acc.micros.as_ref().map(integer_to_i64).unwrap_or(0);
    let total_micros = secs
        .saturating_mul(1_000_000)
        .saturating_add(millis.saturating_mul(1_000))
        .saturating_add(micros);
    // ceiling division to full seconds
    total_micros.saturating_add(999_999) / 1_000_000
}

fn validate_timestamp_sig(
    sig_alg: &bcder::Oid,
    hash_alg: &bcder::Oid,
    sig_val: &OctetString,
    tbs: &[u8],
    signing_key_der: &[u8],
) -> Result<(), TimeStampError> {
    let Some(validator) = validator_for_sig_and_hash_algs(
        &c2pa_raw_crypto::Oid::new(sig_alg.as_ref()),
        &c2pa_raw_crypto::Oid::new(hash_alg.as_ref()),
    ) else {
        return Err(TimeStampError::UnsupportedAlgorithm);
    };

    validator
        .validate(&sig_val.to_bytes(), tbs, signing_key_der)
        .map_err(|_| TimeStampError::InvalidData)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::str::FromStr;

    use super::DigestAlgorithm;

    fn oid(s: &str) -> bcder::Oid {
        bcder::Oid::from_str(s).expect("valid OID")
    }

    #[test]
    fn message_imprint_rejects_sha1_and_unlisted_algorithms() {
        for o in [
            "1.3.14.3.2.26",          // SHA-1
            "2.16.840.1.101.3.4.2.4", // SHA-224
            "2.16.840.1.101.3.4.2.8", // SHA3-256
            "1.2.840.113549.2.5",     // MD5
        ] {
            assert!(
                DigestAlgorithm::for_message_imprint(&oid(o)).is_none(),
                "{o}"
            );
        }
    }

    #[test]
    fn message_imprint_accepts_sha2() {
        for o in [
            "2.16.840.1.101.3.4.2.1",
            "2.16.840.1.101.3.4.2.2",
            "2.16.840.1.101.3.4.2.3",
        ] {
            assert!(DigestAlgorithm::for_message_imprint(&oid(o)).is_some());
        }
    }

    #[test]
    fn cms_digest_still_accepts_sha1() {
        assert!(DigestAlgorithm::try_from(&oid("1.3.14.3.2.26")).is_ok());
    }

    #[test]
    fn digesters_match_published_abc_vectors_across_updates() {
        for (algorithm, expected) in [
            (DigestAlgorithm::Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (DigestAlgorithm::Sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (DigestAlgorithm::Sha384, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
            (DigestAlgorithm::Sha512, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        ] {
            let mut hasher = algorithm.digester();
            hasher.update(b"a");
            hasher.update(b"bc");
            assert_eq!(hex::encode(hasher.finish().as_ref()), expected);
        }
    }

    #[test]
    fn accuracy_rounds_up_subseconds_and_saturates() {
        use super::{integer_to_i64, tst_accuracy_seconds, Accuracy};
        assert_eq!(tst_accuracy_seconds(None), 0);
        let mut accuracy = Accuracy {
            seconds: None,
            millis: None,
            micros: None,
        };

        assert_eq!(tst_accuracy_seconds(Some(&accuracy)), 0);
        accuracy.micros = Some(1.into());
        assert_eq!(tst_accuracy_seconds(Some(&accuracy)), 1);
        accuracy.seconds = Some(2.into());
        accuracy.millis = Some(999.into());
        accuracy.micros = Some(999.into());
        assert_eq!(tst_accuracy_seconds(Some(&accuracy)), 3);
        accuracy.seconds = Some(i64::MAX.into());
        assert_eq!(tst_accuracy_seconds(Some(&accuracy)), i64::MAX / 1_000_000);
        assert_eq!(integer_to_i64(&bcder::Integer::from(-1)), 255);
    }

    #[test]
    fn timestamp_conversions_reject_unsupported_dates() {
        use chrono::{TimeZone, Utc};

        use super::{time_to_datetime, timestamp_to_generalized_time};
        assert!(timestamp_to_generalized_time(-1).is_none());
        assert!(timestamp_to_generalized_time(i64::MAX).is_none());
        let utc = Utc.timestamp_opt(1_577_836_800, 0).single().expect("date");
        assert_eq!(time_to_datetime(rasn_pkix::Time::Utc(utc)), utc);
        assert_eq!(time_to_datetime(rasn_pkix::Time::General(utc.into())), utc);
    }

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

    #[derive(Default)]
    struct TokenOptions<'a> {
        gen_time: Option<&'a [u8]>,
        accuracy: Option<&'a [u8]>,
        signed_time: Option<(u8, &'a [u8])>,
        signed_attrs: bool,
        profile_extensions: bool,
        cms_digest: Option<(&'a [u8], MessageDigest)>,
    }

    fn build_token_with(
        imprint_oid: &[u8],
        imprint_md: MessageDigest,
        data: &[u8],
        options: TokenOptions<'_>,
    ) -> Vec<u8> {
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
        cb.set_not_before(&Asn1Time::from_unix(1_500_000_000).unwrap())
            .unwrap();
        cb.set_not_after(&Asn1Time::from_unix(1_900_000_000).unwrap())
            .unwrap();
        cb.append_extension(ExtendedKeyUsage::new().time_stamping().build().unwrap())
            .unwrap();
        if options.profile_extensions {
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
        let cert = cb.build();

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

    fn decode_token(token: &[u8]) -> rasn_cms::SignedData {
        super::signed_data_from_time_stamp_response(token)
            .unwrap()
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
    fn signed_signing_time_overrides_tst_info_time() {
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
                1_609_556_645
            );
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
    fn signer_lookup_matches_issuer_serial_and_current_raw_ski_convention() {
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
            // Current lookup compares the DER-wrapped extension value rather
            // than the decoded key identifier required by CMS.
            signer.sid = SignerIdentifier::SubjectKeyIdentifier(if raw_extension {
                ski
            } else {
                rasn::der::decode::<rasn::types::OctetString>(&ski).unwrap()
            });
            sd.signer_infos = vec![signer].into();
            let token = encode_token(&sd);
            assert_eq!(
                super::tsa_signer_cert_der_from_token(&token).unwrap(),
                if raw_extension {
                    Some(expected.clone())
                } else {
                    None
                }
            );
            let result = verify_time_stamp(
                &token,
                DATA,
                &CertificateTrustPolicy::default(),
                &mut StatusTracker::default(),
                false,
            );
            assert_eq!(result.is_ok(), raw_extension);
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
            let tst = verify_time_stamp(&token, DATA, &policy, &mut log, true).unwrap();
            assert_eq!(
                generalized_time_to_datetime(tst.gen_time.clone()).timestamp(),
                1_577_836_800
            );
            assert!(log.has_status(TIMESTAMP_VALIDATED));
            assert!(log.has_status(TIMESTAMP_TRUSTED));
            assert!(!log.has_status(TIMESTAMP_UNTRUSTED));
            assert!(log
                .logged_items()
                .iter()
                .any(|item| item.description.contains("test:legacy")));

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
            assert_eq!(trusted_tst.gen_time, tst.gen_time);
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
    fn legacy_cms_decoder_preserves_signed_attribute_signature_input() {
        use bcder::{decode::Constructed, encode::Values, Mode};

        use crate::crypto::asn1::rfc5652::{ContentInfo, SignedData, SignerInfo};
        for signed_attrs in [false, true] {
            let token = build_token_with(
                OID_SHA256,
                MessageDigest::sha256(),
                DATA,
                TokenOptions {
                    signed_attrs,
                    ..Default::default()
                },
            );
            let content =
                Constructed::decode(token.as_slice(), Mode::Der, ContentInfo::take_opt_from)
                    .unwrap()
                    .unwrap();
            let legacy =
                Constructed::decode(content.content.as_slice(), Mode::Der, SignedData::take_from)
                    .unwrap();
            let current = decode_token(&token);
            assert_eq!(legacy.signer_infos.len(), 1);
            assert_eq!(legacy.digest_algorithms.len(), 1);
            let mut signer = legacy.signer_infos[0].clone();
            let expected =
                super::signed_attributes_digested_content(current.signer_infos.to_vec()[0])
                    .unwrap();
            assert_eq!(
                signer.signed_attributes_digested_content().unwrap(),
                expected
            );
            signer.signed_attributes_data = None;
            if signed_attrs {
                // The legacy encoder wraps Attribute's complete SEQUENCE in
                // another primitive SEQUENCE tag. Captured input is lossless;
                // regenerating it is currently not.
                assert_ne!(
                    signer.signed_attributes_digested_content().unwrap(),
                    expected
                );
            } else {
                assert_eq!(signer.signed_attributes_digested_content().unwrap(), None);
            }

            let mut encoded = Vec::new();
            signer
                .encode_ref()
                .write_encoded(Mode::Der, &mut encoded)
                .unwrap();
            let roundtrip =
                Constructed::decode(encoded.as_slice(), Mode::Der, SignerInfo::take_opt_from);
            if signed_attrs {
                assert!(roundtrip.is_err());
                continue;
            }

            let roundtrip = roundtrip.unwrap().unwrap();
            assert_eq!(roundtrip.signature, signer.signature);
            assert_eq!(roundtrip.sid, signer.sid);
            assert_eq!(
                roundtrip.signed_attributes_digested_content().unwrap(),
                expected
            );
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
