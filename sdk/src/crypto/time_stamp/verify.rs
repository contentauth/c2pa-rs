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
use bcder::{decode::SliceSource, OctetString};
use chrono::{offset::LocalResult, DateTime, TimeZone, Utc};
use rasn::{prelude::*, types};
use rasn_cms::{CertificateChoices, SignerIdentifier};
use x509_certificate::{
    asn1time::{GeneralizedTime, GeneralizedTimeAllowedTimezone},
    DigestAlgorithm,
};

use crate::{
    crypto::{
        asn1::rfc3161::TstInfo,
        cose::CertificateTrustPolicy,
        raw_signature::validator_for_sig_and_hash_algs,
        time_stamp::{
            response::{signed_data_from_time_stamp_response, tst_info_from_signed_data},
            TimeStampError,
        },
    },
    log_item,
    settings::get_settings_value,
    status_tracker::StatusTracker,
    validation_status::{
        TIMESTAMP_MALFORMED, TIMESTAMP_MISMATCH, TIMESTAMP_OUTSIDE_VALIDITY, TIMESTAMP_TRUSTED,
        TIMESTAMP_UNTRUSTED, TIMESTAMP_VALIDATED,
    },
};

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
) -> Result<TstInfo, TimeStampError> {
    // Get the signed data frorm the timestamp data
    let Ok(Some(sd)) = signed_data_from_time_stamp_response(ts) else {
        log_item!("", "count not parse timestamp data", "verify_time_stamp")
            .validation_status(TIMESTAMP_MALFORMED)
            .informational(validation_log);

        return Err(TimeStampError::DecodeError(
            "unable to find signed data".to_string(),
        ));
    };

    // Grab the list of certs used in signing this timestamp
    let Some(certs) = &sd.certificates else {
        log_item!("", "count not parse timestamp data", "verify_time_stamp")
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
        log_item!("", "count not parse timestamp data", "verify_time_stamp")
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
                                    "unable to decode igned message data".to_string(),
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
        if _sync {
            // IMPORTANT: The synchronous implementation of validate_timestamp_sync
            // on WASM is unable to support _some_ signature algorithms. The async path
            // should be used whenever possible (for WASM, at least).
            if validate_timestamp_sig(&sig_alg, &hash_alg, &sig_val, &tbs, &signing_key_der)
                .is_err()
            {
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
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            if validate_timestamp_sig(&sig_alg, &hash_alg, &sig_val, &tbs, &signing_key_der)
                .is_err()
            {
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

            // NOTE: We're keeping the WASM-specific async path alive for now because it
            // supports more signature algorithms. Look for future WASM platform to provide
            // the opportunity to unify.
            #[cfg(target_arch = "wasm32")]
            if validate_timestamp_sig_async(&sig_alg, &hash_alg, &sig_val, &tbs, &signing_key_der)
                .await
                .is_err()
            {
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
        }

        // Make sure the time stamp's cert was valid for the stated signing time.
        let not_before = time_to_datetime(cert.tbs_certificate.validity.not_before).timestamp();
        let not_after = time_to_datetime(cert.tbs_certificate.validity.not_after).timestamp();

        if !(signing_time >= not_before && signing_time <= not_after) {
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
        let digest_algorithm = match DigestAlgorithm::try_from(&mi.hash_algorithm.algorithm) {
            Ok(d) => d,
            Err(_) => {
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
        let verify_trust = get_settings_value("verify.verify_timestamp_trust").unwrap_or(true);

        if verify_trust
            && ctp
                .check_certificate_trust(&cert_ders[0..], &cert_ders[0], Some(signing_time))
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

        log_item!(
            "",
            format!("timestamp cert trusted: {}", &common_name),
            "verify_time_stamp"
        )
        .validation_status(TIMESTAMP_TRUSTED)
        .success(&mut current_validation_log);

        // If we find a valid value, we're done.
        validation_log.append(&current_validation_log);
        return Ok(tst);
    }

    validation_log.append(&current_validation_log);
    Err(last_err)
}

fn generalized_time_to_datetime<T: Into<DateTime<Utc>>>(gt: T) -> DateTime<Utc> {
    gt.into()
}

fn timestamp_to_generalized_time(dt: i64) -> Option<GeneralizedTime> {
    match Utc.timestamp_opt(dt, 0) {
        LocalResult::Single(time) => {
            let formatted_time = time.format("%Y%m%d%H%M%SZ").to_string();

            GeneralizedTime::parse(
                SliceSource::new(formatted_time.as_bytes()),
                false,
                GeneralizedTimeAllowedTimezone::Z,
            )
            .ok()
        }
        _ => None,
    }
}

fn time_to_datetime(t: rasn_pkix::Time) -> DateTime<Utc> {
    match t {
        rasn_pkix::Time::Utc(u) => u,
        rasn_pkix::Time::General(gt) => generalized_time_to_datetime(gt),
    }
}

fn validate_timestamp_sig(
    sig_alg: &bcder::Oid,
    hash_alg: &bcder::Oid,
    sig_val: &OctetString,
    tbs: &[u8],
    signing_key_der: &[u8],
) -> Result<(), TimeStampError> {
    let Some(validator) = validator_for_sig_and_hash_algs(sig_alg, hash_alg) else {
        return Err(TimeStampError::UnsupportedAlgorithm);
    };

    validator
        .validate(&sig_val.to_bytes(), tbs, signing_key_der)
        .map_err(|_| TimeStampError::InvalidData)
}

#[cfg(target_arch = "wasm32")]
async fn validate_timestamp_sig_async(
    sig_alg: &bcder::Oid,
    hash_alg: &bcder::Oid,
    sig_val: &OctetString,
    tbs: &[u8],
    signing_key_der: &[u8],
) -> Result<(), TimeStampError> {
    if let Some(validator) =
        crate::crypto::raw_signature::async_validator_for_sig_and_hash_algs(sig_alg, hash_alg)
    {
        validator
            .validate_async(&sig_val.to_bytes(), tbs, signing_key_der)
            .await
            .map_err(|_| TimeStampError::InvalidData)
    } else if let Some(validator) =
        crate::crypto::raw_signature::validator_for_sig_and_hash_algs(sig_alg, hash_alg)
    {
        validator
            .validate(&sig_val.to_bytes(), tbs, signing_key_der)
            .map_err(|_| TimeStampError::InvalidData)
    } else {
        Err(TimeStampError::UnsupportedAlgorithm)
    }
}
