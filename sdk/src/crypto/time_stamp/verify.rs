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
use chrono::{DateTime, Utc};
use der::asn1::ObjectIdentifier;
use rasn::{prelude::*, types};
use rasn_cms::{CertificateChoices, SignerIdentifier};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use crate::{
    crypto::{
        asn1::rfc3161::{Accuracy, TstInfo},
        cose::{check_end_entity_certificate_profile, CertificateTrustPolicy},
        time_stamp::{
            response::{
                signed_data_and_bytes_from_time_stamp_response,
                signed_data_from_time_stamp_response, tst_info_from_signed_data,
            },
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

// Decode the raw SignerInfo entries from the same SignedData bytes used by
// rasn. Preserve duplicates here: a SET OF decoder may collapse equal entries.
// Returns None if the entries cannot be parsed, in which case callers fall back
// to the DER re-encoding of each decoded SignerInfo's attributes.
fn received_signer_infos(sd_bytes: &[u8]) -> Option<Vec<asn1_rs::Any<'_>>> {
    use asn1_rs::{Class, Tag};

    let (rest, sd) = asn1_rs::Any::from_der(sd_bytes).ok()?;
    if !rest.is_empty() || sd.class() != Class::Universal || sd.tag() != Tag::Sequence {
        return None;
    }
    let signer_infos = timestamp_asn1_children(sd.data)?.pop()?;
    if signer_infos.class() != Class::Universal || signer_infos.tag() != Tag::Set {
        return None;
    }
    let entries = timestamp_asn1_children(signer_infos.data)?;
    for entry in &entries {
        if entry.class() != Class::Universal || entry.tag() != Tag::Sequence {
            return None;
        }
        raw_signature(entry)?;
    }
    Some(entries)
}

fn raw_signature<'a>(signer_info: &asn1_rs::Any<'a>) -> Option<&'a [u8]> {
    use asn1_rs::{Class, Tag};

    timestamp_asn1_children(signer_info.data)?
        .into_iter()
        .find(|field| field.class() == Class::Universal && field.tag() == Tag::OctetString)
        .map(|field| field.data)
}

// A signature value must identify exactly one SignerInfo. Check the decoded
// entries and, when available, the raw entries, since rasn may collapse
// identical entries while decoding the SET OF.
fn has_duplicate_signatures(
    sd: &rasn_cms::SignedData,
    raw_signer_infos: Option<&[asn1_rs::Any<'_>]>,
) -> bool {
    let mut decoded = std::collections::HashSet::new();
    if !sd
        .signer_infos
        .to_vec()
        .iter()
        .all(|si| decoded.insert(si.signature.as_ref()))
    {
        return true;
    }

    let mut raw = std::collections::HashSet::new();
    raw_signer_infos.is_some_and(|entries| {
        !entries
            .iter()
            .all(|entry| raw_signature(entry).is_some_and(|sig| raw.insert(sig)))
    })
}

fn timestamp_asn1_children(data: &[u8]) -> Option<Vec<asn1_rs::Any<'_>>> {
    let mut rest = data;
    let mut items = Vec::new();
    while !rest.is_empty() {
        let (rem, item) = asn1_rs::Any::from_der(rest).ok()?;
        items.push(item);
        rest = rem;
    }
    Some(items)
}

// RFC 5652 section 5.4 requires DER-encoded signed attributes (including sorted
// SET OF order). Accepting an unsorted encoding is an interoperability allowance
// for nonconforming tokens, not an alternative permitted by that RFC.
//
// Replace the IMPLICIT [0] tag with a SET OF header, and require the located bytes
// to decode to the attributes whose message digest was checked.
// Signature values are unique because verify_time_stamp rejects duplicates.
fn received_signed_attributes(
    signer_infos: &[asn1_rs::Any<'_>],
    signer_info: &rasn_cms::SignerInfo,
) -> Option<Vec<u8>> {
    use asn1_rs::{Class, Header, Length, Tag, ToDer};

    let signature: &[u8] = signer_info.signature.as_ref();
    let expected = signer_info.signed_attrs.as_ref()?;
    let mut found: Option<&[u8]> = None;
    for si in signer_infos {
        let fields = timestamp_asn1_children(si.data)?;
        let matches = fields.iter().any(|f| {
            f.class() == Class::Universal && f.tag() == Tag::OctetString && f.data == signature
        });
        if !matches {
            continue;
        }
        if found.is_some() {
            return None;
        }
        // signedAttrs is a constructed [0]. A subjectKeyIdentifier sid is a
        // primitive [0] and must not be mistaken for the attributes.
        let attrs = fields.iter().find(|f| {
            f.class() == Class::ContextSpecific && f.tag() == Tag(0) && f.header.is_constructed()
        })?;
        found = Some(attrs.data);
    }
    let attrs_body = found?;
    let header = Header::new(
        Class::Universal,
        true,
        Tag::Set,
        Length::Definite(attrs_body.len()),
    );
    let mut out = header.to_der_vec().ok()?;
    out.extend_from_slice(attrs_body);

    let decoded: rasn_cms::SignedAttributes = rasn::der::decode(&out).ok()?;
    if &decoded != expected {
        return None;
    }
    Some(out)
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
    // Get the signed data and the exact bytes supplied to its decoder.
    let Ok(Some((sd, sd_bytes))) = signed_data_and_bytes_from_time_stamp_response(ts) else {
        log_item!("", "could not parse timestamp data", "verify_time_stamp")
            .validation_status(TIMESTAMP_MALFORMED)
            .informational(validation_log);

        return Err(TimeStampError::DecodeError(
            "unable to find signed data".to_string(),
        ));
    };

    // Reject ambiguous signatures before trying any signer, including identical
    // SignerInfo entries that rasn may have collapsed while decoding the SET OF.
    let raw_signer_infos = received_signer_infos(&sd_bytes);
    if has_duplicate_signatures(&sd, raw_signer_infos.as_deref()) {
        log_item!(
            "",
            "timestamp signer infos contain duplicate signatures",
            "verify_time_stamp"
        )
        .validation_status(TIMESTAMP_MALFORMED)
        .informational(validation_log);

        return Err(TimeStampError::DecodeError(
            "timestamp signer infos contain duplicate signatures".to_string(),
        ));
    }

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
        let Ok(Some(tst)) = tst_info_from_signed_data(&sd) else {
            log_item!("", "timestamp response had no TstInfo", "verify_time_stamp")
                .validation_status(TIMESTAMP_MALFORMED)
                .informational(&mut current_validation_log);

            last_err = TimeStampError::InvalidData;
            continue;
        };

        let mi = &tst.message_imprint;

        // Check for time stamp expiration.
        // The attested time is the TSTInfo genTime (C2PA validation, RFC 3161). A CMS
        // signingTime attribute is not the attested time and is not used.
        let signing_time = generalized_time_to_datetime(tst.gen_time.clone()).timestamp();

        // Check the signer info's signed attributes.
        if let Some(attributes) = &signer_info.signed_attrs {
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
                Some(tbs) => raw_signer_infos
                    .as_deref()
                    .and_then(|raw| received_signed_attributes(raw, signer_info))
                    .unwrap_or(tbs),
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

            match ctp.check_certificate_trust(
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
    fn timestamp_conversions_preserve_utc_and_generalized_dates() {
        use chrono::{TimeZone, Utc};

        use super::time_to_datetime;
        let utc = Utc.timestamp_opt(1_577_836_800, 0).single().expect("date");
        assert_eq!(time_to_datetime(rasn_pkix::Time::Utc(utc)), utc);
        assert_eq!(time_to_datetime(rasn_pkix::Time::General(utc.into())), utc);
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
        build_token_with_times(imprint_oid, imprint_md, data, b"20200101000000Z", None)
    }

    fn build_token_with_times(
        imprint_oid: &[u8],
        imprint_md: MessageDigest,
        data: &[u8],
        gen_time: &[u8],
        signing_time: Option<(u8, &[u8])>,
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
                &tlv(0x18, gen_time),
            ]),
        );

        let signed_attrs = signing_time.map(|(tag, time)| {
            let mut attributes = [
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
                        &tlv(
                            0x31,
                            &tlv(0x04, &hash(MessageDigest::sha256(), &tst_info).unwrap()),
                        ),
                    ]),
                ),
                tlv(
                    0x30,
                    &cat(&[
                        &[
                            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05,
                        ],
                        &tlv(0x31, &tlv(tag, time)),
                    ]),
                ),
            ];
            attributes.sort();
            tlv(0x31, &attributes.concat())
        });
        let signed_content = signed_attrs.as_deref().unwrap_or(&tst_info);
        let signature = Signer::new(MessageDigest::sha256(), &key)
            .unwrap()
            .sign_oneshot_to_vec(signed_content)
            .unwrap();

        let issuer_and_serial = tlv(0x30, &cat(&[&cert.issuer_name().to_der().unwrap(), INT_1]));
        let mut encoded_attrs = signed_attrs.unwrap_or_default();
        if let Some(tag) = encoded_attrs.first_mut() {
            *tag = 0xa0;
        }
        let signer_info = tlv(
            0x30,
            &cat(&[
                INT_1,
                &issuer_and_serial,
                &tlv(0x30, OID_SHA256),
                &encoded_attrs,
                &tlv(0x30, OID_ECDSA_SHA256),
                &tlv(0x04, &signature),
            ]),
        );
        let signed_data = tlv(
            0x30,
            &cat(&[
                &[0x02, 0x01, 0x03],
                &tlv(0x31, &tlv(0x30, OID_SHA256)),
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

    #[test]
    fn signed_signing_time_does_not_override_expired_tst_info_time() {
        for (tag, time) in [
            (0x17, b"210102030405Z".as_slice()),
            (0x18, b"20210102030405Z".as_slice()),
            (0x05, b"".as_slice()),
        ] {
            let token = build_token_with_times(
                OID_SHA256,
                MessageDigest::sha256(),
                DATA,
                b"20400101000000Z",
                Some((tag, time)),
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
    }
}

#[cfg(test)]
mod signed_attrs_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const DATA: &[u8] = b"some sample content to sign";

    #[test]
    fn verifies_signed_attributes_in_encoded_order() {
        // The signer wrote its signed attributes in an order other than DER's
        // sorted order, and signed that encoding.
        let ts =
            include_bytes!("../../../tests/fixtures/crypto/time_stamp/unsorted_signed_attrs.tst");
        let mut log = StatusTracker::default();

        verify_time_stamp(
            ts,
            DATA,
            &CertificateTrustPolicy::default(),
            &mut log,
            false,
        )
        .unwrap();

        assert!(log.has_status(TIMESTAMP_VALIDATED));
        assert!(!log.has_status(TIMESTAMP_UNTRUSTED));
    }

    #[test]
    fn verifies_signed_attributes_in_timestamp_response() {
        let mut response = tlv(0x30, &tlv(0x02, &[0]));
        response.extend_from_slice(TOKEN);
        let mut log = StatusTracker::default();
        verify_time_stamp(
            &tlv(0x30, &response),
            DATA,
            &CertificateTrustPolicy::default(),
            &mut log,
            false,
        )
        .unwrap();
        assert!(log.has_status(TIMESTAMP_VALIDATED));
    }

    // Returns the TLV for `tag` wrapping `body`.
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = body.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let lb: Vec<u8> = len
                .to_be_bytes()
                .into_iter()
                .skip_while(|b| *b == 0)
                .collect();
            out.push(0x80 | lb.len() as u8);
            out.extend_from_slice(&lb);
        }
        out.extend_from_slice(body);
        out
    }

    const TOKEN: &[u8] =
        include_bytes!("../../../tests/fixtures/crypto/time_stamp/unsorted_signed_attrs.tst");
    const FORGED_DATA: &[u8] = b"attacker-controlled content";

    // Preserve each SignerInfo's original attribute order when rebuilding the
    // envelope; re-encoding SignedData with rasn would sort those attributes.
    fn rebuild_token(token: &[u8], content: Option<&[u8]>, signer_infos: &[Vec<u8>]) -> Vec<u8> {
        let (_, outer) = asn1_rs::Any::from_der(token).unwrap();
        let ci = timestamp_asn1_children(outer.data).unwrap();
        let (_, sd) = asn1_rs::Any::from_der(ci[1].data).unwrap();
        let sd_items = timestamp_asn1_children(sd.data).unwrap();
        let (_, head) = sd_items.split_last().unwrap();
        let mut sd_body = Vec::new();
        for (i, item) in head.iter().enumerate() {
            if let (2, Some(content)) = (i, content) {
                let eci = timestamp_asn1_children(item.data).unwrap();
                let mut body = tlv_of(&eci[0]);
                body.extend(tlv(0xa0, &tlv(0x04, content)));
                sd_body.extend(tlv(0x30, &body));
            } else {
                sd_body.extend(tlv_of(item));
            }
        }
        sd_body.extend(tlv(0x31, &signer_infos.concat()));
        let mut ci_body = tlv_of(&ci[0]);
        ci_body.extend(tlv(0xa0, &tlv(0x30, &sd_body)));
        tlv(0x30, &ci_body)
    }

    fn original_signer_info(token: &[u8]) -> Vec<u8> {
        let (_, bytes) = signed_data_and_bytes_from_time_stamp_response(token)
            .unwrap()
            .unwrap();
        tlv_of(&received_signer_infos(&bytes).unwrap()[0])
    }

    fn replace_hash(bytes: &mut [u8], old: &[u8], new: &[u8]) {
        let positions: Vec<_> = bytes
            .windows(old.len())
            .enumerate()
            .filter_map(|(i, window)| (window == old).then_some(i))
            .collect();
        assert_eq!(positions.len(), 1);
        let start = positions[0];
        bytes[start..start + old.len()].copy_from_slice(new);
    }

    // Change the imprint and the second signer's messageDigest without access
    // to the TSA key. Both SignerInfos retain the genuine signature bytes.
    fn forged_token(token: &[u8], keep_original: bool, original_first: bool) -> Vec<u8> {
        use sha2::Digest;

        let sd = signed_data_from_time_stamp_response(token)
            .unwrap()
            .unwrap();
        let original_content = sd.encap_content_info.content.unwrap().to_vec();
        let mut forged_content = original_content.clone();
        replace_hash(
            &mut forged_content,
            &Sha256::digest(DATA),
            &Sha256::digest(FORGED_DATA),
        );
        let original = original_signer_info(token);
        let mut forged = original.clone();
        replace_hash(
            &mut forged,
            &Sha256::digest(&original_content),
            &Sha256::digest(&forged_content),
        );
        let mut signers = vec![forged];
        if keep_original {
            signers.push(original);
            if original_first {
                signers.reverse();
            }
        }
        rebuild_token(token, Some(&forged_content), &signers)
    }

    fn assert_rejected(token: &[u8], data: &[u8]) {
        let mut log = StatusTracker::default();
        let result = verify_time_stamp(
            token,
            data,
            &CertificateTrustPolicy::default(),
            &mut log,
            false,
        );
        assert!(
            result.is_err(),
            "unexpected timestamp validation: {result:?}"
        );
        assert!(!log.has_status(TIMESTAMP_VALIDATED));
        assert!(!log.has_status(TIMESTAMP_TRUSTED));
    }

    fn tlv_of(item: &asn1_rs::Any<'_>) -> Vec<u8> {
        let tag = item.header.raw_tag().map(|t| t[0]).unwrap_or_else(|| {
            let class = (item.class() as u8) << 6;
            let constructed = if item.header.is_constructed() {
                0x20
            } else {
                0
            };
            class | constructed | item.tag().0 as u8
        });
        tlv(tag, item.data)
    }

    #[test]
    fn rejects_token_with_duplicated_signature() {
        let si = original_signer_info(TOKEN);
        let token = rebuild_token(TOKEN, None, &[si.clone(), si]);
        assert_rejected(&token, DATA);
    }

    #[test]
    fn rejects_forged_timestamp_with_copied_signature() {
        for original_first in [false, true] {
            let token = forged_token(TOKEN, true, original_first);
            // Ensure the attack passes the messageDigest check for the forged
            // signer; rejection must not merely be an imprint mismatch.
            let sd = signed_data_from_time_stamp_response(&token)
                .unwrap()
                .unwrap();
            let content = sd.encap_content_info.content.as_ref().unwrap();
            let digest = DigestAlgorithm::Sha256;
            let mut hasher = digest.digester();
            hasher.update(content);
            let expected = hasher.finish();
            assert!(sd.signer_infos.to_vec().iter().any(|si| {
                si.signed_attrs
                    .as_ref()
                    .unwrap()
                    .to_vec()
                    .iter()
                    .any(|attr| {
                        attr.r#type == Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_MESSAGE_DIGEST
                            && rasn::der::decode::<types::OctetString>(
                                attr.values.to_vec()[0].as_bytes(),
                            )
                            .unwrap()
                            .as_ref()
                                == expected.as_ref()
                    })
            }));
            assert_rejected(&token, FORGED_DATA);
        }
    }

    #[test]
    fn rejects_forged_timestamp_with_only_modified_signer() {
        assert_rejected(&forged_token(TOKEN, false, false), FORGED_DATA);
    }

    // A valid, sorted token would pass the old DER fallback even with duplicate
    // signatures. Re-sign with the existing fixture key to cover that path.
    #[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
    #[test]
    fn rejects_duplicate_signatures_in_der_sorted_token() {
        use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};

        let sd = signed_data_from_time_stamp_response(TOKEN)
            .unwrap()
            .unwrap();
        let si = sd.signer_infos.to_vec()[0];
        let attrs = rasn::der::encode(si.signed_attrs.as_ref().unwrap()).unwrap();
        let key = PKey::private_key_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es256.priv"
        ))
        .unwrap();
        let signature = Signer::new(MessageDigest::sha256(), &key)
            .unwrap()
            .sign_oneshot_to_vec(&attrs)
            .unwrap();
        let original = original_signer_info(TOKEN);
        let (_, raw_si) = asn1_rs::Any::from_der(&original).unwrap();
        let fields = timestamp_asn1_children(raw_si.data).unwrap();
        let (_, raw_attrs) = asn1_rs::Any::from_der(&attrs).unwrap();
        let mut body = Vec::new();
        for (i, field) in fields.iter().enumerate() {
            match i {
                3 => body.extend(tlv(0xa0, raw_attrs.data)),
                5 => body.extend(tlv(0x04, &signature)),
                _ => body.extend(tlv_of(field)),
            }
        }
        let sorted_si = tlv(0x30, &body);
        let valid = rebuild_token(TOKEN, None, std::slice::from_ref(&sorted_si));
        let mut log = StatusTracker::default();
        verify_time_stamp(
            &valid,
            DATA,
            &CertificateTrustPolicy::default(),
            &mut log,
            false,
        )
        .unwrap();
        assert!(log.has_status(TIMESTAMP_VALIDATED));
        assert_rejected(
            &rebuild_token(&valid, None, &[sorted_si.clone(), sorted_si]),
            DATA,
        );
        for original_first in [false, true] {
            assert_rejected(&forged_token(&valid, true, original_first), FORGED_DATA);
        }
    }

    // A version 3 SignerInfo identifies its signer by subjectKeyIdentifier, a
    // primitive [0] that precedes the constructed [0] signedAttrs.
    #[test]
    fn locates_unsorted_attributes_with_subject_key_identifier() {
        use x509_parser::extensions::ParsedExtension;

        let (_, pem) = x509_parser::pem::parse_x509_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es256.pub"
        ))
        .unwrap();
        let cert = pem.parse_x509().unwrap();
        let ski = cert
            .extensions()
            .iter()
            .find_map(|e| match e.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(k) => Some(k.0.to_vec()),
                _ => None,
            })
            .unwrap();

        let original = original_signer_info(TOKEN);
        let (_, raw_si) = asn1_rs::Any::from_der(&original).unwrap();
        let fields = timestamp_asn1_children(raw_si.data).unwrap();
        let mut body = tlv(0x02, &[3]);
        body.extend(tlv(0x80, &ski));
        for field in &fields[2..] {
            body.extend(tlv_of(field));
        }
        let token = rebuild_token(TOKEN, None, &[tlv(0x30, &body)]);

        let (sd, bytes) = signed_data_and_bytes_from_time_stamp_response(&token)
            .unwrap()
            .unwrap();
        let si = sd.signer_infos.to_vec()[0];
        assert!(matches!(si.sid, SignerIdentifier::SubjectKeyIdentifier(_)));
        let raw = received_signer_infos(&bytes).unwrap();
        let encoded = received_signed_attributes(&raw, si).unwrap();
        assert_ne!(
            encoded,
            rasn::der::encode(si.signed_attrs.as_ref().unwrap()).unwrap()
        );
    }

    // Duplicate signatures must be detected from the decoded SignerInfos even
    // when the raw entries cannot be parsed.
    #[test]
    fn detects_duplicate_signatures_without_raw_signer_infos() {
        let genuine = signed_data_from_time_stamp_response(TOKEN)
            .unwrap()
            .unwrap();
        assert!(!has_duplicate_signatures(&genuine, None));

        let forged = signed_data_from_time_stamp_response(&forged_token(TOKEN, true, false))
            .unwrap()
            .unwrap();
        assert!(has_duplicate_signatures(&forged, None));
    }

    #[test]
    fn rejects_encoded_attributes_that_differ_from_signer_info() {
        let ts =
            include_bytes!("../../../tests/fixtures/crypto/time_stamp/unsorted_signed_attrs.tst");
        let (sd, bytes) = signed_data_and_bytes_from_time_stamp_response(ts)
            .unwrap()
            .unwrap();
        let raw = received_signer_infos(&bytes).unwrap();
        let mut si = sd.signer_infos.to_vec()[0].clone();
        assert!(received_signed_attributes(&raw, &si).is_some());

        // Attributes the caller checked are not the ones that were encoded.
        si.signed_attrs = si.signed_attrs.map(|a| {
            let mut v: Vec<_> = a.to_vec().into_iter().cloned().collect();
            v.pop();
            rasn::types::SetOf::from_vec(v)
        });
        assert!(received_signed_attributes(&raw, &si).is_none());
    }

    #[test]
    fn uses_gen_time_not_cms_signing_time() {
        // genTime is within the signing certificate's validity; the CMS
        // signingTime attribute is after the certificate expires.
        let ts = include_bytes!(
            "../../../tests/fixtures/crypto/time_stamp/signing_time_after_expiry.tst"
        );
        let mut log = StatusTracker::default();

        let tst = verify_time_stamp(
            ts,
            DATA,
            &CertificateTrustPolicy::default(),
            &mut log,
            false,
        )
        .unwrap();

        let gen_time = generalized_time_to_datetime(tst.gen_time).timestamp();
        assert_eq!(gen_time, 1_735_689_600); // 2025-01-01T00:00:00Z
        assert!(log.has_status(TIMESTAMP_VALIDATED));
        assert!(!log.has_status(TIMESTAMP_OUTSIDE_VALIDITY));
    }
}
