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

use std::ops::Deref;

use async_generic::async_generic;
use bcder::{decode::SliceSource, encode::Values, ConstOid, OctetString};
use chrono::{offset::LocalResult, DateTime, TimeZone, Utc};
use x509_certificate::{
    asn1time::{GeneralizedTime, GeneralizedTimeAllowedTimezone, Time},
    DigestAlgorithm,
};

use crate::{
    asn1::{
        rfc3161::TstInfo,
        rfc5652::{
            CertificateChoices::Certificate, SignerIdentifier, OID_MESSAGE_DIGEST, OID_SIGNING_TIME,
        },
    },
    raw_signature::validator_for_sig_and_hash_algs,
    time_stamp::{
        response::{signed_data_from_time_stamp_response, tst_info_from_signed_data},
        TimeStampError,
    },
};

/// Decode the TimeStampToken info and verify it against the supplied data.
#[async_generic]
pub(crate) fn verify_time_stamp(ts: &[u8], data: &[u8]) -> Result<TstInfo, TimeStampError> {
    // Did the time stamp expire between issuance and verification?
    let Some(sd) = signed_data_from_time_stamp_response(ts)? else {
        return Err(TimeStampError::DecodeError(
            "unable to find signed data".to_string(),
        ));
    };

    let certs = sd.certificates.clone().ok_or(TimeStampError::DecodeError(
        "time stamp contains no certificates".to_string(),
    ))?;

    let mut last_err = TimeStampError::InvalidData;

    // Look for any valid signer.
    for signer_info in sd.signer_infos.iter() {
        // Find signer's cert.
        let cert = match certs.iter().find_map(|cc| {
            let c = match cc {
                Certificate(c) => c,
                _ => return None,
            };

            match &signer_info.sid {
                SignerIdentifier::IssuerAndSerialNumber(sn) => {
                    if sn.issuer == c.tbs_certificate.issuer
                        && sn.serial_number == c.tbs_certificate.serial_number
                    {
                        Some(c.clone())
                    } else {
                        None
                    }
                }

                SignerIdentifier::SubjectKeyIdentifier(ski) => {
                    const SKI_OID: ConstOid = bcder::Oid(&[2, 5, 29, 14]);
                    if let Some(extensions) = &c.tbs_certificate.extensions {
                        if extensions.iter().any(|e| {
                            if e.id == SKI_OID {
                                return *ski == e.value;
                            }
                            false
                        }) {
                            Some(c.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            }
        }) {
            Some(c) => c,
            None => continue,
        };

        // Load unprotected TstInfo. We will verify its contents below against signed
        // values.
        let tst_opt = tst_info_from_signed_data(&sd)?;
        let mut tst = tst_opt.ok_or(TimeStampError::DecodeError(
            "unable to read unprotected TstInfo".to_string(),
        ))?;
        let mi = &tst.message_imprint;

        // Check for time stamp expiration.
        let mut signing_time = generalized_time_to_datetime(tst.gen_time.clone()).timestamp();

        // Check the signer info's signed attributes.
        if let Some(attributes) = &signer_info.signed_attributes {
            // If there is a signed signing time make sure it has not changed.
            if let Some(Some(attrib_signing_time)) = attributes
                .iter()
                .find(|attr| attr.typ == OID_SIGNING_TIME)
                .map(|attr| {
                    if attr.values.len() != 1 {
                        // per CMS spec can only contain 1 signing time value
                        return None;
                    }

                    attr.values
                        .first()
                        .and_then(|v| v.deref().clone().decode(Time::take_from).ok())
                })
            {
                let signed_signing_time = match attrib_signing_time {
                    Time::UtcTime(u) => u.timestamp(),
                    Time::GeneralTime(g) => generalized_time_to_datetime(g).timestamp(),
                };

                // Use signed date to avoid spoofing. Check to see if time string has been
                // modified. TO DO: When is this an error case?
                // TO REVIEW: `_time_diff` was unused in previous code. What was planned here?
                let _time_diff = (signing_time - signed_signing_time).abs();

                if let Some(gt) = timestamp_to_generalized_time(signed_signing_time) {
                    // Use actual signed time.
                    signing_time = generalized_time_to_datetime(gt.clone()).timestamp();
                    tst.gen_time = gt;
                };
            }

            // Check that the mandatory signed message digest is self-consistent.
            match attributes
                .iter()
                .find(|attr| attr.typ == OID_MESSAGE_DIGEST)
            {
                Some(message_digest) => {
                    // message digest attribute MUST have exactly 1 value.
                    if message_digest.values.len() != 1 {
                        last_err = TimeStampError::DecodeError(format!(
                            "message digest attribute has {n} values, should have one",
                            n = message_digest.values.len()
                        ));
                        continue;
                    }

                    // Get signed message digest.
                    let signed_message_digest = message_digest
                        .values
                        .first()
                        .ok_or(TimeStampError::InternalError(
                            "first() failed after checking length".to_string(),
                        ))?
                        .deref()
                        .clone()
                        .decode(OctetString::take_from)
                        .map_err(|_| {
                            TimeStampError::DecodeError(
                                "unable to decode message digest".to_string(),
                            )
                        })?
                        .to_bytes();

                    // Get message digest hash algorithm.
                    let digest_algorithm =
                        match DigestAlgorithm::try_from(&signer_info.digest_algorithm) {
                            Ok(d) => d,
                            Err(_) => {
                                last_err = TimeStampError::DecodeError(
                                    "unsupported digest algorithm".to_string(),
                                );
                                continue;
                            }
                        };

                    let mut h = digest_algorithm.digester();
                    if let Some(content) = &sd.content_info.content {
                        h.update(&content.to_bytes());
                    }

                    let digest = h.finish();

                    if signed_message_digest != digest.as_ref() {
                        last_err = TimeStampError::InvalidData;
                        continue;
                    }
                }

                None => {
                    last_err = TimeStampError::InvalidData;
                    continue;
                }
            }
        }

        // Build CMS structure to verify.
        let tbs = match signer_info.signed_attributes_digested_content() {
            Ok(sdc) => match sdc {
                Some(tbs) => tbs,
                None => match &sd.content_info.content {
                    Some(d) => d.to_bytes().to_vec(),
                    None => {
                        return Err(TimeStampError::DecodeError(
                            "time stamp does not contain digested content".to_string(),
                        ))
                    }
                },
            },
            Err(_) => {
                last_err = TimeStampError::DecodeError(
                    "time stamp does not contain digested content".to_string(),
                );
                continue;
            }
        };

        let hash_alg = &signer_info.digest_algorithm.algorithm;
        let sig_alg = &signer_info.signature_algorithm.algorithm;

        // Grab signing certificate.
        let sig_val = &signer_info.signature;
        let mut signing_key_der = Vec::<u8>::new();
        cert.tbs_certificate
            .subject_public_key_info
            .encode_ref()
            .write_encoded(bcder::Mode::Der, &mut signing_key_der)?;

        // Verify signature of time stamp signature.
        if _sync {
            // IMPORTANT: The synchronous implementation of validate_timestamp_sync
            // on WASM is unable to support _some_ signature algorithms. The async path
            // should be used whenever possible (for WASM, at least).
            validate_timestamp_sig(sig_alg, hash_alg, sig_val, &tbs, &signing_key_der)?;
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            validate_timestamp_sig(sig_alg, hash_alg, sig_val, &tbs, &signing_key_der)?;

            // NOTE: We're keeping the WASM-specific async path alive for now because it
            // supports more signature algorithms. Look for future WASM platform to provide
            // the opportunity to unify.
            #[cfg(target_arch = "wasm32")]
            validate_timestamp_sig_async(sig_alg, hash_alg, sig_val, &tbs, &signing_key_der)
                .await?;
        }

        // Make sure the time stamp's cert was valid for the stated signing time.
        let not_before = time_to_datetime(cert.tbs_certificate.validity.not_before).timestamp();
        let not_after = time_to_datetime(cert.tbs_certificate.validity.not_after).timestamp();

        if !(signing_time >= not_before && signing_time <= not_after) {
            last_err = TimeStampError::ExpiredCertificate;
            continue;
        }

        // Make sure the time stamp is valid for the specified data.
        let digest_algorithm = match DigestAlgorithm::try_from(&mi.hash_algorithm.algorithm) {
            Ok(d) => d,
            Err(_) => {
                last_err = TimeStampError::UnsupportedAlgorithm;
                continue;
            }
        };

        let mut h = digest_algorithm.digester();
        h.update(data);

        let digest = h.finish();
        if digest.as_ref() != mi.hashed_message.to_bytes() {
            last_err = TimeStampError::InvalidData;
            continue;
        }

        // If we find a valid value, we're done.
        return Ok(tst);
    }

    Err(last_err)
}

fn generalized_time_to_datetime(gt: GeneralizedTime) -> DateTime<Utc> {
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

fn time_to_datetime(t: Time) -> DateTime<Utc> {
    match t {
        Time::UtcTime(u) => *u,
        Time::GeneralTime(gt) => generalized_time_to_datetime(gt),
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
    let Some(validator) =
        crate::raw_signature::webcrypto::async_validator_for_sig_and_hash_algs(sig_alg, hash_alg)
    else {
        return Err(TimeStampError::UnsupportedAlgorithm);
    };

    validator
        .validate_async(&sig_val.to_bytes(), tbs, signing_key_der)
        .await
        .map_err(|_| TimeStampError::InvalidData)?;

    Ok(())
}
