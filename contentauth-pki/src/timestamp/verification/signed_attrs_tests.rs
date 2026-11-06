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

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const DATA: &[u8] = b"some sample content to sign";
const FORGED_DATA: &[u8] = b"attacker-controlled content";
const TOKEN: &[u8] = include_bytes!("../../../tests/fixtures/time_stamp/unsorted_signed_attrs.tst");

// Fixed variant of TOKEN, signed once with the same fixture key over DER-sorted
// attributes. Tests need no signing provider, private key or runtime randomness.
const SORTED_TOKEN: &[u8] =
    include_bytes!("../../../tests/fixtures/time_stamp/sorted_signed_attrs.tst");

fn required<T>(value: Option<T>) -> TestResult<T> {
    value.ok_or_else(|| std::io::Error::other("missing timestamp test fixture field").into())
}

fn any(bytes: &[u8]) -> TestResult<asn1_rs::Any<'_>> {
    let (remaining, value) =
        asn1_rs::Any::from_der(bytes).map_err(|error| std::io::Error::other(error.to_string()))?;

    assert!(remaining.is_empty());

    Ok(value)
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = body.len();

    if len < 0x80 {
        out.push(len as u8);
    } else {
        let length: Vec<_> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|byte| *byte == 0)
            .collect();

        out.push(0x80 | length.len() as u8);

        out.extend_from_slice(&length);
    }

    out.extend_from_slice(body);
    out
}

fn tlv_of(item: &asn1_rs::Any<'_>) -> Vec<u8> {
    let tag = item.header.raw_tag().map(|tag| tag[0]).unwrap_or_else(|| {
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

// Re-encoding SignedData through rasn would silently sort the signed attributes.
// Rebuild only the envelope, retaining the exact received SignerInfo encodings.
fn rebuild_token(
    token: &[u8],
    content: Option<&[u8]>,
    signer_infos: &[Vec<u8>],
) -> TestResult<Vec<u8>> {
    let outer = any(token)?;
    let ci = required(timestamp_asn1_children(outer.data))?;
    let sd = any(ci[1].data)?;
    let sd_items = required(timestamp_asn1_children(sd.data))?;
    let (_, head) = required(sd_items.split_last())?;
    let mut sd_body = Vec::new();

    for (index, item) in head.iter().enumerate() {
        if let (2, Some(content)) = (index, content) {
            let eci = required(timestamp_asn1_children(item.data))?;
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

    Ok(tlv(0x30, &ci_body))
}

fn original_signer_info(token: &[u8]) -> TestResult<Vec<u8>> {
    let (_, bytes) = required(signed_data_and_bytes_from_time_stamp_response(token)?)?;
    let entries = required(received_signer_infos(&bytes))?;

    Ok(tlv_of(required(entries.first())?))
}

fn replace_hash(bytes: &mut [u8], old: &[u8], new: &[u8]) {
    let positions: Vec<_> = bytes
        .windows(old.len())
        .enumerate()
        .filter_map(|(index, window)| (window == old).then_some(index))
        .collect();

    assert_eq!(positions.len(), 1);

    assert_eq!(old.len(), new.len());

    let start = positions[0];
    bytes[start..start + old.len()].copy_from_slice(new);
}

// Modify the imprint and messageDigest without the TSA key, retaining the
// genuine signature. An optional original signer carries the same signature.
fn forged_token(token: &[u8], keep_original: bool, original_first: bool) -> TestResult<Vec<u8>> {
    use sha2::Digest;

    let sd = required(signed_data_from_time_stamp_response(token)?)?;
    let original_content = required(sd.encap_content_info.content)?.to_vec();
    let mut forged_content = original_content.clone();

    replace_hash(
        &mut forged_content,
        &Sha256::digest(DATA),
        &Sha256::digest(FORGED_DATA),
    );

    let original = original_signer_info(token)?;
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

fn assert_crypto_verified(token: &[u8]) -> TestResult {
    let parsed = ParsedTimestamp::parse(token)?;
    let mut candidates = parsed.verify_signatures();
    let signed = required(candidates.next())??;
    let verified = signed.verify_message_imprint(DATA)?;

    assert!(!verified.signature().signer_certificate().is_empty());
    assert!(candidates.next().is_none());

    // Neither successful stage establishes certificate profile, chain or trust.
    Ok(())
}

fn assert_duplicate_rejected(token: &[u8]) -> TestResult {
    let error = required(ParsedTimestamp::parse(token).err())?;

    assert_eq!(error.stage, VerificationStage::DuplicateSigners);
    assert!(matches!(error.kind, VerificationErrorKind::DecodeError(_)));

    Ok(())
}

#[test]
fn verifies_signed_attributes_in_encoded_order() -> TestResult {
    let (sd, bytes) = required(signed_data_and_bytes_from_time_stamp_response(TOKEN)?)?;
    let signers = sd.signer_infos.to_vec();
    let signer = required(signers.first())?;
    let raw = required(received_signer_infos(&bytes))?;
    let encoded = required(received_signed_attributes(&raw, signer))?;
    let sorted = rasn::der::encode(required(signer.signed_attrs.as_ref())?)?;

    assert_ne!(encoded, sorted);
    assert_crypto_verified(TOKEN)
}

#[test]
fn verifies_signed_attributes_in_timestamp_response() -> TestResult {
    let mut response = tlv(0x30, &tlv(0x02, &[0]));
    response.extend_from_slice(TOKEN);
    assert_crypto_verified(&tlv(0x30, &response))
}

#[test]
fn verifies_der_sorted_signed_attributes() -> TestResult {
    let (sd, bytes) = required(signed_data_and_bytes_from_time_stamp_response(
        SORTED_TOKEN,
    )?)?;

    let signers = sd.signer_infos.to_vec();
    let signer = required(signers.first())?;
    let raw = required(received_signer_infos(&bytes))?;

    assert_eq!(
        required(received_signed_attributes(&raw, signer))?,
        rasn::der::encode(required(signer.signed_attrs.as_ref())?)?
    );

    assert_crypto_verified(SORTED_TOKEN)
}

#[test]
fn rejects_token_with_duplicated_signature() -> TestResult {
    for token in [TOKEN, SORTED_TOKEN] {
        // The unmodified token must verify; duplicated signers alone cause the
        // rejection, including the sorted-input DER fallback regression.
        assert_crypto_verified(token)?;
        let signer = original_signer_info(token)?;
        assert_duplicate_rejected(&rebuild_token(token, None, &[signer.clone(), signer])?)?;
    }

    Ok(())
}

#[test]
fn rejects_forged_timestamp_with_copied_signature() -> TestResult {
    for original in [TOKEN, SORTED_TOKEN] {
        for original_first in [false, true] {
            let token = forged_token(original, true, original_first)?;
            let sd = required(signed_data_from_time_stamp_response(&token)?)?;
            let mut matching_digests = 0;

            for signer in sd.signer_infos.to_vec() {
                if verify_attribute_digest(signer, &sd).is_ok() {
                    matching_digests += 1;
                }
            }

            // The forged messageDigest matches its forged content, so rejection
            // must happen for ambiguity, not merely a content digest mismatch.
            assert_eq!(matching_digests, 1);
            assert_duplicate_rejected(&token)?;
        }
    }

    Ok(())
}

#[test]
fn rejects_forged_timestamp_with_only_modified_signer() -> TestResult {
    for original in [TOKEN, SORTED_TOKEN] {
        let token = forged_token(original, false, false)?;
        let parsed = ParsedTimestamp::parse(&token)?;
        let signers = parsed.signed_data.signer_infos.to_vec();
        let signer = required(signers.first())?;
        verify_attribute_digest(signer, &parsed.signed_data)?;

        // The attacker also supplied the right imprint for its own data.
        let tst = required(tst_info_from_signed_data(&parsed.signed_data)?)?;
        let mut hasher = DigestAlgorithm::Sha256.digester();
        hasher.update(FORGED_DATA);

        assert_eq!(
            tst.message_imprint.hashed_message.to_bytes(),
            hasher.finish().as_ref()
        );

        let mut candidates = parsed.verify_signatures();
        let error = required(required(candidates.next())?.err())?;

        assert_eq!(error.stage, VerificationStage::Signature);
        assert_eq!(error.kind, VerificationErrorKind::SignatureMismatch);
        assert!(candidates.next().is_none());
    }

    Ok(())
}

#[test]
fn detects_duplicate_signatures_without_raw_signer_infos() -> TestResult {
    for original in [TOKEN, SORTED_TOKEN] {
        let genuine = required(signed_data_from_time_stamp_response(original)?)?;

        assert!(!has_duplicate_signatures(&genuine, None));

        let token = forged_token(original, true, false)?;
        let forged = required(signed_data_from_time_stamp_response(&token)?)?;

        assert!(has_duplicate_signatures(&forged, None));
    }

    Ok(())
}

#[test]
fn locates_unsorted_attributes_with_subject_key_identifier() -> TestResult {
    let sd = required(signed_data_from_time_stamp_response(TOKEN)?)?;
    let certificates = required(sd.certificates.as_ref())?.to_vec();

    let certificate = required(certificates.iter().find_map(|choice| match choice {
        CertificateChoices::Certificate(certificate) => Some(certificate),
        _ => None,
    }))?;

    let extensions = required(certificate.tbs_certificate.extensions.as_ref())?;

    let extension = required(
        extensions
            .iter()
            .find(|extension| extension.extn_id.to_string() == "2.5.29.14"),
    )?;

    let ski = rasn::der::decode::<types::OctetString>(&extension.extn_value)?;
    let original = original_signer_info(TOKEN)?;
    let raw_signer = any(&original)?;
    let fields = required(timestamp_asn1_children(raw_signer.data))?;
    let mut body = tlv(0x02, &[3]);
    body.extend(tlv(0x80, &ski));

    for field in &fields[2..] {
        body.extend(tlv_of(field));
    }

    let token = rebuild_token(TOKEN, None, &[tlv(0x30, &body)])?;
    let (sd, bytes) = required(signed_data_and_bytes_from_time_stamp_response(&token)?)?;
    let signers = sd.signer_infos.to_vec();
    let signer = required(signers.first())?;

    assert!(matches!(
        signer.sid,
        SignerIdentifier::SubjectKeyIdentifier(_)
    ));

    let raw = required(received_signer_infos(&bytes))?;

    assert_ne!(
        required(received_signed_attributes(&raw, signer))?,
        rasn::der::encode(required(signer.signed_attrs.as_ref())?)?
    );

    assert_eq!(
        signer_certificate_from_token(&token)?,
        signer_certificate_from_token(TOKEN)?
    );

    assert_crypto_verified(&token)
}

#[test]
fn rejects_encoded_attributes_that_differ_from_signer_info() -> TestResult {
    let (sd, bytes) = required(signed_data_and_bytes_from_time_stamp_response(TOKEN)?)?;
    let raw = required(received_signer_infos(&bytes))?;
    let signers = sd.signer_infos.to_vec();
    let mut signer = (*required(signers.first())?).clone();

    assert!(received_signed_attributes(&raw, &signer).is_some());

    let attrs = required(signer.signed_attrs.take())?;
    let mut attrs: Vec<_> = attrs.to_vec().into_iter().cloned().collect();
    required(attrs.pop())?;
    signer.signed_attrs = Some(rasn::types::SetOf::from_vec(attrs));

    assert!(received_signed_attributes(&raw, &signer).is_none());

    Ok(())
}

#[test]
fn legacy_cms_decoder_preserves_signed_attribute_signature_input() -> TestResult {
    use bcder::{decode::Constructed, encode::Values, Mode};

    use crate::asn1::rfc5652::{ContentInfo, SignedData, SignerInfo};

    for token in [TOKEN, SORTED_TOKEN] {
        let original = original_signer_info(token)?;
        let raw_signer = any(&original)?;
        let fields = required(timestamp_asn1_children(raw_signer.data))?;

        let body: Vec<_> = fields
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != 3)
            .flat_map(|(_, field)| tlv_of(field))
            .collect();

        // This variant exercises codec behavior only, not signature validity.
        let without_attrs = rebuild_token(token, None, &[tlv(0x30, &body)])?;

        for (has_attrs, token) in [(true, token), (false, without_attrs.as_slice())] {
            let content = required(Constructed::decode(
                token,
                Mode::Der,
                ContentInfo::take_opt_from,
            )?)?;

            let legacy =
                Constructed::decode(content.content.as_slice(), Mode::Der, SignedData::take_from)?;

            let (current, bytes) =
                required(signed_data_and_bytes_from_time_stamp_response(token)?)?;

            assert_eq!(legacy.signer_infos.len(), 1);

            assert_eq!(legacy.digest_algorithms.len(), 1);

            let signers = current.signer_infos.to_vec();
            let signer = required(signers.first())?;
            let raw = required(received_signer_infos(&bytes))?;

            let expected = if has_attrs {
                Some(required(received_signed_attributes(&raw, signer))?)
            } else {
                assert!(signed_attributes_digested_content(signer)?.is_none());
                None
            };

            let mut legacy_signer = required(legacy.signer_infos.first())?.clone();

            assert_eq!(
                legacy_signer.signed_attributes_digested_content()?,
                expected
            );

            legacy_signer.signed_attributes_data = None;

            if has_attrs {
                // Captured input is lossless; regenerating it uses the legacy
                // encoder's extra primitive SEQUENCE wrapper.
                assert_ne!(
                    legacy_signer.signed_attributes_digested_content()?,
                    expected
                );
            } else {
                assert!(legacy_signer
                    .signed_attributes_digested_content()?
                    .is_none());
            }

            let mut encoded = Vec::new();

            legacy_signer
                .encode_ref()
                .write_encoded(Mode::Der, &mut encoded)?;

            let roundtrip =
                Constructed::decode(encoded.as_slice(), Mode::Der, SignerInfo::take_opt_from);

            if has_attrs {
                assert!(roundtrip.is_err());
            } else {
                let roundtrip = required(roundtrip?)?;

                assert_eq!(roundtrip.signature, legacy_signer.signature);
                assert_eq!(roundtrip.sid, legacy_signer.sid);
                assert_eq!(roundtrip.signed_attributes_digested_content()?, expected);
            }
        }
    }

    Ok(())
}
