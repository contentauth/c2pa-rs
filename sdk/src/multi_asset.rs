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

//! Validation of multi-asset byte-range locators (including multipart JPEGs).

use std::io::{self, Read, Seek, SeekFrom};

use serde::Deserialize;

use crate::{
    assertion::{AssertionBase, AssertionData},
    assertions::{labels, BoxHash, DataHash},
    claim::{Claim, ClaimAssertion},
    context::{Context, ProgressPhase},
    error::{Error, Result},
    hashed_uri::HashedUri,
    jumbf::labels::{to_absolute_uri, to_normalized_uri},
    read_seek::ReadSeek,
    utils::hash_utils::{hash_size_by_alg, vec_compare},
    validation_status::{
        ASSERTION_MULTI_ASSET_HASH_MALFORMED as MALFORMED,
        ASSERTION_MULTI_ASSET_HASH_MISMATCH as MISMATCH,
        ASSERTION_MULTI_ASSET_HASH_MISSING_PART as MISSING_PART,
    },
};

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
struct MultiAssetHash {
    parts: Vec<Part>,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(rename_all = "camelCase")]
struct Part {
    location: Location,
    hash_assertion: HashedUri,
    #[serde(default)]
    optional: bool,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Location {
    byte_offset: u64,
    length: u64,
}

fn failure(code: &str) -> Error {
    Error::C2PAValidation(code.to_owned())
}

fn same_uri(claim: &Claim, uri: &str, target: &str) -> bool {
    to_normalized_uri(&to_absolute_uri(claim.label(), uri)) == to_normalized_uri(target)
}

// Loaded assertion hashes include the assertion box and its salt. Require the
// claim's authenticated reference before interpreting a fallback or part binding.
fn authenticated(claim: &Claim, assertion: &ClaimAssertion) -> bool {
    let target = claim.assertion_uri(&assertion.label());
    let mut found = false;
    for reference in claim
        .assertions()
        .iter()
        .filter(|r| same_uri(claim, &r.url(), &target))
    {
        found = true;
        if hash_size_by_alg(assertion.hash_alg()).is_err()
            || reference.alg().as_deref().unwrap_or(claim.alg()) != assertion.hash_alg()
            || !vec_compare(&reference.hash(), assertion.hash())
        {
            return false;
        }
    }
    found
}

pub(crate) fn verify(
    claim: &Claim,
    assertions: &[ClaimAssertion],
    stream: &mut dyn ReadSeek,
    format: &str,
    context: &Context,
) -> Result<()> {
    let mut candidates = assertions
        .iter()
        .filter(|a| a.label_raw() == labels::MULTI_ASSET_HASH);
    let assertion = candidates.next().ok_or_else(|| failure(MALFORMED))?;
    if candidates.next().is_some() || !authenticated(claim, assertion) {
        return Err(failure(MALFORMED));
    }
    let AssertionData::Cbor(data) = assertion.assertion().decode_data() else {
        return Err(failure(MALFORMED));
    };
    let multi: MultiAssetHash = c2pa_cbor::from_slice(data).map_err(|_| failure(MALFORMED))?;
    if multi.parts.is_empty() {
        return Err(failure(MALFORMED));
    }
    let asset_length = stream.seek(SeekFrom::End(0))?;
    let mut covered = 0;
    // Validate the entire structure before reading any part hashes.
    let mut located = Vec::new();
    for part in &multi.parts {
        let start = part.location.byte_offset;
        let length = part.location.length;
        let end = start
            .checked_add(length)
            .ok_or_else(|| failure(MALFORMED))?;
        if length == 0 {
            return Err(failure(MALFORMED));
        }
        let reference = &part.hash_assertion;
        let binding = assertions
            .iter()
            .find(|a| same_uri(claim, &reference.url(), &claim.assertion_uri(&a.label())))
            .ok_or_else(|| failure(MALFORMED))?;
        if !matches!(
            binding.label_raw().as_str(),
            "c2pa.hash.data.part" | "c2pa.hash.boxes.part"
        ) || !authenticated(claim, binding)
            || reference.alg().as_deref().unwrap_or(claim.alg()) != binding.hash_alg()
            || !vec_compare(&reference.hash(), binding.hash())
        {
            return Err(failure(MALFORMED));
        }
        if start >= asset_length {
            if part.optional {
                continue;
            }
            return Err(failure(MISSING_PART));
        }
        if start != covered {
            return Err(failure(MALFORMED));
        }
        if end > asset_length {
            return Err(failure(MISMATCH));
        }
        covered = end;
        located.push((part, binding));
    }
    if located.is_empty() || covered != asset_length {
        return Err(failure(MALFORMED));
    }
    for (part, binding) in located {
        let mut reader = PartReader::new(stream, part.location.byte_offset, part.location.length)?;
        let mut progress =
            |step, total| context.check_progress(ProgressPhase::VerifyingAssetHash, step, total);
        let result = if binding.label_raw() == "c2pa.hash.data.part" {
            let hash =
                DataHash::from_assertion(binding.assertion()).map_err(|_| failure(MALFORMED))?;
            if hash.is_remote_hash()
                || hash.exclusions.as_ref().is_some_and(|ranges| {
                    ranges.iter().any(|r| {
                        r.start()
                            .checked_add(r.length())
                            .is_none_or(|end| end > part.location.length)
                    })
                })
            {
                return Err(failure(MALFORMED));
            }
            hash_size_by_alg(hash.alg.as_deref().unwrap_or(claim.alg()))
                .map_err(|_| failure(crate::validation_status::ALGORITHM_UNSUPPORTED))?;
            hash.verify_stream_hash_with_progress(&mut reader, Some(claim.alg()), &mut progress)
        } else {
            let hash =
                BoxHash::from_assertion(binding.assertion()).map_err(|_| failure(MALFORMED))?;
            for item in &hash.boxes {
                hash_size_by_alg(item.alg.as_deref().unwrap_or(claim.alg()))
                    .map_err(|_| failure(crate::validation_status::ALGORITHM_UNSUPPORTED))?;
            }
            let processor = context
                .io()
                .handler(format)
                .and_then(|handler| handler.asset_box_hash_ref())
                .ok_or_else(|| failure(MALFORMED))?;
            hash.verify_stream_hash_with_progress(
                &mut reader,
                Some(claim.alg()),
                processor,
                &mut progress,
            )
            .map(|_| ())
        };
        match result {
            Ok(()) => (),
            Err(Error::OperationCancelled) => return Err(Error::OperationCancelled),
            Err(Error::UnsupportedType) => {
                return Err(failure(crate::validation_status::ALGORITHM_UNSUPPORTED))
            }
            Err(_) => return Err(failure(MISMATCH)),
        }
    }
    Ok(())
}

// Part hash exclusions and seeks are relative to the part, not the source asset.
// The bounded view avoids allocating attacker-controlled locator lengths.
struct PartReader<'a> {
    source: &'a mut dyn ReadSeek,
    start: u64,
    length: u64,
    position: u64,
}

impl<'a> PartReader<'a> {
    fn new(source: &'a mut dyn ReadSeek, start: u64, length: u64) -> io::Result<Self> {
        source.seek(SeekFrom::Start(start))?;
        Ok(Self {
            source,
            start,
            length,
            position: 0,
        })
    }
}

impl Read for PartReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let limit = self
            .length
            .saturating_sub(self.position)
            .min(buffer.len() as u64) as usize;
        let count = self.source.read(&mut buffer[..limit])?;
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for PartReader<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
            SeekFrom::End(offset) => i128::from(self.length) + i128::from(offset),
        };
        if position < 0 || position > i128::from(self.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside asset part",
            ));
        }
        let position = position as u64;
        let absolute = self.start.checked_add(position).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "asset part offset overflow")
        })?;
        self.source.seek(SeekFrom::Start(absolute))?;
        self.position = position;
        Ok(position)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::io::Cursor;

    use super::*;
    use crate::{status_tracker::StatusTracker, store::Store, validation_status};

    const FIXTURES: &[(&str, &[u8], &str)] = &[
        (
            "intact",
            include_bytes!("../tests/fixtures/conformance/multipart_intact.jpg"),
            validation_status::ASSERTION_DATAHASH_MATCH,
        ),
        (
            "required intact",
            include_bytes!("../tests/fixtures/conformance/multipart_required_part_intact.jpg"),
            validation_status::ASSERTION_DATAHASH_MATCH,
        ),
        (
            "one removed",
            include_bytes!("../tests/fixtures/conformance/multipart_one_optional_part_removed.jpg"),
            validation_status::ASSERTION_MULTI_ASSET_HASH_MATCH,
        ),
        (
            "two removed",
            include_bytes!(
                "../tests/fixtures/conformance/multipart_two_optional_parts_removed.jpg"
            ),
            validation_status::ASSERTION_MULTI_ASSET_HASH_MATCH,
        ),
        (
            "required removed",
            include_bytes!("../tests/fixtures/conformance/multipart_required_part_removed.jpg"),
            MISSING_PART,
        ),
        (
            "tampered",
            include_bytes!("../tests/fixtures/conformance/multipart_optional_part_mismatch.jpg"),
            MISMATCH,
        ),
        (
            "truncated",
            include_bytes!(
                "../tests/fixtures/conformance/multipart_optional_part_partly_removed.jpg"
            ),
            MISMATCH,
        ),
        (
            "gap",
            include_bytes!("../tests/fixtures/conformance/multipart_gap.jpg"),
            MALFORMED,
        ),
        (
            "extra data",
            include_bytes!("../tests/fixtures/conformance/multipart_extra_data.jpg"),
            MALFORMED,
        ),
    ];

    fn check(name: &str, expected: &str, report: &StatusTracker) {
        assert!(
            report.has_status(expected),
            "{name}: expected {expected}, got {:?}",
            report.logged_items()
        );
        if expected == validation_status::ASSERTION_DATAHASH_MATCH {
            assert!(
                !report.has_status(validation_status::ASSERTION_MULTI_ASSET_HASH_MATCH),
                "{name}"
            );
        } else {
            assert!(
                !report.has_status(validation_status::ASSERTION_DATAHASH_MATCH),
                "{name}"
            );
            assert!(
                !report.has_status(validation_status::ASSERTION_DATAHASH_MISMATCH),
                "{name}"
            );
            if expected != validation_status::ASSERTION_MULTI_ASSET_HASH_MATCH {
                assert!(
                    !report.has_status(validation_status::ASSERTION_MULTI_ASSET_HASH_MATCH),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn multipart_jpeg_conformance() {
        for &(name, bytes, expected) in FIXTURES {
            let mut report = StatusTracker::default();
            Store::from_stream(
                "image/jpeg",
                Cursor::new(bytes),
                &mut report,
                &Context::new(),
            )
            .unwrap();
            check(name, expected, &report);
        }
    }

    #[tokio::test]
    async fn multipart_jpeg_conformance_async() {
        for &(name, bytes, expected) in FIXTURES {
            let mut report = StatusTracker::default();
            Store::from_stream_async(
                "image/jpeg",
                Cursor::new(bytes),
                &mut report,
                &Context::new(),
            )
            .await
            .unwrap();
            check(name, expected, &report);
        }
    }

    fn synthetic(parts: impl FnOnce(&mut MultiAssetHash)) -> Claim {
        use crate::{assertion::AssertionBase, assertions::UserCbor, utils::hash_utils::HashRange};
        let mut claim = Claim::new("multi-asset test", Some("test"), 1);
        let mut hashes = Vec::new();
        for (index, bytes) in [b"abcd".as_slice(), b"efgh".as_slice()]
            .into_iter()
            .enumerate()
        {
            let mut hash = DataHash::new("part", "sha256");
            // Exercise part-relative exclusions on both the primary and second part.
            hash.add_exclusion(HashRange::new(1, 1));
            hash.gen_hash_from_stream(&mut Cursor::new(bytes)).unwrap();
            let assertion = hash.to_assertion().unwrap();
            let AssertionData::Cbor(data) = assertion.decode_data() else {
                unreachable!()
            };
            let reference = claim
                .add_assertion(&UserCbor::new("c2pa.hash.data.part", data.clone()))
                .unwrap();
            hashes.push(Part {
                location: Location {
                    byte_offset: index as u64 * 4,
                    length: 4,
                },
                hash_assertion: reference,
                optional: index == 1,
            });
        }
        let mut multi = MultiAssetHash { parts: hashes };
        parts(&mut multi);
        claim
            .add_assertion(&UserCbor::new(
                labels::MULTI_ASSET_HASH,
                c2pa_cbor::to_vec(&multi).unwrap(),
            ))
            .unwrap();
        claim
    }

    fn validate_synthetic(claim: &Claim, bytes: &[u8]) -> Result<()> {
        verify(
            claim,
            claim.claim_assertion_store(),
            &mut Cursor::new(bytes),
            "image/jpeg",
            &Context::new(),
        )
    }

    fn assert_code(result: Result<()>, code: &str) {
        assert!(
            matches!(result, Err(Error::C2PAValidation(ref actual)) if actual == code),
            "{result:?}"
        );
    }

    #[test]
    fn part_relative_exclusions_and_optional_removal() {
        let claim = synthetic(|_| ());
        validate_synthetic(&claim, b"abcdexgh").unwrap(); // only excluded byte changes
        validate_synthetic(&claim, b"abcd").unwrap();
        assert_code(validate_synthetic(&claim, b"abcdeXgX"), MISMATCH);
        assert_code(validate_synthetic(&claim, b"abcde"), MISMATCH);
    }

    #[test]
    fn malformed_locators_and_coverage() {
        for claim in [
            synthetic(|m| m.parts.clear()),
            synthetic(|m| m.parts[1].location.byte_offset = 3),
            synthetic(|m| m.parts[1].location.byte_offset = 5),
            synthetic(|m| m.parts[1].location.length = 0),
        ] {
            assert_code(validate_synthetic(&claim, b"abcdefgh"), MALFORMED);
        }
        let claim = synthetic(|_| ());
        assert_code(validate_synthetic(&claim, b"abcdefghi"), MALFORMED);
    }

    #[test]
    fn required_part_missing() {
        let claim = synthetic(|m| m.parts[1].optional = false);
        assert_code(validate_synthetic(&claim, b"abcd"), MISSING_PART);
    }

    #[test]
    fn part_references_must_authenticate_same_manifest_binding() {
        for claim in [
            synthetic(|m| {
                m.parts[1].hash_assertion = HashedUri::new(
                    "self#jumbf=/c2pa/foreign/c2pa.assertions/c2pa.hash.data.part__1".into(),
                    None,
                    &m.parts[1].hash_assertion.hash(),
                )
            }),
            synthetic(|m| {
                m.parts[1].hash_assertion =
                    HashedUri::new(m.parts[1].hash_assertion.url(), None, &[0; 32])
            }),
            synthetic(|m| {
                m.parts[1].hash_assertion = HashedUri::new(
                    m.parts[1].hash_assertion.url(),
                    Some("sha512".into()),
                    &m.parts[1].hash_assertion.hash(),
                )
            }),
        ] {
            assert_code(validate_synthetic(&claim, b"abcdefgh"), MALFORMED);
        }
        let claim = synthetic(|_| ());
        let mut assertions = claim.claim_assertion_store().clone();
        let assertion = assertions[0].assertion().clone();
        assertions[0]
            .update_assertion(assertion, vec![0; 32])
            .unwrap();
        assert_code(
            verify(
                &claim,
                &assertions,
                &mut Cursor::new(b"abcdefgh"),
                "image/jpeg",
                &Context::new(),
            ),
            MALFORMED,
        );
    }

    #[test]
    fn duplicate_or_rejected_multi_asset_assertion() {
        let claim = synthetic(|_| ());
        let mut assertions = claim.claim_assertion_store().clone();
        assertions.push(assertions.last().unwrap().clone());
        assert_code(
            verify(
                &claim,
                &assertions,
                &mut Cursor::new(b"abcdefgh"),
                "image/jpeg",
                &Context::new(),
            ),
            MALFORMED,
        );
        assertions.pop();
        let multi = assertions.last_mut().unwrap();
        multi
            .update_assertion(multi.assertion().clone(), vec![0; 32])
            .unwrap();
        assert_code(
            verify(
                &claim,
                &assertions,
                &mut Cursor::new(b"abcdefgh"),
                "image/jpeg",
                &Context::new(),
            ),
            MALFORMED,
        );
    }

    #[test]
    fn malformed_schema_and_locator_overflow() {
        use crate::assertion::Assertion;
        let claim = synthetic(|_| ());
        let mut multi = MultiAssetHash {
            parts: vec![Part {
                location: Location {
                    byte_offset: u64::MAX,
                    length: 4,
                },
                hash_assertion: claim.assertions()[0].clone(),
                optional: true,
            }],
        };
        let mut invalid = vec![
            c2pa_cbor::to_vec(&multi).unwrap(),
            c2pa_cbor::to_vec(&serde_json::json!({})).unwrap(),
            c2pa_cbor::to_vec(
                &serde_json::json!({"parts": [{"location": {"byteOffset": -1, "length": 4}}]}),
            )
            .unwrap(),
        ];
        multi.parts[0].location.byte_offset = 0;
        multi.parts[0].location.length = 4;
        let mut value = serde_json::to_value(&multi).unwrap();
        value["parts"][0]["location"] = serde_json::json!({"bmffBox": "/mdat"});
        invalid.push(c2pa_cbor::to_vec(&value).unwrap());
        for data in invalid {
            // Exercise the decoder with a pre-authenticated assertion box; the
            // claim builder cannot serialize a locator larger than i64::MAX.
            let mut assertions = claim.claim_assertion_store().clone();
            let assertion = assertions.last_mut().unwrap();
            assertion
                .update_assertion(
                    Assertion::new(labels::MULTI_ASSET_HASH, None, AssertionData::Cbor(data)),
                    assertion.hash().to_vec(),
                )
                .unwrap();
            assert_code(
                verify(
                    &claim,
                    &assertions,
                    &mut Cursor::new(b"abcdefgh"),
                    "image/jpeg",
                    &Context::new(),
                ),
                MALFORMED,
            );
        }
    }

    #[test]
    fn jpeg_box_hash_parts_and_fallback() {
        use crate::{
            assertion::AssertionBase, assertions::UserCbor, claim::ClaimAssetData,
            store::StoreValidationInfo,
        };
        let jpeg = include_bytes!("../tests/fixtures/CA.jpg");
        let context = Context::new();
        let processor = context
            .io()
            .handler("image/jpeg")
            .unwrap()
            .asset_box_hash_ref()
            .unwrap();
        let mut claim = Claim::new("box parts", Some("test"), 1);
        let mut hash = BoxHash { boxes: vec![] };
        hash.generate_box_hash_from_stream(&mut Cursor::new(jpeg), "sha256", processor, false)
            .unwrap();
        let AssertionData::Cbor(data) = hash.to_assertion().unwrap().decode_data().clone() else {
            unreachable!()
        };
        let reference = claim
            .add_assertion(&UserCbor::new("c2pa.hash.boxes.part", data))
            .unwrap();
        let parts = MultiAssetHash {
            parts: vec![Part {
                location: Location {
                    byte_offset: 0,
                    length: jpeg.len() as u64,
                },
                hash_assertion: reference,
                optional: false,
            }],
        };
        claim
            .add_assertion(&UserCbor::new(
                labels::MULTI_ASSET_HASH,
                c2pa_cbor::to_vec(&parts).unwrap(),
            ))
            .unwrap();
        // The ordinary box hash refers to a longer multipart source asset.
        let mut full = jpeg.to_vec();
        full.extend_from_slice(jpeg);
        let mut ordinary = BoxHash { boxes: vec![] };
        ordinary
            .generate_box_hash_from_stream(&mut Cursor::new(full), "sha256", processor, false)
            .unwrap();
        claim.add_assertion(&ordinary).unwrap();
        let svi = StoreValidationInfo {
            binding_claim: claim.label().to_owned(),
            ..Default::default()
        };
        let mut report = StatusTracker::default();
        Claim::verify_hash_binding(
            &claim,
            &mut ClaimAssetData::Bytes(jpeg, "image/jpeg"),
            &svi,
            &mut report,
            &context,
        )
        .unwrap();
        assert!(
            report.has_status(validation_status::ASSERTION_MULTI_ASSET_HASH_MATCH),
            "{:?}",
            report.logged_items()
        );
        assert!(!report.has_status(validation_status::ASSERTION_BOXHASH_MISMATCH));
    }

    #[test]
    fn fallback_respects_stop_on_first_error_and_asset_inputs() {
        use crate::{
            claim::ClaimAssetData, status_tracker::ErrorBehavior, store::StoreValidationInfo,
        };
        let context = Context::new();
        for &(name, bytes, expected) in FIXTURES {
            let (jumbf, _) =
                Store::load_jumbf_from_stream("image/jpeg", &mut Cursor::new(bytes), &context)
                    .unwrap();
            let store = Store::from_jumbf(&jumbf, &mut StatusTracker::default()).unwrap();
            let claim = store.provenance_claim().unwrap();
            let hash = DataHash::from_assertion(claim.hash_assertions()[0].assertion()).unwrap();
            let svi = StoreValidationInfo {
                binding_claim: claim.label().to_owned(),
                is_embedded: true,
                manifest_store_range: hash
                    .exclusions
                    .as_ref()
                    .and_then(|ranges| ranges.first().cloned()),
                ..Default::default()
            };
            let mut cursor = Cursor::new(bytes);
            for mut input in [
                ClaimAssetData::Bytes(bytes, "image/jpeg"),
                ClaimAssetData::Stream(&mut cursor, "image/jpeg"),
            ] {
                let mut report =
                    StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
                let result =
                    Claim::verify_hash_binding(claim, &mut input, &svi, &mut report, &context);
                assert_eq!(
                    result.is_ok(),
                    expected.ends_with(".match"),
                    "{name}: {result:?}"
                );
                check(name, expected, &report);
            }
            #[cfg(feature = "file_io")]
            {
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("multipart.jpg");
                std::fs::write(&path, bytes).unwrap();
                let mut report =
                    StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
                let result = Claim::verify_hash_binding(
                    claim,
                    &mut ClaimAssetData::Path(&path),
                    &svi,
                    &mut report,
                    &context,
                );
                assert_eq!(
                    result.is_ok(),
                    expected.ends_with(".match"),
                    "{name}: {result:?}"
                );
                check(name, expected, &report);
            }
        }
    }

    #[test]
    fn invalid_manifest_exclusion_cannot_recover_via_parts() {
        use crate::{
            claim::ClaimAssetData, store::StoreValidationInfo, utils::hash_utils::HashRange,
        };
        let mut claim = synthetic(|_| ());
        let mut ordinary = DataHash::new("ordinary", "sha256");
        ordinary.add_exclusion(HashRange::new(0, 1));
        ordinary
            .gen_hash_from_stream(&mut Cursor::new(b"abcdefghi"))
            .unwrap();
        claim.add_assertion(&ordinary).unwrap();
        let svi = StoreValidationInfo {
            binding_claim: claim.label().to_owned(),
            is_embedded: true,
            manifest_store_range: Some(HashRange::new(2, 1)),
            ..Default::default()
        };
        let mut report = StatusTracker::default();
        Claim::verify_hash_binding(
            &claim,
            &mut ClaimAssetData::Bytes(b"abcdefgh", "image/jpeg"),
            &svi,
            &mut report,
            &Context::new(),
        )
        .unwrap();
        assert!(report.has_status(validation_status::ASSERTION_DATAHASH_MISMATCH));
        assert!(!report.has_status(validation_status::ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    #[test]
    fn cancellation_is_preserved() {
        let claim = synthetic(|_| ());
        let context = Context::new().with_progress_callback(|_, _, _| false);
        assert!(matches!(
            verify(
                &claim,
                claim.claim_assertion_store(),
                &mut Cursor::new(b"abcdefgh"),
                "image/jpeg",
                &context
            ),
            Err(Error::OperationCancelled)
        ));
    }

    #[test]
    fn part_reader_bounds_and_relative_seeks() {
        let mut source = Cursor::new(b"0123456789");
        let mut reader = PartReader::new(&mut source, 3, 4).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"3456");
        assert_eq!(reader.seek(SeekFrom::End(-2)).unwrap(), 2);
        assert_eq!(reader.seek(SeekFrom::Current(-1)).unwrap(), 1);
        assert!(reader.seek(SeekFrom::End(1)).is_err());
        assert!(reader.seek(SeekFrom::Current(-2)).is_err());
        assert_eq!(reader.seek(SeekFrom::Start(0)).unwrap(), 0);
    }
}
