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

//! The `c2pa.hash.segment` hard binding for append-only text files.

use std::io::SeekFrom;

use serde::{Deserialize, Serialize};

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::labels,
    asset_handlers::append_only_text_io::{ManifestReference, Sentinel},
    error::{Error, Result},
    read_seek::ReadSeek,
    utils::hash_utils::{vec_compare, Hasher},
    validation_status,
};

/// The only `version` this implementation understands.
pub const SEGMENT_HASH_VERSION: u64 = 1;

const ASSERTION_CREATION_VERSION: usize = 1;
const HASH_CHUNK: usize = 64 * 1024;

/// Locates and authenticates the sentinel line of the preceding checkpoint.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PredecessorSentinel {
    /// Byte offset of the first byte of the preceding sentinel line.
    pub start: u64,
    /// Byte length of the preceding sentinel line, including its line ending.
    pub length: u64,
    /// Hash of the bytes `[start, start + length)`.
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
}

/// A `c2pa.hash.segment` assertion: binds a checkpoint manifest to the bytes added to an
/// append-only text file since the previous checkpoint.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SegmentHash {
    /// Assertion format version; must be [`SEGMENT_HASH_VERSION`].
    pub version: u64,
    /// Hash algorithm for `hash` and `predecessorSentinel.hash`; defaults to the claim's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Hash of the segment bytes `[segment_start, segment_end)`.
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
    /// Byte offset of the first byte of the segment.
    pub segment_start: u64,
    /// Byte offset of this checkpoint's sentinel line (exclusive end of the segment).
    pub segment_end: u64,
    /// Byte length of this checkpoint's sentinel line; present only for an external URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sentinel_length: Option<u64>,
    /// The preceding checkpoint's sentinel line; absent only for the first checkpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predecessor_sentinel: Option<PredecessorSentinel>,
}

fn status(code: &str) -> Error {
    Error::C2PAValidation(code.to_string())
}

/// Hashes `len` bytes of `stream` starting at `start`.
pub(crate) fn hash_range(
    stream: &mut dyn ReadSeek,
    alg: &str,
    start: u64,
    len: u64,
) -> Result<Vec<u8>> {
    let mut hasher = Hasher::new(alg)?;
    stream.seek(SeekFrom::Start(start))?;
    let mut remaining = len;
    let mut buf = vec![0u8; HASH_CHUNK];
    while remaining > 0 {
        let n = remaining.min(HASH_CHUNK as u64) as usize;
        stream.read_exact(&mut buf[..n])?;
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    Ok(Hasher::finalize(hasher))
}

impl SegmentHash {
    /// Label prefix for a segment hash assertion.
    pub const LABEL: &'static str = labels::SEGMENT_HASH;

    /// Hash algorithm to use, falling back to the claim's.
    fn alg<'a>(&'a self, claim_alg: &'a str) -> &'a str {
        self.alg.as_deref().unwrap_or(claim_alg)
    }

    /// Validates this assertion as the active checkpoint of the asset in `stream`, whose
    /// length is `file_len` and whose last sentinel line is `sentinel`.
    ///
    /// Covers the spec's general, coverage, and predecessor-hash checks for one
    /// checkpoint. Validating the earlier checkpoints' manifests is done by the store.
    /// Failures are returned as [`Error::C2PAValidation`] carrying the status code.
    pub(crate) fn verify_checkpoint(
        &self,
        stream: &mut dyn ReadSeek,
        file_len: u64,
        sentinel: &Sentinel,
        claim_alg: &str,
    ) -> Result<()> {
        // General
        if self.version != SEGMENT_HASH_VERSION || self.segment_end < self.segment_start {
            return Err(status(validation_status::ASSERTION_SEGMENTHASH_MALFORMED));
        }
        let inline = matches!(sentinel.reference, ManifestReference::Inline(_));
        if self.sentinel_length.is_some() == inline {
            return Err(status(validation_status::ASSERTION_SEGMENTHASH_MALFORMED));
        }
        let alg = self.alg(claim_alg);
        if sentinel.start != self.segment_end {
            return Err(status(validation_status::ASSERTION_SEGMENTHASH_MISMATCH));
        }
        let segment = hash_range(
            stream,
            alg,
            self.segment_start,
            self.segment_end - self.segment_start,
        )?;
        if !vec_compare(&segment, &self.hash) {
            return Err(status(validation_status::ASSERTION_SEGMENTHASH_MISMATCH));
        }

        // Coverage
        let end_boundary = self
            .segment_end
            .checked_add(self.sentinel_length.unwrap_or(sentinel.len));
        if end_boundary != Some(file_len) {
            return Err(status(
                validation_status::ASSERTION_SEGMENTHASH_PARTIAL_COVERAGE,
            ));
        }
        let expected_start = match &self.predecessor_sentinel {
            None => Some(0),
            Some(p) => p.start.checked_add(p.length),
        };
        if expected_start != Some(self.segment_start) {
            return Err(status(
                validation_status::ASSERTION_SEGMENTHASH_PARTIAL_COVERAGE,
            ));
        }

        // Predecessor sentinel bytes
        if let Some(p) = &self.predecessor_sentinel {
            // Coverage above guarantees p.start + p.length == segment_start <= file_len.
            let digest = hash_range(stream, alg, p.start, p.length)?;
            if !vec_compare(&digest, &p.hash) {
                return Err(status(
                    validation_status::ASSERTION_SEGMENTHASH_PREDECESSOR_MISMATCH,
                ));
            }
        }
        Ok(())
    }
}

impl AssertionCbor for SegmentHash {}

impl AssertionBase for SegmentHash {
    const LABEL: &'static str = Self::LABEL;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use std::io::Cursor;

    use super::*;
    use crate::{
        asset_handlers::append_only_text_io::{find_active_sentinel, SentinelForm},
        crypto::base64,
    };

    const URI: &str = "https://northwindtraders.com/provenance/chk1.c2pa";

    fn sentinel_line(eol: &str) -> String {
        format!("-----BEGIN C2PA CHECKPOINT----- {URI} -----END C2PA CHECKPOINT-----{eol}")
    }

    fn b64(s: &str) -> Vec<u8> {
        base64::decode(s).unwrap()
    }

    fn verify(file: &[u8], sh: &SegmentHash) -> Result<()> {
        let mut c = Cursor::new(file.to_vec());
        let s = find_active_sentinel(&mut c, SentinelForm::Armour, file.len() as u64)?.unwrap();
        sh.verify_checkpoint(&mut c, file.len() as u64, &s, "sha256")
    }

    fn code(r: Result<()>) -> String {
        match r {
            Err(Error::C2PAValidation(c)) => c,
            other => panic!("expected a validation code, got {other:?}"),
        }
    }

    /// Spec test vector: first checkpoint, LF line endings.
    fn lf_vector() -> (Vec<u8>, SegmentHash) {
        let file = format!("alpha\nbravo\n{}", sentinel_line("\n")).into_bytes();
        let sh = SegmentHash {
            version: 1,
            alg: Some("sha256".into()),
            hash: b64("Hsg2fWyLWendDHpPRyFNuNLnbr0s1b9BVVCMsnJj3S8="),
            segment_start: 0,
            segment_end: 12,
            sentinel_length: Some(112),
            predecessor_sentinel: None,
        };
        (file, sh)
    }

    /// Spec test vector: second checkpoint, CRLF line endings.
    fn crlf_vector() -> (Vec<u8>, SegmentHash) {
        let file = format!(
            "alpha\r\nbravo\r\n{}charlie\r\ndelta\r\n{}",
            sentinel_line("\r\n"),
            sentinel_line("\r\n")
        )
        .into_bytes();
        let sh = SegmentHash {
            version: 1,
            alg: Some("sha256".into()),
            hash: b64("axfDsyQ12xTN4nWbwIPzKx/rxSLSC1UQhasygsqD4Ls="),
            segment_start: 127,
            segment_end: 143,
            sentinel_length: Some(113),
            predecessor_sentinel: Some(PredecessorSentinel {
                start: 14,
                length: 113,
                hash: b64("52VROEjEl9C7I15jXoXVjuO9LzZvsBVf04bXeubHuM8="),
            }),
        };
        (file, sh)
    }

    #[test]
    fn spec_vectors_verify() {
        let (file, sh) = lf_vector();
        assert_eq!(sentinel_line("\n").len(), 112);
        verify(&file, &sh).unwrap();

        let (file, sh) = crlf_vector();
        assert_eq!(file.len(), 143 + 113);
        verify(&file, &sh).unwrap();
    }

    #[test]
    fn spec_vector_round_trips_through_cbor() {
        let (_, sh) = crlf_vector();
        let back = SegmentHash::from_assertion(&sh.to_assertion().unwrap()).unwrap();
        assert_eq!(back, sh);
        assert_eq!(SegmentHash::LABEL, "c2pa.hash.segment");
    }

    #[test]
    fn altered_segment_is_a_mismatch() {
        let (mut file, sh) = crlf_vector();
        file[130] ^= 1; // inside "charlie"
        assert_eq!(
            code(verify(&file, &sh)),
            validation_status::ASSERTION_SEGMENTHASH_MISMATCH
        );
    }

    #[test]
    fn altered_predecessor_sentinel_is_detected() {
        let (mut file, sh) = crlf_vector();
        file[60] ^= 1; // inside the first sentinel's URI
        assert_eq!(
            code(verify(&file, &sh)),
            validation_status::ASSERTION_SEGMENTHASH_PREDECESSOR_MISMATCH
        );
    }

    #[test]
    fn content_after_the_active_checkpoint_is_partial_coverage() {
        let (mut file, sh) = lf_vector();
        file.extend_from_slice(b"charlie\n");
        assert_eq!(
            code(verify(&file, &sh)),
            validation_status::ASSERTION_SEGMENTHASH_PARTIAL_COVERAGE
        );
    }

    #[test]
    fn gap_before_the_segment_is_partial_coverage() {
        let (file, mut sh) = crlf_vector();
        let p = sh.predecessor_sentinel.as_mut().unwrap();
        p.length -= 1; // segment no longer starts right after the predecessor
        assert_eq!(
            code(verify(&file, &sh)),
            validation_status::ASSERTION_SEGMENTHASH_PARTIAL_COVERAGE
        );

        let (file, mut sh) = lf_vector();
        sh.segment_start = 6;
        sh.hash = hash_range(&mut Cursor::new(&file), "sha256", 6, 6).unwrap();
        assert_eq!(
            code(verify(&file, &sh)),
            validation_status::ASSERTION_SEGMENTHASH_PARTIAL_COVERAGE
        );
    }

    #[test]
    fn sentinel_not_at_segment_end_is_a_mismatch() {
        let (file, mut sh) = lf_vector();
        sh.segment_end = 11;
        assert_eq!(
            code(verify(&file, &sh)),
            validation_status::ASSERTION_SEGMENTHASH_MISMATCH
        );
    }

    #[test]
    fn malformed_assertions() {
        let (file, mut sh) = lf_vector();
        sh.version = 2;
        assert_eq!(
            code(verify(&file, &sh)),
            validation_status::ASSERTION_SEGMENTHASH_MALFORMED
        );

        let (file, mut sh) = lf_vector();
        sh.sentinel_length = None; // required for an external URI
        assert_eq!(
            code(verify(&file, &sh)),
            validation_status::ASSERTION_SEGMENTHASH_MALFORMED
        );
    }
}
