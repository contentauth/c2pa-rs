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

//! Validates the chain of checkpoints before the active one in an append-only text file
//! ("Validating the chain of checkpoints").

use std::{
    borrow::Cow,
    io::{Read, Seek, SeekFrom},
};

use async_generic::async_generic;

use crate::{
    assertion::AssertionBase,
    assertions::SegmentHash,
    asset_handlers::append_only_text_io::{read_sentinel_at, ManifestReference, SentinelForm},
    claim::{Claim, ClaimAssetData},
    context::Context,
    error::{Error, Result},
    log_item,
    read_seek::ReadSeek,
    status_tracker::{LogKind, StatusTracker},
    store::Store,
    validation_status,
};

/// A read-only view of the first `len` bytes of a stream: the file as it stood when an
/// earlier checkpoint was the active one.
pub(crate) struct Prefix<'a> {
    inner: &'a mut dyn ReadSeek,
    len: u64,
    pos: u64,
}

impl<'a> Prefix<'a> {
    pub(crate) fn new(inner: &'a mut dyn ReadSeek, len: u64) -> Self {
        Self { inner, len, pos: 0 }
    }
}

impl Read for Prefix<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }
        let max = buf.len().min((self.len - self.pos) as usize);
        self.inner.seek(SeekFrom::Start(self.pos))?;
        let n = self.inner.read(&mut buf[..max])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Prefix<'_> {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let target = match from {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = target.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek before start")
        })?;
        Ok(self.pos)
    }
}

/// The provenance claim's segment hash binding, if it has one.
fn segment_hash_of(claim: &Claim) -> Option<(String, SegmentHash)> {
    let binding = claim
        .hash_assertions()
        .into_iter()
        .find(|a| a.label_raw().starts_with(SegmentHash::LABEL))?;
    let sh = SegmentHash::from_assertion(binding.assertion()).ok()?;
    Some((claim.assertion_uri(&binding.label()), sh))
}

impl Store {
    /// Validates every checkpoint before the active one, newest first.
    ///
    /// Each earlier checkpoint's Manifest Store is read from its own sentinel line (inline
    /// or by URI) and validated against the file truncated to the end of that sentinel,
    /// where it was the active checkpoint. Its claim signature and segment hash binding are
    /// checked; its ingredients are not re-checked, since the active manifest's ingredient
    /// checks already cover the embedded history.
    ///
    /// Failures are logged against the active manifest's segment hash assertion. A
    /// checkpoint whose external Manifest Store cannot be retrieved is reported as
    /// `manifest.inaccessible` without rejecting the active checkpoint; that checkpoint and
    /// every earlier one are left unverified.
    #[async_generic]
    pub(crate) fn verify_checkpoint_chain(
        store: &Store,
        format: &str,
        stream: &mut dyn ReadSeek,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<()> {
        let Some((active_uri, mut current)) = store.provenance_claim().and_then(segment_hash_of)
        else {
            return Ok(());
        };
        if validation_log
            .filter_errors()
            .any(|item| item.label == active_uri)
        {
            // The active binding already failed; its chain carries no weight.
            return Ok(());
        }

        let form = SentinelForm::for_format(format);
        let mut verified = 0usize;

        while let Some(pred) = current.predecessor_sentinel.clone() {
            let end = match pred.start.checked_add(pred.length) {
                Some(end) if end <= current.segment_start => end,
                _ => {
                    log_item!(
                        active_uri.clone(),
                        "earlier checkpoint is not before the one that references it",
                        "verify_checkpoint_chain"
                    )
                    .validation_status(validation_status::ASSERTION_SEGMENTHASH_PARTIAL_COVERAGE)
                    .failure(
                        validation_log,
                        Error::HashMismatch("checkpoint chain out of order".into()),
                    )?;
                    break;
                }
            };

            let sentinel =
                read_sentinel_at(stream, form, pred.start)?.filter(|s| s.len == pred.length);
            let Some(sentinel) = sentinel else {
                log_item!(
                    active_uri.clone(),
                    format!("no checkpoint sentinel line at byte {}", pred.start),
                    "verify_checkpoint_chain"
                )
                .validation_status(validation_status::ASSERTION_SEGMENTHASH_MISMATCH)
                .failure(
                    validation_log,
                    Error::HashMismatch("predecessor is not a sentinel line".into()),
                )?;
                break;
            };

            let manifest = match sentinel.reference {
                ManifestReference::Inline(bytes) => bytes,
                ManifestReference::External(url) => {
                    let fetched = if _sync {
                        Store::handle_remote_manifest(&url, context)
                    } else {
                        Store::handle_remote_manifest_async(&url, context).await
                    };
                    match fetched {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            log_item!(
                                url.clone(),
                                format!(
                                    "checkpoint manifest could not be retrieved ({e}); bytes \
                                     before {end} are unverified"
                                ),
                                "verify_checkpoint_chain"
                            )
                            .validation_status(validation_status::MANIFEST_INACCESSIBLE)
                            .informational(validation_log);
                            break;
                        }
                    }
                }
            };

            let mut sub_log = StatusTracker::default();
            let mut prefix = Prefix::new(&mut *stream, end);
            let next = if _sync {
                Self::verify_checkpoint_manifest(
                    &manifest,
                    format,
                    &mut prefix,
                    &mut sub_log,
                    context,
                )
            } else {
                Self::verify_checkpoint_manifest_async(
                    &manifest,
                    format,
                    &mut prefix,
                    &mut sub_log,
                    context,
                )
                .await
            };

            let failure = sub_log
                .logged_items()
                .iter()
                .find(|item| item.kind == LogKind::Failure)
                .cloned();
            let next = next.map(|store| {
                store
                    .provenance_claim()
                    .and_then(segment_hash_of)
                    .map(|(_, sh)| sh)
            });
            match (next, failure) {
                (Ok(Some(sh)), None) => {
                    verified += 1;
                    current = sh;
                }
                (next, failure) => {
                    let description = failure.as_ref().map_or_else(
                        || match &next {
                            Err(e) => e.to_string(),
                            _ => "no segment hash binding".to_string(),
                        },
                        |f| f.description.to_string(),
                    );
                    let mut item = log_item!(
                        active_uri.clone(),
                        format!("checkpoint ending at byte {end} failed validation: {description}"),
                        "verify_checkpoint_chain"
                    );
                    item.validation_status = Some(
                        failure
                            .and_then(|f| f.validation_status)
                            .unwrap_or(Cow::Borrowed(
                                validation_status::ASSERTION_SEGMENTHASH_MISMATCH,
                            )),
                    );
                    item.failure(
                        validation_log,
                        Error::HashMismatch(format!("checkpoint chain failure: {description}")),
                    )?;
                    break;
                }
            }
        }

        if verified > 0 {
            log_item!(
                active_uri,
                format!("{verified} earlier checkpoint(s) verified"),
                "verify_checkpoint_chain"
            )
            .validation_status(validation_status::ASSERTION_SEGMENTHASH_MATCH)
            .success(validation_log);
        }
        Ok(())
    }

    /// Validates one earlier checkpoint's Manifest Store against `prefix`, the file as it
    /// stood when that checkpoint was written: its claim signature and its segment hash
    /// binding, without re-checking its ingredients. Returns the loaded store.
    #[async_generic(async_signature(
        manifest: &[u8],
        format: &str,
        prefix: &mut dyn ReadSeek,
        validation_log: &mut StatusTracker,
        context: &Context,
    ))]
    pub(crate) fn verify_checkpoint_manifest(
        manifest: &[u8],
        format: &str,
        prefix: &mut dyn ReadSeek,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<Store> {
        let store = Store::from_jumbf_with_context(manifest, validation_log, context)?;
        let claim = store.provenance_claim().ok_or(Error::ProvenanceMissing)?;
        let mut asset_data = ClaimAssetData::Stream(prefix, format);
        let svi = store.get_store_validation_info(
            claim,
            Some(&mut asset_data),
            validation_log,
            context,
        )?;
        if _sync {
            Claim::verify_claim(claim, &svi, true, &store.ctp, validation_log, context)?;
        } else {
            Claim::verify_claim_async(claim, &svi, true, &store.ctp, validation_log, context)
                .await?;
        }
        Claim::verify_hash_binding(claim, &mut asset_data, &svi, validation_log, context)?;
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use std::io::Cursor;

    use c2pa_raw_crypto::SigningAlg;

    use super::*;
    use crate::{
        assertions::{segment_hash_range as hash_range, PredecessorSentinel},
        asset_handlers::append_only_text_io::{BEGIN_CHECKPOINT, END_CHECKPOINT},
        crypto::base64,
        utils::{
            test::{create_min_test_claim, test_context},
            test_signer::test_signer,
        },
        validation_results::{StatusCodes, ValidationState},
        validation_status::ValidationStatus,
        Reader,
    };

    const JSONL: &str = "application/jsonl";

    /// Test-only checkpoint writer following the spec's writing procedure. `url` selects the
    /// external URI form; `None` embeds the Manifest Store inline.
    struct Writer {
        file: Vec<u8>,
        form: SentinelForm,
        previous: Option<(u64, u64)>,
        /// Manifest Stores by URL, for serving external checkpoints.
        stores: Vec<(String, Vec<u8>)>,
    }

    impl Writer {
        fn new(form: SentinelForm) -> Self {
            Self {
                file: Vec::new(),
                form,
                previous: None,
                stores: Vec::new(),
            }
        }

        fn sentinel(&self, reference: &str) -> Vec<u8> {
            match self.form {
                SentinelForm::Armour => {
                    format!("{BEGIN_CHECKPOINT} {reference} {END_CHECKPOINT}\n")
                }
                SentinelForm::Json => format!("{{\"c2pa:checkpoint\":\"{reference}\"}}\n"),
            }
            .into_bytes()
        }

        fn checkpoint(&mut self, content: &str, url: Option<&str>) {
            let start = self.file.len() as u64;
            self.file.extend_from_slice(content.as_bytes());
            let end = self.file.len() as u64;
            let mut cursor = Cursor::new(self.file.clone());
            let predecessor = self.previous.map(|(s, l)| PredecessorSentinel {
                start: s,
                length: l,
                hash: hash_range(&mut cursor, "sha256", s, l).unwrap(),
            });
            let line = url.map(|u| self.sentinel(u));
            let sh = SegmentHash {
                version: 1,
                alg: Some("sha256".into()),
                hash: hash_range(&mut cursor, "sha256", start, end - start).unwrap(),
                segment_start: start,
                segment_end: end,
                sentinel_length: line.as_ref().map(|l| l.len() as u64),
                predecessor_sentinel: predecessor,
            };
            let store = sign(&sh);
            let line = match (line, url) {
                (Some(line), Some(u)) => {
                    self.stores.push((u.to_string(), store));
                    line
                }
                _ => self.sentinel(&format!(
                    "data:application/c2pa;base64,{}",
                    base64::encode(&store)
                )),
            };
            self.previous = Some((end, line.len() as u64));
            self.file.extend_from_slice(&line);
        }
    }

    fn context() -> Context {
        test_context().with_signer(test_signer(SigningAlg::Ps256))
    }

    fn sign(sh: &SegmentHash) -> Vec<u8> {
        let context = context();
        let mut claim = create_min_test_claim().unwrap();
        claim.add_assertion(sh).unwrap();
        let mut store = Store::from_context(&context);
        store.commit_claim(claim).unwrap();
        store.sign_manifest(&context, None).unwrap()
    }

    fn read(format: &str, file: &[u8]) -> Reader {
        Reader::from_context(context())
            .with_stream(format, Cursor::new(file.to_vec()))
            .unwrap()
    }

    fn codes(reader: &Reader, pick: fn(&StatusCodes) -> &Vec<ValidationStatus>) -> Vec<String> {
        reader
            .validation_results()
            .and_then(|r| r.active_manifest())
            .map(|m| pick(m).iter().map(|s| s.code().to_string()).collect())
            .unwrap_or_default()
    }

    fn failures(reader: &Reader) -> Vec<String> {
        codes(reader, |m| m.failure())
    }

    fn three_inline_checkpoints() -> Writer {
        let mut w = Writer::new(SentinelForm::Json);
        w.checkpoint("{\"event\":1}\n{\"event\":2}\n", None);
        w.checkpoint("{\"event\":3}\n", None);
        w.checkpoint("{\"event\":4}\n{\"event\":5}\n", None);
        w
    }

    #[test]
    fn jsonl_chain_of_inline_checkpoints_validates() {
        let w = three_inline_checkpoints();
        let reader = read(JSONL, &w.file);
        assert_eq!(failures(&reader), Vec::<String>::new());
        assert_ne!(reader.validation_state(), ValidationState::Invalid);
        let success = codes(&reader, |m| m.success());
        assert!(success
            .iter()
            .any(|c| c == validation_status::ASSERTION_SEGMENTHASH_MATCH));
        let explanations: Vec<_> = reader
            .validation_results()
            .unwrap()
            .active_manifest()
            .unwrap()
            .success()
            .iter()
            .filter_map(|s| s.explanation().map(str::to_string))
            .collect();
        assert!(
            explanations
                .iter()
                .any(|e| e.contains("2 earlier checkpoint(s) verified")),
            "{explanations:?}"
        );
    }

    #[test]
    fn altering_an_earlier_segment_fails_the_chain() {
        let mut w = three_inline_checkpoints();
        let pos = w.file.windows(9).position(|x| x == b"\"event\":3").unwrap(); // second segment
        w.file[pos + 8] = b'9';
        let reader = read(JSONL, &w.file);
        assert_eq!(reader.validation_state(), ValidationState::Invalid);
        assert!(
            failures(&reader)
                .contains(&validation_status::ASSERTION_SEGMENTHASH_MISMATCH.to_string()),
            "{:?}",
            failures(&reader)
        );
    }

    #[test]
    fn altering_an_earlier_sentinel_fails_the_chain() {
        let mut w = three_inline_checkpoints();
        // The first sentinel starts right after the first segment; flip a byte in its key.
        let first = w
            .file
            .windows(15)
            .position(|x| x == b"c2pa:checkpoint")
            .unwrap();
        w.file[first + 1] = b'3';
        let reader = read(JSONL, &w.file);
        assert_eq!(reader.validation_state(), ValidationState::Invalid);
        assert!(
            failures(&reader).contains(
                &validation_status::ASSERTION_SEGMENTHASH_PREDECESSOR_MISMATCH.to_string()
            ),
            "{:?}",
            failures(&reader)
        );
    }

    #[test]
    fn content_after_the_last_checkpoint_is_partial_coverage() {
        let mut w = three_inline_checkpoints();
        w.file.extend_from_slice(b"{\"event\":6}\n");
        let reader = read(JSONL, &w.file);
        assert!(failures(&reader)
            .contains(&validation_status::ASSERTION_SEGMENTHASH_PARTIAL_COVERAGE.to_string()));
    }

    #[test]
    fn truncation_at_a_checkpoint_still_validates() {
        // Documented limit of the format: cutting the file at a checkpoint boundary leaves a
        // valid, shorter log. Detecting it needs a copy of the newest checkpoint elsewhere.
        let mut w = Writer::new(SentinelForm::Json);
        w.checkpoint("{\"event\":1}\n", None);
        w.checkpoint("{\"event\":2}\n", None);
        let cut = w.file.len();
        w.checkpoint("{\"event\":3}\n", None);
        let reader = read(JSONL, &w.file[..cut]);
        assert_eq!(failures(&reader), Vec::<String>::new());
    }

    #[test]
    fn malformed_last_sentinel_reports_no_sentinel() {
        let mut w = three_inline_checkpoints();
        w.file.extend_from_slice(b"{\"c2pa:checkpoint\":17}\n");
        let err = Reader::from_context(context())
            .with_stream(JSONL, Cursor::new(w.file))
            .unwrap_err();
        assert!(
            matches!(&err, Error::C2PAValidation(c) if c == validation_status::MANIFEST_APPEND_ONLY_TEXT_NO_SENTINEL),
            "{err:?}"
        );
    }

    mod writer {
        use super::*;
        use crate::{Builder, BuilderIntent, CheckpointPlacement, Relationship};

        fn builder() -> Builder {
            let mut builder = Builder::from_context(context());
            builder.set_intent(BuilderIntent::Create(
                crate::assertions::DigitalSourceType::TrainedAlgorithmicData,
            ));
            builder
        }

        fn append(file: &mut Cursor<Vec<u8>>, text: &str) {
            file.seek(SeekFrom::End(0)).unwrap();
            std::io::Write::write_all(file, text.as_bytes()).unwrap();
        }

        /// Writes three inline JSONL checkpoints with the public API.
        fn inline_log() -> Vec<u8> {
            let mut builder = builder();
            let mut file = Cursor::new(Vec::new());
            for batch in [
                "{\"event\":1}\n{\"event\":2}\n",
                "{\"event\":3}\n",
                "{\"event\":4}\n",
            ] {
                append(&mut file, batch);
                builder
                    .sign_checkpoint(JSONL, &mut file, CheckpointPlacement::Inline, None)
                    .unwrap();
            }
            file.into_inner()
        }

        #[test]
        fn inline_checkpoints_validate_and_chain_through_parent_of() {
            let file = inline_log();
            let reader = read(JSONL, &file);
            assert_eq!(failures(&reader), Vec::<String>::new());
            assert_ne!(reader.validation_state(), ValidationState::Invalid);

            // The newest checkpoint's parent is the previous one, which carries its own
            // parent: the store holds all three manifests, as the specification has it.
            let active = reader.active_manifest().unwrap();
            let parents: Vec<_> = active
                .ingredients()
                .iter()
                .filter(|i| *i.relationship() == Relationship::ParentOf)
                .collect();
            assert_eq!(parents.len(), 1);
            assert!(parents[0].active_manifest().is_some());
            assert_eq!(reader.iter_manifests().count(), 3);

            // Each line is either an event or a checkpoint.
            let text = String::from_utf8(file).unwrap();
            assert_eq!(
                text.lines()
                    .filter(|l| l.contains("c2pa:checkpoint"))
                    .count(),
                3
            );
        }

        #[test]
        fn crlf_plain_text_keeps_the_file_line_ending() {
            let mut builder = builder();
            let mut file = Cursor::new(b"alpha\r\nbravo\r\n".to_vec());
            builder
                .sign_checkpoint("text/plain", &mut file, CheckpointPlacement::Inline, None)
                .unwrap();
            append(&mut file, "charlie\r\n");
            builder
                .sign_checkpoint("text/plain", &mut file, CheckpointPlacement::Inline, None)
                .unwrap();
            let file = file.into_inner();
            assert!(file.ends_with(format!("{END_CHECKPOINT}\r\n").as_bytes()));
            let reader = read("text/plain", &file);
            assert_eq!(failures(&reader), Vec::<String>::new());
        }

        #[test]
        fn misuse_is_rejected() {
            let mut no_intent = Builder::from_context(context());
            let mut first = Cursor::new(b"{\"event\":1}\n".to_vec());
            assert!(matches!(
                no_intent.sign_checkpoint(JSONL, &mut first, CheckpointPlacement::Inline, None),
                Err(Error::BadParam(_))
            ));

            let mut builder = builder();

            let mut partial = Cursor::new(b"{\"event\":1}".to_vec());
            assert!(matches!(
                builder.sign_checkpoint(JSONL, &mut partial, CheckpointPlacement::Inline, None),
                Err(Error::BadParam(_))
            ));

            let mut external = Cursor::new(b"{\"event\":1}\n".to_vec());
            builder
                .sign_checkpoint(
                    JSONL,
                    &mut external,
                    CheckpointPlacement::External("https://example.com/1.c2pa"),
                    None,
                )
                .unwrap();
            append(&mut external, "{\"event\":2}\n");
            assert!(matches!(
                builder.sign_checkpoint(JSONL, &mut external, CheckpointPlacement::Inline, None),
                Err(Error::BadParam(_)) // previous checkpoint is external: its store is needed
            ));

            let mut png = Cursor::new(Vec::new());
            assert!(matches!(
                builder.sign_checkpoint("image/png", &mut png, CheckpointPlacement::Inline, None),
                Err(Error::UnsupportedType)
            ));
        }
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "fetch_remote_manifests"))]
    mod remote {
        use httpmock::prelude::*;

        use super::*;

        fn serve(server: &MockServer, w: &mut Writer, skip: Option<usize>) {
            for (i, (url, store)) in w.stores.iter().enumerate() {
                let path = url.trim_start_matches(&server.base_url()).to_string();
                if Some(i) == skip {
                    server.mock(|when, then| {
                        when.method(GET).path(path.clone());
                        then.status(404);
                    });
                    continue;
                }
                let store = store.clone();
                server.mock(move |when, then| {
                    when.method(GET).path(path);
                    then.status(200)
                        .header("content-type", "application/c2pa")
                        .body(store);
                });
            }
        }

        fn plain_text_log(server: &MockServer) -> Writer {
            let mut w = Writer::new(SentinelForm::Armour);
            w.checkpoint("alpha\nbravo\n", Some(&server.url("/chk1.c2pa")));
            w.checkpoint("charlie\n", Some(&server.url("/chk2.c2pa")));
            w.checkpoint("delta\necho\n", Some(&server.url("/chk3.c2pa")));
            w
        }

        #[test]
        fn plain_text_log_with_external_checkpoints_validates() {
            let server = MockServer::start();
            let mut w = plain_text_log(&server);
            serve(&server, &mut w, None);
            let reader = read("text/plain", &w.file);
            assert_eq!(failures(&reader), Vec::<String>::new());
            assert!(codes(&reader, |m| m.success())
                .contains(&validation_status::ASSERTION_SEGMENTHASH_MATCH.to_string()));
        }

        #[test]
        fn external_checkpoints_written_by_the_builder_validate() {
            use crate::{Builder, BuilderIntent, CheckpointPlacement};

            let server = MockServer::start();
            let mut builder = Builder::from_context(context());
            builder.set_intent(BuilderIntent::Create(
                crate::assertions::DigitalSourceType::TrainedAlgorithmicData,
            ));
            let mut file = Cursor::new(Vec::new());
            let mut previous: Option<Vec<u8>> = None;
            for (i, batch) in ["alpha\nbravo\n", "charlie\n", "delta\n"]
                .iter()
                .enumerate()
            {
                file.seek(SeekFrom::End(0)).unwrap();
                std::io::Write::write_all(&mut file, batch.as_bytes()).unwrap();
                let path = format!("/log/chk{i}.c2pa");
                let url = server.url(&path);
                let store = builder
                    .sign_checkpoint(
                        "text/plain",
                        &mut file,
                        CheckpointPlacement::External(&url),
                        previous.as_deref(),
                    )
                    .unwrap();
                let body = store.clone();
                server.mock(move |when, then| {
                    when.method(GET).path(path);
                    then.status(200).body(body);
                });
                previous = Some(store);
            }
            let reader = read("text/plain", &file.into_inner());
            assert_eq!(failures(&reader), Vec::<String>::new());
            assert!(codes(&reader, |m| m.success())
                .contains(&validation_status::ASSERTION_SEGMENTHASH_MATCH.to_string()));
        }

        #[test]
        fn unreachable_earlier_checkpoint_is_inaccessible_not_rejected() {
            let server = MockServer::start();
            let mut w = plain_text_log(&server);
            serve(&server, &mut w, Some(1));
            let reader = read("text/plain", &w.file);
            assert_eq!(failures(&reader), Vec::<String>::new());
            assert_ne!(reader.validation_state(), ValidationState::Invalid);
            assert!(codes(&reader, |m| m.informational())
                .contains(&validation_status::MANIFEST_INACCESSIBLE.to_string()));
        }
    }
}
