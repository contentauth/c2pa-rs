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

//! Reads a manifest store directly and eagerly, instead of translating every claim into a
//! JSON-serializable [`crate::Manifest`] the way [`crate::Reader`] does.
//!
//! `StoreReader` has no `Manifest`/`Ingredient` layer — [`StoreReader::claims`] and
//! [`StoreReader::get_assertion`] hand back the small, owned [`crate::Claim`]/
//! [`crate::ClaimAssertion`] types (see `sdk/src/claim_assertion.rs`), built by copying data out
//! of the store. They never wrap or expose the crate's internal claim representation. This is
//! [`crate::ClaimBuilder`]'s read-side counterpart: where `ClaimBuilder` builds a claim directly
//! instead of staging a `ManifestDefinition`, `StoreReader` reads one back directly instead of
//! building a `Manifest`.
//!
//! Validation only ever happens against an asset — [`StoreReader::with_c2pa_data`] (no stream)
//! verifies the claim signature and certificate trust chain but cannot check the asset hash
//! binding, since there's no asset to check it against. [`StoreReader::with_stream`] and
//! [`StoreReader::with_manifest_data_and_stream`] verify all of it, subject to the `verify`
//! settings (see [`crate::settings::Settings`]).

use std::{
    io::{Read, Seek},
    sync::Arc,
};

use async_generic::async_generic;
use serde_json::Value;

use crate::{
    claim_assertion::{Claim, ClaimAssertion, ClaimAssertionKind},
    context::Context,
    error::{Error, Result},
    jumbf_io,
    reader::MaybeSend,
    status_tracker::StatusTracker,
    store::Store,
    validation_results::{ValidationResults, ValidationState},
    validation_status::ValidationStatus,
};

/// Reads a manifest store directly. See the module documentation for the model this implements
/// and how it differs from [`crate::Reader`].
pub struct StoreReader {
    pub(crate) store: Arc<Store>,
    context: Arc<Context>,
    validation_status: Option<Vec<ValidationStatus>>,
    validation_results: Option<ValidationResults>,
}

impl StoreReader {
    /// Creates a `StoreReader` with no store loaded yet — call [`StoreReader::with_c2pa_data`],
    /// [`StoreReader::with_stream`], or [`StoreReader::with_manifest_data_and_stream`] next.
    pub fn new(context: Arc<Context>) -> Self {
        Self {
            store: Arc::new(Store::new()),
            context,
            validation_status: None,
            validation_results: None,
        }
    }

    /// Loads a manifest store from `c2pa_data` (JUMBF bytes) alone, with no asset stream.
    ///
    /// This verifies the provenance claim's signature and certificate trust chain, and checks
    /// the ingredient chain — everything the store validation does without asset bytes. It
    /// cannot verify the asset hash binding; use [`StoreReader::with_manifest_data_and_stream`]
    /// for that.
    #[async_generic]
    pub fn with_c2pa_data(self, c2pa_data: &[u8]) -> Result<Self> {
        let mut validation_log = StatusTracker::default();
        let store = Store::from_jumbf_with_context(c2pa_data, &mut validation_log, &self.context)?;
        if _sync {
            Store::verify_store(&store, None, &mut validation_log, &self.context)
        } else {
            Store::verify_store_async(&store, None, &mut validation_log, &self.context).await
        }?;
        self.finish(store, &validation_log)
    }

    /// Loads a manifest store from `stream`, and validates it against the stream's bytes
    /// (subject to the `verify.verify_after_reading` setting).
    ///
    /// # Arguments
    /// * `format` - The MIME type or file extension of the stream, used as a fallback when
    ///   content-based format detection cannot determine the format from the stream's leading
    ///   bytes.
    /// * `stream` - The stream to read from. Must implement the Read and Seek traits.
    #[async_generic]
    pub fn with_stream(
        self,
        format: &str,
        mut stream: impl Read + Seek + MaybeSend,
    ) -> Result<Self> {
        let mut validation_log = StatusTracker::default();
        stream.rewind()?;

        let format_owned = jumbf_io::format_from_stream(format, &mut stream);
        let format = format_owned.as_str();

        let store = if _sync {
            Store::from_stream(format, stream, &mut validation_log, &self.context)
        } else {
            Store::from_stream_async(format, stream, &mut validation_log, &self.context).await
        }?;
        self.finish(store, &validation_log)
    }

    /// Loads a manifest store from `c2pa_data`, and validates it against `stream` (subject to
    /// the `verify.verify_after_reading` setting). Use this to validate a remote or sidecar
    /// manifest against the asset it describes.
    ///
    /// # Arguments
    /// * `c2pa_data` - A C2PA manifest store in JUMBF format.
    /// * `format` - The format of the stream.
    /// * `stream` - The stream to verify the store against.
    #[async_generic]
    pub fn with_manifest_data_and_stream(
        self,
        c2pa_data: &[u8],
        format: &str,
        stream: impl Read + Seek + MaybeSend,
    ) -> Result<Self> {
        let mut validation_log = StatusTracker::default();
        let store = if _sync {
            Store::from_manifest_data_and_stream(
                c2pa_data,
                format,
                stream,
                &mut validation_log,
                &self.context,
            )
        } else {
            Store::from_manifest_data_and_stream_async(
                c2pa_data,
                format,
                stream,
                &mut validation_log,
                &self.context,
            )
            .await
        }?;
        self.finish(store, &validation_log)
    }

    fn finish(mut self, store: Store, validation_log: &StatusTracker) -> Result<Self> {
        let validation_results = ValidationResults::from_store(&store, validation_log);
        self.validation_status = validation_results.validation_errors();
        self.validation_results = Some(validation_results);
        self.store = Arc::new(store);
        Ok(self)
    }

    /// Returns every claim in the store, in the order they were added.
    pub fn claims(&self) -> Vec<Claim> {
        self.store
            .claims()
            .into_iter()
            .map(claim_from_store)
            .collect()
    }

    /// Returns the claim labeled `label`, if it's in the store.
    pub fn get_claim(&self, label: &str) -> Option<Claim> {
        self.store.get_claim(label).map(claim_from_store)
    }

    /// Returns the label of the active (most recent) manifest in the store.
    pub fn provenance_label(&self) -> Option<String> {
        self.store.provenance_label()
    }

    /// Returns the active (most recent) claim in the store.
    pub fn active_claim(&self) -> Option<Claim> {
        self.store.provenance_claim().map(claim_from_store)
    }

    /// Returns if this `StoreReader` was loaded from an embedded manifest.
    pub fn is_embedded(&self) -> bool {
        self.store.is_embedded()
    }

    /// Returns the remote url of the manifest if this `StoreReader` obtained the manifest
    /// remotely.
    pub fn remote_url(&self) -> Option<&str> {
        self.store.remote_url()
    }

    /// Returns the assertion referenced by `uri` (a JUMBF assertion URI, e.g.
    /// `self#jumbf=/c2pa/<claim>/c2pa.assertions/<label>` or a URI relative to a claim already
    /// in this store).
    pub fn get_assertion(&self, uri: &str) -> Result<ClaimAssertion> {
        self.store
            .get_claim_assertion_from_uri(uri)
            .map(claim_assertion_from_store)
    }

    /// Get the [`ValidationStatus`] array of the manifest store if it exists.
    pub fn validation_status(&self) -> Option<&[ValidationStatus]> {
        self.validation_status.as_deref()
    }

    /// Get the [`ValidationResults`] map of the manifest store if it exists.
    pub fn validation_results(&self) -> Option<&ValidationResults> {
        self.validation_results.as_ref()
    }

    /// Get the [`ValidationState`] of the manifest store.
    pub fn validation_state(&self) -> ValidationState {
        if let Some(validation_results) = self.validation_results() {
            return validation_results.validation_state();
        }

        let verify_trust = self.context.settings().verify.verify_trust;
        match self.validation_status() {
            Some(status) => {
                let errs = status
                    .iter()
                    .any(|s| s.code() != crate::validation_status::SIGNING_CREDENTIAL_UNTRUSTED);
                if errs {
                    ValidationState::Invalid
                } else if verify_trust {
                    ValidationState::Trusted
                } else {
                    ValidationState::Valid
                }
            }
            None => {
                if verify_trust {
                    ValidationState::Trusted
                } else {
                    ValidationState::Valid
                }
            }
        }
    }

    /// Get the manifest store as a crJSON [`Value`](serde_json::Value).
    ///
    /// crJSON is a standardized JSON format for C2PA manifest data.
    pub fn to_crjson_value(&self) -> Result<Value> {
        crate::crjson::from_store(
            &self.store,
            self.provenance_label().as_deref(),
            self.validation_results(),
        )
    }

    /// Get the manifest store as a pretty-printed crJSON string.
    ///
    /// crJSON is a standardized JSON format for C2PA manifest data.
    /// Returns empty valid JSON `"{}"` if conversion or formatting fails.
    pub fn crjson(&self) -> String {
        self.crjson_checked().unwrap_or_else(|_| "{}".to_string())
    }

    /// Get the manifest store as a pretty-printed crJSON string, returning an error if it fails.
    ///
    /// crJSON is a standardized JSON format for C2PA manifest data.
    pub fn crjson_checked(&self) -> Result<String> {
        self.to_crjson_value()
            .and_then(|v| serde_json::to_string_pretty(&v).map_err(Error::JsonError))
    }
}

/// Copies one internal `claim::ClaimAssertion` (borrowed from the store) into an owned, public
/// [`ClaimAssertion`].
fn claim_assertion_from_store(ca: &crate::claim::ClaimAssertion) -> ClaimAssertion {
    let kind = match ca.assertion_type() {
        crate::claim::ClaimAssertionType::V1 => ClaimAssertionKind::V1,
        crate::claim::ClaimAssertionType::Created => ClaimAssertionKind::Created,
        crate::claim::ClaimAssertionType::Gathered => ClaimAssertionKind::Gathered,
    };
    ClaimAssertion::new(
        ca.label(),
        kind,
        ca.assertion().content_type().to_owned(),
        ca.assertion().data().to_owned(),
    )
}

/// Copies one internal `claim::Claim` (borrowed from the store) into an owned, public [`Claim`].
fn claim_from_store(claim: &crate::claim::Claim) -> Claim {
    let assertions = claim
        .claim_assertion_store()
        .iter()
        .map(claim_assertion_from_store)
        .collect();
    Claim::new(
        claim.label().to_owned(),
        claim.title().cloned(),
        claim.instance_id().to_owned(),
        claim.alg().to_owned(),
        claim.version(),
        assertions,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use std::io::Cursor;

    use super::*;
    use crate::{
        assertions::{c2pa_action, Action, Actions, BoxHash, DigitalSourceType},
        claim_assertion::ClaimAssertionBuilder,
        claim_builder::ClaimBuilder,
        jumbf_io,
        utils::test::test_context,
        ValidationState,
    };

    const TEST_IMAGE_CLEAN: &[u8] = include_bytes!("../tests/fixtures/IMG_0003.jpg");

    /// Signs a minimal manifest via `ClaimBuilder`, embeds it, and returns the embedded stream
    /// bytes alongside the raw signed JUMBF bytes (as `ClaimBuilder::sign` returns them).
    fn signed_asset() -> (Vec<u8>, Vec<u8>, Arc<Context>) {
        let context = Arc::new(test_context());
        let mut stream = Cursor::new(TEST_IMAGE_CLEAN);

        let mut claim_builder = ClaimBuilder::new(context.clone());
        claim_builder.set_title("Test StoreReader");

        // At least one c2pa.created/c2pa.opened action is required by spec.
        let action = Action::new(c2pa_action::CREATED).set_source_type(DigitalSourceType::Empty);
        claim_builder
            .add_gathered_assertion(
                ClaimAssertionBuilder::new(Actions::LABEL)
                    .with_assertion(&Actions::new().add_action(action))
                    .expect("with_assertion"),
            )
            .expect("add actions assertion");

        claim_builder
            .add_created_assertion(
                ClaimAssertionBuilder::new(BoxHash::LABEL).with_stream("image/jpeg", &mut stream),
            )
            .expect("set hard binding");
        let jumbf = claim_builder.sign().expect("sign");

        let mut embedded_stream = Cursor::new(Vec::new());
        jumbf_io::save_jumbf_to_stream("image/jpeg", &mut stream, &mut embedded_stream, &jumbf)
            .expect("save jumbf to stream");

        (embedded_stream.into_inner(), jumbf, context)
    }

    #[test]
    fn test_store_reader_with_stream() {
        let (embedded, _jumbf, context) = signed_asset();

        let store_reader = StoreReader::new(context)
            .with_stream("image/jpeg", Cursor::new(embedded))
            .expect("read signed asset");

        assert_eq!(store_reader.validation_state(), ValidationState::Trusted);
        assert!(store_reader.is_embedded());
        assert_eq!(store_reader.claims().len(), 1);

        let claim = store_reader.active_claim().expect("active claim");
        assert_eq!(claim.title(), Some("Test StoreReader"));

        let uri = crate::jumbf::labels::to_assertion_uri(claim.label(), BoxHash::LABEL);
        let assertion = store_reader.get_assertion(&uri).expect("get_assertion");
        assert_eq!(assertion.label(), BoxHash::LABEL);
        assert_eq!(assertion.content_type(), "application/cbor");
        let decoded: BoxHash = assertion.to_assertion().expect("decode BoxHash");
        assert!(!decoded.boxes.is_empty());

        let crjson = store_reader.to_crjson_value().expect("crjson");
        assert!(crjson.get("manifests").is_some());
    }

    #[test]
    fn test_store_reader_with_c2pa_data_no_stream() {
        let (_embedded, jumbf, context) = signed_asset();

        // No asset stream — can't check the hash binding, but claim/signature/trust
        // verification still runs.
        let store_reader = StoreReader::new(context)
            .with_c2pa_data(&jumbf)
            .expect("read c2pa_data only");

        assert!(!store_reader.is_embedded());
        assert_eq!(store_reader.claims().len(), 1);
        assert!(store_reader.active_claim().is_some());
    }

    #[test]
    fn test_store_reader_embedded_data_content_type_and_binary_roundtrip() {
        let context = Arc::new(test_context());
        let mut asset_stream = Cursor::new(TEST_IMAGE_CLEAN);
        let thumbnail_bytes = b"thumbnail bytes".to_vec();

        let mut claim_builder = ClaimBuilder::new(context.clone());
        let action = Action::new(c2pa_action::CREATED).set_source_type(DigitalSourceType::Empty);
        claim_builder
            .add_gathered_assertion(
                ClaimAssertionBuilder::new(Actions::LABEL)
                    .with_assertion(&Actions::new().add_action(action))
                    .expect("with_assertion"),
            )
            .expect("add actions assertion");
        claim_builder
            .add_gathered_assertion(
                ClaimAssertionBuilder::new("org.test.thumbnail")
                    .with_stream("jpg", &mut Cursor::new(thumbnail_bytes.clone()))
                    .with_content_type("image/jpeg"),
            )
            .expect("add embedded-data assertion");
        claim_builder
            .add_created_assertion(
                ClaimAssertionBuilder::new(BoxHash::LABEL)
                    .with_stream("image/jpeg", &mut asset_stream),
            )
            .expect("set hard binding");
        let jumbf = claim_builder.sign().expect("sign");

        let mut embedded_stream = Cursor::new(Vec::new());
        jumbf_io::save_jumbf_to_stream(
            "image/jpeg",
            &mut asset_stream,
            &mut embedded_stream,
            &jumbf,
        )
        .expect("save jumbf to stream");

        let store_reader = StoreReader::new(context)
            .with_stream("image/jpeg", Cursor::new(embedded_stream.into_inner()))
            .expect("read signed asset");

        let claim = store_reader.active_claim().expect("active claim");
        let uri = crate::jumbf::labels::to_assertion_uri(claim.label(), "org.test.thumbnail");
        let assertion = store_reader.get_assertion(&uri).expect("get_assertion");

        // The explicit with_content_type overrides the format_to_mime-derived guess.
        assert_eq!(assertion.content_type(), "image/jpeg");

        let mut out = Vec::new();
        let written = assertion
            .write_to_stream(&mut out)
            .expect("write_to_stream");
        assert_eq!(written, thumbnail_bytes.len());
        assert_eq!(out, thumbnail_bytes);
    }

    #[test]
    fn test_store_reader_get_assertion_not_found() {
        let (embedded, _jumbf, context) = signed_asset();
        let store_reader = StoreReader::new(context)
            .with_stream("image/jpeg", Cursor::new(embedded))
            .expect("read signed asset");

        assert!(store_reader
            .get_assertion("self#jumbf=/c2pa/nope/c2pa.assertions/nope")
            .is_err());
    }
}
