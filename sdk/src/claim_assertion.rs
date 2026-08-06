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

//! Describes one assertion to add to a [`crate::ClaimBuilder`].
//!
//! [`ClaimAssertion`] is a builder: start with [`ClaimAssertion::new`] and a label, then attach
//! whichever of `with_json`/`with_stream`/`with_c2pa_data`/`with_exclusions` that label needs.
//! Nothing is validated or converted until the assertion is handed to
//! [`crate::ClaimBuilder::add_gathered_assertion`]/[`crate::ClaimBuilder::add_created_assertion`]
//! — that's also where it's interpreted using the `ClaimBuilder`'s own [`crate::Context`] (for
//! hard-binding hash generation and ingredient provenance reading).

use std::io::{Read, Seek};

use serde::Serialize;

use crate::{asset_io::CAIRead, error::Result, maybe_send_sync::MaybeSend, HashRange};

/// One assertion to add via [`crate::ClaimBuilder::add_gathered_assertion`]/
/// [`crate::ClaimBuilder::add_created_assertion`].
///
/// Which `with_*` calls are valid depends on `label`:
/// * `DataHash`/`BmffHash`/`BoxHash` labels require [`ClaimAssertion::with_stream`] (the asset to
///   hash) and accept [`ClaimAssertion::with_exclusions`] (`DataHash` only — the placeholder
///   region to exclude from hashing).
/// * [`crate::assertions::IngredientAssertion::LABEL`] requires [`ClaimAssertion::with_json`]
///   (the ingredient's own metadata) and accepts [`ClaimAssertion::with_stream`] (the
///   ingredient's own asset, to extract its provenance) plus [`ClaimAssertion::with_c2pa_data`]
///   (a sidecar/remote manifest for that asset, when its provenance isn't embedded in-band).
/// * Everything else takes [`ClaimAssertion::with_json`] (structured data — decoded into the
///   label's native schema if it's a known one, else wrapped generically) or
///   [`ClaimAssertion::with_stream`] (binary data, e.g. a thumbnail — wrapped in `EmbeddedData`).
pub struct ClaimAssertion<'a> {
    pub(crate) label: String,
    pub(crate) value: Option<c2pa_cbor::Value>,
    pub(crate) stream: Option<(String, &'a mut dyn CAIRead)>,
    pub(crate) c2pa_data: Option<Vec<u8>>,
    pub(crate) exclusions: Option<Vec<HashRange>>,
}

impl ClaimAssertion<'static> {
    /// Starts building an assertion under `label` (e.g.
    /// [`crate::assertions::Actions::LABEL`], [`crate::assertions::IngredientAssertion::LABEL`],
    /// `DataHash::LABEL`, or any custom reverse-domain label).
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: None,
            stream: None,
            c2pa_data: None,
            exclusions: None,
        }
    }
}

impl<'a> ClaimAssertion<'a> {
    /// Sets structured data for this assertion. If `label` matches a known assertion type, `data`
    /// is decoded into that concrete type so it's stored with its native schema; otherwise it's
    /// wrapped generically under `label`.
    pub fn with_json<T: Serialize>(mut self, data: &T) -> Result<Self> {
        self.value = Some(c2pa_cbor::value::to_value(data)?);
        Ok(self)
    }

    /// Attaches a stream to this assertion — the asset to hash (hard-binding labels), the asset
    /// to extract provenance from ([`crate::assertions::IngredientAssertion::LABEL`]), or raw
    /// binary content to store as-is (everything else). `format` is the stream's MIME type or
    /// file extension.
    pub fn with_stream<'b>(
        self,
        format: impl Into<String>,
        stream: &'b mut (impl Read + Seek + MaybeSend),
    ) -> ClaimAssertion<'b> {
        let stream: &'b mut dyn CAIRead = stream;
        ClaimAssertion {
            label: self.label,
            value: self.value,
            stream: Some((format.into(), stream)),
            c2pa_data: self.c2pa_data,
            exclusions: self.exclusions,
        }
    }

    /// Supplies the ingredient's manifest store directly (JUMBF bytes) instead of extracting it
    /// from the stream in-band — for a sidecar or remote manifest.
    /// [`crate::assertions::IngredientAssertion::LABEL`] only.
    pub fn with_c2pa_data(mut self, c2pa_data: Vec<u8>) -> Self {
        self.c2pa_data = Some(c2pa_data);
        self
    }

    /// Sets the byte ranges to exclude when hashing — the region where the caller embedded the
    /// manifest placeholder. `DataHash::LABEL` only.
    pub fn with_exclusions(mut self, exclusions: Vec<HashRange>) -> Self {
        self.exclusions = Some(exclusions);
        self
    }
}
