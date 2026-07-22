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

//! Shared helpers for the native C2PA text handlers: bounded read, the
//! `c2pa.hash.data` object layout, and A.9 ASCII-armour / `data:` URI encoding.

use crate::{
    asset_io::{CAIRead, HashBlockObjectType, HashObjectPositions},
    crypto::base64,
    error::{Error, Result},
    utils::io_utils::{stream_len, ReaderUtils},
};

/// `c2pa.hash.data` layout: excluded manifest region, plus content before/after.
pub(crate) fn hash_positions(
    full_len: usize,
    region_start: usize,
    region_len: usize,
) -> Vec<HashObjectPositions> {
    let region_end = region_start + region_len;
    vec![
        HashObjectPositions {
            offset: region_start,
            length: region_len,
            htype: HashBlockObjectType::Cai,
        },
        HashObjectPositions {
            offset: 0,
            length: region_start,
            htype: HashBlockObjectType::Other,
        },
        HashObjectPositions {
            offset: region_end,
            length: full_len.saturating_sub(region_end),
            htype: HashBlockObjectType::Other,
        },
    ]
}

/// Reads a text asset into a `String` with a bounded allocation (no OOM on a huge stream).
pub(crate) fn read_text_stream(mut reader: &mut dyn CAIRead) -> Result<String> {
    reader.rewind()?;
    let len = stream_len(reader)?;
    let bytes = reader.read_to_vec(len)?;
    String::from_utf8(bytes)
        .map_err(|_| Error::InvalidAsset("text asset is not valid UTF-8".to_string()))
}

pub(crate) const BEGIN_DELIMITER: &str = "-----BEGIN C2PA MANIFEST-----";
pub(crate) const END_DELIMITER: &str = "-----END C2PA MANIFEST-----";
pub(crate) const DATA_URI_PREFIX: &str = "data:application/c2pa;base64,";

pub(crate) fn encode_data_uri(store_bytes: &[u8]) -> String {
    format!("{DATA_URI_PREFIX}{}", base64::encode(store_bytes))
}

pub(crate) enum ManifestReference {
    Embedded(Vec<u8>),
    /// External reference; handlers treat it as no embedded store.
    External,
}

pub(crate) fn parse_manifest_reference(reference: &str) -> Result<ManifestReference> {
    let reference = reference.trim();
    match reference.strip_prefix(DATA_URI_PREFIX) {
        Some(b64) => {
            let bytes = base64::decode(b64.trim())
                .map_err(|_| Error::InvalidAsset("invalid base64 in c2pa data URI".into()))?;
            Ok(ManifestReference::Embedded(bytes))
        }
        None => Ok(ManifestReference::External),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn data_uri_round_trip_and_external() {
        let store = b"\x00\x01\x02manifest";
        let uri = encode_data_uri(store);
        assert!(uri.starts_with(DATA_URI_PREFIX));
        match parse_manifest_reference(&uri).unwrap() {
            ManifestReference::Embedded(b) => assert_eq!(b, store),
            ManifestReference::External => panic!("expected embedded"),
        }
        match parse_manifest_reference("https://example.com/a.c2pa").unwrap() {
            ManifestReference::External => {}
            ManifestReference::Embedded(_) => panic!("expected external"),
        }
    }
}
