// Copyright 2024 Adobe. All rights reserved.
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

//! Integration tests for CrJsonReader output structure.
//! CrJSON format does not include asset_info, content, or metadata.

use c2pa::{CrJsonReader, Result};
use std::io::Cursor;

const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("../fixtures/CA.jpg");

#[test]
fn test_cr_json_omits_asset_info_content_metadata() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;

    let json_value = reader.to_json_value()?;

    // CrJSON does not include these top-level properties
    assert!(
        json_value.get("asset_info").is_none(),
        "asset_info should not be present in CrJSON output"
    );
    assert!(
        json_value.get("content").is_none(),
        "content should not be present in CrJSON output"
    );
    assert!(
        json_value.get("metadata").is_none(),
        "metadata should not be present in CrJSON output"
    );

    // Required CrJSON fields should still be present
    assert!(json_value.get("@context").is_some());
    assert!(json_value.get("manifests").is_some());

    Ok(())
}

#[test]
#[cfg(feature = "file_io")]
fn test_cr_json_from_file_omits_asset_info_content_metadata() -> Result<()> {
    let reader = CrJsonReader::from_file("tests/fixtures/CA.jpg")?;

    let json_value = reader.to_json_value()?;

    assert!(json_value.get("asset_info").is_none());
    assert!(json_value.get("content").is_none());
    assert!(json_value.get("metadata").is_none());
    assert!(json_value.get("@context").is_some());
    assert!(json_value.get("manifests").is_some());

    Ok(())
}
