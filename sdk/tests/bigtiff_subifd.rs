// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing, this software is
// distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY
// KIND, either express or implied. See the LICENSE-MIT and LICENSE-APACHE
// files for the specific language governing permissions and limitations under
// each license.

//! A BigTIFF whose SubIFD entry holds 8-byte offsets (IFD8) must be read through
//! the public reader without a short-read error.

#![cfg(feature = "file_io")]

use std::path::Path;

use c2pa::Reader;

#[test]
fn bigtiff_subifd_array_reads_without_short_read() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bigtiff_subifd.tif");

    // The fixture carries no manifest, so the reader must reach the end of the
    // file and report the missing manifest, not fail while parsing the SubIFDs.
    let err = Reader::default()
        .with_file(&path)
        .err()
        .expect("fixture has no manifest");
    assert_eq!(err.to_string(), "no JUMBF data found");
}
