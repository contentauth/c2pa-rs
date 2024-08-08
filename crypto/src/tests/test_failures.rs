// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for thema
// specific language governing permissions and limitations under
// each license.

mod common;
use c2pa::{Reader, Result};
use common::fixture_stream;

#[test]
fn test_reader_ts_changed() -> Result<()> {
    let (format, mut stream) = fixture_stream("CA_ct.jpg")?;
    let reader = Reader::from_stream(&format, &mut stream).unwrap();

    let vl = reader.validation_status().unwrap();

    assert!(!vl.is_empty());
    Ok(())
}
