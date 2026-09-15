// Copyright 2022 Adobe. All rights reserved.
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

pub mod boxes;
pub mod boxio;
pub mod labels;

/// True if `bytes` begin with a JUMBF superbox header:
/// a 4-byte length followed by the box type `jumb` at offset 4.
/// This does not validate the box body:
/// a truncated or malformed `jumb` box passes here and fails in the parser.
pub(crate) fn starts_with_superbox(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && &bytes[4..8] == b"jumb"
}

#[cfg(test)]
mod tests {
    use super::starts_with_superbox;

    #[test]
    fn recognizes_a_jumb_superbox_header() {
        // Length (4 bytes) then the `jumb` box type.
        assert!(starts_with_superbox(b"\x00\x00\x00\x1cjumb\x00\x00"));

        // A JPEG start-of-image marker is not a superbox.
        assert!(!starts_with_superbox(b"\xff\xd8\xff\xe0\x00\x10JF"));

        // Too short...
        assert!(!starts_with_superbox(b"jumb"));
    }
}
