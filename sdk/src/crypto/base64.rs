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

//! Base64 convenience functions.

use ::base64::{engine::general_purpose, DecodeError, Engine as _};

/// Encode a byte slice to Base64 string using general encoding without padding.
pub fn encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Decode a Base 64 string into a byte slice.
pub fn decode(data: &str) -> Result<Vec<u8>, DecodeError> {
    general_purpose::STANDARD.decode(data)
}

/// Encode a byte slice into a crJSON `b64'<base64>'`-wrapped string.
pub fn encode_b64_wrapped(data: &[u8]) -> String {
    format!("b64'{}'", encode(data))
}

/// Decode a crJSON `b64'<base64>'`-wrapped string back into raw bytes.
///
/// Returns `None` if `value` isn't wrapped in the `b64'...'` delimiters (e.g. it's
/// an ordinary string), so callers can tell "not base64" apart from "malformed base64".
pub fn decode_b64_wrapped(value: &str) -> Option<Vec<u8>> {
    let inner = value.strip_prefix("b64'")?.strip_suffix('\'')?;
    decode(inner).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::crypto::base64;

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn encode() {
        assert_eq!(base64::encode(b"Hello, world"), "SGVsbG8sIHdvcmxk");
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn decode() {
        assert_eq!(
            base64::decode("SGVsbG8sIHdvcmxk"),
            Ok(b"Hello, world".to_vec())
        );
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn encode_b64_wrapped() {
        assert_eq!(
            base64::encode_b64_wrapped(b"Hello, world"),
            "b64'SGVsbG8sIHdvcmxk'"
        );
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn decode_b64_wrapped_roundtrip() {
        let wrapped = base64::encode_b64_wrapped(b"Hello, world");
        assert_eq!(
            base64::decode_b64_wrapped(&wrapped),
            Some(b"Hello, world".to_vec())
        );
        assert_eq!(base64::decode_b64_wrapped("not wrapped"), None);
    }
}
