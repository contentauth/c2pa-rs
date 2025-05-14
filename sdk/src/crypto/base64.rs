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
