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

/// True if `bytes` begin with a JUMBF superbox header: a 4-byte length followed
/// by the box type `jumb` at offset 4. Does not validate the box body.
/// A truncated or malformed `jumb` box passes here and fails later in the parser.
pub(crate) fn starts_with_superbox(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && &bytes[4..8] == b"jumb"
}
