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

//! Hash convenience functions.

use sha1::{Digest, Sha1};

/// Given a byte slice, return the SHA-1 hash of that content.
pub fn sha1(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::default();
    hasher.update(data);
    hasher.finalize().to_vec()
}
