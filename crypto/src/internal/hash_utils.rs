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

use sha2::{Digest, Sha256};

/// Return a SHA-256 hash of array of bytes.
pub(crate) fn hash_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Return a SHA-1 hash of array of bytes.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn hash_sha1(data: &[u8]) -> Vec<u8> {
    use sha1::Sha1;

    // create a Sha1 object
    let mut hasher = Sha1::new();

    // process input message
    hasher.update(data);

    // acquire hash digest in the form of GenericArray,
    // which in this case is equivalent to [u8; 20]
    hasher.finalize().to_vec()
}
