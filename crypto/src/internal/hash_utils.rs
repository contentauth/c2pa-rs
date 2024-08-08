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

use multihash::Sha2_256;

/// Return a SHA-256 hash of array of bytes.
pub(crate) fn hash_sha256(data: &[u8]) -> Vec<u8> {
    let mh = Sha2_256::digest(data);
    let digest = mh.digest();

    digest.to_vec()
}

/// Return a SHA-1 hash of array of bytes.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn hash_sha1(data: &[u8]) -> Vec<u8> {
    let mh = multihash::Sha1::digest(data);
    let digest = mh.digest();
    digest.to_vec()
}
