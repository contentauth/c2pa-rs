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

pub(crate) mod cbor_types;
#[allow(dead_code)]
pub(crate) mod hash_utils;
#[allow(dead_code)] // for wasm build
pub(crate) mod patch;
#[cfg(all(feature = "add_thumbnails", any(feature = "file_io", feature = "sign")))]
pub(crate) mod thumbnail;
pub(crate) mod time_it;
#[allow(dead_code)] // for wasm builds
pub(crate) mod xmp_inmemory_utils;
// shared unit testing utilities
#[cfg(test)]
#[allow(dead_code)] // for wasm build
pub mod test;
