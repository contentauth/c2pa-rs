// Copyright 2024 Adobe. All rights reserved.
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

//! This module provides functions for working with the [`SubtleCrypto`] library
//! typically available in web browser environments.
//!
//! It is only available when this crate is compiled for `wasm` architecture and
//! not `wasi` target.
//!
//! [`SubtleCrypto`]: https://rustwasm.github.io/wasm-bindgen/api/web_sys/struct.SubtleCrypto.html

pub mod validators;

mod window_or_worker;
pub use window_or_worker::{WasmCryptoError, WindowOrWorker};
