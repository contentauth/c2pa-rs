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

//! This module provides functions for working with the [`openssl` native code
//! library].
//!
//! It is only available if the `openssl` feature is enabled.
//!
//! [`openssl` native code library]: https://crates.io/crates/openssl

mod cert_chain;

mod ffi_mutex;
pub use ffi_mutex::{OpenSslMutex, OpenSslMutexUnavailable};

pub mod signers;
pub mod validators;
