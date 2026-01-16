// Copyright 2023 Adobe. All rights reserved.
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

/// This module exports a C2PA library
// Declare foundational modules first
mod error;
mod ffi_handle_system;

// Then macros that depend on them
#[macro_use]
mod ffi_macros;

// Then everything else
mod c2pa_stream;
mod c_api;
#[cfg(feature = "file_io")]
mod json_api;
mod signer_info;

// Re-export handle system internals for macro use
pub use c2pa::{
    AsyncSigner, Builder, Error as C2paError, Reader, Result as C2paResult, Signer, SigningAlg,
};
pub use c2pa_stream::*;
pub use c_api::*;
pub use error::{Error, Result};
#[doc(hidden)]
pub use ffi_handle_system::{get_handles, handle_to_ptr, ptr_to_handle, Handle};
pub use signer_info::SignerInfo;
