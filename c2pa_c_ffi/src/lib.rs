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
mod c2pa_stream;
#[macro_use]
mod cimpl;
mod c_api;
mod error;
#[cfg(feature = "file_io")]
mod json_api;
mod signer_info;

pub use c2pa::{
    AsyncSigner, Builder, Error as C2paError, Reader, Result as C2paResult, Signer, SigningAlg,
};
pub use c2pa_stream::*;
pub use c_api::*;
// Re-export for macro use
#[doc(hidden)]
pub use cimpl::cimpl_error::CimplError;
pub use cimpl::*;
pub use error::{Error, Result};
pub use signer_info::SignerInfo;
