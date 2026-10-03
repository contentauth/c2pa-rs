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
pub use c2pa::{
    AsyncSigner, Builder, Error as C2paError, Reader, Result as C2paResult, Signer, SigningAlg,
};

mod c2pa_stream;
mod c_api;
mod error;
mod macros;
mod maybe_send_sync;
mod signer_info;

pub use c2pa_stream::*;
pub use c_api::*;
pub use cimpl::{
    checkout_exclusive, checkout_shared, cimpl_free, is_safe_buffer_size,
    safe_slice_from_raw_parts, to_c_bytes, to_c_string, track_arc, track_arc_mutex, track_box,
    untrack_owned, untrack_owned_pair, CimplError, ExclusiveCheckout, SharedCheckout,
    TypedExclusive, TypedShared,
};
pub use error::{Error, Result};
pub use signer_info::SignerInfo;
