// Copyright 2025 Adobe. All rights reserved.
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

// Portions derived from serde_cbor (https://github.com/pyfisch/cbor)

//! Compatibility layer for serde_cbor API
//!
//! This module provides a thin compatibility layer matching serde_cbor's API.
//! All functions and types are just re-exports or aliases to the core API.

use serde::Serialize;

use crate::Error;
/// Serialize to Vec
///
/// This is an alias for [`crate::to_vec`]
pub use crate::to_vec;
/// Write to writer
///
/// This is an alias for [`crate::to_writer`]
pub use crate::to_writer;

/// Serialize to Vec with packed/canonical encoding (definite-length only)
///
/// Note: This is currently identical to [`to_vec`] since we always produce
/// deterministic, definite-length CBOR output.
#[inline]
pub fn to_vec_packed<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    crate::to_vec(value)
}

/// A serializer for CBOR encoding
///
/// This is a type alias for [`crate::Encoder`]. The Encoder already implements
/// `serde::Serializer`, so no wrapper is needed.
pub type Serializer<W> = crate::Encoder<W>;
