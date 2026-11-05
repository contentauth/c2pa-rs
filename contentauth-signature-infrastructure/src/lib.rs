// Copyright 2026 Adobe. All rights reserved.
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

//! Experimental sans-I/O signature infrastructure.
//!
//! Currently provides host-driven RFC 3161 timestamp acquisition through
//! [`timestamp::acquisition`]. Acquisition returns unverified response bytes;
//! cryptographic verification, certificate-profile validation and trust
//! evaluation remain in the host SDK.
//!
//! Workflow APIs are scoped to their protocol modules, not re-exported at the
//! crate root:
//!
//! ```
//! use contentauth_signature_infrastructure::timestamp::acquisition::{
//!     acquire, AcquisitionWorkflow,
//! };
//! ```
//!
//! ```compile_fail
//! use contentauth_signature_infrastructure::{acquire, AcquisitionWorkflow};
//! ```
//!
//! Shared ASN.1 codecs and timestamp response helpers are private implementation
//! details:
//!
//! ```compile_fail
//! use contentauth_signature_infrastructure::asn1;
//! ```
//!
//! ```compile_fail
//! use contentauth_signature_infrastructure::timestamp::response;
//! ```
//!
//! The opt-in `sdk-compat` feature exposes a provisional bridge for legacy SDK
//! codec consumers while they migrate. It is not a stable public codec API and
//! does not confer cryptographic validity or trust on parsed values.

#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod timestamp;

mod asn1;

#[cfg(feature = "sdk-compat")]
pub mod sdk_compat;

#[cfg(test)]
mod tests;
