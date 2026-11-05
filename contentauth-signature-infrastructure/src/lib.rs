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
//! The first layer implements RFC 3161 acquisition, not cryptographic
//! verification, certificate-profile validation or trust evaluation.
//!
//! Codecs are private implementation details:
//!
//! ```compile_fail
//! use contentauth_signature_infrastructure::asn1;
//! ```
//!
//! ```compile_fail
//! use contentauth_signature_infrastructure::response;
//! ```
//!
//! ```compile_fail
//! use contentauth_signature_infrastructure::timestamp::response;
//! ```
//!
//! Workflow APIs remain scoped to their modules:
//!
//! ```compile_fail
//! use contentauth_signature_infrastructure::{acquire, AcquisitionWorkflow};
//! ```

#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod timestamp;

mod asn1;

#[cfg(feature = "sdk-compat")]
pub mod sdk_compat;

#[cfg(test)]
mod tests;
