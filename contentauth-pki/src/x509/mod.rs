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

//! Deterministic X.509 mechanics, with host-selected time and policy.
//!
//! A profile-valid certificate is not signature-verified or trusted. An anchor
//! association establishes a path to the supplied anchors, not permission to
//! trust that anchor for a particular application role. The host selects roles,
//! composes EKU settings per anchor, handles private credentials, and reports
//! application-specific acceptance. No clock, network, or settings are consulted.
//!
//! ```rust
//! use std::collections::HashSet;
//!
//! use contentauth_pki::x509::{chain, profile, ParsedCertificate};
//!
//! fn check_host_selected_tsa(
//!     certificate: &[u8],
//!     ordered_chain: &[Vec<u8>],
//!     tsa_anchors: &[Vec<u8>],
//!     validation_time: i64,
//! ) -> Result<(), Box<dyn std::error::Error>> {
//!     let allowed = HashSet::new();
//!     let required = HashSet::from(["1.3.6.1.5.5.7.3.8".to_string()]);
//!
//!     let policy = profile::ProfilePolicy {
//!         allowed_ekus: &allowed,
//!         mandatory_ekus: &required,
//!         allow_email_protection_when_empty: true,
//!         allow_specialty_purposes: true,
//!         end_entity: true,
//!     };
//!
//!     let certificate = ParsedCertificate::from_der(certificate)?;
//!
//!     let profile_valid = policy.check_certificate(&certificate, validation_time)?;
//!
//!     let associated = chain::validate_chain_to_anchors(
//!         ordered_chain,
//!         profile_valid.certificate_der(),
//!         tsa_anchors,
//!         validation_time,
//!     )?;
//!
//!     // The host must still establish timestamp cryptography/message binding,
//!     // revocation and its own trust/acceptance policy.
//!     let _ = associated;
//!
//!     Ok(())
//! }
//! ```

pub mod chain;
pub mod profile;

pub(crate) mod certificate;

pub use certificate::ParsedCertificate;
