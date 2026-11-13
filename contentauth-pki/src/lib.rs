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

//! Experimental sans-I/O public key infrastructure (PKI) workflows.
//!
//! Signature workflows driven by your application. The crate describes the
//! external operations it needs; your host performs them using its own HTTP
//! client, runtime, credentials, and network policy.
//!
//! # Available workflows
//!
//! - **[Timestamp acquisition](timestamp::acquisition):** request an RFC 3161
//!   timestamp for a message, using a standard SHA-256 request or a customized
//!   request body. Supply a fresh nonce, execute the requested HTTP POST, and
//!   return its response to the workflow. See the module's host-driver example.
//! - **[Timestamp verification](timestamp::verification):** parse a response or
//!   bare CMS token, authenticate signer facts, then verify its message imprint.
//!   These are deterministic functions, not suspended workflows. Certificate
//!   policy selection, trust and acceptance remain host decisions.
//! - **[X.509 mechanics](x509):** certificate signatures, explicit profile
//!   constraints and chain evaluation against host-selected anchors and time.
//!   Signature verification, profile validity and anchor association are distinct
//!   outcomes; none alone grants application trust.
//!
//! # Driving a workflow
//!
//! Workflows use `contentauth-sans-io-core`: advance until an operation needs
//! host input, fulfill that operation with its result, then advance again.
//! On completion, consume the workflow to obtain its output. Your host controls
//! I/O, entropy, time inputs, timeout, retries, and cancellation; this crate does
//! not start network requests or require an executor.
//!
//! # What acquisition establishes
//!
//! Timestamp acquisition checks the HTTP envelope, response structure, and
//! reflected nonce, and returns the original, **unverified** response bytes.
//! It does not establish a correct message imprint, signature validity,
//! certificate-profile validity, or TSA trust. Use `timestamp::verification` for
//! cryptographic checks, then apply host profile/trust policy before acceptance.
//!
//! This crate is an unpublished experiment. Timestamp acquisition and cryptographic
//! verification and X.509 mechanics are provided. Application role/policy
//! selection, trust reporting, OCSP and COSE orchestration remain host-side.
//! COSE is supporting machinery, not a general-purpose COSE environment.

#![deny(missing_docs)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]

pub mod timestamp;
pub mod x509;

mod asn1;

#[cfg(feature = "sdk-compat")]
pub mod sdk_compat;
