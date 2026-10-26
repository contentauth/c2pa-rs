// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

//! Experimental RFC 3161 timestamp workflows.
//!
//! Currently implements acquisition only. Cryptographic verification and TSA
//! trust evaluation remain the caller's responsibility.
//!
//! ASN.1 codecs and response parsing are implementation details, not public modules:
//!
//! ```compile_fail
//! use contentauth_rfc3161::asn1;
//! ```
//!
//! ```compile_fail
//! use contentauth_rfc3161::response;
//! ```

#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod acquisition;

mod asn1;
mod response;

#[cfg(feature = "sdk-compat")]
pub mod sdk_compat;

pub use acquisition::{
    acquire, acquire_with_body, request_body, AcquisitionError, AcquisitionReply,
    AcquisitionRequest, AcquisitionWorkflow, UnverifiedTimeStampResponse, MAX_RESPONSE_BYTES,
};

#[cfg(test)]
mod tests;
