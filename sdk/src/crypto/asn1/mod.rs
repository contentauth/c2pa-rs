// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(missing_docs)]

//! Holds Rust struct definitions for various ASN.1 primitives.

// This code is copied from a subset of version 0.22.0 of the
// cryptographic-message-syntax crate located at:
// https://github.com/indygreg/cryptography-rs/tree/main/cryptographic-message-syntax/src/asn1

#[allow(dead_code)]
pub mod rfc3161;
#[allow(dead_code)]
pub mod rfc3281;
#[allow(dead_code)]
pub mod rfc4210;
#[allow(dead_code)]
pub mod rfc5652;
