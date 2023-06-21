// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/*! Holds Rust struct definitions for various ASN.1 primitives. */

// This code is copied from a subset of version 0.22.0 of the
// cryptographic-message-syntax crate located at:
// https://github.com/indygreg/cryptography-rs/tree/main/cryptographic-message-syntax/src/asn1

// We can not incorporate the entire crate directly because other parts of the
// crate contain dependencies on blocking calls in reqwest. Those calls are not
// available in WASM environment.

pub mod rfc3161;
pub mod rfc3281;
pub mod rfc4210;
pub mod rfc5652;
