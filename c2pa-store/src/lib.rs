// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

//! `c2pa-store` — standalone C2PA manifest store with JUMBF I/O.
//!
//! Manages an ordered list of C2PA manifests (claims) and converts them
//! to and from raw JUMBF bytes. No asset streams, no file I/O, no sdk
//! dependency.

pub mod error;
pub mod io_utils;
pub mod jumbf;
pub mod store;

pub use c2pa_claim::{assertion::Assertion, Claim, ClaimGeneratorInfo, HashedUri};
pub use error::{Error, Result};
pub use store::Store;
