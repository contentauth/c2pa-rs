// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use thiserror::Error;

use crate::jumbf::boxes::JumbfParseError;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("JUMBF parse error: {0}")]
    Jumbf(#[from] JumbfParseError),

    #[error("claim error: {0}")]
    Claim(#[from] c2pa_claim::Error),

    #[error("claim CBOR not found in manifest")]
    ClaimMissing,

    #[error("unexpected block UUID: {0}")]
    UnexpectedBlockUuid(String),
}

pub type Result<T> = std::result::Result<T, Error>;
