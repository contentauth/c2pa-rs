// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("claim decoding: {0}")]
    ClaimDecoding(String),

    #[error("assertion encoding: {0}")]
    AssertionEncoding(String),

    #[error("assertion decoding: {0}")]
    AssertionDecoding(String),

    #[error(transparent)]
    CborError(#[from] c2pa_cbor::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
