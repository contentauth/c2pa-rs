// Derived from
// https://github.com/spruceid/ssi/blob/ssi/v0.9.0/crates/dids/core/src/did.rs
// which was published under an Apache 2.0 license.

// Subsequent modifications are subject to license from Adobe
// as follows:

// Copyright 2024 Adobe. All rights reserved.
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

#![allow(unused)] // TEMPORARY

use std::{fmt, ops::Deref, str::FromStr, sync::LazyLock};

use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[allow(clippy::unwrap_used)]
static VALID_DID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^did:[a-z0-9]+:[A-Za-z0-9/.%#\?_-]+"#).unwrap());
// TO DO: Improve:
//  * handing of %xx encoding
//  * ? query handling
//  * # fragment handling
//  * path parsing

/// DID.
///
/// This type is unsized and used to represent borrowed DIDs. Use `DidBuf` for
/// owned DIDs.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Did<'a>(&'a str);

impl<'a> Did<'a> {
    /// Converts the input `data` to a DID.
    ///
    /// Fails if the data is not a DID according to the
    /// [DID Syntax](https://w3c.github.io/did-core/#did-syntax).
    pub fn new(data: &'a str) -> Result<Self, InvalidDid> {
        if Regex::is_match(&VALID_DID, data) {
            Ok(Self(data))
        } else {
            Err(InvalidDid(data.to_string()))
        }
    }

    pub unsafe fn new_unchecked(data: &'a str) -> Self {
        // UNSAFE because we aren't checking here to see if this is a DID.
        Self(data)
    }

    /// Returns the offset of the `:` byte just after the method name.
    #[allow(clippy::unwrap_used)]
    fn method_name_separator_offset(&self) -> usize {
        // SAFETY: We have validated that this is a well-formed DID already.
        self.0[5..].chars().position(|c| c == ':').unwrap() + 5
        // +5 and not +4 because the method name cannot be empty.
    }

    /// Returns the DID method name.
    pub fn method_name(&self) -> &str {
        &self.0[4..self.method_name_separator_offset()]
    }

    /// Returns the DID method specific identifier.
    pub fn method_specific_id(&self) -> &str {
        &self.0[self.method_name_separator_offset() + 1..]
    }

    /// Returns the DID without any fragment qualifier.
    pub fn split_fragment(self) -> (Self, Option<&'a str>) {
        // NOTE: Can replace with split_once when we move over to str.
        if let Some((primary, fragment)) = self.0.split_once('#') {
            // SAFETY: A known subset of an existing checked DID.
            let primary = unsafe { Self::new_unchecked(primary) };
            (primary, Some(fragment))
        } else {
            (self, None)
        }
    }
}

impl<'a> Deref for Did<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> PartialEq<DidBuf> for Did<'a> {
    fn eq(&self, other: &DidBuf) -> bool {
        self == &other.as_did()
    }
}

impl<'a> fmt::Display for Did<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Owned DID.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DidBuf(String);

impl DidBuf {
    pub fn new(data: String) -> Result<Self, InvalidDid> {
        if Regex::is_match(&VALID_DID, &data) {
            Ok(Self(data))
        } else {
            Err(InvalidDid(data))
        }
    }

    pub fn as_did(&self) -> Did {
        unsafe {
            // SAFETY: we validated the data in `Self::new`.
            Did::new_unchecked(&self.0)
        }
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    #[cfg(test)] // currently only used in test code
    pub fn into_uri(self) -> iref::UriBuf {
        unsafe { iref::UriBuf::new_unchecked(self.0.into_bytes()) }
    }
}

impl TryFrom<String> for DidBuf {
    type Error = InvalidDid;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        DidBuf::new(value)
    }
}

impl FromStr for DidBuf {
    type Err = InvalidDid;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_owned().try_into()
    }
}

impl fmt::Display for DidBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for DidBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialEq<str> for DidBuf {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<'a> PartialEq<&'a str> for DidBuf {
    fn eq(&self, other: &&'a str) -> bool {
        self.as_str() == *other
    }
}

impl<'a> PartialEq<Did<'a>> for DidBuf {
    fn eq(&self, other: &Did<'a>) -> bool {
        &self.as_did() == other
    }
}

impl PartialEq<&Did<'_>> for DidBuf {
    fn eq(&self, other: &&Did<'_>) -> bool {
        &self.as_did() == *other
    }
}

impl Serialize for DidBuf {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DidBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = DidBuf;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a DID")
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.try_into().map_err(|e| E::custom(e))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_string(v.to_string())
            }
        }

        deserializer.deserialize_string(Visitor)
    }
}

/// Error raised when a conversion to a DID fails.
#[derive(Debug, Error)]
#[error("invalid DID `{0}`")]
pub struct InvalidDid(pub String);
