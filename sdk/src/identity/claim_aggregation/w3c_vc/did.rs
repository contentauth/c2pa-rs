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

impl Deref for Did<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl PartialEq<DidBuf> for Did<'_> {
    fn eq(&self, other: &DidBuf) -> bool {
        self == &other.as_did()
    }
}

impl fmt::Display for Did<'_> {
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

        impl serde::de::Visitor<'_> for Visitor {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    mod did {
        mod new {
            #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
            use wasm_bindgen_test::wasm_bindgen_test;

            use crate::identity::claim_aggregation::w3c_vc::did::Did;

            #[test]
            #[cfg_attr(
                all(target_arch = "wasm32", not(target_os = "wasi")),
                wasm_bindgen_test
            )]
            fn valid_dids() {
                let did = Did::new("did:method:foo").unwrap();
                assert_eq!(did.method_name(), "method");
                assert_eq!(did.method_specific_id(), "foo");

                let did = Did::new("did:a:b").unwrap();
                assert_eq!(did.method_name(), "a");
                assert_eq!(did.method_specific_id(), "b");

                let did = Did::new("did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9").unwrap();
                assert_eq!(did.method_name(), "jwk");
                assert_eq!(did.method_specific_id(), "eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9");

                let did = Did::new("did:web:example.com%3A443:u:bob").unwrap();
                assert_eq!(did.method_name(), "web");
                assert_eq!(did.method_specific_id(), "example.com%3A443:u:bob");
            }

            #[test]
            #[cfg_attr(
                all(target_arch = "wasm32", not(target_os = "wasi")),
                wasm_bindgen_test
            )]
            fn err_invalid_did() {
                Did::new("http:a:b").unwrap_err();
                Did::new("did::b").unwrap_err();
                Did::new("did:a:").unwrap_err();
            }
        }

        mod split_fragment {
            #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
            use wasm_bindgen_test::wasm_bindgen_test;

            use crate::identity::claim_aggregation::w3c_vc::did::Did;

            #[test]
            #[cfg_attr(
                all(target_arch = "wasm32", not(target_os = "wasi")),
                wasm_bindgen_test
            )]
            fn has_fragment() {
                let did = Did::new("did:method:foo#bar").unwrap();
                assert_eq!(did.method_name(), "method");
                assert_eq!(did.method_specific_id(), "foo#bar");

                let did_without_fragment = Did::new("did:method:foo").unwrap();
                let fragment: &str = "bar";
                assert_eq!(did.split_fragment(), (did_without_fragment, Some(fragment)));
            }

            #[test]
            #[cfg_attr(
                all(target_arch = "wasm32", not(target_os = "wasi")),
                wasm_bindgen_test
            )]
            fn no_fragment() {
                let did = Did::new("did:method:foo").unwrap();
                let did2 = Did::new("did:method:foo").unwrap();
                assert_eq!(did.split_fragment(), (did2, None));
            }
        }
    }

    mod did_buf {
        mod new {
            #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
            use wasm_bindgen_test::wasm_bindgen_test;

            use crate::identity::claim_aggregation::w3c_vc::did::DidBuf;

            #[test]
            #[cfg_attr(
                all(target_arch = "wasm32", not(target_os = "wasi")),
                wasm_bindgen_test
            )]
            fn valid_dids() {
                let did = DidBuf::new("did:method:foo".to_string()).unwrap();
                let did = did.as_did();
                assert_eq!(did.method_name(), "method");
                assert_eq!(did.method_specific_id(), "foo");

                let did = DidBuf::new("did:a:b".to_string()).unwrap();
                let did = did.as_did();
                assert_eq!(did.method_name(), "a");
                assert_eq!(did.method_specific_id(), "b");

                let did = DidBuf::new("did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9".to_string()).unwrap();
                let did = did.as_did();
                assert_eq!(did.method_name(), "jwk");
                assert_eq!(did.method_specific_id(), "eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9");

                let did = DidBuf::new("did:web:example.com%3A443:u:bob".to_string()).unwrap();
                let did = did.as_did();
                assert_eq!(did.method_name(), "web");
                assert_eq!(did.method_specific_id(), "example.com%3A443:u:bob");
            }

            #[test]
            #[cfg_attr(
                all(target_arch = "wasm32", not(target_os = "wasi")),
                wasm_bindgen_test
            )]
            fn err_invalid_did() {
                DidBuf::new("http:a:b".to_string()).unwrap_err();
                DidBuf::new("did::b".to_string()).unwrap_err();
                DidBuf::new("did:a:".to_string()).unwrap_err();
            }
        }

        mod impl_serde {
            #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
            use wasm_bindgen_test::wasm_bindgen_test;

            use crate::identity::claim_aggregation::w3c_vc::did::DidBuf;

            #[derive(serde::Serialize, serde::Deserialize)]
            struct Sample {
                did: DidBuf,
            }

            const SAMPLE_WITH_DID: &str = r#"{"did":"did:method:foo"}"#;
            const SAMPLE_WITH_BAD_DID: &str = r#"{"did": "did::b"}"#;

            #[test]
            #[cfg_attr(
                all(target_arch = "wasm32", not(target_os = "wasi")),
                wasm_bindgen_test
            )]
            fn from_json() {
                let s: Sample = serde_json::from_str(SAMPLE_WITH_DID).unwrap();
                let did = s.did;
                let did = did.as_did();
                assert_eq!(did.method_name(), "method");
                assert_eq!(did.method_specific_id(), "foo");
            }

            #[test]
            #[cfg_attr(
                all(target_arch = "wasm32", not(target_os = "wasi")),
                wasm_bindgen_test
            )]
            #[should_panic]
            fn from_json_err_invalid_did() {
                let _: Sample = serde_json::from_str(SAMPLE_WITH_BAD_DID).unwrap();
            }

            #[test]
            #[cfg_attr(
                all(target_arch = "wasm32", not(target_os = "wasi")),
                wasm_bindgen_test
            )]
            fn to_json() {
                let s = Sample {
                    did: DidBuf::new("did:method:foo".to_string()).unwrap(),
                };
                let json = serde_json::to_string(&s).unwrap();
                assert_eq!(&json, SAMPLE_WITH_DID);
            }
        }
    }
}
