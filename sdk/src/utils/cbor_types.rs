// Copyright 2022 Adobe. All rights reserved.
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

use std::{fmt, ops::Deref};

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};
use serde_bytes::ByteBuf;
use serde_cbor::tags::Tagged;

// New types for C2PA that will serialize to the correct
// CBOR type specified in the C2PA spec.
//
// Based on samples from cbor rust git repository.
//
// https://tools.ietf.org/html/rfc7049#section-2.4.1
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct DateT(pub String);

impl Serialize for DateT {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        Tagged::new(Some(0), &self.0).serialize(s)
    }
}

impl<'de> Deserialize<'de> for DateT {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let tagged = Tagged::<String>::deserialize(deserializer)?;
        match tagged.tag {
            Some(0) | None => Ok(DateT(tagged.value)),
            Some(_) => Err(serde::de::Error::custom("unexpected tag")),
        }
    }
}

impl AsRef<str> for DateT {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for DateT {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl fmt::Display for DateT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// https://tools.ietf.org/html/rfc7049#section-2.4.4.3
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UriT(pub String);

impl Serialize for UriT {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        Tagged::new(Some(32), &self.0).serialize(s)
    }
}
impl<'de> Deserialize<'de> for UriT {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let tagged = Tagged::<String>::deserialize(deserializer)?;
        match tagged.tag {
            // allow deserialization even if there is no tag. Allows roundtrip via other formats such as json
            Some(32) | None => Ok(UriT(tagged.value)),
            Some(_) => Err(serde::de::Error::custom("unexpected tag")),
        }
    }
}

impl AsRef<str> for UriT {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UriT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BytesT(pub Vec<u8>);

impl Serialize for BytesT {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        Tagged::new(Some(64), &ByteBuf::from(self.0.clone())).serialize(s)
    }
}

impl<'de> Deserialize<'de> for BytesT {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let tagged = Tagged::<ByteBuf>::deserialize(deserializer)?;
        match tagged.tag {
            Some(64) | None => Ok(BytesT(tagged.value.to_vec())),
            Some(_) => Err(serde::de::Error::custom("unexpected tag")),
        }
    }
}

impl AsRef<Vec<u8>> for BytesT {
    fn as_ref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl std::ops::Deref for BytesT {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for BytesT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            format!("{:02x?}", &self.0.to_vec()).replace(',', "")
        )
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_round_trip() {
        let uri = UriT("Some data value".into());

        let uri_cbor = serde_cbor::ser::to_vec(&uri).expect("should serialize");

        let uri_restored: UriT = serde_cbor::from_slice(&uri_cbor).expect("should deserialize");

        assert_eq!(uri.as_ref(), uri_restored.as_ref());
    }
}
