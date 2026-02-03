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

use c2pa_cbor::tags::Tagged;
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};
use serde_bytes::ByteBuf;

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

#[allow(dead_code)]
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

// Convert map member to concrete value.  mp must be a Value::Map, key is the value of
// the map you would like to extract
pub(crate) fn map_cbor_to_type<T: serde::de::DeserializeOwned>(
    key: &str,
    mp: &c2pa_cbor::Value,
) -> Option<T> {
    if let c2pa_cbor::Value::Map(m) = mp {
        let k = c2pa_cbor::Value::Text(key.to_string());
        let v = m.get(&k)?;
        let v_bytes = c2pa_cbor::ser::to_vec(v).ok()?;
        let output: T = c2pa_cbor::from_slice(&v_bytes).ok()?;
        Some(output)
    } else {
        None
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    // DateT tests (CBOR tag 0)
    #[test]
    fn test_date_t_serialization_has_tag_0() {
        let date = DateT("2024-01-30T12:00:00Z".into());
        let cbor_bytes = c2pa_cbor::ser::to_vec(&date).expect("should serialize");

        // Use from_tagged_slice to explicitly check the tag
        let tagged = Tagged::<String>::from_tagged_slice(&cbor_bytes).expect("should deserialize");
        assert_eq!(tagged.tag, Some(0), "DateT should use CBOR tag 0");
        assert_eq!(tagged.value, "2024-01-30T12:00:00Z");
    }

    #[test]
    fn test_date_t_deserialization_with_tag() {
        let date_str = "2024-01-30T12:00:00Z";
        let tagged = Tagged::new(Some(0), date_str);
        let cbor_bytes = c2pa_cbor::ser::to_vec(&tagged).unwrap();

        let date: DateT = c2pa_cbor::from_slice(&cbor_bytes).expect("should deserialize");
        assert_eq!(date.0, date_str);
    }

    #[test]
    fn test_date_t_deserialization_without_tag() {
        let date_str = "2024-01-30T12:00:00Z";
        let cbor_bytes = c2pa_cbor::ser::to_vec(&date_str.to_string()).unwrap();

        let date: DateT = c2pa_cbor::from_slice(&cbor_bytes).expect("should deserialize");
        assert_eq!(date.0, date_str);
    }

    // UriT tests (CBOR tag 32)
    #[test]
    fn test_uri_t_serialization_has_tag_32() {
        let uri = UriT("https://example.com/test".into());
        let cbor_bytes = c2pa_cbor::ser::to_vec(&uri).expect("should serialize");

        // Use from_tagged_slice to explicitly check the tag
        let tagged = Tagged::<String>::from_tagged_slice(&cbor_bytes).expect("should deserialize");
        assert_eq!(tagged.tag, Some(32), "UriT should use CBOR tag 32");
        assert_eq!(tagged.value, "https://example.com/test");
    }

    #[test]
    fn test_uri_t_round_trip() {
        let uri = UriT("https://example.com/test".into());
        let cbor_bytes = c2pa_cbor::ser::to_vec(&uri).expect("should serialize");
        let uri_restored: UriT = c2pa_cbor::from_slice(&cbor_bytes).expect("should deserialize");
        assert_eq!(uri.0, uri_restored.0);
    }

    // BytesT tests (CBOR tag 64)
    #[test]
    fn test_bytes_t_serialization_has_tag_64() {
        let bytes = BytesT(vec![0x01, 0x02, 0x03, 0x04]);
        let cbor_bytes = c2pa_cbor::ser::to_vec(&bytes).expect("should serialize");

        // Use from_tagged_slice to explicitly check the tag
        let tagged = Tagged::<ByteBuf>::from_tagged_slice(&cbor_bytes).expect("should deserialize");
        assert_eq!(tagged.tag, Some(64), "BytesT should use CBOR tag 64");
        assert_eq!(tagged.value.to_vec(), vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_bytes_t_round_trip() {
        let bytes = BytesT(vec![0x01, 0x02, 0x03, 0x04, 0xff, 0x00]);
        let cbor_bytes = c2pa_cbor::ser::to_vec(&bytes).expect("should serialize");
        let bytes_restored: BytesT =
            c2pa_cbor::from_slice(&cbor_bytes).expect("should deserialize");
        assert_eq!(bytes.0, bytes_restored.0);
    }
}
