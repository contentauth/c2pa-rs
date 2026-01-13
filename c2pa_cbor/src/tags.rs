use std::{fmt, io::Write, marker::PhantomData};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, Visitor},
};

use crate::{Encoder, Result, constants::*};

/// A tagged CBOR value
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Tagged<T> {
    /// The CBOR tag number (optional for compatibility)
    pub tag: Option<u64>,
    /// The tagged value
    pub value: T,
}

impl<T> Tagged<T> {
    /// Create a new tagged value
    pub fn new(tag: Option<u64>, value: T) -> Self {
        Tagged { tag, value }
    }
}

// Custom deserialization that handles both tagged CBOR values and plain values (e.g., from JSON)
impl<'de, T> Deserialize<'de> for Tagged<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TaggedVisitor<T> {
            marker: PhantomData<T>,
        }

        impl<'de, T> Visitor<'de> for TaggedVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = Tagged<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a tagged value or a plain value")
            }

            // Handle the case where we get a plain value (e.g., from JSON)
            // Just wrap it in Tagged with no tag
            fn visit_bool<E>(self, v: bool) -> std::result::Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::BoolDeserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::I64Deserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::U64Deserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_f64<E>(self, v: f64) -> std::result::Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::F64Deserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::StrDeserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_string<E>(self, v: String) -> std::result::Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::StringDeserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Tagged<T>, E>
            where
                E: de::Error,
            {
                T::deserialize(serde::de::value::BytesDeserializer::new(v))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_seq<A>(self, seq: A) -> std::result::Result<Tagged<T>, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                T::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
                    .map(|value| Tagged { tag: None, value })
            }

            fn visit_map<A>(self, map: A) -> std::result::Result<Tagged<T>, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                // Try to deserialize as a struct with tag and value fields
                // If that fails, deserialize as the inner type directly
                #[derive(Deserialize)]
                struct TaggedHelper<T> {
                    tag: Option<u64>,
                    value: T,
                }

                match TaggedHelper::deserialize(serde::de::value::MapAccessDeserializer::new(map)) {
                    Ok(helper) => Ok(Tagged {
                        tag: helper.tag,
                        value: helper.value,
                    }),
                    Err(_) => {
                        // If deserializing as TaggedHelper fails, try deserializing as T directly
                        Err(de::Error::custom(
                            "expected tagged value structure or plain value",
                        ))
                    }
                }
            }
        }

        deserializer.deserialize_any(TaggedVisitor {
            marker: PhantomData,
        })
    }
}

// Tagged value helpers
/// Encode a tagged value (tag number + content)
pub fn encode_tagged<W: Write, T: Serialize>(writer: &mut W, tag: u64, value: &T) -> Result<()> {
    let mut encoder = Encoder::new(writer);
    encoder.write_tag(tag)?;
    encoder.encode(value)?;
    Ok(())
}

/// Helper to encode a date/time string (tag 0)
pub fn encode_datetime_string<W: Write>(writer: &mut W, datetime: &str) -> Result<()> {
    encode_tagged(writer, TAG_DATETIME_STRING, &datetime)
}

/// Helper to encode an epoch timestamp (tag 1)
pub fn encode_epoch_datetime<W: Write>(writer: &mut W, epoch: i64) -> Result<()> {
    encode_tagged(writer, TAG_EPOCH_DATETIME, &epoch)
}

/// Helper to encode a URI (tag 32)
pub fn encode_uri<W: Write>(writer: &mut W, uri: &str) -> Result<()> {
    encode_tagged(writer, TAG_URI, &uri)
}

/// Helper to encode base64url data (tag 33)
pub fn encode_base64url<W: Write>(writer: &mut W, data: &str) -> Result<()> {
    encode_tagged(writer, TAG_BASE64URL, &data)
}

/// Helper to encode base64 data (tag 34)
pub fn encode_base64<W: Write>(writer: &mut W, data: &str) -> Result<()> {
    encode_tagged(writer, TAG_BASE64, &data)
}

// RFC 8746 - Typed array helpers

/// Helper to encode a uint8 array (tag 64)
pub fn encode_uint8_array<W: Write>(writer: &mut W, data: &[u8]) -> Result<()> {
    encode_tagged(writer, TAG_UINT8_ARRAY, &data)
}

// Macro to generate typed array encoding functions
macro_rules! define_typed_array_encoder {
    ($(#[$doc:meta] $name:ident, $tag:ident, $ty:ty, $to_bytes:ident);* $(;)?) => {
        $(
            #[$doc]
            pub fn $name<W: Write>(writer: &mut W, data: &[$ty]) -> Result<()> {
                let bytes: Vec<u8> = data.iter().flat_map(|&n| n.$to_bytes()).collect();
                encode_tagged(writer, $tag, &bytes)
            }
        )*
    };
}

define_typed_array_encoder! {
    /// Helper to encode a uint16 big-endian array (tag 65)
    encode_uint16be_array, TAG_UINT16BE_ARRAY, u16, to_be_bytes;
    /// Helper to encode a uint32 big-endian array (tag 66)
    encode_uint32be_array, TAG_UINT32BE_ARRAY, u32, to_be_bytes;
    /// Helper to encode a uint64 big-endian array (tag 67)
    encode_uint64be_array, TAG_UINT64BE_ARRAY, u64, to_be_bytes;
    /// Helper to encode a uint16 little-endian array (tag 69)
    encode_uint16le_array, TAG_UINT16LE_ARRAY, u16, to_le_bytes;
    /// Helper to encode a uint32 little-endian array (tag 70)
    encode_uint32le_array, TAG_UINT32LE_ARRAY, u32, to_le_bytes;
    /// Helper to encode a uint64 little-endian array (tag 71)
    encode_uint64le_array, TAG_UINT64LE_ARRAY, u64, to_le_bytes;
    /// Helper to encode a float32 big-endian array (tag 81)
    encode_float32be_array, TAG_FLOAT32BE_ARRAY, f32, to_be_bytes;
    /// Helper to encode a float64 big-endian array (tag 82)
    encode_float64be_array, TAG_FLOAT64BE_ARRAY, f64, to_be_bytes;
    /// Helper to encode a float32 little-endian array (tag 85)
    encode_float32le_array, TAG_FLOAT32LE_ARRAY, f32, to_le_bytes;
    /// Helper to encode a float64 little-endian array (tag 86)
    encode_float64le_array, TAG_FLOAT64LE_ARRAY, f64, to_le_bytes;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tagged_deserialize_from_json_string() {
        // From JSON: plain string should deserialize to Tagged with no tag
        let json = r#""https://example.com""#;
        let tagged: Tagged<String> = serde_json::from_str(json).unwrap();

        assert_eq!(tagged.tag, None);
        assert_eq!(tagged.value, "https://example.com");
    }

    #[test]
    fn test_tagged_deserialize_from_json_object() {
        // From JSON: object with tag and value fields
        let json = r#"{"tag": 32, "value": "https://example.com"}"#;
        let tagged: Tagged<String> = serde_json::from_str(json).unwrap();

        assert_eq!(tagged.tag, Some(32));
        assert_eq!(tagged.value, "https://example.com");
    }

    #[test]
    fn test_tagged_deserialize_from_cbor() {
        // From CBOR: should handle both tagged and untagged
        let tagged_original = Tagged::new(Some(32), "https://example.com".to_string());
        let cbor = crate::to_vec(&tagged_original).unwrap();
        let tagged_decoded: Tagged<String> = crate::from_slice(&cbor).unwrap();

        assert_eq!(tagged_decoded.tag, Some(32));
        assert_eq!(tagged_decoded.value, "https://example.com");
    }

    #[test]
    fn test_tagged_deserialize_plain_number() {
        // From JSON: plain number
        let json = r#"42"#;
        let tagged: Tagged<u32> = serde_json::from_str(json).unwrap();

        assert_eq!(tagged.tag, None);
        assert_eq!(tagged.value, 42);
    }
}
