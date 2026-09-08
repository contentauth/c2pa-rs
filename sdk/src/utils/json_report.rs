// Copyright 2026 Adobe. All rights reserved.
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

//! JSON reporting that distinguishes byte strings from numeric arrays.

use std::fmt;

use serde::{
    de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
    ser, Deserializer, Serialize,
};
use serde_json::Value;

use crate::crypto::base64;

/// Serialize bytes as base64 while preserving ordinary sequences, including
/// sequences of integers in the byte range. This is only for report output.
pub(crate) fn to_value<T: ?Sized + Serialize>(value: &T) -> serde_json::Result<Value> {
    serde_json::to_value(ReportValue(value))
}

// Adapt serialization directly, retaining serde_json::to_value's supported
// nesting depth and map-key behavior without parsing an intermediate JSON string.
struct ReportValue<'a, T: ?Sized>(&'a T);

impl<T: ?Sized + Serialize> Serialize for ReportValue<'_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.0.serialize(Base64Serializer(serializer))
    }
}

struct Base64Serializer<S>(S);
struct Base64Compound<S>(S);

macro_rules! forward_scalar {
    ($($method:ident($ty:ty)),* $(,)?) => {
        $(
            fn $method(self, value: $ty) -> Result<Self::Ok, Self::Error> {
                self.0.$method(value)
            }
        )*
    };
}

impl<S: ser::Serializer> ser::Serializer for Base64Serializer<S> {
    type Error = S::Error;
    type Ok = S::Ok;
    type SerializeMap = Base64Compound<S::SerializeMap>;
    type SerializeSeq = Base64Compound<S::SerializeSeq>;
    type SerializeStruct = Base64Compound<S::SerializeStruct>;
    type SerializeStructVariant = Base64Compound<S::SerializeStructVariant>;
    type SerializeTuple = Base64Compound<S::SerializeTuple>;
    type SerializeTupleStruct = Base64Compound<S::SerializeTupleStruct>;
    type SerializeTupleVariant = Base64Compound<S::SerializeTupleVariant>;

    forward_scalar! {
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_i128(i128),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_u128(u128),
        serialize_f32(f32),
        serialize_f64(f64),
        serialize_char(char),
        serialize_str(&str),
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_str(&base64::encode(value))
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_none()
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_some(&ReportValue(value))
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_unit()
    }

    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_unit_struct(name)
    }

    fn serialize_unit_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_unit_variant(name, index, variant)
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_newtype_struct(name, &ReportValue(value))
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.0
            .serialize_newtype_variant(name, index, variant, &ReportValue(value))
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        self.0.serialize_seq(len).map(Base64Compound)
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.0.serialize_tuple(len).map(Base64Compound)
    }

    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.0.serialize_tuple_struct(name, len).map(Base64Compound)
    }

    fn serialize_tuple_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.0
            .serialize_tuple_variant(name, index, variant, len)
            .map(Base64Compound)
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        self.0.serialize_map(len).map(Base64Compound)
    }

    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        self.0.serialize_struct(name, len).map(Base64Compound)
    }

    fn serialize_struct_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        self.0
            .serialize_struct_variant(name, index, variant, len)
            .map(Base64Compound)
    }

    fn is_human_readable(&self) -> bool {
        self.0.is_human_readable()
    }
}

macro_rules! serialize_sequence {
    ($trait:ident, $method:ident) => {
        impl<S: ser::$trait> ser::$trait for Base64Compound<S> {
            type Error = S::Error;
            type Ok = S::Ok;

            fn $method<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), S::Error> {
                self.0.$method(&ReportValue(value))
            }

            fn end(self) -> Result<S::Ok, S::Error> {
                self.0.end()
            }
        }
    };
}

serialize_sequence!(SerializeSeq, serialize_element);
serialize_sequence!(SerializeTuple, serialize_element);
serialize_sequence!(SerializeTupleStruct, serialize_field);
serialize_sequence!(SerializeTupleVariant, serialize_field);

impl<S: ser::SerializeMap> ser::SerializeMap for Base64Compound<S> {
    type Error = S::Error;
    type Ok = S::Ok;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), S::Error> {
        self.0.serialize_key(key)
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), S::Error> {
        self.0.serialize_value(&ReportValue(value))
    }

    fn end(self) -> Result<S::Ok, S::Error> {
        self.0.end()
    }
}

macro_rules! serialize_struct {
    ($trait:ident) => {
        impl<S: ser::$trait> ser::$trait for Base64Compound<S> {
            type Error = S::Error;
            type Ok = S::Ok;

            fn serialize_field<T: ?Sized + Serialize>(
                &mut self,
                key: &'static str,
                value: &T,
            ) -> Result<(), S::Error> {
                self.0.serialize_field(key, &ReportValue(value))
            }

            fn skip_field(&mut self, key: &'static str) -> Result<(), S::Error> {
                self.0.skip_field(key)
            }

            fn end(self) -> Result<S::Ok, S::Error> {
                self.0.end()
            }
        }
    };
}

serialize_struct!(SerializeStruct);
serialize_struct!(SerializeStructVariant);

/// Restore byte-string formatting after a CBOR assertion has been converted to
/// JSON. Use the original CBOR types, never the values or names of JSON fields.
/// Only matching byte arrays are replaced so normalized report fields are kept.
pub(crate) fn encode_cbor_byte_strings(cbor: &[u8], report: &mut Value) -> c2pa_cbor::Result<()> {
    CborBytes(report).deserialize(&mut c2pa_cbor::Deserializer::from_slice(cbor))
}

// Walk the CBOR directly rather than decoding into c2pa_cbor::Value: that value
// type only represents i64 integers, whereas report transcoding supports u64.
struct CborBytes<'a>(&'a mut Value);

impl<'de> DeserializeSeed<'de> for CborBytes<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for CborBytes<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a CBOR assertion value")
    }

    fn visit_bytes<E>(self, bytes: &[u8]) -> Result<(), E> {
        if let Some(values) = self.0.as_array() {
            if values.len() == bytes.len()
                && values
                    .iter()
                    .zip(bytes)
                    .all(|(value, byte)| value.as_u64() == Some(u64::from(*byte)))
            {
                *self.0 = Value::String(base64::encode(bytes));
            }
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        if let Some(values) = self.0.as_array_mut() {
            for value in values {
                if sequence.next_element_seed(CborBytes(value))?.is_none() {
                    return Ok(());
                }
            }
        }
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<Value>()? {
            let key = match key {
                Value::String(key) => Some(key),
                Value::Number(key) => Some(key.to_string()),
                Value::Bool(key) => Some(key.to_string()),
                _ => None,
            };
            if let Some(value) = key.as_deref().and_then(|key| self.0.get_mut(key)) {
                map.next_value_seed(CborBytes(value))?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }

    fn visit_bool<E>(self, _value: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        self.deserialize(deserializer)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        self.deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn json_report_preserves_supported_nesting_depth() -> crate::Result<()> {
        let mut value = json!([0, 255]);
        for _ in 0..130 {
            value = json!({"nested": value});
        }
        assert_eq!(to_value(&value)?, serde_json::to_value(&value)?);
        Ok(())
    }

    #[test]
    fn json_report_handles_unsigned_integers_and_numeric_keys() -> crate::Result<()> {
        #[derive(Serialize)]
        struct Data {
            maximum: u64,
            bytes: serde_bytes::ByteBuf,
            values: Vec<u64>,
            nested: std::collections::BTreeMap<u64, serde_bytes::ByteBuf>,
        }
        let data = Data {
            maximum: u64::MAX,
            bytes: serde_bytes::ByteBuf::from(vec![0, 255]),
            values: vec![0, 255, 256, u64::MAX],
            nested: [(u64::MAX, serde_bytes::ByteBuf::from(vec![]))]
                .into_iter()
                .collect(),
        };
        let mut report = serde_json::to_value(&data)?;
        encode_cbor_byte_strings(&c2pa_cbor::to_vec(&data)?, &mut report)?;
        assert_eq!(report, to_value(&data)?);
        assert_eq!(report["maximum"], json!(u64::MAX));
        assert_eq!(report["values"], json!([0, 255, 256, u64::MAX]));
        assert_eq!(report["bytes"], json!("AP8="));
        assert_eq!(report["nested"][u64::MAX.to_string()], json!(""));
        Ok(())
    }

    #[test]
    fn json_report_keeps_normalized_fields() -> crate::Result<()> {
        #[derive(Serialize)]
        struct Data {
            bytes: serde_bytes::ByteBuf,
            signature: serde_bytes::ByteBuf,
            omitted: Vec<serde_bytes::ByteBuf>,
            nested: serde_bytes::ByteBuf,
        }
        let data = Data {
            bytes: serde_bytes::ByteBuf::from(vec![0, 255]),
            signature: serde_bytes::ByteBuf::from(vec![96, 128]),
            omitted: vec![serde_bytes::ByteBuf::from(vec![1, 2])],
            nested: serde_bytes::ByteBuf::from(vec![0, 255]),
        };
        let mut report = json!({
            "bytes": [96, 384],
            "signature": {"algorithm": "ES256"},
            "nested": {"identifier": "resource"},
            "extra": [0, 255]
        });
        let expected = report.clone();
        encode_cbor_byte_strings(&c2pa_cbor::to_vec(&data)?, &mut report)?;
        assert_eq!(report, expected);
        Ok(())
    }
}
