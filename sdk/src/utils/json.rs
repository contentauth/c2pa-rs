// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License, Version 2.0
// (http://www.apache.org/licenses/LICENSE-2.0) or the MIT license
// (http://opensource.org/licenses/MIT), at your option.
// Unless required by applicable law or agreed to in writing, this software
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
// OF ANY KIND, either express or implied. See the license for the specific
// language governing permissions and limitations under each license.

use serde::{
    ser::{
        SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
        SerializeTupleStruct, SerializeTupleVariant,
    },
    Serialize, Serializer,
};
use serde_json::Value;

use crate::crypto::base64::{decode_b64_wrapped, encode};

/// Serialize report bytes as base64 without mistaking numeric sequences for bytes.
pub(crate) fn to_value<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Value> {
    ReportValue(value).serialize(serde_json::value::Serializer)
}

/// Use original byte markers to format matching fields in normalized assertions.
/// Only matching fields are changed; normalized names and resource references stay intact.
pub(crate) fn restore_byte_strings(value: &mut Value, source: &Value) {
    match (value, source) {
        (Value::Object(value), Value::Object(source)) => {
            for (key, source) in source {
                if let Some(value) = value.get_mut(key) {
                    restore_byte_strings(value, source);
                }
            }
        }
        (Value::Array(value), Value::Array(source)) if value.len() == source.len() => {
            for (value, source) in value.iter_mut().zip(source) {
                restore_byte_strings(value, source);
            }
        }
        (value @ Value::Array(_), Value::String(source)) => {
            if let Some(bytes) = decode_b64_wrapped(source) {
                if *value == serde_json::json!(bytes) {
                    *value = Value::String(encode(&bytes));
                }
            }
        }
        _ => {}
    }
}

struct ReportValue<'a, T: ?Sized>(&'a T);

impl<T: Serialize + ?Sized> Serialize for ReportValue<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(ReportSerializer(serializer))
    }
}

struct ReportSerializer<S>(S);
struct Compound<S>(S);

macro_rules! forward {
    ($($method:ident($($arg:ident: $ty:ty),*);)*) => {
        $(
            fn $method(self, $($arg: $ty),*) -> Result<Self::Ok, Self::Error> {
                self.0.$method($($arg),*)
            }
        )*
    };
}

impl<S: Serializer> Serializer for ReportSerializer<S> {
    type Error = S::Error;
    type Ok = S::Ok;
    type SerializeMap = Compound<S::SerializeMap>;
    type SerializeSeq = Compound<S::SerializeSeq>;
    type SerializeStruct = Compound<S::SerializeStruct>;
    type SerializeStructVariant = Compound<S::SerializeStructVariant>;
    type SerializeTuple = Compound<S::SerializeTuple>;
    type SerializeTupleStruct = Compound<S::SerializeTupleStruct>;
    type SerializeTupleVariant = Compound<S::SerializeTupleVariant>;

    forward! {
        serialize_bool(value: bool);
        serialize_i8(value: i8);
        serialize_i16(value: i16);
        serialize_i32(value: i32);
        serialize_i64(value: i64);
        serialize_i128(value: i128);
        serialize_u8(value: u8);
        serialize_u16(value: u16);
        serialize_u32(value: u32);
        serialize_u64(value: u64);
        serialize_u128(value: u128);
        serialize_f32(value: f32);
        serialize_f64(value: f64);
        serialize_char(value: char);
        serialize_str(value: &str);
        serialize_none();
        serialize_unit();
        serialize_unit_struct(name: &'static str);
        serialize_unit_variant(name: &'static str, index: u32, variant: &'static str);
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_str(&encode(value))
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_some(&ReportValue(value))
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_newtype_struct(name, &ReportValue(value))
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
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
        self.0.serialize_seq(len).map(Compound)
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.0.serialize_tuple(len).map(Compound)
    }

    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.0.serialize_tuple_struct(name, len).map(Compound)
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
            .map(Compound)
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        self.0.serialize_map(len).map(Compound)
    }

    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        self.0.serialize_struct(name, len).map(Compound)
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
            .map(Compound)
    }

    fn is_human_readable(&self) -> bool {
        self.0.is_human_readable()
    }
}

macro_rules! sequence {
    ($trait:ident, $method:ident) => {
        impl<S: $trait> $trait for Compound<S> {
            type Error = S::Error;
            type Ok = S::Ok;

            fn $method<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
                self.0.$method(&ReportValue(value))
            }

            fn end(self) -> Result<Self::Ok, Self::Error> {
                self.0.end()
            }
        }
    };
}

sequence!(SerializeSeq, serialize_element);
sequence!(SerializeTuple, serialize_element);
sequence!(SerializeTupleStruct, serialize_field);
sequence!(SerializeTupleVariant, serialize_field);

impl<S: SerializeMap> SerializeMap for Compound<S> {
    type Error = S::Error;
    type Ok = S::Ok;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Self::Error> {
        self.0.serialize_key(key)
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.0.serialize_value(&ReportValue(value))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

macro_rules! structure {
    ($trait:ident) => {
        impl<S: $trait> $trait for Compound<S> {
            type Error = S::Error;
            type Ok = S::Ok;

            fn serialize_field<T: Serialize + ?Sized>(
                &mut self,
                key: &'static str,
                value: &T,
            ) -> Result<(), Self::Error> {
                self.0.serialize_field(key, &ReportValue(value))
            }

            fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
                self.0.skip_field(key)
            }

            fn end(self) -> Result<Self::Ok, Self::Error> {
                self.0.end()
            }
        }
    };
}

structure!(SerializeStruct);
structure!(SerializeStructVariant);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;

    #[test]
    fn json_report_serialization_preserves_types() {
        #[derive(Serialize)]
        struct Data {
            #[serde(with = "serde_bytes")]
            bytes: Vec<u8>,
            numbers: Vec<u64>,
        }

        let data = Data {
            bytes: vec![96, 128],
            numbers: vec![96, 384, u64::MAX],
        };
        assert_eq!(
            to_value(&data).unwrap(),
            json!({"bytes": "YIA=", "numbers": [96, 384, u64::MAX]})
        );
        assert_eq!(
            serde_json::to_value(&data).unwrap()["bytes"],
            json!([96, 128])
        );

        let map = BTreeMap::from([(u64::MAX, Some(serde_bytes::ByteBuf::from(vec![0, 255])))]);
        assert_eq!(
            to_value(&map).unwrap(),
            json!({u64::MAX.to_string(): "AP8="})
        );
        assert!(to_value(&BTreeMap::from([(vec![1, 2], 3)])).is_err());
    }

    #[test]
    fn json_report_serialization_preserves_json_semantics() {
        struct HumanReadable;
        impl Serialize for HumanReadable {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let human_readable = serializer.is_human_readable();
                serializer.serialize_bool(human_readable)
            }
        }

        #[derive(Serialize)]
        enum Data {
            Unit,
            Newtype(serde_bytes::ByteBuf),
            Tuple(serde_bytes::ByteBuf, Vec<i32>),
            Struct { bytes: serde_bytes::ByteBuf },
        }

        let bytes = || serde_bytes::ByteBuf::from(vec![96, 128]);
        assert_eq!(to_value(&HumanReadable).unwrap(), json!(true));
        assert_eq!(to_value(&Data::Unit).unwrap(), json!("Unit"));
        assert_eq!(
            to_value(&Data::Newtype(bytes())).unwrap(),
            json!({"Newtype": "YIA="})
        );
        assert_eq!(
            to_value(&Data::Tuple(bytes(), vec![-1, 384])).unwrap(),
            json!({"Tuple": ["YIA=", [-1, 384]]})
        );
        assert_eq!(
            to_value(&Data::Struct { bytes: bytes() }).unwrap(),
            json!({"Struct": {"bytes": "YIA="}})
        );

        let mut deep = json!([96, 384]);
        for _ in 0..150 {
            deep = json!({"nested": deep});
        }
        assert_eq!(to_value(&deep).unwrap(), deep);
    }

    #[test]
    fn json_report_serialization_preserves_compound_shapes() {
        #[derive(Serialize)]
        struct Newtype(serde_bytes::ByteBuf);

        #[derive(Serialize)]
        struct Tuple(serde_bytes::ByteBuf, Vec<u64>);

        #[derive(Serialize)]
        struct Unit;

        #[derive(Serialize)]
        struct Optional {
            #[serde(skip_serializing_if = "Option::is_none")]
            omitted: Option<String>,
            present: u64,
        }

        #[derive(Serialize)]
        enum Variant {
            Optional {
                #[serde(skip_serializing_if = "Option::is_none")]
                omitted: Option<String>,
                bytes: serde_bytes::ByteBuf,
            },
        }

        let bytes = || serde_bytes::ByteBuf::from(vec![96, 128]);
        assert_eq!(to_value(&Newtype(bytes())).unwrap(), json!("YIA="));
        assert_eq!(
            to_value(&Tuple(bytes(), vec![96, 384])).unwrap(),
            json!(["YIA=", [96, 384]])
        );
        assert_eq!(
            to_value(&(bytes(), vec![96, 384])).unwrap(),
            json!(["YIA=", [96, 384]])
        );
        assert_eq!(to_value(&Unit).unwrap(), Value::Null);
        assert_eq!(to_value(&()).unwrap(), Value::Null);
        assert_eq!(to_value(&None::<u8>).unwrap(), Value::Null);
        assert_eq!(
            to_value(&Optional {
                omitted: None,
                present: u64::MAX,
            })
            .unwrap(),
            json!({"present": u64::MAX})
        );
        assert_eq!(
            to_value(&Variant::Optional {
                omitted: None,
                bytes: bytes(),
            })
            .unwrap(),
            json!({"Optional": {"bytes": "YIA="}})
        );
    }

    #[test]
    fn json_report_serialization_forwards_primitives_and_errors() {
        macro_rules! check {
            ($($value:expr),* $(,)?) => {
                $(
                    assert_eq!(
                        to_value(&$value).unwrap(),
                        serde_json::to_value($value).unwrap()
                    );
                )*
            };
        }

        check!(
            true,
            i8::MIN,
            i16::MIN,
            i32::MIN,
            i64::MIN,
            i128::from(i64::MIN),
            u8::MAX,
            u16::MAX,
            u32::MAX,
            u64::MAX,
            u128::from(u64::MAX),
            1.5_f32,
            2.5_f64,
            f64::NAN,
            'x',
            "text",
        );
        assert!(to_value(&u128::MAX).is_err());
        assert!(to_value(&i128::MIN).is_err());

        struct Invalid;
        impl Serialize for Invalid {
            fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("invalid report data"))
            }
        }

        #[derive(Serialize)]
        struct Nested {
            value: Invalid,
        }

        for error in [
            to_value(&Invalid).unwrap_err(),
            to_value(&Nested { value: Invalid }).unwrap_err(),
            to_value(&vec![Invalid]).unwrap_err(),
            to_value(&BTreeMap::from([("value", Invalid)])).unwrap_err(),
        ] {
            assert_eq!(error.to_string(), "invalid report data");
        }
    }

    #[test]
    fn json_report_restoration_leaves_nonmatching_values_unchanged() {
        for (mut value, source) in [
            (json!([96, 128]), json!("not a byte marker")),
            (json!([96, 128]), json!("b64'!invalid!'")),
            (json!([0, 255]), json!("b64'YIA='")),
            (json!(["b64'YIA='"]), json!([])),
            (
                json!({"values": [96, 384]}),
                json!({"missing": "b64'YIA='"}),
            ),
            (Value::Null, json!("b64'YIA='")),
            (json!(true), json!({"bytes": "b64'YIA='"})),
        ] {
            let expected = value.clone();
            restore_byte_strings(&mut value, &source);
            assert_eq!(value, expected);
        }
    }

    #[test]
    fn json_report_restores_only_matching_byte_fields() {
        let mut normalized = json!({
            "hash": [96, 128],
            "values": [96, 384],
            "changed": [0, 255],
            "nested": [{"bytes": []}],
            "icon": {"identifier": "resource"},
            "normalized": true
        });
        let source = json!({
            "hash": "b64'YIA='",
            "values": [96, 384],
            "changed": "b64'YIA='",
            "nested": [{"bytes": "b64''"}],
            "icon": {"url": "self#jumbf=original", "hash": "b64'AP8='"}
        });
        restore_byte_strings(&mut normalized, &source);
        assert_eq!(
            normalized,
            json!({
                "hash": "YIA=",
                "values": [96, 384],
                "changed": [0, 255],
                "nested": [{"bytes": ""}],
                "icon": {"identifier": "resource"},
                "normalized": true
            })
        );
    }
}
