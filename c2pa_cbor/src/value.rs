use std::{collections::BTreeMap, fmt};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};

/// Dynamic CBOR value type for working with untyped CBOR data
///
/// This type can represent any CBOR value without knowing its type at compile time.
/// It's useful for working with dynamic data or when you need to inspect CBOR structure.
///
/// # Example
/// ```
/// use std::collections::BTreeMap;
///
/// use c2pa_cbor::{Value, from_slice, to_vec};
///
/// // Create a dynamic value
/// let mut map = BTreeMap::new();
/// map.insert(
///     Value::Text("name".to_string()),
///     Value::Text("Alice".to_string()),
/// );
/// map.insert(Value::Text("age".to_string()), Value::Integer(30));
/// let value = Value::Map(map);
///
/// // Serialize and deserialize
/// let bytes = to_vec(&value).unwrap();
/// let decoded: Value = from_slice(&bytes).unwrap();
/// assert_eq!(value, decoded);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Null value
    Null,
    /// Boolean value
    Bool(bool),
    /// Integer value (signed 64-bit)
    Integer(i64),
    /// Floating point value
    Float(f64),
    /// Byte string
    Bytes(Vec<u8>),
    /// Text string
    Text(String),
    /// Array of values
    Array(Vec<Value>),
    /// Map of values
    Map(BTreeMap<Value, Value>),
    /// Tagged value (tag number, boxed content)
    Tag(u64, Box<Value>),
}

impl Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Value::Null => serializer.serialize_none(),
            Value::Bool(b) => serializer.serialize_bool(*b),
            Value::Integer(i) => serializer.serialize_i64(*i),
            Value::Float(f) => serializer.serialize_f64(*f),
            Value::Bytes(b) => serializer.serialize_bytes(b),
            Value::Text(s) => serializer.serialize_str(s),
            Value::Array(a) => a.serialize(serializer),
            Value::Map(m) => m.serialize(serializer),
            Value::Tag(_tag, _value) => {
                // For now, serialize the inner value
                // Full tag support would require custom CBOR encoding
                _value.serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = Value;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("any valid CBOR value")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
                Ok(Value::Bool(value))
            }

            fn visit_i8<E>(self, value: i8) -> Result<Value, E> {
                Ok(Value::Integer(value as i64))
            }

            fn visit_i16<E>(self, value: i16) -> Result<Value, E> {
                Ok(Value::Integer(value as i64))
            }

            fn visit_i32<E>(self, value: i32) -> Result<Value, E> {
                Ok(Value::Integer(value as i64))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
                Ok(Value::Integer(value))
            }

            fn visit_u8<E>(self, value: u8) -> Result<Value, E> {
                Ok(Value::Integer(value as i64))
            }

            fn visit_u16<E>(self, value: u16) -> Result<Value, E> {
                Ok(Value::Integer(value as i64))
            }

            fn visit_u32<E>(self, value: u32) -> Result<Value, E> {
                Ok(Value::Integer(value as i64))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Value, E>
            where
                E: de::Error,
            {
                if value <= i64::MAX as u64 {
                    Ok(Value::Integer(value as i64))
                } else {
                    Err(E::custom(format!("u64 value {} too large for i64", value)))
                }
            }

            fn visit_f32<E>(self, value: f32) -> Result<Value, E> {
                Ok(Value::Float(value as f64))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
                Ok(Value::Float(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Value, E>
            where
                E: de::Error,
            {
                Ok(Value::Text(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Value, E> {
                Ok(Value::Text(value))
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Value, E>
            where
                E: de::Error,
            {
                Ok(Value::Bytes(value.to_vec()))
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Value, E> {
                Ok(Value::Bytes(value))
            }

            fn visit_none<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                Deserialize::deserialize(deserializer)
            }

            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }

            fn visit_seq<V>(self, mut visitor: V) -> Result<Value, V::Error>
            where
                V: de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(elem) = visitor.next_element()? {
                    vec.push(elem);
                }
                Ok(Value::Array(vec))
            }

            fn visit_map<V>(self, mut visitor: V) -> Result<Value, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let mut map = BTreeMap::new();
                while let Some((key, value)) = visitor.next_entry()? {
                    map.insert(key, value);
                }
                Ok(Value::Map(map))
            }
        }

        deserializer.deserialize_any(ValueVisitor)
    }
}

impl Value {
    /// Returns true if the value is null
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Returns true if the value is a boolean
    pub fn is_bool(&self) -> bool {
        matches!(self, Value::Bool(_))
    }

    /// Returns true if the value is an integer
    pub fn is_integer(&self) -> bool {
        matches!(self, Value::Integer(_))
    }

    /// Returns true if the value is a float
    pub fn is_float(&self) -> bool {
        matches!(self, Value::Float(_))
    }

    /// Returns true if the value is bytes
    pub fn is_bytes(&self) -> bool {
        matches!(self, Value::Bytes(_))
    }

    /// Returns true if the value is text
    pub fn is_text(&self) -> bool {
        matches!(self, Value::Text(_))
    }

    /// Returns true if the value is an array
    pub fn is_array(&self) -> bool {
        matches!(self, Value::Array(_))
    }

    /// Returns true if the value is a map
    pub fn is_map(&self) -> bool {
        matches!(self, Value::Map(_))
    }

    /// Returns true if the value is tagged
    pub fn is_tag(&self) -> bool {
        matches!(self, Value::Tag(_, _))
    }

    /// Returns the value as a boolean, if it is one
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns the value as an integer, if it is one
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns the value as a float, if it is one
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// Returns the value as bytes, if it is a byte string
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Returns the value as text, if it is a text string
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the value as an array, if it is one
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Returns the value as a map, if it is one
    pub fn as_map(&self) -> Option<&BTreeMap<Value, Value>> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the tag number and inner value, if this is a tagged value
    pub fn as_tag(&self) -> Option<(u64, &Value)> {
        match self {
            Value::Tag(tag, value) => Some((*tag, value)),
            _ => None,
        }
    }
}

// Implement Eq, PartialOrd, and Ord for Value to allow it to be used as a map key
impl Eq for Value {}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;

        use Value::*;

        match (self, other) {
            // Null is only equal to Null
            (Null, Null) => Ordering::Equal,
            (Null, _) => Ordering::Less,
            (_, Null) => Ordering::Greater,

            // Bool comparison
            (Bool(a), Bool(b)) => a.cmp(b),
            (Bool(_), _) => Ordering::Less,
            (_, Bool(_)) => Ordering::Greater,

            // Integer comparison
            (Integer(a), Integer(b)) => a.cmp(b),
            (Integer(_), _) => Ordering::Less,
            (_, Integer(_)) => Ordering::Greater,

            // Float comparison - NaN is treated as equal to NaN for ordering purposes
            (Float(a), Float(b)) => {
                if a.is_nan() && b.is_nan() {
                    Ordering::Equal
                } else if a.is_nan() {
                    Ordering::Greater // NaN sorts last
                } else if b.is_nan() {
                    Ordering::Less
                } else {
                    a.partial_cmp(b).unwrap_or(Ordering::Equal)
                }
            }
            (Float(_), _) => Ordering::Less,
            (_, Float(_)) => Ordering::Greater,

            // Bytes comparison
            (Bytes(a), Bytes(b)) => a.cmp(b),
            (Bytes(_), _) => Ordering::Less,
            (_, Bytes(_)) => Ordering::Greater,

            // Text comparison
            (Text(a), Text(b)) => a.cmp(b),
            (Text(_), _) => Ordering::Less,
            (_, Text(_)) => Ordering::Greater,

            // Array comparison
            (Array(a), Array(b)) => a.cmp(b),
            (Array(_), _) => Ordering::Less,
            (_, Array(_)) => Ordering::Greater,

            // Map comparison
            (Map(a), Map(b)) => {
                // Compare maps by converting to sorted vectors and comparing
                let a_vec: Vec<_> = a.iter().collect();
                let b_vec: Vec<_> = b.iter().collect();
                a_vec.cmp(&b_vec)
            }
            (Map(_), _) => Ordering::Less,
            (_, Map(_)) => Ordering::Greater,

            // Tag comparison
            (Tag(tag_a, val_a), Tag(tag_b, val_b)) => match tag_a.cmp(tag_b) {
                Ordering::Equal => val_a.cmp(val_b),
                other => other,
            },
        }
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Convert a `T` into `Value` which is an enum that can represent any valid CBOR data.
///
/// This conversion can fail if `T`'s implementation of `Serialize` decides to
/// fail, or if `T` contains a map with non-string keys.
///
/// Note: Due to how serde works, `Some(x)` will serialize as just `x`, and `None` as `Null`.
/// This means you cannot distinguish between `Some(T)` and `T` in the resulting `Value`.
pub fn to_value<T>(value: T) -> Result<Value, crate::Error>
where
    T: Serialize,
{
    value.serialize(ValueSerializer)
}

struct ValueSerializer;

impl Serializer for ValueSerializer {
    type Error = crate::Error;
    type Ok = Value;
    type SerializeMap = SerializeMap;
    type SerializeSeq = SerializeVec;
    type SerializeStruct = SerializeMap;
    type SerializeStructVariant = SerializeStructVariant;
    type SerializeTuple = SerializeVec;
    type SerializeTupleStruct = SerializeVec;
    type SerializeTupleVariant = SerializeTupleVariant;

    fn serialize_bool(self, v: bool) -> Result<Value, crate::Error> {
        Ok(Value::Bool(v))
    }

    fn serialize_i8(self, v: i8) -> Result<Value, crate::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_i16(self, v: i16) -> Result<Value, crate::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_i32(self, v: i32) -> Result<Value, crate::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_i64(self, v: i64) -> Result<Value, crate::Error> {
        Ok(Value::Integer(v))
    }

    fn serialize_u8(self, v: u8) -> Result<Value, crate::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_u16(self, v: u16) -> Result<Value, crate::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_u32(self, v: u32) -> Result<Value, crate::Error> {
        Ok(Value::Integer(v as i64))
    }

    fn serialize_u64(self, v: u64) -> Result<Value, crate::Error> {
        if v <= i64::MAX as u64 {
            Ok(Value::Integer(v as i64))
        } else {
            Err(crate::Error::Message(format!(
                "u64 value {} too large for i64",
                v
            )))
        }
    }

    fn serialize_f32(self, v: f32) -> Result<Value, crate::Error> {
        Ok(Value::Float(v as f64))
    }

    fn serialize_f64(self, v: f64) -> Result<Value, crate::Error> {
        Ok(Value::Float(v))
    }

    fn serialize_char(self, v: char) -> Result<Value, crate::Error> {
        Ok(Value::Text(v.to_string()))
    }

    fn serialize_str(self, v: &str) -> Result<Value, crate::Error> {
        Ok(Value::Text(v.to_string()))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Value, crate::Error> {
        Ok(Value::Bytes(v.to_vec()))
    }

    fn serialize_none(self) -> Result<Value, crate::Error> {
        Ok(Value::Null)
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Value, crate::Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Value, crate::Error> {
        Ok(Value::Null)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Value, crate::Error> {
        Ok(Value::Null)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Value, crate::Error> {
        Ok(Value::Text(variant.to_string()))
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Value, crate::Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Value, crate::Error> {
        let mut map = BTreeMap::new();
        map.insert(
            Value::Text(variant.to_string()),
            value.serialize(ValueSerializer)?,
        );
        Ok(Value::Map(map))
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, crate::Error> {
        Ok(SerializeVec { vec: Vec::new() })
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, crate::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, crate::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, crate::Error> {
        Ok(SerializeTupleVariant {
            name: variant.to_string(),
            vec: Vec::new(),
        })
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, crate::Error> {
        Ok(SerializeMap {
            map: BTreeMap::new(),
            next_key: None,
        })
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, crate::Error> {
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, crate::Error> {
        Ok(SerializeStructVariant {
            name: variant.to_string(),
            map: BTreeMap::new(),
        })
    }
}

struct SerializeVec {
    vec: Vec<Value>,
}

impl serde::ser::SerializeSeq for SerializeVec {
    type Error = crate::Error;
    type Ok = Value;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), crate::Error> {
        self.vec.push(value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Value, crate::Error> {
        Ok(Value::Array(self.vec))
    }
}

impl serde::ser::SerializeTuple for SerializeVec {
    type Error = crate::Error;
    type Ok = Value;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), crate::Error> {
        serde::ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Value, crate::Error> {
        serde::ser::SerializeSeq::end(self)
    }
}

impl serde::ser::SerializeTupleStruct for SerializeVec {
    type Error = crate::Error;
    type Ok = Value;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), crate::Error> {
        serde::ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Value, crate::Error> {
        serde::ser::SerializeSeq::end(self)
    }
}

struct SerializeTupleVariant {
    name: String,
    vec: Vec<Value>,
}

impl serde::ser::SerializeTupleVariant for SerializeTupleVariant {
    type Error = crate::Error;
    type Ok = Value;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), crate::Error> {
        self.vec.push(value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Value, crate::Error> {
        let mut map = BTreeMap::new();
        map.insert(Value::Text(self.name), Value::Array(self.vec));
        Ok(Value::Map(map))
    }
}

struct SerializeMap {
    map: BTreeMap<Value, Value>,
    next_key: Option<Value>,
}

impl serde::ser::SerializeMap for SerializeMap {
    type Error = crate::Error;
    type Ok = Value;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), crate::Error> {
        self.next_key = Some(key.serialize(ValueSerializer)?);
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), crate::Error> {
        let key = self.next_key.take().ok_or_else(|| {
            crate::Error::Message("serialize_value called before serialize_key".to_string())
        })?;
        self.map.insert(key, value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Value, crate::Error> {
        Ok(Value::Map(self.map))
    }
}

impl serde::ser::SerializeStruct for SerializeMap {
    type Error = crate::Error;
    type Ok = Value;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), crate::Error> {
        serde::ser::SerializeMap::serialize_entry(self, key, value)
    }

    fn end(self) -> Result<Value, crate::Error> {
        serde::ser::SerializeMap::end(self)
    }
}

struct SerializeStructVariant {
    name: String,
    map: BTreeMap<Value, Value>,
}

impl serde::ser::SerializeStructVariant for SerializeStructVariant {
    type Error = crate::Error;
    type Ok = Value;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), crate::Error> {
        self.map.insert(
            Value::Text(key.to_string()),
            value.serialize(ValueSerializer)?,
        );
        Ok(())
    }

    fn end(self) -> Result<Value, crate::Error> {
        let mut outer_map = BTreeMap::new();
        outer_map.insert(Value::Text(self.name), Value::Map(self.map));
        Ok(Value::Map(outer_map))
    }
}

/// Interpret a `Value` as an instance of type `T`.
///
/// This conversion can fail if the structure of the `Value` does not match the
/// structure expected by `T`, for example if `T` is a struct type but the
/// `Value` contains something other than a CBOR map.
pub fn from_value<T>(value: Value) -> Result<T, crate::Error>
where
    T: for<'de> Deserialize<'de>,
{
    let bytes = crate::to_vec(&value)?;
    crate::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{from_slice, to_vec};

    #[test]
    fn test_value_null() {
        let value = Value::Null;
        assert!(value.is_null());

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_bool() {
        let value = Value::Bool(true);
        assert!(value.is_bool());
        assert_eq!(value.as_bool(), Some(true));

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_integer() {
        let value = Value::Integer(42);
        assert!(value.is_integer());
        assert_eq!(value.as_i64(), Some(42));

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_text() {
        let value = Value::Text("hello".to_string());
        assert!(value.is_text());
        assert_eq!(value.as_str(), Some("hello"));

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_array() {
        let value = Value::Array(vec![
            Value::Integer(1),
            Value::Integer(2),
            Value::Integer(3),
        ]);
        assert!(value.is_array());
        assert_eq!(value.as_array().unwrap().len(), 3);

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_map() {
        let mut map = BTreeMap::new();
        map.insert(Value::Text("key".to_string()), Value::Integer(42));
        let value = Value::Map(map);
        assert!(value.is_map());

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_value_bytes() {
        // Note: Value::Bytes serializes as CBOR bytes
        let value = Value::Bytes(vec![1, 2, 3, 4, 5]);
        assert!(value.is_bytes());
        assert_eq!(value.as_bytes(), Some(&[1, 2, 3, 4, 5][..]));

        let bytes = to_vec(&value).unwrap();
        let decoded: Value = from_slice(&bytes).unwrap();
        assert_eq!(value, decoded);
    }
}
