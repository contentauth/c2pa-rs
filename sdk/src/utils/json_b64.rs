// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.
//
// Unless required by applicable law or agreed to in writing,
// software distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the LICENSE-MIT and LICENSE-APACHE files for the specific language
// governing permissions and limitations under each license.

//! JSON values with `b64'<base64>'` markers for byte strings, not full crJSON documents.
//!
//! Conversion uses `c2pa_cbor` and inherits its supported integer range.

use serde::Serialize;
use serde_json::Value;

use crate::{
    crypto::base64::{decode_b64_wrapped, encode_b64_wrapped},
    error::Result,
};

/// Converts serializable data to json_b64, representing byte strings as `b64'<base64>'`.
pub(crate) fn to_json_b64<T: Serialize>(value: T) -> Result<Value> {
    Ok(cbor_to_json_b64(c2pa_cbor::value::to_value(value)?))
}

/// Converts input to CBOR, decoding json_b64 byte markers at any depth.
/// Only valid markers are decoded; other strings, numeric arrays, and map keys
/// retain their original types.
pub(crate) fn from_json_b64<T: Serialize>(value: T) -> Result<c2pa_cbor::Value> {
    fn decode_byte_strings(value: &mut c2pa_cbor::Value) {
        use c2pa_cbor::Value as Cbor;

        match value {
            Cbor::Text(text) => {
                if let Some(bytes) = decode_b64_wrapped(text) {
                    *value = Cbor::Bytes(bytes);
                }
            }
            Cbor::Array(array) => array.iter_mut().for_each(decode_byte_strings),
            Cbor::Map(map) => map.values_mut().for_each(decode_byte_strings),
            Cbor::Tag(_, inner) => decode_byte_strings(inner),
            _ => {}
        }
    }

    let mut value = c2pa_cbor::value::to_value(value)?;
    decode_byte_strings(&mut value);
    Ok(value)
}

/// Converts a decoded CBOR value to json_b64, not a full crJSON document.
///
/// Byte strings become `b64'<base64>'`-wrapped strings rather than JSON number
/// arrays. Tags are unwrapped, non-finite floats become null, and non-text map
/// keys are stringified. This is not a lossless mapping of arbitrary CBOR maps.
pub(crate) fn cbor_to_json_b64(value: c2pa_cbor::Value) -> Value {
    use c2pa_cbor::Value as Cbor;

    match value {
        Cbor::Null => Value::Null,
        Cbor::Bool(b) => Value::Bool(b),
        Cbor::Integer(i) => Value::Number(i.into()),
        Cbor::Float(f) => serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Cbor::Bytes(b) => Value::String(encode_b64_wrapped(&b)),
        Cbor::Text(s) => Value::String(s),
        Cbor::Array(a) => Value::Array(a.into_iter().map(cbor_to_json_b64).collect()),
        Cbor::Map(m) => {
            let mut obj = serde_json::Map::with_capacity(m.len());
            for (k, v) in m {
                obj.insert(cbor_key_to_string(k), cbor_to_json_b64(v));
            }
            Value::Object(obj)
        }
        Cbor::Tag(_, inner) => cbor_to_json_b64(*inner),
    }
}

fn cbor_key_to_string(key: c2pa_cbor::Value) -> String {
    use c2pa_cbor::Value as Cbor;

    match key {
        Cbor::Text(s) => s,
        Cbor::Integer(i) => i.to_string(),
        Cbor::Bool(b) => b.to_string(),
        other => cbor_to_json_b64(other).to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use serde_bytes::ByteBuf;

    use super::*;

    #[test]
    fn byte_strings_round_trip() {
        #[derive(Serialize)]
        struct BytesAndArrays {
            bytes: ByteBuf,
            empty: ByteBuf,
            nested: Vec<ByteBuf>,
            values: Vec<i64>,
        }

        let data = BytesAndArrays {
            bytes: ByteBuf::from(vec![96, 128]),
            empty: ByteBuf::new(),
            nested: vec![ByteBuf::from(vec![0, 255]), ByteBuf::new()],
            values: vec![96, 384, -1],
        };
        let expected = c2pa_cbor::value::to_value(&data).unwrap();
        let json = to_json_b64(&data).unwrap();
        assert_eq!(from_json_b64(&json).unwrap(), expected);
        assert_eq!(from_json_b64(&data).unwrap(), expected);

        for bytes in [ByteBuf::new(), ByteBuf::from(vec![0, 255])] {
            let json = to_json_b64(&bytes).unwrap();
            assert_eq!(
                from_json_b64(json).unwrap(),
                c2pa_cbor::Value::Bytes(bytes.into_vec())
            );
        }
    }

    #[test]
    fn input_preserves_arrays_text_and_map_keys() {
        let json = serde_json::json!({
            "values": [96, 384],
            "empty": [],
            "nested": [[0, 255], {"values": [-1, 1.5]}],
            "plain": "AP8=",
            "invalid_marker": "b64'!'",
            "b64'AP8='": "unchanged"
        });
        assert_eq!(
            from_json_b64(&json).unwrap(),
            c2pa_cbor::value::to_value(&json).unwrap()
        );
    }

    #[test]
    fn json_values_match_serde_json() {
        let value = serde_json::json!({
            "null": null,
            "bool": true,
            "string": "metadata \u{1f5bc}",
            "minimum": i64::MIN,
            "maximum": i64::MAX,
            "float": 1.5,
            "arrays": [[], [0, 255, 384], {"nested": false}]
        });
        assert_eq!(to_json_b64(&value).unwrap(), value);
        assert_eq!(
            from_json_b64(&value).unwrap(),
            c2pa_cbor::value::to_value(&value).unwrap()
        );
    }

    #[test]
    fn unsupported_integers_return_errors_without_truncation() {
        for value in [1u64 << 63, u64::MAX] {
            assert!(matches!(
                to_json_b64(value),
                Err(crate::Error::CborError(_))
            ));
            assert!(matches!(
                from_json_b64(value),
                Err(crate::Error::CborError(_))
            ));
        }
    }

    #[test]
    fn malformed_markers_remain_text() {
        for text in [
            "b64'!'",
            "b64'AA='",
            "b64'AB=='",
            "b64'AP8=",
            "AP8='",
            "b64'\u{1f5bc}'",
        ] {
            assert_eq!(
                from_json_b64(text).unwrap(),
                c2pa_cbor::Value::Text(text.to_owned())
            );
        }
    }

    #[test]
    fn large_byte_strings_round_trip() {
        for bytes in [(0..=255).collect::<Vec<u8>>(), vec![0xa5; 1024 * 1024]] {
            let json = to_json_b64(ByteBuf::from(bytes.clone())).unwrap();
            assert_eq!(from_json_b64(json).unwrap(), c2pa_cbor::Value::Bytes(bytes));
        }
    }

    #[test]
    fn nested_values_round_trip() {
        let mut value = c2pa_cbor::Value::Bytes(vec![0, 255]);
        for _ in 0..128 {
            value = c2pa_cbor::Value::Array(vec![value]);
        }
        let json = cbor_to_json_b64(value.clone());
        assert_eq!(from_json_b64(json).unwrap(), value);
    }

    #[test]
    fn tags_and_non_text_keys_keep_legacy_projection() {
        use c2pa_cbor::Value as Cbor;

        let value = Cbor::Map(
            [
                (Cbor::Integer(42), Cbor::Text("number key".to_owned())),
                (Cbor::Bool(false), Cbor::Bytes(vec![0, 255])),
                (
                    Cbor::Text("tag".to_owned()),
                    Cbor::Tag(0, Box::new(Cbor::Text("2026-11-02T00:00:00Z".to_owned()))),
                ),
            ]
            .into_iter()
            .collect(),
        );
        assert_eq!(
            cbor_to_json_b64(value),
            serde_json::json!({
                "42": "number key",
                "false": "b64'AP8='",
                "tag": "2026-11-02T00:00:00Z"
            })
        );
        for float in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                cbor_to_json_b64(Cbor::Float(float)),
                serde_json::to_value(float).unwrap()
            );
        }
    }

    #[test]
    fn serialization_errors_are_propagated() {
        struct Invalid;
        impl Serialize for Invalid {
            fn serialize<S: serde::Serializer>(
                &self,
                _: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("deliberate serialization error"))
            }
        }
        assert!(to_json_b64(Invalid)
            .unwrap_err()
            .to_string()
            .contains("deliberate serialization error"));
        assert!(from_json_b64(Invalid)
            .unwrap_err()
            .to_string()
            .contains("deliberate serialization error"));
    }
}
