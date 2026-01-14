// Copyright 2025 Adobe. All rights reserved.
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

// Portions derived from serde_cbor (https://github.com/pyfisch/cbor)

// NOTE: we don't use serde_cbor here, we just verify we can emulate it.
use c2pa_cbor as serde_cbor;

#[test]
fn test_value_module_compat() {
    // Test value::to_value and value::from_value
    let val = serde_cbor::value::to_value(vec![1, 2, 3]).unwrap();
    let back: Vec<i32> = serde_cbor::value::from_value(val).unwrap();
    assert_eq!(back, vec![1, 2, 3]);
}

#[test]
fn test_ser_module_compat() {
    // Test ser::to_vec and ser::to_vec_packed
    let data = vec![1u8, 2, 3];
    let bytes = serde_cbor::ser::to_vec(&data).unwrap();
    let bytes2 = serde_cbor::ser::to_vec_packed(&data).unwrap();
    assert_eq!(bytes, bytes2);
}

#[test]
fn test_deserializer_from_slice() {
    // Test Deserializer::from_slice
    let data = vec![1u8, 2, 3];
    let bytes = serde_cbor::ser::to_vec(&data).unwrap();
    let decoded: Vec<u8> =
        serde::Deserialize::deserialize(&mut serde_cbor::Deserializer::from_slice(&bytes)).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn test_encoder_into_inner() {
    // Test Encoder::into_inner with owned writer
    let buf = Vec::new();
    let mut enc = serde_cbor::Encoder::new(buf);
    enc.encode(&42).unwrap();
    let result = enc.into_inner();
    assert!(!result.is_empty());
}

#[test]
fn test_tags_module() {
    // Test tags::Tagged
    let tagged = serde_cbor::tags::Tagged::new(Some(123), "test");
    assert_eq!(tagged.tag, Some(123));
    assert_eq!(tagged.value, "test");
}
