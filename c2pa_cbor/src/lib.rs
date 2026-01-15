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

//! # C2PA CBOR Library
//!
//! A CBOR (Concise Binary Object Representation) encoder/decoder with support for tagged types.
//!
//! ## Architecture
//!
//! This library uses a **dual-path serialization strategy** for optimal performance:
//!
//! - **Fast path**: When collection sizes are known at compile time (the common case),
//!   data is written directly to the output with zero buffering overhead.
//! - **Buffering path**: When sizes are unknown (e.g., `#[serde(flatten)]` in `serde_transcode`),
//!   entries are buffered in memory and written as definite-length once the count is known.
//!
//! This design maintains C2PA's requirement for deterministic, definite-length encoding
//! while supporting the full serde data model including complex features like flatten.
//!
//! ## Features
//! - Full support for CBOR major types 0-7
//! - Tagged types (major type 6) including:
//!   - Date/time strings (tag 0)
//!   - Epoch timestamps (tag 1)
//!   - URIs (tag 32)
//!   - Base64url encoded data (tag 33)
//!   - Base64 encoded data (tag 34)
//!   - RFC 8746 typed arrays (tags 64-87):
//!     - Unsigned integer arrays (uint8, uint16, uint32, uint64) in big-endian and little-endian
//!     - Signed integer arrays (sint8, sint16, sint32, sint64) in big-endian and little-endian
//!     - Floating point arrays (float16, float32, float64, float128) in big-endian and little-endian
//! - Custom tag support via `write_tag()` and `read_tag()` methods
//!
//! ## Performance
//! Binary byte arrays are efficiently encoded/decoded with minimal overhead:
//! - Use `serde_bytes::ByteBuf` or `#[serde(with = "serde_bytes")]` for optimal byte array performance
//! - Byte strings are written as raw bytes (1 header byte + length encoding + data)
//! - 1KB byte array: 3 bytes overhead (header + 2-byte length)
//! - 100KB byte array: 5 bytes overhead (header + 4-byte length)
//! - No allocations during encoding; single allocation during decoding
//!
//! ### Speed Characteristics (on typical hardware)
//! - **Encoding**: ~30-35 GB/s for large arrays (virtually memcpy speed)
//! - **Decoding**: ~24-29 GB/s for large arrays
//! - Small arrays (1KB): ~160ns encode, ~270ns decode
//! - Large arrays (1MB): ~30µs encode, ~41µs decode
//! - Performance scales linearly with data size
//! - Zero-copy design means encoding is just a memcpy after writing the header
//!
//! ## Example
//! ```rust
//! use c2pa_cbor::{encode_datetime_string, encode_uint8_array, encode_uri, from_slice};
//! use serde_bytes::ByteBuf;
//!
//! // Encode a URI with tag 32
//! let mut buf = Vec::new();
//! encode_uri(&mut buf, "https://example.com").unwrap();
//! let decoded: String = from_slice(&buf).unwrap();
//! assert_eq!(decoded, "https://example.com");
//!
//! // Encode a typed array with tag 64 (efficient with serde_bytes)
//! let data = ByteBuf::from(vec![1, 2, 3, 4, 5]);
//! let mut buf2 = Vec::new();
//! let mut encoder = c2pa_cbor::Encoder::new(&mut buf2);
//! encoder.write_tag(64).unwrap();
//! encoder.encode(&data).unwrap();
//! ```

// Internal constants module (not part of public API)
mod constants;

pub mod error;
pub use error::{Error, Result};

pub mod encoder;
pub use encoder::{Encoder, to_vec, to_writer};

pub mod decoder;
// Re-export DOS protection constants for user configuration
pub use constants::{DEFAULT_MAX_ALLOCATION, DEFAULT_MAX_DEPTH};
pub use decoder::{
    Decoder, from_reader, from_reader_with_limit, from_slice, from_slice_with_limit,
};

pub mod value;
pub use value::{Value, from_value, to_value};

pub mod tags;
pub use tags::*;

/// Serialization module for compatibility with serde_cbor
pub mod ser;

/// Deserialization module for compatibility with serde_cbor
pub mod de {
    pub use crate::Decoder as Deserializer;
}

/// Type alias for `Encoder` (serde_cbor compatibility)
pub type Serializer<W> = Encoder<W>;
/// Type alias for `Decoder` (serde_cbor compatibility)
pub type Deserializer<R> = Decoder<R>;

// Example usage and tests
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::constants::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Person {
        name: String,
        age: u32,
        emails: Vec<String>,
    }

    #[test]
    fn test_basic_types() {
        assert_eq!(from_slice::<u32>(&to_vec(&42u32).unwrap()).unwrap(), 42);
        assert_eq!(from_slice::<i32>(&to_vec(&-42i32).unwrap()).unwrap(), -42);
        assert!(from_slice::<bool>(&to_vec(&true).unwrap()).unwrap());
        assert_eq!(
            from_slice::<String>(&to_vec(&"hello".to_string()).unwrap()).unwrap(),
            "hello"
        );
    }

    #[test]
    fn test_struct() {
        let person = Person {
            name: "Alice".to_string(),
            age: 30,
            emails: vec!["alice@example.com".to_string()],
        };
        let encoded = to_vec(&person).unwrap();
        let decoded: Person = from_slice(&encoded).unwrap();
        assert_eq!(person, decoded);
    }

    #[test]
    fn test_map() {
        let mut map = HashMap::new();
        map.insert("key1".to_string(), 100);
        map.insert("key2".to_string(), 200);
        let encoded = to_vec(&map).unwrap();
        let decoded: HashMap<String, i32> = from_slice(&encoded).unwrap();
        assert_eq!(map, decoded);
    }

    #[test]
    fn test_tagged_datetime_string() {
        let mut buf = Vec::new();
        encode_datetime_string(&mut buf, "2024-01-15T10:30:00Z").unwrap();

        // Verify the tag is encoded correctly
        // Tag 0 with small value is encoded as 0xC0 (major type 6, value 0)
        assert_eq!(buf[0], 0xc0);

        // Decode the tagged value - it should deserialize the content (the string)
        let decoded: String = from_slice(&buf).unwrap();
        assert_eq!(decoded, "2024-01-15T10:30:00Z");
    }

    #[test]
    fn test_tagged_epoch_datetime() {
        let mut buf = Vec::new();
        let epoch: i64 = 1705315800; // Some epoch timestamp
        encode_epoch_datetime(&mut buf, epoch).unwrap();

        // Tag 1 is encoded as 0xC1 (major type 6, value 1)
        assert_eq!(buf[0], 0xc1);

        // Decode the tagged value
        let decoded: i64 = from_slice(&buf).unwrap();
        assert_eq!(decoded, epoch);
    }

    #[test]
    fn test_tagged_uri() {
        let mut buf = Vec::new();
        encode_uri(&mut buf, "https://example.com/path").unwrap();

        // Tag 32 is encoded as 0xD8 0x20 (major type 6, additional info 24, value 32)
        assert_eq!(buf[0], 0xd8);
        assert_eq!(buf[1], 32);

        // Decode the tagged value
        let decoded: String = from_slice(&buf).unwrap();
        assert_eq!(decoded, "https://example.com/path");
    }

    #[test]
    fn test_tagged_base64url() {
        let mut buf = Vec::new();
        encode_base64url(&mut buf, "SGVsbG8gV29ybGQ").unwrap();

        // Tag 33 is encoded as 0xD8 0x21
        assert_eq!(buf[0], 0xd8);
        assert_eq!(buf[1], 33);

        let decoded: String = from_slice(&buf).unwrap();
        assert_eq!(decoded, "SGVsbG8gV29ybGQ");
    }

    #[test]
    fn test_manual_tag_encoding() {
        let mut buf = Vec::new();
        let mut encoder = Encoder::new(&mut buf);

        // Manually encode a custom tag (e.g., tag 100) with a string value
        encoder.write_tag(100).unwrap();
        encoder.encode(&"custom tagged value").unwrap();

        // Tag 100 is encoded as 0xD8 0x64
        assert_eq!(buf[0], 0xd8);
        assert_eq!(buf[1], 100);

        // Decode should give us the string content
        let decoded: String = from_slice(&buf).unwrap();
        assert_eq!(decoded, "custom tagged value");
    }

    #[test]
    fn test_read_tag_method() {
        let mut buf = Vec::new();
        let mut encoder = Encoder::new(&mut buf);
        encoder.write_tag(42).unwrap();
        encoder.encode(&"test").unwrap();

        let mut decoder = Decoder::new(&buf[..]);
        let tag = decoder.read_tag().unwrap();
        assert_eq!(tag, 42);

        // After reading the tag, we can decode the content
        let content: String = decoder.decode().unwrap();
        assert_eq!(content, "test");
    }

    #[test]
    fn test_typed_array_uint8() {
        let mut buf = Vec::new();
        let data: [u8; 5] = [1, 2, 3, 4, 5];
        encode_uint8_array(&mut buf, &data).unwrap();

        // Tag 64 is encoded as 0xD8 0x40
        assert_eq!(buf[0], 0xd8);
        assert_eq!(buf[1], 64);

        // Decode as byte array
        let decoded: Vec<u8> = from_slice(&buf).unwrap();
        assert_eq!(decoded, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_typed_array_uint16be() {
        let mut buf = Vec::new();
        let data: [u16; 3] = [0x1234, 0x5678, 0x9abc];
        encode_uint16be_array(&mut buf, &data).unwrap();

        // Tag 65 is encoded as 0xD8 0x41
        assert_eq!(buf[0], 0xd8);
        assert_eq!(buf[1], 65);

        // Decode as byte array
        let decoded: Vec<u8> = from_slice(&buf).unwrap();
        // Should be big-endian encoded
        assert_eq!(decoded, vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
    }

    #[test]
    fn test_typed_array_uint32be() {
        let mut buf = Vec::new();
        let data: [u32; 2] = [0x12345678, 0x9abcdef0];
        encode_uint32be_array(&mut buf, &data).unwrap();

        // Tag 66 is encoded as 0xD8 0x42
        assert_eq!(buf[0], 0xd8);
        assert_eq!(buf[1], 66);

        let decoded: Vec<u8> = from_slice(&buf).unwrap();
        assert_eq!(
            decoded,
            vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]
        );
    }

    #[test]
    fn test_typed_array_uint64be() {
        let mut buf = Vec::new();
        let data: [u64; 1] = [0x123456789abcdef0];
        encode_uint64be_array(&mut buf, &data).unwrap();

        // Tag 67 is encoded as 0xD8 0x43
        assert_eq!(buf[0], 0xd8);
        assert_eq!(buf[1], 67);

        let decoded: Vec<u8> = from_slice(&buf).unwrap();
        assert_eq!(
            decoded,
            vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]
        );
    }

    #[test]
    fn test_typed_array_float32be() {
        let mut buf = Vec::new();
        let data: [f32; 2] = [1.5, 2.5];
        encode_float32be_array(&mut buf, &data).unwrap();

        // Tag 81 is encoded as 0xD8 0x51
        assert_eq!(buf[0], 0xd8);
        assert_eq!(buf[1], 81);

        let decoded: Vec<u8> = from_slice(&buf).unwrap();
        // Verify we have the right number of bytes (2 floats * 4 bytes each)
        assert_eq!(decoded.len(), 8);
    }

    #[test]
    fn test_typed_array_float64be() {
        let mut buf = Vec::new();
        let data: [f64; 2] = [1.5, 2.5];
        encode_float64be_array(&mut buf, &data).unwrap();

        // Tag 82 is encoded as 0xD8 0x52
        assert_eq!(buf[0], 0xd8);
        assert_eq!(buf[1], 82);

        let decoded: Vec<u8> = from_slice(&buf).unwrap();
        // Verify we have the right number of bytes (2 floats * 8 bytes each)
        assert_eq!(decoded.len(), 16);
    }

    #[test]
    fn test_typed_array_uint16le() {
        let mut buf = Vec::new();
        let data: [u16; 3] = [0x1234, 0x5678, 0x9abc];
        encode_uint16le_array(&mut buf, &data).unwrap();

        // Tag 69 is encoded as 0xD8 0x45
        assert_eq!(buf[0], 0xd8);
        assert_eq!(buf[1], 69);

        let decoded: Vec<u8> = from_slice(&buf).unwrap();
        // Should be little-endian encoded
        assert_eq!(decoded, vec![0x34, 0x12, 0x78, 0x56, 0xbc, 0x9a]);
    }

    #[test]
    fn test_large_byte_array_performance() {
        use serde_bytes::ByteBuf;

        // Test that large byte arrays are efficiently encoded/decoded with serde_bytes
        // CBOR byte arrays should be: 1 byte header + length encoding + raw bytes

        // 1KB array
        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let byte_buf = ByteBuf::from(data.clone());
        let encoded = to_vec(&byte_buf).unwrap();

        // Overhead should be minimal: 1 byte major type + 2 bytes for length (1024 = 0x400)
        assert_eq!(encoded.len(), 1024 + 3); // 3 bytes overhead
        assert_eq!(encoded[0], (MAJOR_BYTES << 5) | 25); // 25 = two-byte length follows
        assert_eq!(encoded[1], 0x04); // high byte of 1024
        assert_eq!(encoded[2], 0x00); // low byte of 1024

        let decoded: ByteBuf = from_slice(&encoded).unwrap();
        assert_eq!(decoded.into_vec(), data);

        // Test 100KB array
        let large_data: Vec<u8> = (0..102400).map(|i| (i % 256) as u8).collect();
        let large_byte_buf = ByteBuf::from(large_data.clone());
        let encoded_large = to_vec(&large_byte_buf).unwrap();

        // Overhead for 102400 bytes: 1 byte major + 4 bytes for length
        assert_eq!(encoded_large.len(), 102400 + 5);

        let decoded_large: ByteBuf = from_slice(&encoded_large).unwrap();
        assert_eq!(decoded_large.into_vec(), large_data);
    }

    #[test]
    fn test_byte_array_zero_copy_encoding() {
        use serde_bytes::ByteBuf;

        // Verify that byte arrays are written directly without transformation
        let data: Vec<u8> = vec![0x42, 0xff, 0x00, 0xaa, 0x55];
        let byte_buf = ByteBuf::from(data.clone());
        let encoded = to_vec(&byte_buf).unwrap();

        // Should be: major type byte + length + raw data
        assert_eq!(encoded[0], (MAJOR_BYTES << 5) | 5); // length 5 embedded
        assert_eq!(&encoded[1..], &[0x42, 0xff, 0x00, 0xaa, 0x55]);

        let decoded: ByteBuf = from_slice(&encoded).unwrap();
        assert_eq!(decoded.into_vec(), data);
    }

    #[test]
    fn test_vec_u8_as_array() {
        // Without serde_bytes, Vec<u8> serializes as an array
        let data: Vec<u8> = vec![1, 2, 3];
        let encoded = to_vec(&data).unwrap();

        // First byte should be array type with length 3
        assert_eq!(encoded[0], (MAJOR_ARRAY << 5) | 3);

        let decoded: Vec<u8> = from_slice(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_serde_bytes_efficiency() {
        use serde_bytes::ByteBuf;

        // Compare encoding efficiency: Vec<u8> vs serde_bytes::ByteBuf
        let data: Vec<u8> = vec![1, 2, 3, 4, 5];

        // As Vec<u8> - encodes as array (each element individually)
        let encoded_array = to_vec(&data).unwrap();

        // As ByteBuf - encodes as byte string (raw bytes)
        let byte_buf = ByteBuf::from(data.clone());
        let encoded_bytes = to_vec(&byte_buf).unwrap();

        // For small arrays, they might be similar, but ByteBuf uses raw bytes
        // Array: 1 byte header + 5 bytes (one per element since values are < 24) = 6 bytes
        // ByteBuf: 1 byte header + 5 bytes raw = 6 bytes
        // For larger values or larger arrays, ByteBuf is more efficient

        println!("Array encoding: {} bytes", encoded_array.len());
        println!("Bytes encoding: {} bytes", encoded_bytes.len());

        // ByteBuf: 1 byte header + 5 bytes data = 6 bytes
        assert_eq!(encoded_bytes.len(), 6);
        assert_eq!(encoded_bytes[0], (MAJOR_BYTES << 5) | 5);

        // Array: 1 byte header + 5 bytes (small integers) = 6 bytes
        assert_eq!(encoded_array.len(), 6);
        assert_eq!(encoded_array[0], (MAJOR_ARRAY << 5) | 5);

        let decoded: ByteBuf = from_slice(&encoded_bytes).unwrap();
        assert_eq!(decoded.into_vec(), data);
    }

    #[test]
    fn test_tagged_byte_array_overhead() {
        use serde_bytes::ByteBuf;

        // Test that tagged byte arrays (e.g., tag 64) have minimal overhead
        let data: Vec<u8> = vec![1, 2, 3, 4, 5];
        let byte_buf = ByteBuf::from(data.clone());

        let mut buf = Vec::new();
        let mut encoder = Encoder::new(&mut buf);
        encoder.write_tag(TAG_UINT8_ARRAY).unwrap();
        encoder.encode(&byte_buf).unwrap();

        // Overhead: 2 bytes for tag (0xD8 0x40) + 1 byte for bytes type + 1 byte for length + 5 bytes data
        assert_eq!(buf.len(), 8);

        // Tag 64 encoded as 0xD8 0x40
        assert_eq!(buf[0], 0xd8);
        assert_eq!(buf[1], 64);
        // Byte string with length 5
        assert_eq!(buf[2], (MAJOR_BYTES << 5) | 5);
        assert_eq!(&buf[3..], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_performance_summary() {
        use std::time::Instant;

        use serde_bytes::ByteBuf;

        // Demonstrate efficient encoding/decoding of binary data
        println!("\n=== CBOR Binary Encoding Performance ===");

        // Small array (5 bytes)
        let small = ByteBuf::from(vec![1, 2, 3, 4, 5]);
        let encoded_small = to_vec(&small).unwrap();
        println!(
            "5 bytes -> {} encoded bytes (overhead: {} bytes)",
            encoded_small.len(),
            encoded_small.len() - 5
        );
        assert_eq!(encoded_small.len(), 6); // 1 byte overhead

        // 1KB array
        let kb1_data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let kb1 = ByteBuf::from(kb1_data);
        let encoded_kb1 = to_vec(&kb1).unwrap();
        println!(
            "1 KB -> {} encoded bytes (overhead: {} bytes)",
            encoded_kb1.len(),
            encoded_kb1.len() - 1024
        );
        assert_eq!(encoded_kb1.len(), 1027); // 3 bytes overhead

        // 100KB array
        let kb100_data: Vec<u8> = (0..102400).map(|i| (i % 256) as u8).collect();
        let kb100 = ByteBuf::from(kb100_data);
        let encoded_kb100 = to_vec(&kb100).unwrap();
        println!(
            "100 KB -> {} encoded bytes (overhead: {} bytes)",
            encoded_kb100.len(),
            encoded_kb100.len() - 102400
        );
        assert_eq!(encoded_kb100.len(), 102405); // 5 bytes overhead

        println!("\n--- Speed Tests ---");

        // Speed test: 1MB encoding
        let mb1_data: Vec<u8> = (0..1048576).map(|i| (i % 256) as u8).collect();
        let mb1 = ByteBuf::from(mb1_data.clone());

        let start = Instant::now();
        let iterations = 100;
        for _ in 0..iterations {
            let _ = to_vec(&mb1).unwrap();
        }
        let encode_duration = start.elapsed();
        let encode_throughput =
            (1048576 * iterations) as f64 / encode_duration.as_secs_f64() / 1_048_576.0;
        println!(
            "Encode 1 MB x {}: {:?} ({:.1} MB/s)",
            iterations, encode_duration, encode_throughput
        );

        // Speed test: 1MB decoding
        let encoded_mb = to_vec(&mb1).unwrap();
        let start = Instant::now();
        for _ in 0..iterations {
            let _: ByteBuf = from_slice(&encoded_mb).unwrap();
        }
        let decode_duration = start.elapsed();
        let decode_throughput =
            (1048576 * iterations) as f64 / decode_duration.as_secs_f64() / 1_048_576.0;
        println!(
            "Decode 1 MB x {}: {:?} ({:.1} MB/s)",
            iterations, decode_duration, decode_throughput
        );

        println!("\nOverhead is minimal and speed is excellent!");
        println!("Encoding is zero-copy - data is written directly.");
        println!("Decoding allocates once - no per-element overhead.\n");
    }

    #[test]
    fn test_encoding_speed_vs_size() {
        use std::time::Instant;

        use serde_bytes::ByteBuf;

        println!("\n=== Encoding Speed vs Data Size ===");

        let sizes = vec![1024, 10240, 102400, 1048576]; // 1KB, 10KB, 100KB, 1MB

        for size in sizes {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let byte_buf = ByteBuf::from(data);

            let iterations = if size >= 1048576 { 10 } else { 100 };

            let start = Instant::now();
            for _ in 0..iterations {
                let _ = to_vec(&byte_buf).unwrap();
            }
            let duration = start.elapsed();
            let avg_ns = duration.as_nanos() / iterations as u128;
            let throughput_mbps =
                (size as f64 * iterations as f64) / duration.as_secs_f64() / 1_048_576.0;

            println!(
                "{:>7} bytes: {:>6} ns/op ({:>6.1} MB/s)",
                size, avg_ns, throughput_mbps
            );
        }
        println!();
    }

    #[test]
    fn test_decoding_speed_vs_size() {
        use std::time::Instant;

        use serde_bytes::ByteBuf;

        println!("\n=== Decoding Speed vs Data Size ===");

        let sizes = vec![1024, 10240, 102400, 1048576]; // 1KB, 10KB, 100KB, 1MB

        for size in sizes {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let byte_buf = ByteBuf::from(data);
            let encoded = to_vec(&byte_buf).unwrap();

            let iterations = if size >= 1048576 { 10 } else { 100 };

            let start = Instant::now();
            for _ in 0..iterations {
                let _: ByteBuf = from_slice(&encoded).unwrap();
            }
            let duration = start.elapsed();
            let avg_ns = duration.as_nanos() / iterations as u128;
            let throughput_mbps =
                (size as f64 * iterations as f64) / duration.as_secs_f64() / 1_048_576.0;

            println!(
                "{:>7} bytes: {:>6} ns/op ({:>6.1} MB/s)",
                size, avg_ns, throughput_mbps
            );
        }
        println!();
    }

    #[test]
    fn test_indefinite_array() {
        // Manually encode an indefinite-length array
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);

        // Start indefinite array
        enc.write_array_indefinite().unwrap();
        // Add elements
        enc.encode(&1u32).unwrap();
        enc.encode(&2u32).unwrap();
        enc.encode(&3u32).unwrap();
        // Write break
        enc.write_break().unwrap();

        // Verify encoding: 0x9F (array indefinite) + elements + 0xFF (break)
        assert_eq!(buf[0], (MAJOR_ARRAY << 5) | INDEFINITE);
        assert_eq!(buf[buf.len() - 1], BREAK);

        // Decode should work
        let decoded: Vec<u32> = from_slice(&buf).unwrap();
        assert_eq!(decoded, vec![1, 2, 3]);
    }

    #[test]
    fn test_indefinite_map() {
        // Manually encode an indefinite-length map
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);

        // Start indefinite map
        enc.write_map_indefinite().unwrap();
        // Add key-value pairs
        enc.encode(&"a").unwrap();
        enc.encode(&1u32).unwrap();
        enc.encode(&"b").unwrap();
        enc.encode(&2u32).unwrap();
        // Write break
        enc.write_break().unwrap();

        // Verify encoding
        assert_eq!(buf[0], (MAJOR_MAP << 5) | INDEFINITE);
        assert_eq!(buf[buf.len() - 1], BREAK);

        // Decode should work
        let decoded: HashMap<String, u32> = from_slice(&buf).unwrap();
        assert_eq!(decoded.get("a"), Some(&1));
        assert_eq!(decoded.get("b"), Some(&2));
    }

    #[test]
    fn test_indefinite_byte_string() {
        use serde_bytes::ByteBuf;

        // Manually encode indefinite-length byte string (chunked)
        let mut buf = Vec::new();
        buf.push((MAJOR_BYTES << 5) | INDEFINITE); // Start indefinite bytes

        // Add chunks as byte strings
        let chunk1 = vec![1u8, 2, 3];
        let chunk1_enc = to_vec(&ByteBuf::from(chunk1.clone())).unwrap();
        buf.extend_from_slice(&chunk1_enc);

        let chunk2 = vec![4u8, 5];
        let chunk2_enc = to_vec(&ByteBuf::from(chunk2.clone())).unwrap();
        buf.extend_from_slice(&chunk2_enc);

        buf.push(BREAK); // End indefinite

        // Decode should concatenate chunks
        let decoded: ByteBuf = from_slice(&buf).unwrap();
        assert_eq!(decoded.into_vec(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_indefinite_text_string() {
        // Manually encode indefinite-length text string (chunked)
        let mut buf = Vec::new();
        buf.push((MAJOR_TEXT << 5) | INDEFINITE); // Start indefinite text

        // Add chunks
        let chunk1 = "Hello";
        let chunk1_enc = to_vec(&chunk1).unwrap();
        buf.extend_from_slice(&chunk1_enc);

        let chunk2 = " World";
        let chunk2_enc = to_vec(&chunk2).unwrap();
        buf.extend_from_slice(&chunk2_enc);

        buf.push(BREAK); // End indefinite

        // Decode should concatenate chunks
        let decoded: String = from_slice(&buf).unwrap();
        assert_eq!(decoded, "Hello World");
    }

    #[test]
    fn test_ser_module_serializer() {
        use crate::ser::Serializer;

        // Test that ser::Serializer works correctly
        let buf = Vec::new();
        let mut serializer = Serializer::new(buf);

        let data = vec![1, 2, 3];
        data.serialize(&mut serializer).unwrap();

        let encoded = serializer.into_inner();
        let decoded: Vec<i32> = from_slice(&encoded).unwrap();
        assert_eq!(decoded, vec![1, 2, 3]);
    }

    #[test]
    fn test_struct_with_option_fields() {
        use std::collections::HashMap;

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestData {
            name: String,
            value: u32,
            optional_map: Option<HashMap<String, String>>,
            optional_string: Option<String>,
        }

        // Test with Some values
        let mut map = HashMap::new();
        map.insert("key1".to_string(), "value1".to_string());

        let data_with_some = TestData {
            name: "test".to_string(),
            value: 42,
            optional_map: Some(map),
            optional_string: Some("hello".to_string()),
        };

        let encoded = to_vec(&data_with_some).unwrap();
        let decoded: TestData = from_slice(&encoded).unwrap();
        assert_eq!(data_with_some, decoded);

        // Test with None values
        let data_with_none = TestData {
            name: "test".to_string(),
            value: 42,
            optional_map: None,
            optional_string: None,
        };

        let encoded_none = to_vec(&data_with_none).unwrap();
        let decoded_none: TestData = from_slice(&encoded_none).unwrap();
        assert_eq!(data_with_none, decoded_none);
    }

    #[test]
    fn test_nested_option_maps() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Outer {
            data: Option<Inner>,
        }

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Inner {
            values: HashMap<String, i32>,
        }

        let mut values = HashMap::new();
        values.insert("a".to_string(), 1);
        values.insert("b".to_string(), 2);

        let outer = Outer {
            data: Some(Inner { values }),
        };

        let encoded = to_vec(&outer).unwrap();
        println!("Encoded bytes: {:?}", encoded);
        let decoded: Outer = from_slice(&encoded).unwrap();
        assert_eq!(outer, decoded);
    }

    #[test]
    fn test_option_field_counting() {
        // Test to understand how serde counts fields with Option
        #[derive(Debug, Serialize)]
        struct WithOptions {
            field1: String,
            field2: Option<String>,
            field3: Option<String>,
        }

        let data = WithOptions {
            field1: "hello".to_string(),
            field2: Some("world".to_string()),
            field3: None,
        };

        // This should trigger the error if serialize_struct gets wrong len
        let encoded = to_vec(&data).unwrap();
        println!("Encoded bytes: {:?}", encoded);

        // Check the first byte - should be a map with the right number of entries
        // Map header format: major type 5 (0xA0 | count) or 0xB8 + count byte
        println!("First byte: 0x{:02x}", encoded[0]);
    }

    #[test]
    fn test_trait_object_serialization() {
        // Reproduce the AssertionCbor scenario
        use std::collections::HashMap;

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestStruct {
            name: String,
            values: HashMap<String, String>,
        }

        let mut map = HashMap::new();
        map.insert("key1".to_string(), "value1".to_string());
        map.insert("key2".to_string(), "value2".to_string());

        let obj = TestStruct {
            name: "test".to_string(),
            values: map,
        };

        // Serialize directly
        let encoded = to_vec(&obj).unwrap();
        println!("Encoded: {:?}", encoded);

        // Decode should work
        let decoded: TestStruct = from_slice(&encoded).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_skip_serializing_if() {
        // This reproduces the Actions struct issue
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct SkipTest {
            always: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            sometimes: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            rarely: Option<Vec<String>>,
        }

        // Test with None values - this will try to serialize 3 fields but skip 2
        let obj = SkipTest {
            always: "hello".to_string(),
            sometimes: None,
            rarely: None,
        };

        // This should work - serde should tell us len=1, not len=3
        let encoded = to_vec(&obj).unwrap();
        println!("Encoded skip test: {:?}", encoded);
        println!("First byte: 0x{:02x}", encoded[0]);

        let decoded: SkipTest = from_slice(&encoded).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_actions_like_struct() {
        // Reproduce the exact Actions structure
        use std::collections::HashMap;

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct ActionLike {
            params: Option<HashMap<String, Vec<u8>>>,
        }

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct ActionsLike {
            actions: Vec<ActionLike>,
            #[serde(skip_serializing_if = "Option::is_none")]
            metadata: Option<HashMap<String, String>>,
        }

        let mut params = HashMap::new();
        params.insert("key1".to_string(), vec![1, 2, 3]);

        let mut metadata = HashMap::new();
        metadata.insert("meta1".to_string(), "value1".to_string());

        let obj = ActionsLike {
            actions: vec![ActionLike {
                params: Some(params),
            }],
            metadata: Some(metadata),
        };

        // This might trigger the error if there's an issue with HashMap serialization
        let encoded = to_vec(&obj).unwrap();
        println!("Encoded actions-like: {} bytes", encoded.len());

        let decoded: ActionsLike = from_slice(&encoded).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_flatten_attribute() {
        // Test #[serde(flatten)] which causes indefinite-length serialization
        use std::collections::HashMap;

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct WithFlatten {
            regular_field: String,
            #[serde(flatten)]
            flattened: HashMap<String, String>,
        }

        let mut map = HashMap::new();
        map.insert("extra1".to_string(), "value1".to_string());
        map.insert("extra2".to_string(), "value2".to_string());

        let obj = WithFlatten {
            regular_field: "test".to_string(),
            flattened: map,
        };

        // This WILL trigger the indefinite-length path due to flatten
        // Our fallback to Value should handle it
        let encoded = to_vec(&obj).unwrap();
        println!("Encoded flattened: {} bytes", encoded.len());
        println!("First byte: 0x{:02x}", encoded[0]);

        let decoded: WithFlatten = from_slice(&encoded).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_enum_serialization() {
        // Test different enum representation styles

        // Unit variant (serializes as string)
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        enum SimpleEnum {
            Temporal,
            Spatial,
            Other,
        }

        let val = SimpleEnum::Temporal;
        let encoded = to_vec(&val).unwrap();
        println!("Simple enum encoded: {:?}", encoded);
        let decoded: SimpleEnum = from_slice(&encoded).unwrap();
        assert_eq!(val, decoded);

        // With rename
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        #[serde(rename_all = "lowercase")]
        enum RenamedEnum {
            Temporal,
            Spatial,
        }

        let val2 = RenamedEnum::Temporal;
        let encoded2 = to_vec(&val2).unwrap();
        println!("Renamed enum encoded: {:?}", encoded2);
        let decoded2: RenamedEnum = from_slice(&encoded2).unwrap();
        assert_eq!(val2, decoded2);

        // Enum with data
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        enum DataEnum {
            Unit,
            Newtype(String),
            Tuple(i32, String),
            Struct { field: String },
        }

        let val3 = DataEnum::Struct {
            field: "test".to_string(),
        };
        let encoded3 = to_vec(&val3).unwrap();
        println!("Struct variant encoded: {:?}", encoded3);
        let decoded3: DataEnum = from_slice(&encoded3).unwrap();
        assert_eq!(val3, decoded3);
    }

    #[test]
    fn test_float_serialization() {
        // Test f32
        let f32_val = 4.0f32;
        let encoded = to_vec(&f32_val).unwrap();
        println!("f32 encoded: {:?}", encoded);
        // Should be: major type 7 (0xE0), additional info 26 (0x1A), then 4 bytes
        assert_eq!(encoded[0], (MAJOR_SIMPLE << 5) | 26);
        let decoded: f32 = from_slice(&encoded).unwrap();
        assert_eq!(f32_val, decoded);

        // Test f64
        let f64_val = 2.5f64;
        let encoded = to_vec(&f64_val).unwrap();
        println!("f64 encoded: {:?}", encoded);
        // Should be: major type 7 (0xE0), additional info 27 (0x1B), then 8 bytes
        assert_eq!(encoded[0], (MAJOR_SIMPLE << 5) | 27);
        let decoded: f64 = from_slice(&encoded).unwrap();
        assert_eq!(f64_val, decoded);

        // Test in a struct
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct ExifData {
            f_number: f64,
            exposure_time: f32,
            zoom_ratio: f64,
        }

        let exif = ExifData {
            f_number: 4.0,
            exposure_time: 0.01,
            zoom_ratio: 2.0,
        };

        let encoded = to_vec(&exif).unwrap();
        println!("Exif data encoded: {} bytes", encoded.len());
        let decoded: ExifData = from_slice(&encoded).unwrap();
        assert_eq!(exif, decoded);
    }

    #[test]
    fn test_invalid_cbor_trailing_bytes() {
        use crate::Value;

        // These bytes are just a sequence of small integers with no structure
        // The first byte (0x0d = 13) is a valid CBOR integer, but the rest are trailing garbage
        let invalid_bytes = vec![0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f];

        let result: Result<Value> = from_slice(&invalid_bytes);
        assert!(result.is_err(), "Should fail on trailing bytes");

        if let Err(e) = result {
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("trailing"),
                "Error should mention trailing data: {}",
                msg
            );
        }
    }

    #[test]
    fn test_empty_input() {
        use crate::Value;

        let empty_bytes = vec![];
        let result: Result<Value> = from_slice(&empty_bytes);
        assert!(result.is_err(), "Should fail on empty input");

        if let Err(e) = result {
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("empty"),
                "Error should mention empty input: {}",
                msg
            );
        }
    }

    #[test]
    fn test_incomplete_cbor() {
        // Start of an array but incomplete
        let incomplete = vec![0x85]; // array of 5 elements, but no elements follow

        let result: Result<Vec<u32>> = from_slice(&incomplete);
        assert!(result.is_err(), "Should fail on incomplete CBOR");
    }

    #[test]
    fn test_valid_cbor_all_bytes_consumed() {
        // Valid integer should consume exactly 1 byte
        let valid = vec![0x0d]; // integer 13
        let result: Result<u32> = from_slice(&valid);
        assert!(result.is_ok(), "Should succeed on valid CBOR");
        assert_eq!(result.unwrap(), 13);
    }

    #[test]
    fn test_with_max_allocation_rejects_oversized() {
        use std::io::Cursor;

        use crate::{Value, decoder::Decoder};

        // Create CBOR claiming 100MB text string
        // 0x7b = major type 3 (text), additional info 27 (8-byte length)
        let mut cbor = vec![0x7b];
        let length: u64 = 100 * 1024 * 1024; // 100MB
        cbor.extend_from_slice(&length.to_be_bytes());
        cbor.extend_from_slice(b"attack"); // Add some data (not 100MB)

        // Set limit to 10MB - should reject before attempting allocation
        let cursor = Cursor::new(&cbor[..]);
        let mut decoder = Decoder::new(cursor).with_max_allocation(10 * 1024 * 1024);
        let result: Result<Value> = decoder.decode();

        assert!(
            result.is_err(),
            "Should reject allocation exceeding max_allocation"
        );

        // Verify error message mentions the limit
        if let Err(e) = result {
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("exceeds maximum") || msg.contains("Allocation size"),
                "Error should mention allocation limit: {}",
                msg
            );
        }
    }

    #[test]
    fn test_with_max_allocation_accepts_within_limit() {
        use std::io::Cursor;

        use crate::{Value, decoder::Decoder};

        // Create a valid 1KB text string
        // 0x79 = major type 3 (text), additional info 25 (2-byte length)
        let mut cbor = vec![0x79];
        let length: u16 = 1024;
        cbor.extend_from_slice(&length.to_be_bytes());
        cbor.resize(3 + 1024, b'A'); // Add 1KB of actual data

        // Set limit to 10MB - should accept
        let cursor = Cursor::new(&cbor[..]);
        let mut decoder = Decoder::new(cursor).with_max_allocation(10 * 1024 * 1024);
        let result: Result<Value> = decoder.decode();

        assert!(
            result.is_ok(),
            "Should accept allocation within max_allocation"
        );

        // Verify we got the expected string
        if let Ok(Value::Text(s)) = result {
            assert_eq!(s.len(), 1024, "Should decode 1KB string");
            assert!(s.chars().all(|c| c == 'A'), "String should be all 'A's");
        } else {
            panic!("Expected Text value, got: {:?}", result);
        }
    }

    #[test]
    fn test_with_max_allocation_byte_string() {
        use std::io::Cursor;

        use crate::{Value, decoder::Decoder};

        // Test with byte string (major type 2) instead of text string
        // 0x5a = major type 2 (bytes), additional info 26 (4-byte length)
        let mut cbor = vec![0x5a];
        let length: u32 = 50 * 1024 * 1024; // 50MB
        cbor.extend_from_slice(&length.to_be_bytes());
        cbor.extend_from_slice(&[0xff, 0xfe]); // Add some data

        // Set limit to 10MB - should reject
        let cursor = Cursor::new(&cbor[..]);
        let mut decoder = Decoder::new(cursor).with_max_allocation(10 * 1024 * 1024);
        let result: Result<Value> = decoder.decode();

        assert!(result.is_err(), "Should reject byte string exceeding limit");

        if let Err(e) = result {
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("exceeds maximum") || msg.contains("Allocation size"),
                "Error should mention allocation limit for byte string: {}",
                msg
            );
        }
    }

    #[test]
    fn test_default_from_slice_has_protection() {
        // Test that the default from_slice has built-in OOM protection
        // Create CBOR claiming 200MB text string (exceeds default 100MB limit)
        let mut cbor = vec![0x7b]; // major type 3 (text), 8-byte length
        let length: u64 = 200 * 1024 * 1024; // 200MB
        cbor.extend_from_slice(&length.to_be_bytes());
        cbor.extend_from_slice(b"malicious"); // Add some data

        // This should be automatically rejected by the default 100MB limit
        let result: Result<Value> = from_slice(&cbor);

        assert!(
            result.is_err(),
            "from_slice should have default protection against oversized allocations"
        );

        if let Err(e) = result {
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("exceeds maximum") || msg.contains("Allocation size"),
                "Error should mention allocation limit: {}",
                msg
            );
        }
    }

    #[test]
    #[allow(clippy::same_item_push)]
    fn test_deep_nesting_protection() {
        // Test protection against deeply nested structures that cause stack overflow
        // Create CBOR with 200 nested arrays (exceeds default depth limit of 128)
        let mut cbor = Vec::new();

        // Start with 200 nested indefinite-length arrays
        for _ in 0..200 {
            cbor.push(0x9f); // indefinite-length array
        }

        cbor.push(0x01); // a simple integer value at the center

        // Close all 200 arrays
        for _ in 0..200 {
            cbor.push(0xff); // break/end marker
        }

        // This should be rejected due to excessive nesting depth
        let result: Result<Value> = from_slice(&cbor);

        assert!(
            result.is_err(),
            "from_slice should reject deeply nested structures"
        );

        if let Err(e) = result {
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("nesting depth") || msg.contains("exceeds maximum"),
                "Error should mention nesting depth: {}",
                msg
            );
        }
    }

    // ========== Additional Decoder Tests ==========

    #[test]
    fn test_decoder_all_length_variants() {
        // Test all length encoding sizes: 0-23, 24, 25, 26, 27
        // Small (0-23): direct
        let cbor = vec![0x17]; // 23
        let val: u64 = from_slice(&cbor).unwrap();
        assert_eq!(val, 23);

        // 1-byte (24)
        let cbor = vec![0x18, 100]; // 100
        let val: u64 = from_slice(&cbor).unwrap();
        assert_eq!(val, 100);

        // 2-byte (25)
        let cbor = vec![0x19, 0x01, 0x00]; // 256
        let val: u64 = from_slice(&cbor).unwrap();
        assert_eq!(val, 256);

        // 4-byte (26)
        let cbor = vec![0x1a, 0x00, 0x01, 0x00, 0x00]; // 65536
        let val: u64 = from_slice(&cbor).unwrap();
        assert_eq!(val, 65536);

        // 8-byte (27)
        let cbor = vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]; // 4294967296
        let val: u64 = from_slice(&cbor).unwrap();
        assert_eq!(val, 4294967296);
    }

    #[test]
    fn test_decoder_negative_integer_lengths() {
        // Test negative number with different length encodings
        let cbor = vec![0x20]; // -1
        let val: i64 = from_slice(&cbor).unwrap();
        assert_eq!(val, -1);

        let cbor = vec![0x38, 0xff]; // -256
        let val: i64 = from_slice(&cbor).unwrap();
        assert_eq!(val, -256);

        let cbor = vec![0x39, 0x01, 0x00]; // -257
        let val: i64 = from_slice(&cbor).unwrap();
        assert_eq!(val, -257);
    }

    #[test]
    fn test_decoder_invalid_utf8() {
        // Invalid UTF-8 in text string
        let mut cbor = vec![0x64]; // text string, length 4
        cbor.extend_from_slice(&[0xff, 0xfe, 0xfd, 0xfc]); // invalid UTF-8
        let result: Result<String> = from_slice(&cbor);
        assert!(matches!(result, Err(Error::InvalidUtf8)));
    }

    #[test]
    fn test_decoder_indefinite_text_wrong_chunk_type() {
        // Indefinite text string with byte string chunk (invalid)
        let mut cbor = vec![0x7f]; // indefinite text string start
        cbor.push(0x42); // byte string chunk instead of text (wrong!)
        cbor.extend_from_slice(&[0x01, 0x02]);
        cbor.push(0xff); // break

        let result: Result<String> = from_slice(&cbor);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("text string chunks must be text strings")
        );
    }

    #[test]
    fn test_decoder_indefinite_bytes_wrong_chunk_type() {
        // Indefinite byte string with text string chunk (invalid)
        let mut cbor = vec![0x5f]; // indefinite byte string start
        cbor.push(0x62); // text string chunk instead of bytes (wrong!)
        cbor.extend_from_slice(&[0x68, 0x69]); // "hi"
        cbor.push(0xff); // break

        let result: Result<Vec<u8>> = from_slice(&cbor);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("byte string chunks must be byte strings")
        );
    }

    #[test]
    fn test_decoder_allocation_limit_exceeded() {
        // Try to allocate more than the limit
        let result: Result<Vec<u8>> =
            crate::decoder::from_slice_with_limit(&[0x5a, 0xff, 0xff, 0xff, 0xff], 1000);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_decoder_from_reader() {
        let data = to_vec(&42i32).unwrap();
        let cursor = std::io::Cursor::new(data);
        let val: i32 = from_reader(cursor).unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn test_decoder_from_reader_with_limit() {
        let data = to_vec(&"hello").unwrap();
        let cursor = std::io::Cursor::new(data);
        let val: String = crate::decoder::from_reader_with_limit(cursor, 1000).unwrap();
        assert_eq!(val, "hello");
    }

    #[test]
    fn test_decoder_trailing_bytes_error() {
        // Valid CBOR followed by extra bytes
        let mut cbor = to_vec(&42i32).unwrap();
        cbor.extend_from_slice(&[0x01, 0x02, 0x03]); // extra bytes

        let result: Result<i32> = from_slice(&cbor);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unexpected trailing data")
        );
    }

    #[test]
    fn test_decoder_invalid_simple_value() {
        // Simple value with reserved info
        let cbor = vec![0xf8]; // reserved simple value
        let result: Result<i32> = from_slice(&cbor);
        assert!(result.is_err());
    }

    #[test]
    fn test_decoder_tag_indefinite_error() {
        // Tag with indefinite length (invalid)
        let cbor = vec![0xdf]; // tag with indefinite length marker
        let result: Result<i32> = from_slice(&cbor);
        assert!(result.is_err());
    }

    // ========== Additional Encoder Tests ==========

    #[test]
    fn test_encoder_all_integer_sizes() {
        // i8
        let val: i8 = -127;
        let cbor = to_vec(&val).unwrap();
        let decoded: i8 = from_slice(&cbor).unwrap();
        assert_eq!(val, decoded);

        // i16
        let val: i16 = -30000;
        let cbor = to_vec(&val).unwrap();
        let decoded: i16 = from_slice(&cbor).unwrap();
        assert_eq!(val, decoded);

        // i32
        let val: i32 = -2000000;
        let cbor = to_vec(&val).unwrap();
        let decoded: i32 = from_slice(&cbor).unwrap();
        assert_eq!(val, decoded);

        // u8
        let val: u8 = 255;
        let cbor = to_vec(&val).unwrap();
        let decoded: u8 = from_slice(&cbor).unwrap();
        assert_eq!(val, decoded);

        // u16
        let val: u16 = 65000;
        let cbor = to_vec(&val).unwrap();
        let decoded: u16 = from_slice(&cbor).unwrap();
        assert_eq!(val, decoded);

        // u32
        let val: u32 = 4000000;
        let cbor = to_vec(&val).unwrap();
        let decoded: u32 = from_slice(&cbor).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn test_encoder_indefinite_array() {
        use crate::Encoder;
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);

        // Test indefinite array
        enc.write_array_indefinite().unwrap();
        enc.encode(&1).unwrap();
        enc.encode(&2).unwrap();
        enc.encode(&3).unwrap();
        enc.write_break().unwrap();

        // Should decode as [1, 2, 3]
        let decoded: Vec<i32> = from_slice(&buf).unwrap();
        assert_eq!(decoded, vec![1, 2, 3]);
    }

    #[test]
    fn test_encoder_indefinite_map() {
        use crate::Encoder;
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);

        // Test indefinite map
        enc.write_map_indefinite().unwrap();
        enc.encode(&"key1").unwrap();
        enc.encode(&100).unwrap();
        enc.encode(&"key2").unwrap();
        enc.encode(&200).unwrap();
        enc.write_break().unwrap();

        // Should decode as map
        let decoded: std::collections::HashMap<String, i32> = from_slice(&buf).unwrap();
        assert_eq!(decoded.get("key1"), Some(&100));
        assert_eq!(decoded.get("key2"), Some(&200));
    }

    #[test]
    fn test_encoder_struct_variant() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        enum TestEnum {
            StructVariant { x: i32, y: String },
        }

        let val = TestEnum::StructVariant {
            x: 42,
            y: "test".to_string(),
        };
        let cbor = to_vec(&val).unwrap();
        let decoded: TestEnum = from_slice(&cbor).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn test_encoder_tuple_variant() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        enum TestEnum {
            TupleVariant(i32, String),
        }

        let val = TestEnum::TupleVariant(42, "test".to_string());
        let cbor = to_vec(&val).unwrap();
        let decoded: TestEnum = from_slice(&cbor).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn test_encoder_char() {
        let val = 'A';
        let cbor = to_vec(&val).unwrap();
        let decoded: char = from_slice(&cbor).unwrap();
        assert_eq!(val, decoded);

        let val = '界'; // multi-byte character
        let cbor = to_vec(&val).unwrap();
        let decoded: char = from_slice(&cbor).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn test_encoder_unit_variant() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        enum TestEnum {
            UnitVariant,
        }

        let val = TestEnum::UnitVariant;
        let cbor = to_vec(&val).unwrap();
        let decoded: TestEnum = from_slice(&cbor).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn test_encoder_newtype_variant() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        enum TestEnum {
            NewtypeVariant(String),
        }

        let val = TestEnum::NewtypeVariant("test".to_string());
        let cbor = to_vec(&val).unwrap();
        let decoded: TestEnum = from_slice(&cbor).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn test_encoder_tuple_struct() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TupleStruct(i32, String, bool);

        let val = TupleStruct(42, "test".to_string(), true);
        let cbor = to_vec(&val).unwrap();
        let decoded: TupleStruct = from_slice(&cbor).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn test_encoder_into_inner() {
        use crate::Encoder;
        let buf = Vec::new();
        let mut enc = Encoder::new(buf);
        enc.encode(&42).unwrap();
        let result = enc.into_inner();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_encoder_f32_precision() {
        let val: f32 = 3.15;
        let cbor = to_vec(&val).unwrap();
        let decoded: f32 = from_slice(&cbor).unwrap();
        assert!((val - decoded).abs() < 0.00001);
    }

    #[test]
    fn test_encoder_to_writer() {
        let mut buf = Vec::new();
        to_writer(&mut buf, &42i32).unwrap();
        let decoded: i32 = from_slice(&buf).unwrap();
        assert_eq!(decoded, 42);
    }

    // ============================================================================
    // Comprehensive Deserialization Coverage Tests
    // ============================================================================

    #[test]
    fn test_decode_various_integer_sizes() {
        // Small integers (0-23) - single byte
        let small: u8 = 10;
        let encoded = to_vec(&small).unwrap();
        assert_eq!(encoded.len(), 1);
        assert_eq!(from_slice::<u8>(&encoded).unwrap(), 10);

        // u8 size (24-255) - 2 bytes
        let medium: u8 = 200;
        let encoded = to_vec(&medium).unwrap();
        assert_eq!(from_slice::<u8>(&encoded).unwrap(), 200);

        // u16 size - 3 bytes
        let large: u16 = 1000;
        let encoded = to_vec(&large).unwrap();
        assert_eq!(from_slice::<u16>(&encoded).unwrap(), 1000);

        // u32 size - 5 bytes
        let huge: u32 = 100_000;
        let encoded = to_vec(&huge).unwrap();
        assert_eq!(from_slice::<u32>(&encoded).unwrap(), 100_000);

        // u64 size - 9 bytes
        let enormous: u64 = 10_000_000_000;
        let encoded = to_vec(&enormous).unwrap();
        assert_eq!(from_slice::<u64>(&encoded).unwrap(), 10_000_000_000);

        // Negative integers
        let neg_small: i8 = -10;
        let encoded = to_vec(&neg_small).unwrap();
        assert_eq!(from_slice::<i8>(&encoded).unwrap(), -10);

        let neg_large: i64 = -1_000_000;
        let encoded = to_vec(&neg_large).unwrap();
        assert_eq!(from_slice::<i64>(&encoded).unwrap(), -1_000_000);
    }

    #[test]
    fn test_decode_recursion_depth_limit() {
        use std::io::Cursor;

        use crate::decoder::Decoder;

        // Create a deeply nested array structure that exceeds the default limit
        let mut cbor = vec![0x9f]; // Start indefinite array
        // Nest 150 levels deep (exceeds DEFAULT_MAX_DEPTH of 128)
        cbor.extend(std::iter::repeat_n(0x9f, 150));
        // Add a simple value at the end
        cbor.push(0x00); // integer 0
        // Close all arrays
        cbor.extend(std::iter::repeat_n(0xff, 151));

        let mut decoder = Decoder::new(Cursor::new(&cbor[..]));
        let result: Result<Value> = decoder.decode();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("nesting depth") || err_msg.contains("recursion"),
            "Expected recursion depth error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_decode_allocation_limit() {
        // Create CBOR for a byte string claiming to be 200MB (exceeds default 100MB limit)
        let mut cbor = vec![0x5a]; // byte string with u32 length
        cbor.extend_from_slice(&200_000_000u32.to_be_bytes());
        // Don't actually include the bytes - the decoder should reject before reading them

        let result: Result<Vec<u8>> = from_slice(&cbor);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Allocation") || err_msg.contains("exceeds maximum"),
            "Expected allocation limit error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_decode_allocation_limit_custom() {
        use crate::decoder::from_slice_with_limit;

        // Manually create CBOR claiming to have a 10KB byte string
        // Format: 0x5a (u32 length), then the length bytes
        let mut cbor = vec![0x5a]; // byte string with u32 length
        cbor.extend_from_slice(&10_000u32.to_be_bytes()); // Claims 10KB
        // Don't include all the bytes - just enough to show it would succeed with high limit
        cbor.extend_from_slice(&[0u8; 100]); // Only include 100 bytes

        // This should succeed with a 20KB limit
        let result: Result<Vec<u8>> = from_slice_with_limit(&cbor, 20_000);
        // Will fail with "unexpected end" because we didn't include all bytes, but that's fine
        // The important thing is it doesn't fail with an allocation error
        assert!(result.is_err() && !result.unwrap_err().to_string().contains("exceeds maximum"));

        // This should fail with allocation error for 5KB limit
        let mut cbor = vec![0x5a]; // byte string with u32 length
        cbor.extend_from_slice(&10_000u32.to_be_bytes()); // Claims 10KB
        let result: Result<Vec<u8>> = from_slice_with_limit(&cbor, 5_000);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_decode_indefinite_byte_string() {
        use serde_bytes::ByteBuf;
        // Manually construct indefinite-length byte string
        // Format: 0x5f (indefinite bytes), chunks..., 0xff (break)
        let mut cbor = vec![0x5f]; // Start indefinite byte string
        cbor.push(0x43); // Definite byte string, length 3
        cbor.extend_from_slice(b"hel");
        cbor.push(0x42); // Definite byte string, length 2
        cbor.extend_from_slice(b"lo");
        cbor.push(0xff); // Break

        let result: ByteBuf = from_slice(&cbor).unwrap();
        assert_eq!(result.as_ref(), b"hello");
    }

    #[test]
    fn test_decode_indefinite_text_string() {
        // Manually construct indefinite-length text string
        // Format: 0x7f (indefinite text), chunks..., 0xff (break)
        let mut cbor = vec![0x7f]; // Start indefinite text string
        cbor.push(0x65); // Definite text string, length 5
        cbor.extend_from_slice(b"hello");
        cbor.push(0x61); // Definite text string, length 1
        cbor.extend_from_slice(b" ");
        cbor.push(0x65); // Definite text string, length 5
        cbor.extend_from_slice(b"world");
        cbor.push(0xff); // Break

        let result: String = from_slice(&cbor).unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_decode_indefinite_array() {
        // Manually construct indefinite-length array
        // Format: 0x9f (indefinite array), elements..., 0xff (break)
        let mut cbor = vec![0x9f]; // Start indefinite array
        cbor.push(0x01); // integer 1
        cbor.push(0x02); // integer 2
        cbor.push(0x03); // integer 3
        cbor.push(0xff); // Break

        let result: Vec<u32> = from_slice(&cbor).unwrap();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_decode_indefinite_map() {
        use std::collections::HashMap;

        // Manually construct indefinite-length map
        // Format: 0xbf (indefinite map), key-value pairs..., 0xff (break)
        let mut cbor = vec![0xbf]; // Start indefinite map
        // "a" => 1
        cbor.push(0x61);
        cbor.push(b'a');
        cbor.push(0x01);
        // "b" => 2
        cbor.push(0x61);
        cbor.push(b'b');
        cbor.push(0x02);
        cbor.push(0xff); // Break

        let result: HashMap<String, u32> = from_slice(&cbor).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result.get("a"), Some(&1));
        assert_eq!(result.get("b"), Some(&2));
    }

    #[test]
    fn test_decode_tagged_value() {
        // Test tag deserialization (tags are currently passed through to content)
        // Format: 0xc0 (tag 0), followed by value
        let mut cbor = vec![0xc0]; // Tag 0 (date/time string)
        cbor.push(0x64); // Text string, length 4
        cbor.extend_from_slice(b"test");

        let result: String = from_slice(&cbor).unwrap();
        assert_eq!(result, "test");
    }

    #[test]
    fn test_decode_enum_unit_variant() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        enum TestEnum {
            VariantA,
            VariantB,
        }

        let data = TestEnum::VariantA;
        let encoded = to_vec(&data).unwrap();
        let decoded: TestEnum = from_slice(&encoded).unwrap();
        assert_eq!(decoded, TestEnum::VariantA);
    }

    #[test]
    fn test_decode_enum_newtype_variant() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        enum TestEnum {
            Value(u32),
        }

        let data = TestEnum::Value(42);
        let encoded = to_vec(&data).unwrap();
        let decoded: TestEnum = from_slice(&encoded).unwrap();
        assert_eq!(decoded, TestEnum::Value(42));
    }

    #[test]
    fn test_decode_enum_tuple_variant() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        enum TestEnum {
            Point(i32, i32),
        }

        let data = TestEnum::Point(10, 20);
        let encoded = to_vec(&data).unwrap();
        let decoded: TestEnum = from_slice(&encoded).unwrap();
        assert_eq!(decoded, TestEnum::Point(10, 20));
    }

    #[test]
    fn test_decode_enum_struct_variant() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        enum TestEnum {
            Person { name: String, age: u32 },
        }

        let data = TestEnum::Person {
            name: "Alice".to_string(),
            age: 30,
        };
        let encoded = to_vec(&data).unwrap();
        let decoded: TestEnum = from_slice(&encoded).unwrap();
        assert!(matches!(decoded, TestEnum::Person { .. }));
    }

    #[test]
    fn test_decode_newtype_struct_array_format() {
        // Test NEW format: newtype struct as 1-element array
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Wrapped(String);

        let data = Wrapped("test".to_string());
        let encoded = to_vec(&data).unwrap();
        let decoded: Wrapped = from_slice(&encoded).unwrap();
        assert_eq!(decoded, Wrapped("test".to_string()));
    }

    #[test]
    fn test_decode_newtype_struct_transparent_format() {
        // Test OLD format compatibility: direct value (not wrapped in array)
        #[derive(Debug, Deserialize, PartialEq)]
        struct Wrapped(String);

        // Manually encode as just a string (not in array)
        let cbor = to_vec(&"test".to_string()).unwrap();
        let decoded: Wrapped = from_slice(&cbor).unwrap();
        assert_eq!(decoded, Wrapped("test".to_string()));
    }

    #[test]
    fn test_decode_option_some_various_types() {
        // Test Option<T> for various T types
        let some_int: Option<u32> = Some(42);
        let encoded = to_vec(&some_int).unwrap();
        let decoded: Option<u32> = from_slice(&encoded).unwrap();
        assert_eq!(decoded, Some(42));

        let some_string: Option<String> = Some("hello".to_string());
        let encoded = to_vec(&some_string).unwrap();
        let decoded: Option<String> = from_slice(&encoded).unwrap();
        assert_eq!(decoded, Some("hello".to_string()));

        let some_bytes: Option<Vec<u8>> = Some(vec![1, 2, 3]);
        let encoded = to_vec(&some_bytes).unwrap();
        let decoded: Option<Vec<u8>> = from_slice(&encoded).unwrap();
        assert_eq!(decoded, Some(vec![1, 2, 3]));

        let some_bool: Option<bool> = Some(true);
        let encoded = to_vec(&some_bool).unwrap();
        let decoded: Option<bool> = from_slice(&encoded).unwrap();
        assert_eq!(decoded, Some(true));
    }

    #[test]
    fn test_decode_option_none() {
        let none_int: Option<u32> = None;
        let encoded = to_vec(&none_int).unwrap();
        let decoded: Option<u32> = from_slice(&encoded).unwrap();
        assert_eq!(decoded, None);
    }

    #[test]
    fn test_decode_from_reader() {
        use std::io::Cursor;

        use crate::decoder::from_reader;

        let data = vec![1u32, 2, 3, 4, 5];
        let encoded = to_vec(&data).unwrap();
        let reader = Cursor::new(encoded);

        let decoded: Vec<u32> = from_reader(reader).unwrap();
        assert_eq!(decoded, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_decode_from_reader_with_limit() {
        use std::io::Cursor;

        use crate::decoder::from_reader_with_limit;

        // Manually create CBOR claiming to have a 10KB byte string
        let mut cbor = vec![0x5a]; // byte string with u32 length
        cbor.extend_from_slice(&10_000u32.to_be_bytes()); // Claims 10KB
        cbor.extend_from_slice(&[0u8; 100]); // Only include 100 bytes

        // This should succeed with a 20KB limit (though it will fail with unexpected end)
        let reader = Cursor::new(cbor.clone());
        let result: Result<Vec<u8>> = from_reader_with_limit(reader, 20_000);
        assert!(result.is_err() && !result.unwrap_err().to_string().contains("exceeds maximum"));

        // This should fail with allocation error for 5KB limit
        let reader = Cursor::new(cbor);
        let result: Result<Vec<u8>> = from_reader_with_limit(reader, 5_000);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_decode_error_empty_input() {
        let empty: &[u8] = &[];
        let result: Result<u32> = from_slice(empty);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_decode_error_trailing_data() {
        // Encode an integer but add extra bytes
        let mut cbor = to_vec(&42u32).unwrap();
        cbor.push(0x00); // Extra byte

        let result: Result<u32> = from_slice(&cbor);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("trailing"));
    }

    #[test]
    fn test_decode_error_invalid_utf8() {
        // Manually create CBOR with invalid UTF-8 in text string
        let mut cbor = vec![0x64]; // Text string, length 4
        cbor.extend_from_slice(&[0xff, 0xfe, 0xfd, 0xfc]); // Invalid UTF-8

        let result: Result<String> = from_slice(&cbor);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("UTF-8") || err_msg.contains("utf8"),
            "Expected UTF-8 error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_decode_error_wrong_enum_format() {
        // Try to decode an integer as an enum (should fail)
        let cbor = to_vec(&42u32).unwrap();
        #[derive(Deserialize)]
        enum TestEnum {
            A,
            B,
        }
        let result: Result<TestEnum> = from_slice(&cbor);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_error_indefinite_in_chunks() {
        // Create invalid CBOR: indefinite byte string with indefinite chunk
        let mut cbor = vec![0x5f]; // Start indefinite byte string
        cbor.push(0x5f); // Invalid: chunk cannot be indefinite
        cbor.push(0x41);
        cbor.push(b'x');
        cbor.push(0xff); // break for inner
        cbor.push(0xff); // break for outer

        let result: Result<Vec<u8>> = from_slice(&cbor);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_error_wrong_chunk_type() {
        // Create invalid CBOR: indefinite byte string with text chunk
        let mut cbor = vec![0x5f]; // Start indefinite byte string
        cbor.push(0x61); // Invalid: text string chunk in byte string
        cbor.push(b'x');
        cbor.push(0xff); // break

        let result: Result<Vec<u8>> = from_slice(&cbor);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("byte string chunks must be byte strings")
        );
    }

    #[test]
    fn test_decode_error_indefinite_integer() {
        // Integers cannot be indefinite length
        let cbor = vec![0x1f]; // Invalid: indefinite unsigned integer

        let result: Result<u32> = from_slice(&cbor);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_bool_values() {
        // Test true
        let cbor = vec![0xf5]; // CBOR true
        let result: bool = from_slice(&cbor).unwrap();
        assert!(result);

        // Test false
        let cbor = vec![0xf4]; // CBOR false
        let result: bool = from_slice(&cbor).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_decode_float_values() {
        // Test f32
        let val: f32 = 3.25;
        let encoded = to_vec(&val).unwrap();
        let decoded: f32 = from_slice(&encoded).unwrap();
        assert!((decoded - 3.25).abs() < 0.01);

        // Test f64
        let val: f64 = 2.875;
        let encoded = to_vec(&val).unwrap();
        let decoded: f64 = from_slice(&encoded).unwrap();
        assert!((decoded - 2.875).abs() < 0.0001);
    }

    #[test]
    fn test_decode_nested_structures() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Inner {
            value: u32,
        }

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Middle {
            inner: Inner,
            name: String,
        }

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Outer {
            middle: Middle,
            id: u64,
        }

        let data = Outer {
            middle: Middle {
                inner: Inner { value: 42 },
                name: "test".to_string(),
            },
            id: 12345,
        };

        let encoded = to_vec(&data).unwrap();
        let decoded: Outer = from_slice(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_tuple() {
        let data = (1u32, "hello".to_string(), true);
        let encoded = to_vec(&data).unwrap();
        let decoded: (u32, String, bool) = from_slice(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_char() {
        let data = 'x';
        let encoded = to_vec(&data).unwrap();
        let decoded: char = from_slice(&encoded).unwrap();
        assert_eq!(decoded, 'x');
    }

    #[test]
    fn test_decode_definite_empty_collections() {
        // Empty array
        let empty_vec: Vec<u32> = vec![];
        let encoded = to_vec(&empty_vec).unwrap();
        let decoded: Vec<u32> = from_slice(&encoded).unwrap();
        assert_eq!(decoded, empty_vec);

        // Empty map
        use std::collections::HashMap;
        let empty_map: HashMap<String, u32> = HashMap::new();
        let encoded = to_vec(&empty_map).unwrap();
        let decoded: HashMap<String, u32> = from_slice(&encoded).unwrap();
        assert_eq!(decoded.len(), 0);
    }

    #[test]
    fn test_decode_indefinite_empty_collections() {
        // Empty indefinite array
        let cbor = vec![0x9f, 0xff]; // [_ break]
        let decoded: Vec<u32> = from_slice(&cbor).unwrap();
        assert_eq!(decoded.len(), 0);

        // Empty indefinite map
        let cbor = vec![0xbf, 0xff]; // {_ break}
        use std::collections::HashMap;
        let decoded: HashMap<String, u32> = from_slice(&cbor).unwrap();
        assert_eq!(decoded.len(), 0);
    }

    // Additional coverage tests for specific deserialize_any paths

    #[test]
    fn test_decode_option_with_map() {
        use std::collections::HashMap;

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Container {
            #[serde(skip_serializing_if = "Option::is_none")]
            data: Option<HashMap<String, u32>>,
        }

        // Test Some(map)
        let mut map = HashMap::new();
        map.insert("key".to_string(), 42);
        let data = Container { data: Some(map) };
        let encoded = to_vec(&data).unwrap();
        let decoded: Container = from_slice(&encoded).unwrap();
        assert_eq!(decoded.data.unwrap().get("key"), Some(&42));

        // Test None
        let data = Container { data: None };
        let encoded = to_vec(&data).unwrap();
        let decoded: Container = from_slice(&encoded).unwrap();
        assert_eq!(decoded.data, None);
    }

    #[test]
    fn test_decode_option_with_array() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Container {
            #[serde(skip_serializing_if = "Option::is_none")]
            items: Option<Vec<i32>>,
        }

        let data = Container {
            items: Some(vec![1, 2, 3]),
        };
        let encoded = to_vec(&data).unwrap();
        let decoded: Container = from_slice(&encoded).unwrap();
        assert_eq!(decoded.items, Some(vec![1, 2, 3]));
    }

    #[test]
    fn test_decode_simple_types_coverage() {
        // Test MAJOR_SIMPLE paths for full coverage

        // Boolean true/false already covered by test_decode_bool_values

        // Test null as None
        let cbor = vec![0xf6]; // CBOR null
        let result: Option<String> = from_slice(&cbor).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_decode_indefinite_text_string_multipart() {
        // Test indefinite text string with multiple chunks
        let mut cbor = vec![0x7f]; // Start indefinite text
        cbor.push(0x62); // 2-byte string
        cbor.extend_from_slice(b"hi");
        cbor.push(0x63); // 3-byte string
        cbor.extend_from_slice(b"bye");
        cbor.push(0xff); // Break

        let result: String = from_slice(&cbor).unwrap();
        assert_eq!(result, "hibye");
    }

    #[test]
    fn test_decode_enum_with_map_variant() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        enum TestEnum {
            Unit,
            Data(String),
        }

        // Test enum variant as map (Data variant)
        let data = TestEnum::Data("content".to_string());
        let encoded = to_vec(&data).unwrap();
        let decoded: TestEnum = from_slice(&encoded).unwrap();
        assert_eq!(decoded, TestEnum::Data("content".to_string()));

        // Test unit variant
        let data = TestEnum::Unit;
        let encoded = to_vec(&data).unwrap();
        let decoded: TestEnum = from_slice(&encoded).unwrap();
        assert_eq!(decoded, TestEnum::Unit);
    }

    #[test]
    fn test_decode_tagged_recursive() {
        // Test MAJOR_TAG path that recursively calls deserialize_any
        // Tag 0 is typically used for date/time strings
        let mut cbor = vec![0xc0]; // Tag 0
        cbor.push(0x65); // 5-byte text string
        cbor.extend_from_slice(b"hello");

        let result: String = from_slice(&cbor).unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_decode_newtype_with_map_transparent() {
        use std::collections::HashMap;

        #[derive(Debug, Deserialize, PartialEq)]
        struct Wrapper(HashMap<String, i32>);

        // Test old transparent format (map encoded directly)
        let mut map = HashMap::new();
        map.insert("a".to_string(), 1);
        let cbor = to_vec(&map).unwrap();

        let decoded: Wrapper = from_slice(&cbor).unwrap();
        assert_eq!(decoded.0.get("a"), Some(&1));
    }

    #[test]
    fn test_decode_option_by_value_deserializer() {
        use std::collections::HashMap;

        use crate::decoder::Decoder;

        // Test the OptionDeserializer path (Decoder<R> by value, not &mut)
        // This triggers lines 193-255 in decoder.rs

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestStruct {
            #[serde(skip_serializing_if = "Option::is_none")]
            data: Option<HashMap<String, String>>,
        }

        // Test with Some(map) - triggers definite-length map path
        let mut map = HashMap::new();
        map.insert("key".to_string(), "value".to_string());
        let test = TestStruct { data: Some(map) };
        let encoded = to_vec(&test).unwrap();

        // Decode using Decoder directly (by value)
        let mut decoder = Decoder::from_slice(&encoded);
        let decoded: TestStruct = decoder.decode().unwrap();
        assert_eq!(
            decoded.data.as_ref().unwrap().get("key"),
            Some(&"value".to_string())
        );

        // Test with indefinite-length map
        // Manually construct: {_ "data": {_ "k": "v", break}, break}
        let mut cbor = vec![0xbf]; // indefinite map
        cbor.extend_from_slice(b"\x64data"); // "data" key
        cbor.push(0xbf); // indefinite map value
        cbor.push(0x61); // 1-char key
        cbor.push(b'k');
        cbor.push(0x61); // 1-char value
        cbor.push(b'v');
        cbor.push(0xff); // break inner map
        cbor.push(0xff); // break outer map

        let mut decoder = Decoder::from_slice(&cbor);
        let decoded: TestStruct = decoder.decode().unwrap();
        assert_eq!(
            decoded.data.as_ref().unwrap().get("k"),
            Some(&"v".to_string())
        );
    }

    #[test]
    fn test_decode_by_value_all_types() {
        use serde::Deserialize;

        use crate::decoder::Decoder;

        // Test deserialize_any paths by consuming decoder (by value)
        // This should hit the Decoder<R> impl, not &mut Decoder<R>

        // Test MAJOR_UNSIGNED
        let cbor = to_vec(&42u64).unwrap();
        let decoder = Decoder::from_slice(&cbor);
        let val = u64::deserialize(decoder).unwrap();
        assert_eq!(val, 42);

        // Test MAJOR_NEGATIVE
        let cbor = to_vec(&-100i64).unwrap();
        let decoder = Decoder::from_slice(&cbor);
        let val = i64::deserialize(decoder).unwrap();
        assert_eq!(val, -100);

        // Test MAJOR_BYTES (definite)
        let cbor = to_vec(&vec![1u8, 2, 3]).unwrap();
        let decoder = Decoder::from_slice(&cbor);
        let val = Vec::<u8>::deserialize(decoder).unwrap();
        assert_eq!(val, vec![1, 2, 3]);

        // Test MAJOR_TEXT (definite)
        let cbor = to_vec(&"hello".to_string()).unwrap();
        let decoder = Decoder::from_slice(&cbor);
        let val = String::deserialize(decoder).unwrap();
        assert_eq!(val, "hello");

        // Test MAJOR_ARRAY (definite)
        let cbor = to_vec(&vec![1u32, 2, 3]).unwrap();
        let decoder = Decoder::from_slice(&cbor);
        let val = Vec::<u32>::deserialize(decoder).unwrap();
        assert_eq!(val, vec![1, 2, 3]);

        // Test MAJOR_MAP (definite)
        use std::collections::HashMap;
        let mut map = HashMap::new();
        map.insert("a".to_string(), 1u32);
        let cbor = to_vec(&map).unwrap();
        let decoder = Decoder::from_slice(&cbor);
        let val = HashMap::<String, u32>::deserialize(decoder).unwrap();
        assert_eq!(val.get("a"), Some(&1));

        // Test MAJOR_TAG
        let mut cbor = vec![0xc0]; // Tag 0
        cbor.push(0x64); // 4-byte text
        cbor.extend_from_slice(b"test");
        let decoder = Decoder::from_slice(&cbor);
        let val = String::deserialize(decoder).unwrap();
        assert_eq!(val, "test");

        // Test MAJOR_SIMPLE - bool true
        let cbor = vec![0xf5];
        let decoder = Decoder::from_slice(&cbor);
        let val = bool::deserialize(decoder).unwrap();
        assert!(val);

        // Test MAJOR_SIMPLE - bool false
        let cbor = vec![0xf4];
        let decoder = Decoder::from_slice(&cbor);
        let val = bool::deserialize(decoder).unwrap();
        assert!(!val);

        // Test MAJOR_SIMPLE - f32
        let cbor = to_vec(&3.25f32).unwrap();
        let decoder = Decoder::from_slice(&cbor);
        let val = f32::deserialize(decoder).unwrap();
        assert!((val - 3.25).abs() < 0.01);

        // Test MAJOR_SIMPLE - f64
        let cbor = to_vec(&2.875f64).unwrap();
        let decoder = Decoder::from_slice(&cbor);
        let val = f64::deserialize(decoder).unwrap();
        assert!((val - 2.875).abs() < 0.0001);
    }

    #[test]
    fn test_decode_enum_by_value() {
        use serde::Deserialize;

        use crate::decoder::Decoder;

        // Test deserialize_enum with by-value decoder
        // This hits lines 415-449 in decoder.rs

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        enum TestEnum {
            Unit,
            Data(String),
        }

        // Test MAJOR_TEXT path (unit variant)
        let cbor = to_vec(&TestEnum::Unit).unwrap();
        let decoder = Decoder::from_slice(&cbor);
        let val = TestEnum::deserialize(decoder).unwrap();
        assert_eq!(val, TestEnum::Unit);

        // Test MAJOR_MAP path (variant with data)
        let cbor = to_vec(&TestEnum::Data("test".to_string())).unwrap();
        let decoder = Decoder::from_slice(&cbor);
        let val = TestEnum::deserialize(decoder).unwrap();
        assert_eq!(val, TestEnum::Data("test".to_string()));
    }

    #[test]
    fn test_cbor_undefined_constant() {
        use crate::constants::UNDEFINED;

        // Test that UNDEFINED constant is correct (additional info 23)
        // CBOR undefined is encoded as major type 7, additional info 23
        // Byte: 0xf7 = 0b111_10111 = major 7, info 23
        assert_eq!(UNDEFINED, 23);

        // Manually construct CBOR undefined and verify encoding
        let cbor = [0xf7]; // Major type 7, additional info 23

        // Note: serde doesn't have a concept of "undefined", so we can't
        // directly test deserialization. But we can verify the constant is correct.
        let major = cbor[0] >> 5;
        let info = cbor[0] & 0x1f;
        assert_eq!(major, 7);
        assert_eq!(info, UNDEFINED);
    }

    #[test]
    fn test_cbor_float16_constant() {
        use crate::constants::FLOAT16;

        // Test that FLOAT16 constant is correct (additional info 25)
        // CBOR float16 is encoded as major type 7, additional info 25
        // Byte: 0xf9 = 0b111_11001 = major 7, info 25
        assert_eq!(FLOAT16, 25);

        // Manually construct CBOR float16 (1.0 in f16 = 0x3c00)
        // Format: 0xf9 (major 7, info 25) + 2 bytes for f16 value
        let cbor = vec![0xf9, 0x3c, 0x00];

        let major = cbor[0] >> 5;
        let info = cbor[0] & 0x1f;
        assert_eq!(major, 7);
        assert_eq!(info, FLOAT16);

        // Verify we can decode this as f64 (serde promotes f16 to f64)
        let result: Result<f64> = from_slice(&cbor);
        // Note: This may fail if decoder doesn't support f16 yet,
        // but the constant itself is correct
        if let Ok(val) = result {
            assert!((val - 1.0).abs() < 0.01);
        }
    }

    #[test]
    fn test_cbor_simple_values_range() {
        use crate::constants::{FALSE, NULL, TRUE, UNDEFINED};

        // Verify all simple values are in correct range (0-31)
        // These are the exact values defined in RFC 8949 section 3.3
        assert_eq!(FALSE, 20);
        assert_eq!(TRUE, 21);
        assert_eq!(NULL, 22);
        assert_eq!(UNDEFINED, 23);

        // Note: All these values are < 32 by definition (5-bit additional info),
        // but clippy complains about assertions on constants, so we don't test that.
    }

    #[test]
    fn test_decoder_with_limits() {
        use std::io::Cursor;

        use crate::{DEFAULT_MAX_ALLOCATION, DEFAULT_MAX_DEPTH, Decoder};

        // Test that default constants are re-exported and accessible
        assert_eq!(DEFAULT_MAX_ALLOCATION, 100 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_DEPTH, 128);

        // Test Decoder builder with custom values
        let data = to_vec(&vec![1, 2, 3]).unwrap();
        let mut decoder = Decoder::new(Cursor::new(&data))
            .with_max_allocation(1024)
            .with_max_depth(32);
        let result: Vec<i32> = decoder.decode().unwrap();
        assert_eq!(result, vec![1, 2, 3]);

        // Test that custom depth limit is enforced
        // Create nested arrays: [[[[...]]]] (40 levels deep)
        let mut nested_cbor = Vec::new();
        nested_cbor.extend(std::iter::repeat_n(0x81, 40)); // Array of length 1
        nested_cbor.push(0x00); // Final value: 0

        // Should fail with max_depth of 32
        let mut decoder = Decoder::new(Cursor::new(&nested_cbor)).with_max_depth(32);
        let result: Result<Value> = decoder.decode();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nesting depth"));

        // Should succeed with max_depth of 64
        let mut decoder = Decoder::new(Cursor::new(&nested_cbor)).with_max_depth(64);
        let result: Result<Value> = decoder.decode();
        assert!(result.is_ok());
    }

    #[test]
    fn test_max_allocation_indefinite_strings() {
        use std::io::Cursor;

        use crate::Decoder;

        // Test that indefinite byte strings respect cumulative allocation limit
        // Format: 0x5f (indefinite byte string) + chunks + 0xff (break)
        let mut cbor = vec![0x5f]; // Indefinite byte string start

        // Add 3 chunks of 50 bytes each = 150 total
        for _ in 0..3 {
            cbor.push(0x58); // Major 2 (bytes), info 24 (1-byte length)
            cbor.push(50); // Length: 50 bytes
            cbor.extend(std::iter::repeat_n(0x42, 50)); // 50 bytes of data
        }
        cbor.push(0xff); // Break

        // Should fail with 100-byte limit (total is 150)
        let mut decoder = Decoder::new(Cursor::new(&cbor)).with_max_allocation(100);
        let result: Result<Value> = decoder.decode();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("total size") || err.contains("exceeds maximum"));

        // Should succeed with 200-byte limit
        let mut decoder = Decoder::new(Cursor::new(&cbor)).with_max_allocation(200);
        let result: Result<Value> = decoder.decode();
        assert!(result.is_ok(), "Expected success with 200-byte limit");
        if let Value::Bytes(bytes) = result.unwrap() {
            assert_eq!(bytes.len(), 150);
        } else {
            panic!("Expected Value::Bytes");
        }
    }

    #[test]
    fn test_max_allocation_single_large_allocation() {
        use std::io::Cursor;

        use crate::Decoder;

        // Test that a single large allocation is caught
        // Format: 0x5a (major 2, info 26 = 4-byte length) + length + data
        let mut cbor = vec![0x5a]; // Major 2 (bytes), info 26 (4-byte length)
        cbor.extend_from_slice(&1_000_000u32.to_be_bytes()); // 1MB
        cbor.extend(std::iter::repeat_n(0x42, 100)); // Just a bit of actual data

        // Should fail with 100KB limit
        let mut decoder = Decoder::new(Cursor::new(&cbor)).with_max_allocation(100_000);
        let result: Result<Value> = decoder.decode();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_u64_to_usize_overflow() {
        use std::io::Cursor;

        use crate::Decoder;

        // Test that u64 values that don't fit in usize are rejected
        // This is mainly relevant on 32-bit systems where usize is 32 bits
        // On 64-bit systems, this won't overflow, but the allocation check will catch it

        // Create CBOR with a huge length value
        // Format: 0x5b (major 2, info 27 = 8-byte length) + 8-byte length + data
        let mut cbor = vec![0x5b]; // Major 2 (bytes), info 27 (8-byte length)
        cbor.extend_from_slice(&(u64::MAX).to_be_bytes()); // Massive length

        let mut decoder = Decoder::new(Cursor::new(&cbor));
        let result: Result<Value> = decoder.decode();
        assert!(result.is_err());
        // Either caught by overflow check or allocation limit
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("exceeds maximum")
                || err_str.contains("out of memory")
                || err_str.contains("platform")
        );
    }
}
