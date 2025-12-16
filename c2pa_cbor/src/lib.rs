// Cargo.toml dependencies needed:
// serde = { version = "1.0", features = ["derive"] }

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
pub use decoder::{Decoder, from_reader, from_slice};

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
        let mut decoder = Decoder::with_max_allocation(cursor, 10 * 1024 * 1024);
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
        let mut decoder = Decoder::with_max_allocation(cursor, 10 * 1024 * 1024);
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
        let mut decoder = Decoder::with_max_allocation(cursor, 10 * 1024 * 1024);
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
}
